using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Agents.Ingress;
using Sli.Server.Sources;

namespace Sli.Server.Storage.Direct;

// Source: nps_agent_import.import_nps_agent_packet. All checks and the inbox
// acknowledgement run in the caller transaction; worker publication is replayable.
internal static class DirectNpsPacket
{
    internal static async Task ImportAsync(NpgsqlConnection db,NpgsqlTransaction tx,NpgsqlDataSource worker,
        Guid packetId,JsonObject envelopeNode,JsonObject packet,JsonArray rows,string catalogPath,CancellationToken ct,bool pluginAdmission=false)
    {
        string enabled=Environment.GetEnvironmentVariable("SLI_NPS_AGENT_IMPORT_ENABLED") ?? "0";
        if(enabled=="0") throw new InvalidOperationException("agent_nps_import_disabled");
        if(enabled!="1") throw new InvalidOperationException("agent_nps_import_config_invalid");
        if(!pluginAdmission && (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR")) || !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR"))))
            throw new InvalidOperationException("agent_plugin_admission_pending");
        using var queue = await new PostgresImportQueue().AcquireAsync(
            JsonRead.TryString(packet["header"]?["source"], out var sourceName) ? sourceName : null, ct);
        var e=Envelope.Parse(envelopeNode);
        if(e.ModuleId!=NpsPolicy.Nps || !Guid.TryParse(e.PacketId,out var parsed) || parsed!=packetId || !Guid.TryParse(e.AgentId,out var agent))
            throw new InvalidOperationException("agent_packet_attestation_invalid");
        JsonArray assignments;
        await using(var cmd=new NpgsqlCommand("select status,assigned_modules::text from public.lock_nps_import_agent_v304(@id)",db,tx)) {
            cmd.Parameters.AddWithValue("id",agent);await using var reader=await cmd.ExecuteReaderAsync(ct);
            if(!await reader.ReadAsync(ct) || reader.GetString(0)!="active") throw new InvalidOperationException("agent_disabled");
            assignments=JsonNode.Parse(reader.GetString(1))!.AsArray();
        }
        var assignment=AgentPolicyAssignments.FindCurrent(assignments,NpsPolicy.Nps) ?? throw new InvalidOperationException("agent_module_not_assigned");
        NpsPolicy policy;
        try { policy=NpsPolicy.Parse(NpsPolicy.Nps,assignment["config"] as JsonObject ?? new JsonObject()); }
        catch(AgentException) { throw new InvalidOperationException("agent_module_not_assigned"); }
        if(e.SourceInstanceId!=policy.SourceId) throw new InvalidOperationException("agent_source_binding_changed");
        await using(var cmd=new NpgsqlCommand("select envelope::text,envelope_sha256 from sli_agent_receipts where packet_id=@packet and agent_id=@agent and module_id=@module",db,tx)) {
            cmd.Parameters.AddWithValue("packet",packetId);cmd.Parameters.AddWithValue("agent",agent);cmd.Parameters.AddWithValue("module",NpsPolicy.Nps);
            await using var reader=await cmd.ExecuteReaderAsync(ct);
            if(!await reader.ReadAsync(ct) || !PythonMetadataEquality.Equal(JsonNode.Parse(reader.GetString(0)),envelopeNode) || reader.GetString(1)!=Packets.Digest(envelopeNode) || e.PayloadSha256!=Packets.Digest(packet))
                throw new InvalidOperationException("agent_packet_attestation_invalid");
        }
        await using(var cmd=new NpgsqlCommand("select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'))",db,tx)) await cmd.ExecuteNonQueryAsync(ct);
        await using(var cmd=new NpgsqlCommand("select installed,enabled from read_plugin_states_v1() where plugin_id='sli.remote-access'",db,tx)) {
            await using var reader=await cmd.ExecuteReaderAsync(ct);
            if(!await reader.ReadAsync(ct) || !reader.GetBoolean(0) || !reader.GetBoolean(1)) throw new InvalidOperationException("agent_plugin_disabled");
        }
        if(packet["header"]?["source"]?.GetValue<string>()!=policy.Text("source_name") || !PythonMetadataEquality.Equal(AgentCollectionRows.ExtractEvents(packet),rows))
            throw new InvalidOperationException("agent_packet_attestation_invalid");
        long server,domain;long? site;
        await using(var cmd=new NpgsqlCommand("select id,domain_id,site_id from servers where hostname=@name and is_active",db,tx)) {
            cmd.Parameters.AddWithValue("name",policy.Text("source_name"));await using var reader=await cmd.ExecuteReaderAsync(ct);
            if(!await reader.ReadAsync(ct)) throw new InvalidOperationException("agent_nps_source_not_configured");
            server=reader.GetInt64(0);domain=reader.GetInt64(1);site=reader.IsDBNull(2)?null:reader.GetInt64(2);
            if(await reader.ReadAsync(ct)) throw new InvalidOperationException("agent_nps_source_not_configured");
        }
        if(rows.Count==0) return;
        await DirectAdDcPacket.PublishAsync(db,tx,worker,e,packet,rows,catalogPath,policy.Text("source_name"),server,domain,site,ct);
    }
}
