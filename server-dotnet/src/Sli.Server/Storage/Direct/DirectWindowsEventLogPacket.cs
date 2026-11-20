using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.Ingress;

namespace Sli.Server.Storage.Direct;

// The legacy generic module uses record-id cursors, not the AD/DC bookmark
// contract. Only publication is shared with the admitted native-event importer.
internal static class DirectWindowsEventLogPacket
{
    internal const string Module="sli.windows-eventlog";
    internal static async Task ImportAsync(NpgsqlConnection db,NpgsqlTransaction tx,NpgsqlDataSource worker,
        Guid packetId,JsonObject envelopeNode,JsonObject packet,JsonArray rows,string catalogPath,CancellationToken ct)
    {
        _=await DirectRuntimeAuthorization.LoadAsync(db,tx,DateTime.UtcNow,ct)
            ?? throw new InvalidOperationException("agent_storage_unavailable");
        var envelope=Envelope.Parse(envelopeNode);
        if(envelope.ModuleId!=Module || !Guid.TryParse(envelope.PacketId,out var parsedPacket) || parsedPacket!=packetId ||
            !Guid.TryParse(envelope.AgentId,out var agentId) || envelope.PayloadContract!=CollectionPacket.Contract)
            throw new InvalidOperationException("agent_packet_attestation_invalid");

        JsonArray assignments;
        // Assignment/lifecycle writers lock the agent first, as in the AD/DC importer.
        await using(var agent=new NpgsqlCommand("select status,assigned_modules::text from sli_agents where id=@id for key share",db,tx)) {
            agent.Parameters.AddWithValue("id",agentId);await using var reader=await agent.ExecuteReaderAsync(ct);
            if(!await reader.ReadAsync(ct) || reader.GetString(0)!="active")throw new InvalidOperationException("agent_disabled");
            assignments=JsonNode.Parse(reader.GetString(1))!.AsArray();
        }
        var assigned=assignments.Where(node=>node is JsonValue value && value.TryGetValue<string>(out var id) && id==Module ||
            node is JsonObject obj && Text(obj["module_id"])==Module).ToArray();
        if(assigned.Length!=1 || assigned[0] is JsonObject assignment &&
            (assignment["enabled"] is not JsonValue enabled || !enabled.TryGetValue<bool>(out var on) || !on))
            throw new InvalidOperationException("agent_module_not_assigned");

        await using(var receipt=new NpgsqlCommand("select envelope::text,envelope_sha256 from sli_agent_receipts where packet_id=@packet and agent_id=@agent and module_id=@module",db,tx)) {
            receipt.Parameters.AddWithValue("packet",packetId);receipt.Parameters.AddWithValue("agent",agentId);receipt.Parameters.AddWithValue("module",Module);
            await using var reader=await receipt.ExecuteReaderAsync(ct);
            if(!await reader.ReadAsync(ct) || !WorkstationJsonEquality.Equals(JsonNode.Parse(reader.GetString(0)),envelopeNode) ||
                reader.GetString(1)!=Packets.Digest(envelopeNode) || envelope.PayloadSha256!=Packets.Digest(packet))
                throw new InvalidOperationException("agent_packet_attestation_invalid");
        }

        string sourceName;
        await using(var binding=new NpgsqlCommand("""
            select source_instance_id,source_name,channel,module_version from sli_agent_module_bindings
            where agent_id=@agent and module_id=@module
            """,db,tx)) {
            binding.Parameters.AddWithValue("agent",agentId);binding.Parameters.AddWithValue("module",Module);
            await using var reader=await binding.ExecuteReaderAsync(ct);
            if(!await reader.ReadAsync(ct) || reader.GetString(0)!=envelope.SourceInstanceId || reader.GetString(2)!=envelope.Channel ||
                reader.GetString(3)!=envelope.ModuleVersion)throw new InvalidOperationException("agent_eventlog_source_not_bound");
            sourceName=reader.GetString(1);
        }
        // Like AD/DC, a later policy revision does not invalidate already
        // acknowledged evidence. Source identity, channel and version must match.
        if(Text(packet["header"]?["source"])!=sourceName)throw new InvalidOperationException("agent_eventlog_source_not_bound");
        try {
            var validated=EventLogValidator.Validate(envelope,packet,sourceName);
            if(!WorkstationJsonEquality.Equals(validated,rows) || envelope.RecordCount!=rows.Count || envelope.PayloadBytes!=CanonicalJson.Length(packet))
                throw new InvalidOperationException("agent_packet_attestation_invalid");
        } catch(ProtocolException) { throw new InvalidOperationException("agent_packet_attestation_invalid"); }

        long serverId,domainId;long? siteId;
        await using(var source=new NpgsqlCommand("select id,domain_id,site_id from servers where hostname=@source and is_active",db,tx)) {
            source.Parameters.AddWithValue("source",sourceName);await using var reader=await source.ExecuteReaderAsync(ct);
            if(!await reader.ReadAsync(ct))throw new InvalidOperationException("agent_eventlog_source_not_configured");
            serverId=reader.GetInt64(0);domainId=reader.GetInt64(1);siteId=reader.IsDBNull(2)?null:reader.GetInt64(2);
            if(await reader.ReadAsync(ct))throw new InvalidOperationException("agent_eventlog_source_not_configured");
        }
        // Preparation verifies every native XML row before independent worker
        // reservations. Publication retains raw provenance, immutable identities,
        // verified chunks and replayable state jobs; no extra hot-layer storage.
        try {
            await DirectAdDcPacket.PublishAsync(db,tx,worker,envelope,packet,rows,catalogPath,sourceName,serverId,domainId,siteId,ct);
        } catch(InvalidOperationException error) when(error.Message=="agent_ad_dc_channel_not_configured") {
            throw new InvalidOperationException("agent_eventlog_channel_not_configured");
        }
    }
    private static string? Text(JsonNode? node)=>JsonRead.TryString(node,out var value)?value:null;
}
