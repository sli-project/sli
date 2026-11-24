using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Agent.Core;
using Sli.Server.Agents.Ingress;
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.Control;
using Sli.Server.Storage.Direct;

namespace Sli.Server.Agents.FileAudit;

public sealed record FileAuditInboxStep(bool Scanned,bool Imported,string? PendingReason,DateTime Received,Guid PacketId);
internal sealed class FileAuditPending(string code) : Exception(code) { public string Code { get; }=code; }

// No host registration: caller supplies an open connection and owns polling and transaction.
public static class FileAuditInboxConsumer
{
    private static string Text(JsonNode? node)=>JsonRead.TryString(node,out var text)?text:throw new InvalidDataException();
    public static async Task<FileAuditInboxStep> ProcessNextAsync(NpgsqlConnection db,NpgsqlTransaction tx,(DateTime Received,Guid Packet)? after,CancellationToken ct)
    {
        Guid packet;DateTime received;JsonObject envelope,body;JsonArray rows;
        await using(var command=new NpgsqlCommand("""
            select packet_id,received_at,envelope::text,packet::text,event_rows::text from sli_agent_packet_inbox i
            where imported_at is null and module_disabled_at is null and envelope->>'module_id'='sli.file-audit'
              and not exists(select 1 from sli_agent_packet_quarantine q where q.packet_id=i.packet_id)
              and (@after_time is null or (received_at,packet_id)>(@after_time,@after_packet))
            order by received_at,packet_id limit 1 for update skip locked
            """,db,tx)) {
            command.Parameters.AddWithValue("after_time",NpgsqlDbType.TimestampTz,after is null?DBNull.Value:after.Value.Received);
            command.Parameters.AddWithValue("after_packet",NpgsqlDbType.Uuid,after is null?DBNull.Value:after.Value.Packet);
            await using var reader=await command.ExecuteReaderAsync(ct);if(!await reader.ReadAsync(ct)) return new(false,false,null,default,default);
            packet=reader.GetGuid(0);received=reader.GetDateTime(1);envelope=JsonNode.Parse(reader.GetString(2))!.AsObject();body=JsonNode.Parse(reader.GetString(3))!.AsObject();rows=JsonNode.Parse(reader.GetString(4))!.AsArray();
        }
        await tx.SaveAsync("file_projection",ct);string? reason=null;
        try { await ImportClaimedAsync(db,tx,packet,envelope,body,rows,ct); }
        catch(FileAuditPending e) { reason=e.Code;await tx.RollbackAsync("file_projection",ct); }
        catch(OperationCanceledException) when(ct.IsCancellationRequested) { throw; }
        catch(Exception) { reason="agent_projection_failed";await tx.RollbackAsync("file_projection",ct); }
        if(reason is null || reason=="module_disabled") { await using var mark=new NpgsqlCommand(reason=="module_disabled"
            ? "update sli_agent_packet_inbox set module_disabled_at=clock_timestamp() where packet_id=@packet"
            : "update sli_agent_packet_inbox set imported_at=clock_timestamp() where packet_id=@packet",db,tx); mark.Parameters.AddWithValue("packet",packet);if(await mark.ExecuteNonQueryAsync(ct)!=1) throw new InvalidOperationException(); }
        return new(true,reason is null,reason,received,packet);
    }
    internal static async Task ImportClaimedAsync(NpgsqlConnection db,NpgsqlTransaction tx,Guid packet,JsonObject data,JsonObject body,JsonArray rows,CancellationToken ct,DirectAdDcRuntime? direct=null)
    {
        var envelope=Envelope.Parse(data);Guid agent=Guid.Parse(envelope.AgentId);
        if(envelope.ModuleId!="sli.file-audit" || Guid.Parse(envelope.PacketId)!=packet) throw new FileAuditPending("agent_packet_attestation_invalid");
        Guid host;JsonArray assigned;
        await using(var command=new NpgsqlCommand("select status,host_id,source_host_id,assigned_modules::text from sli_agents where id=@id for update",db,tx)) {
            command.Parameters.AddWithValue("id",agent);await using var reader=await command.ExecuteReaderAsync(ct);
            if(!await reader.ReadAsync(ct) || reader.GetString(0)!="active") throw new FileAuditPending("agent_disabled");
            if(reader.IsDBNull(1) && reader.IsDBNull(2)) throw new FileAuditPending("agent_identity_unavailable");host=reader.IsDBNull(2)?reader.GetGuid(1):reader.GetGuid(2);assigned=JsonNode.Parse(reader.GetString(3))!.AsArray();
        }
        if(assigned.OfType<JsonObject>().Any(m=>m["module_id"]?.ToString()=="sli.file-audit" && m["enabled"]?.ToJsonString()=="false"))
            throw new FileAuditPending("module_disabled");
        var current=AgentPolicyAssignments.FindCurrent(assigned,"sli.file-audit") ?? throw new FileAuditPending("agent_module_not_assigned");
        await using(var command=new NpgsqlCommand("select envelope::text,envelope_sha256 from sli_agent_receipts where packet_id=@packet and agent_id=@agent and module_id='sli.file-audit'",db,tx)) {
            command.Parameters.AddWithValue("packet",packet);command.Parameters.AddWithValue("agent",agent);await using var reader=await command.ExecuteReaderAsync(ct);
            if(!await reader.ReadAsync(ct) || !PythonMetadataEquality.Equal(JsonNode.Parse(reader.GetString(0)),data) || reader.GetString(1)!=Packets.Digest(data) || envelope.PayloadSha256!=Packets.Digest(body)) throw new FileAuditPending("agent_packet_attestation_invalid");
        }
        var captured=await AgentPolicyAssignments.ResolveAsync(db,tx,assigned,agent,"sli.file-audit",envelope.PolicyRevision,ct) ?? throw new FileAuditPending("file_audit_policy_not_retained");
        var config=AgentFileAuditPolicy.Parse(captured["config"] as JsonObject ?? new JsonObject());var currentConfig=current["config"] as JsonObject ?? new JsonObject();
        if(!PythonMetadataEquality.Equal(currentConfig["source_name"],config.Value["source_name"]) || Text(currentConfig["source_kind"] ?? JsonValue.Create("server"))!=Text(config.Value["source_kind"] ?? JsonValue.Create("server"))) throw new FileAuditPending("file_audit_source_binding_changed");
        if(config.Workstation) {
            if(!assigned.OfType<JsonObject>().Any(x=>x["module_id"]?.GetValue<string>()=="sli.workstations" && x["enabled"] is JsonValue flag && flag.TryGetValue<bool>(out var enabled) && enabled)) throw new FileAuditPending("file_audit_workstation_not_assigned");
        }
        JsonArray verified;
        try { verified=AgentFileAuditValidator.Validate(envelope,body,config,host); }
        catch(ProtocolException) { throw new FileAuditPending("agent_packet_attestation_invalid"); }
        if(!PythonMetadataEquality.Equal(verified,rows)) throw new FileAuditPending("agent_packet_attestation_invalid");
        if(!await AgentPolicyAssignments.ModuleEnabledAsync(db,tx,envelope.ModuleId,ct)) throw new FileAuditPending("module_disabled");
        // Keep the verified raw journal-clear receipt and inbox evidence without creating a file action.
        if(!config.Workstation && body["context"]?["read_error"]?.GetValue<string>()=="file_audit_journal_gap"
            && rows.Count==1 && rows[0]?["event_id"]?.GetValue<int>()==1102) return;
        if(body["records"]!.AsArray().Any(r=>r?["format"]?.GetValue<string>()!="file_action"))
            throw new FileAuditPending("agent_packet_attestation_invalid");
        await using var write=new NpgsqlCommand("select public.write_file_actions389(@packet,@rows)",db,tx) { CommandTimeout=0 };
        write.Parameters.AddWithValue("packet",packet);
        write.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,rows.ToJsonString());
        await write.ExecuteNonQueryAsync(ct);
    }
}
