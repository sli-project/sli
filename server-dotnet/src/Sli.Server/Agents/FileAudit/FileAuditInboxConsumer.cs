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
        bool transportGap;
        await using(var command=new NpgsqlCommand("select envelope::text,envelope_sha256,coalesce(receipt->'transport_gap'='true'::jsonb,false) from sli_agent_receipts where packet_id=@packet and agent_id=@agent and module_id='sli.file-audit'",db,tx)) {
            command.Parameters.AddWithValue("packet",packet);command.Parameters.AddWithValue("agent",agent);await using var reader=await command.ExecuteReaderAsync(ct);
            if(!await reader.ReadAsync(ct) || !PythonMetadataEquality.Equal(JsonNode.Parse(reader.GetString(0)),data) || reader.GetString(1)!=Packets.Digest(data) || envelope.PayloadSha256!=Packets.Digest(body)) throw new FileAuditPending("agent_packet_attestation_invalid");
            transportGap=reader.GetBoolean(2);
        }
        var captured=await AgentPolicyAssignments.ResolveAsync(db,tx,assigned,agent,"sli.file-audit",envelope.PolicyRevision,ct) ?? throw new FileAuditPending("file_audit_policy_not_retained");
        var config=AgentFileAuditPolicy.Parse(captured["config"] as JsonObject ?? new JsonObject());var currentConfig=current["config"] as JsonObject ?? new JsonObject();
        if(!PythonMetadataEquality.Equal(currentConfig["source_name"],config.Value["source_name"]) || Text(currentConfig["source_kind"] ?? JsonValue.Create("server"))!=Text(config.Value["source_kind"] ?? JsonValue.Create("server"))) throw new FileAuditPending("file_audit_source_binding_changed");
        if(config.Workstation) {
            if(!assigned.OfType<JsonObject>().Any(x=>x["module_id"]?.GetValue<string>()=="sli.workstations" && x["enabled"] is JsonValue flag && flag.TryGetValue<bool>(out var enabled) && enabled)) throw new FileAuditPending("file_audit_workstation_not_assigned");
        }
        JsonArray verified;
        try { verified=AgentFileAuditValidator.Validate(envelope,body,config,host,transportGap:transportGap); }
        catch(ProtocolException) { throw new FileAuditPending("agent_packet_attestation_invalid"); }
        if(!PythonMetadataEquality.Equal(verified,rows)) throw new FileAuditPending("agent_packet_attestation_invalid");
        bool filePermissions=await AgentPolicyAssignments.FilePermissionsAvailableAsync(db,tx,ct);
        using var fileAdmission=filePermissions ? AgentPolicyAssignments.HoldFilePermissions() : null;
        bool enabled=filePermissions
            ? await AgentPolicyAssignments.FilePermissionsAllowedAsync(db,tx,agent,envelope.PolicyRevision,true,ct)
            : await AgentPolicyAssignments.ModuleEnabledAsync(db,tx,envelope.ModuleId,ct);
        if(!enabled) throw new FileAuditPending("module_disabled");
        if(filePermissions && fileAdmission is null) throw new FileAuditPending("file_audit_plugin_unavailable");
        if (filePermissions && !AgentFileAuditValidator.PermissionsOnly(body))
        {
            if (!AgentFileAuditValidator.NativeEventsOnly(body)
                || !await AgentPolicyAssignments.FileActivityAvailableAsync(db,tx,ct))
                throw new FileAuditPending("agent_packet_attestation_invalid");
            await ImportActivityAsync(db,tx,packet,envelope,config,rows,body["context"]?["object_kinds"] as JsonObject,ct);
            return;
        }
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

    private static async Task ImportActivityAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid packet,
        Envelope envelope, FileAuditPolicy policy, JsonArray rows, JsonObject? objectKinds, CancellationToken ct)
    {
        var agent = Guid.Parse(envelope.AgentId);
        async Task<JsonObject?> Run(string sql, params (string Key, object Value)[] args)
        {
            await using var command = new NpgsqlCommand(sql, db, tx);
            command.Parameters.AddWithValue("agent", agent);
            command.Parameters.AddWithValue("packet", packet);
            foreach (var (key, value) in args)
                if (value is JsonNode json) command.Parameters.AddWithValue(key, NpgsqlDbType.Jsonb, json.ToJsonString());
                else command.Parameters.AddWithValue(key, value);
            return await command.ExecuteScalarAsync(ct) is string jsonText ? JsonNode.Parse(jsonText)!.AsObject() : null;
        }
        var observations = rows.OfType<JsonObject>().Select(row => FileAuditObservation.Build(row, policy,
            envelope.AgentId, envelope.SourceInstanceId, envelope.Generation, envelope.PolicyRevision,
            $"agent-file-audit-event:{packet:D}:{row["record_id"]}")).ToArray();
        var actions = new JsonArray();
        var withinPacket = new JsonArray();
        foreach (var observationsInHour in observations.GroupBy(row => AgentAdDcUtc.Parse(Text(row["observed_at"])).UtcTicks / TimeSpan.TicksPerHour))
        {
            var batch = observationsInHour.ToArray();
            var first = batch.Min(row => AgentAdDcUtc.Parse(Text(row["observed_at"])));
            var last = batch.Max(row => AgentAdDcUtc.Parse(Text(row["observed_at"])));
            var context = (await Run("""
                select sli_plugin_file_audit.collection_context_for_packet(@agent,@packet,@start,@end,@keys)::text
                """, ("start", first.AddMinutes(-5)), ("end", last),
                ("keys", new JsonArray(batch.Select(row => row.DeepClone()).ToArray()))))!;
            var prior = context["complete"]!.GetValue<bool>() ? context["observations"]!.AsArray() : new JsonArray();
            foreach (var item in withinPacket) prior.Add(item!.DeepClone());
            foreach (var observation in batch)
            {
                var kind = objectKinds?[observation["record_id"]!.ToJsonString()]?.GetValue<string>() ?? "unknown";
                foreach (var action in FileAuditCorrelation.ProjectActions(observation,prior,kind))
                    actions.Add(action!.DeepClone());
                prior.Add(observation.DeepClone());
                withinPacket.Add(observation.DeepClone());
            }
        }

        await Run("select sli_plugin_file_audit.store_collection(@agent,@packet,@projection)",
            ("projection", new JsonObject { ["observations"] = new JsonArray(observations), ["actions"] = actions }));
        var actionRows = actions.OfType<JsonObject>().ToArray();
        var ruleResults = new Dictionary<string,JsonNode>(StringComparer.Ordinal);
        var seconds = policy.Number("mass_operation_seconds");
        foreach (var hour in actionRows.GroupBy(row => AgentAdDcUtc.Parse(Text(row["observed_at"])).UtcTicks / TimeSpan.TicksPerHour))
        {
            var first = hour.Min(row => AgentAdDcUtc.Parse(Text(row["observed_at"])));
            var last = hour.Max(row => AgentAdDcUtc.Parse(Text(row["observed_at"])));
            var context = (await Run("select sli_plugin_file_audit.rule_context(@agent,@packet,@start,@end)::text",
                ("start", first.AddSeconds(-seconds)), ("end", last)))!;
            if (!context["complete"]!.GetValue<bool>()) continue;
            var currentIds = hour.Select(row => Text(row["action_id"])).ToHashSet(StringComparer.Ordinal);
            foreach (var result in FileAuditActivityRules.Evaluate(context["actions"]!.AsArray(), policy.Value,
                envelope.AgentId, envelope.SourceInstanceId, context["snapshots"]!.AsArray(), null))
                if (result!["action_ids"]!.AsArray().Any(id => currentIds.Contains(Text(id))))
                    ruleResults.TryAdd(Text(result["result_id"]),result.DeepClone());
        }
        if (ruleResults.Count != 0)
            await Run("select sli_plugin_file_audit.publish_rules(@agent,@packet,null,@results)",
                ("results", new JsonArray(ruleResults.Values.ToArray())));

        var latest = actionRows.MaxBy(row => AgentAdDcUtc.Parse(Text(row["observed_at"])));
        if (latest is not null)
            await Run("""
                update public.sli_agents a set file_audit=jsonb_set(a.file_audit,'{last_event}',jsonb_build_object(
                    'collection_scope_id',@scope,'observed_at',@observed,'received_at',i.received_at,'packet_id',i.packet_id))
                from public.sli_agent_packet_inbox i where a.id=@agent and i.packet_id=@packet
                  and (a.file_audit#>>'{last_event,observed_at}' is null
                       or (a.file_audit#>>'{last_event,observed_at}')::timestamptz < @observed)
                """, ("scope", Text(latest["collection_scope_id"])), ("observed", AgentAdDcUtc.Parse(Text(latest["observed_at"]))));
    }
}
