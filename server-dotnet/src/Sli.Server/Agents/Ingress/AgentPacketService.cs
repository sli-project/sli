using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Ingress;

public interface IAgentPacketService
{
    Task<JsonObject> ReceiveAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, AgentIdentity identity,
        X509Certificate2 peer, JsonNode? packet, CancellationToken ct);
}

public sealed class AgentPacketService(TimeProvider clock, AgentInboxLimits limits, AgentIngressDiagnostics diagnostics) : IAgentPacketService
{
    public async Task<JsonObject> ReceiveAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, AgentIdentity identity,
        X509Certificate2 peer, JsonNode? packet, CancellationToken ct)
    {
        Envelope envelope;
        using (var ec = peer.GetECDsaPublicKey())
        using (var rsa = peer.GetRSAPublicKey())
            envelope = ec is not null ? PacketVerifier.Verify(packet,ec) : rsa is not null ? PacketVerifier.Verify(packet,rsa)
                : throw new ProtocolException("agent_signature_invalid");
        var payload=packet!["payload"]!.AsObject(); var ledger=new AgentPacketLedger(connection,transaction);
        var now=Iso8601.Truncate(clock.GetUtcNow());
        JsonObject Reject(string code,string status="rejected") => AgentReceipt.Make(envelope,status,code,null);
        if (envelope.AgentId != identity.Id.ToString("D")) return Reject("agent_identity_mismatch");
        bool accounting=envelope.ModuleId==NpsPolicy.Accounting;
        var existing=accounting ? await ledger.ExistingAsync(envelope,ct) : null;
        bool filePermissions=envelope.ModuleId==FileAuditPolicy.ModuleId &&
            await AgentPolicyAssignments.FilePermissionsAvailableAsync(connection,transaction,ct);
        using var fileAdmission=filePermissions ? AgentPolicyAssignments.HoldFilePermissions() : null;
        WorkstationJournalScope? workstationScope=null;
        if (existing is null && envelope.ModuleId!="sli.heartbeat")
        {
            bool enabled=filePermissions
                ? await AgentPolicyAssignments.FilePermissionsAllowedAsync(connection,transaction,
                    identity.Id,envelope.PolicyRevision,true,ct)
                : await AgentPolicyAssignments.ModuleEnabledAsync(connection,transaction,envelope.ModuleId,ct);
            if (envelope.ModuleId==WorkstationsModule.ModuleId && await WorkstationJournalAdmission.AvailableAsync(connection,transaction,ct))
            {
                if(envelope.Channel=="workstations")
                    workstationScope=await WorkstationJournalAdmission.ReadAsync(connection,transaction,identity.Id,
                        envelope.SourceInstanceId,envelope.PolicyRevision,ct);
                enabled=workstationScope is not null;
            }
            if(!enabled && !accounting) return Reject("module_disabled");
            if(filePermissions && fileAdmission is null) return Reject("file_audit_plugin_unavailable","retry_later");
            if(filePermissions && !AgentFileAuditValidator.PermissionsOnly(payload)) return Reject("agent_file_audit_packet_invalid");
            var state=await ledger.AgentStateAsync(identity.Id,ct);
            if(accounting)
            {
                if(AgentPolicyAssignments.FindCurrent(state.Assignments,envelope.ModuleId) is null)
                    return Reject("module_disabled");
                if(!enabled) return Reject("agent_radius_accounting_paused","retry_later");
            }
            else if(state.Assignments.OfType<JsonObject>().Any(m=>m["module_id"]?.ToString()==envelope.ModuleId && m["enabled"] is JsonValue flag
                && flag.TryGetValue<bool>(out var enabled) && !enabled)) return Reject("module_disabled");
        }
        if(!accounting) existing=await ledger.ExistingAsync(envelope,ct);
        if (existing is not null)
        {
            if (existing.Value.Hash != Packets.Digest(envelope.ToJson())) return Reject("agent_sequence_conflict");
            var duplicate=existing.Value.Receipt; duplicate["status"]="duplicate"; return duplicate;
        }
        var summary=await ledger.SummaryAsync(envelope,ct);
        var expired=summary?["expired_envelope"] as JsonObject;
        if (expired?["sequence"]?.GetValue<long>() == envelope.Sequence)
            return Packets.Digest(expired)==Packets.Digest(envelope.ToJson()) ? Reject("agent_packet_expired") : Reject("agent_sequence_conflict");
        if (await ledger.PacketExistsAsync(envelope.PacketId,envelope.AgentId,ct)) return Reject("agent_packet_id_conflict");
        var age=now-Iso8601.ParseUtc(envelope.ObservedAtUtc);
        if (age < TimeSpan.FromMinutes(-5)) return Reject("agent_replay_window");
        var previous=await ledger.LatestAsync(envelope,ct);
        if (age > TimeSpan.FromDays(7))
        {
            // Only the next signed packet can move the transport tip. No events or delivery receipt are stored.
            bool known=envelope.ModuleId is "sli.heartbeat" or "sli.windows-eventlog" or AgentAdDcValidator.Live or AgentAdDcValidator.History
                or SnapshotPolicy.Ad or SnapshotPolicy.Gpo or WorkstationsModule.ModuleId or FileAuditPolicy.ModuleId or NpsPolicy.Nps or NpsPolicy.Accounting;
            if (known && Follows(envelope,previous)) await ledger.ExpireAsync(envelope,previous,summary,ct);
            return Reject("agent_packet_expired");
        }
        bool transportGap=summary?["expiry_pending"]?.GetValue<bool>() == true && Follows(envelope,previous);
        if (transportGap && envelope.ContinuityState != "gap") return Reject("agent_reset_invalid");
        JsonArray? rows=null; SnapshotPrepared? snapshot=null; JsonObject? workstationCurrent=null;
        if (envelope.ModuleId == "sli.heartbeat")
        {
            if (envelope.SourceInstanceId != identity.HostId.ToString("D") || !HeartbeatValidator.IsValid(identity.HostId,envelope.Channel,envelope.Generation,envelope.ModuleVersion,envelope.PolicyRevision,payload,transportGap ? "not_proven" : envelope.ContinuityState,envelope.FilteredCount,envelope.LostCount)) return Reject("agent_heartbeat_invalid");
        }
        else if (envelope.ModuleId == "sli.windows-eventlog")
        {
            var state=await ledger.AgentStateAsync(identity.Id,ct);
            bool assigned=state.Assignments.Any(n => n is JsonValue v && v.TryGetValue<string>(out var s) && s == envelope.ModuleId
                || n is JsonObject o && o["module_id"] is JsonValue module && module.TryGetValue<string>(out var name) && name == envelope.ModuleId
                && o["enabled"] is JsonValue enabled && enabled.TryGetValue<bool>(out var on) && on);
            if (!assigned) return Reject("agent_module_not_assigned");
            var binding=await ledger.BindingAsync(envelope,ct);
            if (binding is null || binding.Value.SourceId != envelope.SourceInstanceId || binding.Value.Channel != envelope.Channel
                || binding.Value.Version != envelope.ModuleVersion || binding.Value.Revision != envelope.PolicyRevision) return Reject("agent_source_not_bound");
            if (envelope.PayloadContract != CollectionPacket.Contract) return Reject("agent_module_unsupported");
            try { rows=EventLogValidator.Validate(envelope,payload,binding.Value.SourceName); }
            catch (ProtocolException) { return Reject("agent_collection_packet_invalid"); }
        }
        else if (envelope.ModuleId is AgentAdDcValidator.Live or AgentAdDcValidator.History)
        {
            var state=await ledger.AgentStateAsync(identity.Id,ct);
            bool assigned=state.Assignments.Any(n => n is JsonValue v && v.TryGetValue<string>(out var s) && s==envelope.ModuleId
                || n is JsonObject o && o["module_id"] is JsonValue module && module.TryGetValue<string>(out var name) && name==envelope.ModuleId
                && o["enabled"] is JsonValue enabled && enabled.TryGetValue<bool>(out var on) && on);
            if (!assigned) return Reject("agent_module_not_assigned");
            JsonObject? policy=null; string? sourceName=null;
            if (AgentPolicyAssignments.FindCurrent(state.Assignments,envelope.ModuleId) is not null)
            {
                var assignment=await AgentPolicyAssignments.ResolveAsync(connection,transaction,state.Assignments,identity.Id,envelope.ModuleId,envelope.PolicyRevision,ct);
                if (assignment is null) return Reject("agent_source_not_bound");
                try
                {
                    if (assignment["config"] is not null and not JsonObject) return Reject("agent_source_not_bound");
                    policy=AgentAdDcValidator.NormalizePolicy(assignment["config"] as JsonObject ?? new JsonObject(),envelope.ModuleId==AgentAdDcValidator.History);
                    sourceName=policy["source_name"]!.GetValue<string>();
                    if (envelope.SourceInstanceId!=(state.SourceHost ?? identity.HostId).ToString("D") || envelope.Channel!="ad-dc"
                        || !AgentAdDcValidator.SupportsVersion(envelope.ModuleVersion) || envelope.PolicyRevision!=policy["policy_revision"]!.GetValue<string>()) return Reject("agent_source_not_bound");
                }
                catch(Exception e) when (e is AgentException or ProtocolException or ArgumentException or InvalidOperationException or FormatException)
                { return Reject("agent_source_not_bound"); }
            }
            else
            {
                var binding=await ledger.BindingAsync(envelope,ct);
                if (binding is null || binding.Value.SourceId!=envelope.SourceInstanceId || binding.Value.Channel!=envelope.Channel
                    || !AgentAdDcValidator.SupportsVersion(envelope.ModuleVersion) || binding.Value.Revision!=envelope.PolicyRevision) return Reject("agent_source_not_bound");
                sourceName=binding.Value.SourceName;
            }
            if (envelope.PayloadContract!=CollectionPacket.Contract) return Reject("agent_module_unsupported");
            try { rows=AgentAdDcValidator.Validate(envelope,payload,policy,sourceName,transportGap); }
            catch (ProtocolException) { return Reject("agent_collection_packet_invalid"); }
            // Both names must resolve uniquely. A shared short label across domains
            // is never enough to accuse or merge two computers.
            var expectedSource=await Registry.AgentEnrollmentService.ResolveDcAsync(connection,transaction,sourceName,ct,identity.Id);
            if(expectedSource is {} expectedDc)
                foreach(var machine in rows.OfType<JsonObject>().Select(r=>r["machine_name"]?.GetValue<string>()).Where(n=>n is { Length: >0 and <=253 }).Distinct(StringComparer.OrdinalIgnoreCase))
                    if(await Registry.AgentEnrollmentService.ResolveDcAsync(connection,transaction,machine!,ct) is {} actualDc && actualDc.Server!=expectedDc.Server)
                    {
                        await using var conflict=new NpgsqlCommand("update sli_agents set rights_probe=jsonb_set(rights_probe,'{identity_conflict}',@details::jsonb) where id=@id",connection,transaction);
                        conflict.Parameters.AddWithValue("id",identity.Id);
                        conflict.Parameters.AddWithValue("details",new JsonObject { ["computer"]=expectedDc.Name,["other_computer"]=actualDc.Name,["observed_at"]=now.ToString("O") }.ToJsonString());
                        await conflict.ExecuteNonQueryAsync(ct);
                        return Reject("agent_identity_computer_conflict");
                    }
        }
        else if (envelope.ModuleId is SnapshotPolicy.Ad or SnapshotPolicy.Gpo)
        {
            var state=await ledger.AgentStateAsync(identity.Id,ct);
            try { snapshot=await SnapshotIngress.ValidateAsync(connection,transaction,identity,envelope,payload,state.Assignments,ct,transportGap); }
            catch (ProtocolException e) { return Reject(e.Code); }
        }
        else if (envelope.ModuleId == WorkstationsModule.ModuleId)
        {
            var state=await ledger.AgentStateAsync(identity.Id,ct);
            try
            {
                var current=AgentPolicyAssignments.FindCurrent(state.Assignments,envelope.ModuleId) ?? throw new AgentException("agent_module_not_assigned");
                var assignment=await AgentPolicyAssignments.ResolveAsync(connection,transaction,state.Assignments,identity.Id,envelope.ModuleId,envelope.PolicyRevision,ct)
                    ?? throw new AgentException("agent_module_not_assigned");
                var selected=WorkstationPolicy.Parse(assignment["config"] as JsonObject ?? new JsonObject());
                workstationCurrent=current["config"] as JsonObject ?? new JsonObject();
                rows=AgentWorkstationValidator.Validate(envelope,payload,selected,state.SourceHost ?? identity.HostId);
                if(workstationScope is not null && !WorkstationJournalAdmission.MatchesRows(workstationScope,rows))
                    return Reject("agent_workstations_packet_invalid");
            }
            catch (Exception e) when (e is AgentException or ProtocolException or InvalidOperationException or ArgumentException)
            { return Reject("agent_workstations_packet_invalid"); }
        }
        else if (envelope.ModuleId == FileAuditPolicy.ModuleId)
        {
            var state=await ledger.AgentStateAsync(identity.Id,ct);
            try
            {
                var assignment=await AgentPolicyAssignments.ResolveAsync(connection,transaction,state.Assignments,identity.Id,envelope.ModuleId,envelope.PolicyRevision,ct)
                    ?? throw new AgentException("file_audit_not_assigned");
                var policy=AgentFileAuditPolicy.Parse(assignment["config"] as JsonObject ?? new JsonObject());
                rows=AgentFileAuditValidator.Validate(envelope,payload,policy,state.SourceHost ?? identity.HostId);
            }
            catch (Exception e) when (e is AgentException or ProtocolException or InvalidOperationException or ArgumentException)
            { return Reject("agent_file_audit_packet_invalid"); }
        }
        else if (envelope.ModuleId is NpsPolicy.Nps or NpsPolicy.Accounting)
        {
            var state=await ledger.AgentStateAsync(identity.Id,ct);
            try
            {
                var current=AgentPolicyAssignments.FindCurrent(state.Assignments,envelope.ModuleId) ?? throw new AgentException("agent_module_not_assigned");
                var currentPolicy=NpsPolicy.Parse(envelope.ModuleId,current["config"] as JsonObject ?? new JsonObject());
                var assignment=await AgentPolicyAssignments.ResolveAsync(connection,transaction,state.Assignments,identity.Id,envelope.ModuleId,envelope.PolicyRevision,ct)
                    ?? throw new AgentException("agent_nps_policy_not_retained");
                var policy=NpsPolicy.Parse(envelope.ModuleId,assignment["config"] as JsonObject ?? new JsonObject());
                if (policy.SourceId != currentPolicy.SourceId) throw new AgentException("agent_nps_policy_not_retained");
                rows=envelope.ModuleId==NpsPolicy.Nps
                    ? AgentNpsValidator.Validate(envelope,payload,policy,state.SourceHost ?? identity.HostId)
                    : AgentRadiusValidator.Validate(envelope,payload,policy,state.SourceHost ?? identity.HostId);
                if (envelope.ModuleId == NpsPolicy.Accounting &&
                    !await AgentPolicyAssignments.AccountingSourceEnabledAsync(connection,transaction,currentPolicy,policy,ct))
                    return Reject("agent_radius_accounting_paused","retry_later");
            }
            catch (Exception e) when (e is AgentException or ProtocolException or InvalidOperationException or ArgumentException)
            { return Reject("agent_nps_packet_invalid"); }
        }
        else throw new NotSupportedException("Agent module is not implemented by this ingress slice");
        long lastSequence=previous?["sequence"]?.GetValue<long>() ?? 0;
        if (previous is not null && (previous["source_instance_id"]!.GetValue<string>() != envelope.SourceInstanceId || previous["channel"]!.GetValue<string>() != envelope.Channel)) return Reject("agent_stream_identity_changed");
        if (envelope.Sequence <= lastSequence) return Reject("agent_sequence_replayed");
        long expected=checked(lastSequence+1);
        var recovery=new AgentSequenceRecovery(connection,transaction); string? observation=null;
        if (envelope.Sequence > expected)
        {
            if (envelope.ModuleId == "sli.heartbeat" && (envelope.CursorAfter.Strategy != "record_id" || envelope.CursorAfter.Token != envelope.Sequence.ToString(System.Globalization.CultureInfo.InvariantCulture))) return Reject("agent_heartbeat_invalid");
            observation=await recovery.ObserveAsync(identity,envelope,previous,now,ct);
            if (observation is null) return Reject("agent_sequence_gap","retry_later");
        }
        if (observation is null)
        {
            if (previous is not null && previous["generation"]!.GetValue<string>() == envelope.Generation)
            {
                if (!JsonNode.DeepEquals(previous["cursor_after"],envelope.CursorBefore.ToJson())) return Reject("agent_cursor_mismatch");
            }
            else if (envelope.CursorBefore.Token != "" || previous is not null && envelope.ContinuityState != "gap") return Reject("agent_reset_invalid");
        }
        if (envelope.ModuleId == "sli.heartbeat" && (envelope.CursorAfter.Strategy != "record_id" || envelope.CursorAfter.Token != envelope.Sequence.ToString(System.Globalization.CultureInfo.InvariantCulture))) return Reject("agent_heartbeat_invalid");
        if (workstationCurrent is not null)
        {
            var workstationPolicy=WorkstationPolicy.Parse(workstationCurrent);
            if (await AgentWorkstationRate.IsLimitedAsync(connection,transaction,identity.Id,rows!,workstationPolicy,ct))
                return Reject("agent_workstations_rate_limit","retry_later");
        }
        if (envelope.ModuleId==AgentAdDcValidator.History && await ledger.HistoryPendingAsync(identity.Id,ct))
            return Reject("agent_history_pending","retry_later");
        var receipt=AgentReceipt.Make(envelope,"committed",null,now);
        string? quota=snapshot is null
            ? await AgentInboxQuota.CheckAsync(connection,transaction,envelope,payload,rows,receipt,limits,diagnostics,ct)
            : await SnapshotIngress.CheckQuotaAsync(connection,transaction,snapshot,receipt,limits,ct);
        if (quota is not null) return Reject(quota,"retry_later");
        await ledger.StoreAsync(envelope,payload,rows,receipt,ct);
        if (filePermissions)
            await RecordFileAuditEventAsync(connection,transaction,identity.Id,envelope.PolicyRevision,payload,now,ct);
        if (envelope.ContinuityState=="gap") await ledger.GapAsync(envelope,previous,summary,ct);
        if (snapshot is not null) await SnapshotIngress.StoreAsync(connection,transaction,snapshot,ct);
        if (observation is not null) await recovery.AcceptAsync(observation,envelope,now,ct);
        return receipt;
    }

    // Update the card in the same transaction as the signed packet receipt.
    private static async Task RecordFileAuditEventAsync(NpgsqlConnection db,NpgsqlTransaction tx,Guid agent,
        string revision,JsonObject payload,DateTimeOffset received,CancellationToken ct)
    {
        var latest = payload["records"]!.AsArray().OfType<JsonObject>()
            .Where(record => record["format"]?.ToString() == "file_action")
            .Select(record => record["payload"]!.AsObject())
            .MaxBy(row => AgentAdDcUtc.Parse(row["last_seen_utc"]!.GetValue<string>()));
        if (latest is null) return;
        string scope=latest["collection_scope_id"]!.GetValue<string>();
        var observed=AgentAdDcUtc.Parse(latest["last_seen_utc"]!.GetValue<string>());
        var activity=new JsonObject { ["collection_scope_id"]=scope,["observed_at"]=Iso8601.Format(observed),["received_at"]=Iso8601.Format(received) };
        await using var write=new NpgsqlCommand("""
            update public.sli_agents set file_audit=jsonb_set(file_audit,'{last_event}',@activity)
            where id=@agent and file_audit->>'permissions_scope'=@scope
              and file_audit#>>'{request,command,policy_revision}'=@revision
              and (file_audit#>>'{last_event,observed_at}' is null
                   or (file_audit#>>'{last_event,observed_at}')::timestamptz < @observed)
            """,db,tx);
        write.Parameters.AddWithValue("agent",agent);
        write.Parameters.AddWithValue("scope",scope);
        write.Parameters.AddWithValue("revision",revision);
        write.Parameters.AddWithValue("observed",observed);
        write.Parameters.AddWithValue("activity",NpgsqlTypes.NpgsqlDbType.Jsonb,activity.ToJsonString());
        await write.ExecuteNonQueryAsync(ct);
    }

    private static bool Follows(Envelope envelope, JsonObject? previous)
    {
        long sequence=previous?["sequence"]?.GetValue<long>() ?? 0;
        if (sequence==long.MaxValue || envelope.Sequence!=sequence+1) return false;
        if (previous is null) return envelope.CursorBefore.Token=="";
        if (previous["source_instance_id"]!.GetValue<string>()!=envelope.SourceInstanceId || previous["channel"]!.GetValue<string>()!=envelope.Channel) return false;
        return previous["generation"]!.GetValue<string>()==envelope.Generation
            ? JsonNode.DeepEquals(previous["cursor_after"],envelope.CursorBefore.ToJson())
            : envelope.CursorBefore.Token=="" && envelope.ContinuityState=="gap";
    }
}

public static class AgentReceipt
{
    public static JsonObject Make(Envelope envelope, string status, string? code, DateTimeOffset? now) => new()
    {
        ["contract_id"]="sli.agent-receipt.v1", ["packet_id"]=envelope.PacketId, ["payload_sha256"]=envelope.PayloadSha256,
        ["status"]=status, ["committed_cursor"]=status is "committed" or "duplicate" ? envelope.CursorAfter.ToJson() : null,
        ["evidence_ref"]=status is "committed" or "duplicate" ? "agent-packet:"+envelope.PacketId : null,
        ["committed_at_utc"]=now is null ? null : Iso8601.Format(now.Value), ["error_code"]=code
    };
}

