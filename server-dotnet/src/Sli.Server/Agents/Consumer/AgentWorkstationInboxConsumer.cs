using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Server.Infrastructure;
using Sli.Server.Agents.FileAudit;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Ingress;
using Sli.Server.Storage.Direct;

namespace Sli.Server.Agents.Consumer;

public sealed record AgentInboxBatchResult(int Scanned,int Imported,IReadOnlyDictionary<string,int> PendingReasons,int Quarantined=0)
{
    public long Skipped { get; init; }
}
public sealed record AgentInboxStep(bool Scanned,bool Imported,string? PendingReason,DateTime Received,Guid PacketId,bool Quarantined=false)
{
    internal string? AgentId { get; init; }
    internal string? ModuleId { get; init; }
    internal JsonObject? Diagnostic { get; init; }
    internal bool TransactionCompleted { get; init; }
    internal string? StreamKey { get; init; }
}

// Source: agents/consumer.py, import_authorization.py and collection_packet_import.py.
// One caller-owned poller; the host controls scheduling and shutdown.
public sealed partial class AgentWorkstationInboxConsumer(IPostgresConnectionFactory connections, DirectAdDcRuntime? direct = null)
{
    internal JsonObject? Cursor { get; private set; }
    internal string? DirectConfigurationIssue { get; init; }
    private readonly AdDcProjectionFailure failures = new(TimeProvider.System);
    private static readonly AdDcProjectionFailure BorrowedFailures = new(TimeProvider.System);

    internal void ReportDirectConfigurationIssue(CancellationToken ct)
    {
        if (DirectConfigurationIssue is { } issue)
            WriteDiagnostic(failures, new JsonObject { ["code"] = AdDcProjectionFailure.Code, ["step"] = "configuration", ["reason"] = issue }, ct);
    }
    // Per-stream claim cursors survive between polls; each stream wraps independently at its tail.
    private readonly StreamFairness streams=new();
    private readonly SemaphoreSlim gate=new(1,1);
    // Packets whose binding mismatch repeats identically are not retried until the bindings or DC servers change.
    // Memory only: nothing is deleted or marked, and a restart retries each signature once.
    private readonly HashSet<string> unbound=new(StringComparer.Ordinal);
    private readonly HashSet<string> awaitingDcSource=new(StringComparer.Ordinal);
    private string? bindingState;
    public async Task<AgentInboxBatchResult> RunOnceAsync(int limit,CancellationToken ct,Func<CancellationToken,Task>? checkOwnership=null)
    {
        if(limit is <1 or >128) throw new ArgumentOutOfRangeException(nameof(limit));
        await using var db=await connections.OpenAsync(ct);
        return await RunOnceAsync(db,limit,ct,checkOwnership);
    }
    // The caller retains connection ownership. The runtime uses a pooled import
    // connection, separate from its dedicated process-lock session.
    public async Task<AgentInboxBatchResult> RunOnceAsync(NpgsqlConnection db,int limit,CancellationToken ct,Func<CancellationToken,Task>? checkOwnership=null)
    {
        if(limit is <1 or >128) throw new ArgumentOutOfRangeException(nameof(limit));
        await gate.WaitAsync(ct);
        try {
            var reasons=new Dictionary<string,int>(StringComparer.Ordinal); int scanned=0,imported=0,quarantined=0;
            // Only this bounded poll defers an agent/module. Nothing durable is changed on refusal.
            var deferred=new Dictionary<(string Agent,string Module),AgentInboxStep>();
            await using(var marking=await db.BeginTransactionAsync(ct)) {
                await Ingress.AgentPolicyAssignments.MarkDisabledAsync(db,marking,limit,ct);
                await marking.CommitAsync(ct);
            }
            await RefreshBindingStateAsync(db,ct);
            var fairness=streams;
            var claimed=new Queue<Inbox>();
            bool drained=await fairness.PollAsync(limit,async()=> {
                ct.ThrowIfCancellationRequested();
                if(checkOwnership is not null)await checkOwnership(ct);
                if(claimed.Count==0) {
                    await using var claim=await db.BeginTransactionAsync(ct);
                    foreach(var item in await ClaimBatchAsync(db,claim,limit-scanned,deferred.Keys,unbound.ToArray(),fairness,ct))claimed.Enqueue(item);
                    await claim.CommitAsync(ct);
                }
                while(claimed.TryPeek(out var excluded) && (deferred.ContainsKey((excluded.Envelope["agent_id"]?.ToString()??"",excluded.Envelope["module_id"]?.ToString()??"")) || unbound.Contains(BindingKey(excluded))))claimed.Dequeue();
                if(!claimed.TryPeek(out var row))return new AgentInboxStep(false,false,null,default,default);
                // End the current fairness round before consuming a second
                // packet from one stream. Packet order inside a stream is fixed.
                if(fairness.Served.Contains(StreamKeyOf(row)))return new AgentInboxStep(false,false,null,default,default);
                claimed.Dequeue();
                using var npsAdmission=TryNpsAdmission();
                await using var tx=await db.BeginTransactionAsync(ct);
                var step=await ProcessNextCoreAsync(db,tx,null,ct,direct,npsAdmission,failures,deferred.Keys,commitAdDc:true,skipped:unbound.ToArray(),
                    progress:value=>Cursor=new JsonObject { ["phase"]=value.ToString(),["phase_started_at"]=DateTime.UtcNow.ToString("O") },fairness:fairness,claimed:row);
                if (DirectConfigurationIssue is { } issue && step.PendingReason == "agent_storage_unavailable" &&
                    step.ModuleId is "sli.windows.ad-dc" or "sli.windows.ad-dc-history")
                    step = step with { PendingReason = issue };
                if(!step.Scanned) {
                    await tx.CommitAsync(ct);
                    return step;
                }
                scanned++; if(step.Imported) imported++; else if(step.Quarantined) quarantined++; else reasons[step.PendingReason!]=reasons.GetValueOrDefault(step.PendingReason!)+1;
                if(!step.TransactionCompleted)await tx.CommitAsync(ct);
                Cursor = new() { ["received_at"] = step.Received.ToString("O"), ["packet_id"] = step.PacketId.ToString("D") };
                if(step.PendingReason=="agent_ad_dc_source_not_bound") await RememberUnboundAsync(db,step.PacketId,ct);
                if(step.PendingReason==AdDcProjectionFailure.SourceNotConfigured && step.StreamKey is { } blocked)
                    awaitingDcSource.Add(blocked);
                if(IsConfigurationPending(step.PendingReason) && step.AgentId is { } agent && step.ModuleId is { } module)
                    deferred.Add((agent,module),step);
                return step;
            },deferred.Keys.Select(key=>string.Join('\u001f',key.Agent,key.Module)));
            if(drained) Cursor=null;
            // Retain progress across bounded calls; configuration deferral lasts only for this poll.
            long skipped=0;
            // Counts and diagnostics are best effort: imports above have already committed.
            try {
                var diagnostics=new Dictionary<string,List<JsonObject>>(StringComparer.Ordinal);
                foreach(var (key,step) in deferred) {
                    await using var count=new NpgsqlCommand("""
                        select count(*) from sli_agent_packet_inbox i
                        where imported_at is null and module_disabled_at is null and envelope->>'agent_id'=@agent and envelope->>'module_id'=@module
                          and (received_at,packet_id)>(@received,@packet)
                          and not exists(select 1 from sli_agent_packet_quarantine q where q.packet_id=i.packet_id)
                        """,db);
                    count.Parameters.AddWithValue("agent",key.Agent); count.Parameters.AddWithValue("module",key.Module);
                    count.Parameters.AddWithValue("received",step.Received); count.Parameters.AddWithValue("packet",step.PacketId);
                    long remaining=(long)(await count.ExecuteScalarAsync(ct))!; skipped+=remaining;
                    if (step.Diagnostic is null && AdDcProjectionFailure.IsStorageIssue(step.PendingReason)) continue;
                    var diagnostic=step.Diagnostic ?? new JsonObject { ["code"]="agent_packets_pending",["reason"]=step.PendingReason };
                    diagnostic["agent_id"]=key.Agent; diagnostic["module_id"]=key.Module; diagnostic["skipped"]=remaining;
                    if(!diagnostics.TryGetValue(key.Agent,out var entries)) diagnostics[key.Agent]=entries=[];
                    entries.Add(diagnostic);
                }
                foreach(var (agent,entries) in diagnostics) {
                    entries.RemoveAll(entry => !failures.CountAndAllow(entry));
                    if (entries.Count == 0) continue;
                    // One record per agent, retaining individual module/step diagnostics.
                    var diagnostic=entries.Count==1 ? entries[0] : new JsonObject {
                        ["code"]="agent_packets_pending",["agent_id"]=agent,
                        ["skipped"]=entries.Sum(x=>x["skipped"]!.GetValue<long>()),
                        ["modules"]=new JsonArray(entries.Select(x=>(JsonNode)x).ToArray())
                    };
                    Console.Error.WriteLine(diagnostic.ToJsonString());
                }
                // Replaced registrations retain their queue without admitting it to import.
                await using var inactive=new NpgsqlCommand("""
                    select a.id::text,count(*),'agent_not_active' as code
                    from sli_agent_packet_inbox i
                    join sli_agents a on a.id::text=i.envelope->>'agent_id' and a.status in ('replaced','disabled')
                    where i.imported_at is null and i.module_disabled_at is null and not exists(select 1 from sli_agent_packet_quarantine q where q.packet_id=i.packet_id)
                    group by a.id,code
                    """,db);
                await using(var inactiveRows=await inactive.ExecuteReaderAsync(ct))
                    while(await inactiveRows.ReadAsync(ct))
                        Console.Error.WriteLine(new JsonObject { ["code"]=inactiveRows.GetString(2),["agent_id"]=inactiveRows.GetString(0),["skipped"]=inactiveRows.GetInt64(1) }.ToJsonString());
            } catch(OperationCanceledException) when(ct.IsCancellationRequested) { throw; }
            catch(Exception) { /* Optional diagnostics must not discard committed batch results. */ }
            ct.ThrowIfCancellationRequested();
            return new AgentInboxBatchResult(scanned,imported,reasons,quarantined) { Skipped=skipped };
        } finally { gate.Release(); }
    }
    // Caller owns transaction and commits the observation and inbox marker together.
    public static Task<AgentInboxStep> ProcessNextAsync(NpgsqlConnection db,NpgsqlTransaction tx,(DateTime Received,Guid Packet)? after,CancellationToken ct,DirectAdDcRuntime? direct=null)
        => ProcessNextCoreAsync(db,tx,after,ct,direct,null,BorrowedFailures);
    private static async Task<AgentInboxStep> ProcessNextCoreAsync(NpgsqlConnection db,NpgsqlTransaction tx,(DateTime Received,Guid Packet)? after,CancellationToken ct,DirectAdDcRuntime? direct,AgentAssignmentPluginAdmission? npsAdmission,AdDcProjectionFailure failures,IEnumerable<(string Agent,string Module)>? deferred=null,bool commitAdDc=false,string[]? skipped=null,Action<AdDcProjectionStep>? progress=null,StreamFairness? fairness=null,Inbox? claimed=null)
    {
        var row=claimed??await ClaimAsync(db,tx,after,ct,deferred,skipped,fairness);
        if(row is null) return new(false,false,null,default,default);
        if(commitAdDc && direct is not null && Text(row.Envelope["module_id"]) is "sli.windows.ad-dc" or "sli.windows.ad-dc-history")
            return (await ProcessAdDcCommittedAsync(db,tx,row,direct,ct,progress,failures)) with { StreamKey=StreamKeyOf(row) };
        if(claimed is not null) {
            await using var pending=new NpgsqlCommand("select imported_at is null and module_disabled_at is null and not exists(select 1 from sli_agent_packet_quarantine q where q.packet_id=i.packet_id) from sli_agent_packet_inbox i where packet_id=@packet for update",db,tx);
            pending.Parameters.AddWithValue("packet",row.PacketId);
            if(await pending.ExecuteScalarAsync(ct) is not true)return new(true,false,"agent_packet_already_processed",row.Received,row.PacketId) { StreamKey=StreamKeyOf(row) };
        }
        await tx.SaveAsync("projection",ct); bool success=false,quarantined=false; string? reason=null;
        JsonObject? diagnostic=null;
        try { await ImportAsync(db,tx,row,ct,direct,npsAdmission is not null,failures); success=true; }
        catch(WorkstationPendingException e) { reason=e.Code; await tx.RollbackAsync("projection",ct); }
        catch(FileAuditPending e) { reason=e.Code; await tx.RollbackAsync("projection",ct); }
        catch(DirectSourceConflict e) {
            await tx.RollbackAsync("projection",ct);
            await using var quarantine=new NpgsqlCommand("insert into sli_agent_packet_quarantine(packet_id,reason_code,event_ordinal) values(@packet,@reason,@ordinal) on conflict(packet_id) do nothing",db,tx);
            quarantine.Parameters.AddWithValue("packet",row.PacketId);quarantine.Parameters.AddWithValue("reason",e.Reason);quarantine.Parameters.AddWithValue("ordinal",e.Ordinal);
            await quarantine.ExecuteNonQueryAsync(ct);reason=e.Reason;quarantined=true;
        }
        catch(DirectAdDcPending e) {
            reason=e.Message; diagnostic=e.Diagnostic; await tx.RollbackAsync("projection",ct);
            if(e.Permanent) {
                await using var quarantine=new NpgsqlCommand("insert into sli_agent_packet_quarantine(packet_id,reason_code,event_ordinal) values(@packet,@reason,0) on conflict(packet_id) do nothing",db,tx);
                quarantine.Parameters.AddWithValue("packet",row.PacketId);quarantine.Parameters.AddWithValue("reason",reason);
                await quarantine.ExecuteNonQueryAsync(ct);quarantined=true;
            }
        }
        catch(OperationCanceledException) when(ct.IsCancellationRequested) { throw; }
        catch(Exception) { reason="agent_projection_failed"; await tx.RollbackAsync("projection",ct); }
        if(success || reason=="module_disabled") {
            // Terminal refusal must not be reported as a successful import.
            await using var mark=new NpgsqlCommand(reason=="module_disabled"
                ? "update sli_agent_packet_inbox set module_disabled_at=clock_timestamp() where packet_id=@packet"
                : "update sli_agent_packet_inbox set imported_at=clock_timestamp() where packet_id=@packet",db,tx);
            mark.Parameters.AddWithValue("packet",row.PacketId); if(await mark.ExecuteNonQueryAsync(ct)!=1) throw new InvalidOperationException();
        }
        if(diagnostic is not null && (deferred is null || !IsConfigurationPending(reason))) {
            if(reason==AdDcProjectionFailure.SourceNotConfigured && Guid.TryParse(row.Envelope["agent_id"]?.ToString(),out var diagnosticAgent))
                diagnostic["agent_id"]=diagnosticAgent.ToString("D");
            WriteDiagnostic(failures,diagnostic,ct);
        }
        return new(true,success,reason,row.Received,row.PacketId,quarantined) {
            AgentId=JsonRead.TryString(row.Envelope["agent_id"],out var agent) && Guid.TryParse(agent,out _) ? agent : null,
            ModuleId=JsonRead.TryString(row.Envelope["module_id"],out var module) ? module : null, Diagnostic=diagnostic, StreamKey=StreamKeyOf(row)
        };
    }
    private static AgentAssignmentPluginAdmission? TryNpsAdmission()
    {
        if(Environment.GetEnvironmentVariable("SLI_NPS_AGENT_IMPORT_ENABLED")!="1") return null;
        try { return AgentAssignmentPluginAdmission.Enter("sli.remote-access",Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"),Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR")); }
        catch(Exception error) when(error is InvalidOperationException or IOException or UnauthorizedAccessException or PlatformNotSupportedException or ArgumentException) { return null; }
    }
    private async Task RefreshBindingStateAsync(NpgsqlConnection db,CancellationToken ct)
    {
        await using var command=new NpgsqlCommand("""
            select md5(coalesce(string_agg(x,'|' order by x),'')) from (
              select concat_ws(chr(31),'b',agent_id::text,module_id,source_instance_id,source_name,channel,module_version) x from sli_agent_module_bindings
              union all select concat_ws(chr(31),'s',id::text,hostname,fqdn,domain_id::text) from servers where role='domain_controller' and is_active) t
            """,db);
        var state=(string?)await command.ExecuteScalarAsync(ct);
        if(state!=bindingState) {
            unbound.Clear();
            // Resume at the oldest held packet even if this stream keeps receiving data.
            foreach (string stream in awaitingDcSource) {
                streams.Passed.Remove(stream);
                streams.Served.Remove(stream);
            }
            awaitingDcSource.Clear();
            bindingState=state;
        }
    }
    private async Task RememberUnboundAsync(NpgsqlConnection db,Guid packet,CancellationToken ct)
    {
        await using var command=new NpgsqlCommand("""
            select concat_ws(chr(31),envelope->>'agent_id',envelope->>'module_id',envelope->>'source_instance_id',envelope->>'channel',envelope->>'module_version',packet->'header'->>'source')
            from sli_agent_packet_inbox where packet_id=@packet
            """,db);
        command.Parameters.AddWithValue("packet",packet);
        if(await command.ExecuteScalarAsync(ct) is string key) unbound.Add(key);
    }
    // Round-robin over (agent,module) streams, continuing across polls: every stream gets one packet per round, oldest first,
    // so a stream with a deep backlog is reached even while other streams keep receiving packets.
    // Passed holds the last packet tried per stream; an unserved, non-deferred stream has reached its tail.
    internal sealed class StreamFairness
    {
        public HashSet<string> Served{get;}=new(StringComparer.Ordinal);
        public Dictionary<string,(DateTime Received,Guid Packet)> Passed{get;}=new(StringComparer.Ordinal);
        // Returns true after an empty round. Empty rounds never restart, even when cursors were reset.
        public async Task<bool> PollAsync(int limit,Func<Task<AgentInboxStep>> process,IEnumerable<string> deferred)
        {
            // Each claim, including failure, spends one slot. Only a nonempty round can restart;
            // an empty round exits, so a poll makes at most 2*limit+1 claim steps.
            for(int scanned=0;scanned<limit;) {
                var step=await process();
                if(!step.Scanned) {
                    if(Served.Count==0) { Passed.Clear(); return true; }
                    // A deferred stream was excluded from claiming, so this does not establish its tail.
                    var excluded=deferred.ToHashSet(StringComparer.Ordinal);
                    foreach(var tailKey in Passed.Keys.Where(key=>!Served.Contains(key) && !excluded.Contains(key)).ToArray())
                        Passed.Remove(tailKey);
                    Served.Clear();
                    continue;
                }
                if(step.StreamKey is { } key) { Served.Add(key); Passed[key]=(step.Received,step.PacketId); }
                scanned++;
            }
            return false;
        }
    }
    private static string StreamKeyOf(Inbox row)=>string.Join('',JsonRead.TryString(row.Envelope["agent_id"],out var a)?a:"",JsonRead.TryString(row.Envelope["module_id"],out var m)?m:"");
    internal sealed record Inbox(Guid PacketId,DateTime Received,JsonObject Envelope,JsonObject Packet,JsonArray Rows);
    internal const string ClaimSql="""
        select packet_id,received_at,envelope::text,packet::text,event_rows::text from sli_agent_packet_inbox i
        where imported_at is null and module_disabled_at is null and not exists(select 1 from sli_agent_packet_quarantine q where q.packet_id=i.packet_id)
          and not exists(select 1 from sli_agents a where a.id::text=i.envelope->>'agent_id' and a.status in ('replaced','disabled')
        )
          and (@after_time is null or (received_at,packet_id)>(@after_time,@after_packet))
          and (cardinality(@skipped)=0 or not (concat_ws(chr(31),i.envelope->>'agent_id',i.envelope->>'module_id',i.envelope->>'source_instance_id',i.envelope->>'channel',i.envelope->>'module_version',i.packet->'header'->>'source')=any(@skipped)))
          and not exists(select 1 from unnest(@deferred_agents,@deferred_modules) as d(agent_id,module_id)
              where i.envelope->>'agent_id'=d.agent_id and i.envelope->>'module_id'=d.module_id)
          and not (concat_ws(chr(31),i.envelope->>'agent_id',i.envelope->>'module_id')=any(@served))
          and not exists(select 1 from unnest(@cur_keys,@cur_times,@cur_ids) as c(k,t,id)
              where c.k=concat_ws(chr(31),i.envelope->>'agent_id',i.envelope->>'module_id') and (i.received_at,i.packet_id)<=(c.t,c.id))
        order by received_at,packet_id limit 1 for update skip locked
        """;
    private static async Task<Inbox?> ClaimAsync(NpgsqlConnection db,NpgsqlTransaction tx,(DateTime Received,Guid Packet)? after,CancellationToken ct,IEnumerable<(string Agent,string Module)>? deferred,string[]? skipped=null,StreamFairness? fairness=null)
    {
        await using var command=new NpgsqlCommand(ClaimSql,db,tx);
        ClaimParameters(command,after,deferred,skipped,fairness);
        await using var reader=await command.ExecuteReaderAsync(ct);
        if(!await reader.ReadAsync(ct)) return null;
        return new Inbox(reader.GetGuid(0),reader.GetDateTime(1),JsonNode.Parse(reader.GetString(2))!.AsObject(),JsonNode.Parse(reader.GetString(3))!.AsObject(),JsonNode.Parse(reader.GetString(4))!.AsArray());
    }
    private static void ClaimParameters(NpgsqlCommand command,(DateTime Received,Guid Packet)? after,IEnumerable<(string Agent,string Module)>? deferred,string[]? skipped,StreamFairness? fairness)
    {
        var cur=fairness?.Passed.ToArray() ?? [];
        command.Parameters.AddWithValue("served",NpgsqlDbType.Array|NpgsqlDbType.Text,fairness?.Served.ToArray() ?? []);
        command.Parameters.AddWithValue("cur_keys",NpgsqlDbType.Array|NpgsqlDbType.Text,cur.Select(x=>x.Key).ToArray());
        command.Parameters.AddWithValue("cur_times",NpgsqlDbType.Array|NpgsqlDbType.TimestampTz,cur.Select(x=>x.Value.Received).ToArray());
        command.Parameters.AddWithValue("cur_ids",NpgsqlDbType.Array|NpgsqlDbType.Uuid,cur.Select(x=>x.Value.Packet).ToArray());
        command.Parameters.AddWithValue("skipped",NpgsqlDbType.Array|NpgsqlDbType.Text,skipped ?? []);
        command.Parameters.AddWithValue("after_time",NpgsqlDbType.TimestampTz,after is null?DBNull.Value:after.Value.Received);
        command.Parameters.AddWithValue("after_packet",NpgsqlDbType.Uuid,after is null?DBNull.Value:after.Value.Packet);
        var excluded=deferred?.ToArray() ?? [];
        command.Parameters.AddWithValue("deferred_agents",NpgsqlDbType.Array|NpgsqlDbType.Text,excluded.Select(x=>x.Agent).ToArray());
        command.Parameters.AddWithValue("deferred_modules",NpgsqlDbType.Array|NpgsqlDbType.Text,excluded.Select(x=>x.Module).ToArray());
    }
    private static async Task ImportAsync(NpgsqlConnection db,NpgsqlTransaction tx,Inbox row,CancellationToken ct,DirectAdDcRuntime? direct,bool npsAdmission,AdDcProjectionFailure failures)
    {
        var envelope=row.Envelope;
        string module=Text(envelope["module_id"]);
        if(module==DirectWindowsEventLogPacket.Module) {
            if(direct is null)throw new DirectAdDcPending("agent_storage_unavailable");
            try { await DirectWindowsEventLogPacket.ImportAsync(db,tx,direct.Worker,row.PacketId,envelope,row.Packet,row.Rows,direct.CatalogPath,ct); }
            catch(OperationCanceledException) when(ct.IsCancellationRequested) { throw; }
            catch(DirectSourceConflict) { throw; }
            catch(Exception error) {
                string code=error is InvalidOperationException && error.Message is "agent_storage_unavailable" or "agent_disabled" or "agent_module_not_assigned" or
                    "agent_packet_attestation_invalid" or "agent_eventlog_source_not_bound" or "agent_eventlog_source_not_configured" or
                    "agent_eventlog_channel_not_configured" or "storage_v2_projection_schema_missing" ? error.Message : "agent_projection_failed";
                throw new DirectAdDcPending(code);
            }
            return;
        }
        if (module == "sli.vpn-nps") {
            if (direct is null) throw new DirectAdDcPending("agent_storage_unavailable");
            try { await DirectNpsPacket.ImportAsync(db,tx,direct.Worker,row.PacketId,envelope,row.Packet,row.Rows,direct.CatalogPath,ct,npsAdmission); }
            catch (OperationCanceledException) when(ct.IsCancellationRequested) { throw; }
            catch (DirectSourceConflict) { throw; }
            catch (Exception error) {
                string code=error is InvalidOperationException && error.Message is "agent_nps_import_disabled" or "agent_nps_import_config_invalid" or "agent_disabled" or "agent_module_not_assigned" or "agent_source_binding_changed" or "agent_packet_attestation_invalid" or "agent_plugin_disabled" or "agent_nps_source_not_configured" or "agent_plugin_admission_pending" or "agent_nps_archive_publication_pending" ? error.Message : "agent_projection_failed";
                throw new DirectAdDcPending(code);
            }
            return;
        }
        if (module is "sli.windows.ad-dc" or "sli.windows.ad-dc-history") {
            if (direct is null) throw new DirectAdDcPending("agent_storage_unavailable");
            var step=AdDcProjectionStep.Authorization;
            try { await DirectAdDcPacket.ImportAsync(db,tx,direct.Worker,row.PacketId,envelope,row.Packet,row.Rows,direct.CatalogPath,ct,value=>step=value); }
            catch (OperationCanceledException) when(ct.IsCancellationRequested) { throw; }
            catch (DirectSourceConflict error) { WriteDiagnostic(failures,AdDcProjectionFailure.Describe(error,step),ct); throw; }
            catch (Exception error) {
                string code = error is InvalidOperationException && error.Message is "agent_storage_unavailable" or "agent_disabled" or "agent_module_not_assigned" or "agent_packet_attestation_invalid" or "agent_plugin_disabled" or "agent_ad_dc_source_not_bound" or "agent_ad_dc_source_not_configured" or "agent_ad_dc_channel_not_configured" ? error.Message : "agent_ad_dc_projection_failed";
                throw new DirectAdDcPending(AdDcProjectionFailure.IsPermanent(error) ? error.Message : code,AdDcProjectionFailure.Describe(error,step),AdDcProjectionFailure.IsPermanent(error));
            }
            return;
        }
        if(module=="sli.file-audit") {
            await FileAuditInboxConsumer.ImportClaimedAsync(db,tx,row.PacketId,envelope,row.Packet,row.Rows,ct,direct);
            return;
        }
        if(module=="sli.workstations" && await WorkstationJournalAdmission.AvailableAsync(db,tx,ct))
        {
            await WorkstationJournalInbox.ImportAsync(db,tx,row,direct,ct);
            return;
        }
        if(module!="sli.workstations") throw new WorkstationPendingException(module switch {
            "sli.radius-accounting" => "agent_radius_importer_required",
            "sli.windows.ad-dc" or "sli.windows.ad-dc-history" or "sli.vpn-nps" => "agent_plugin_not_installed",
            _ => "agent_module_unknown"
        });
        Guid agent=Guid.Parse(Text(envelope["agent_id"]));
        if(Guid.Parse(Text(envelope["packet_id"]))!=row.PacketId) throw new WorkstationPendingException("agent_packet_attestation_invalid");
        Guid host; Guid sourceAgent; JsonArray assigned;
        await using(var command=new NpgsqlCommand("select status,host_id,source_host_id,source_agent_id,assigned_modules::text from sli_agents where id=@id for update",db,tx)) {
            command.Parameters.AddWithValue("id",agent); await using var reader=await command.ExecuteReaderAsync(ct);
            if(!await reader.ReadAsync(ct)||reader.GetString(0)!="active") throw new WorkstationPendingException("agent_disabled");
            if(reader.IsDBNull(1)&&reader.IsDBNull(2)) throw new WorkstationPendingException("agent_identity_unavailable");
            host=reader.IsDBNull(2)?reader.GetGuid(1):reader.GetGuid(2); sourceAgent=reader.IsDBNull(3)?agent:reader.GetGuid(3);
            assigned=JsonNode.Parse(reader.GetString(4))!.AsArray();
        }
        var matches=assigned.OfType<JsonObject>().Where(x=>x["module_id"] is JsonValue v && v.TryGetValue<string>(out var id) && id==module).ToArray();
        if(matches.Length!=1||matches[0]["enabled"] is not JsonValue flag||!flag.TryGetValue<bool>(out var on)||!on) throw new WorkstationPendingException("agent_module_not_assigned");
        await using(var command=new NpgsqlCommand("select envelope::text,envelope_sha256 from sli_agent_receipts where packet_id=@packet and agent_id=@agent and module_id=@module",db,tx)) {
            command.Parameters.AddWithValue("packet",row.PacketId);command.Parameters.AddWithValue("agent",agent);command.Parameters.AddWithValue("module",module);
            await using var reader=await command.ExecuteReaderAsync(ct);
            if(!await reader.ReadAsync(ct)) throw new WorkstationPendingException("agent_packet_attestation_invalid");
            var received=JsonNode.Parse(reader.GetString(0));
            if(!WorkstationJsonEquality.Equals(received,envelope) || reader.GetString(1)!=Packets.Digest(envelope)
                || Text(envelope["payload_sha256"])!=Packets.Digest(row.Packet)) throw new WorkstationPendingException("agent_packet_attestation_invalid");
        }
        if(Text(envelope["source_instance_id"])!=host.ToString("D") || Text(row.Packet["header"]!["source"])!=host.ToString("D")) throw new WorkstationPendingException("agent_packet_attestation_invalid");
        await using(var command=new NpgsqlCommand("select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'))",db,tx)) await command.ExecuteNonQueryAsync(ct);
        await using(var command=new NpgsqlCommand("select installed,enabled from read_plugin_states_v1() where plugin_id='sli.workstations'",db,tx)) {
            await using var reader=await command.ExecuteReaderAsync(ct);
            if(!await reader.ReadAsync(ct)||!reader.GetBoolean(0)||!reader.GetBoolean(1)) throw new WorkstationPendingException("agent_plugin_disabled");
        }
        long entity;long? adComputer;
        await using(var command=new NpgsqlCommand("select entity_id,ad_computer_id from public.resolve_agent_workstation_v160(@agent,@packet)",db,tx)) {
            command.Parameters.AddWithValue("agent",agent);command.Parameters.AddWithValue("packet",row.PacketId);
            await using var reader=await command.ExecuteReaderAsync(ct);
            if(!await reader.ReadAsync(ct)) throw new WorkstationPendingException("agent_identity_unavailable");
            entity=reader.GetInt64(0);adComputer=reader.IsDBNull(1)?null:reader.GetInt64(1);
        }
        var observations=Workstation1102Projection.Build(row.Packet,row.Rows,sourceAgent.ToString("D"),entity,adComputer);
        foreach(var observation in observations) await StoreAsync(db,tx,observation,sourceAgent.ToString("D"),entity,adComputer,ct);
        var protection=WorkstationProtectionState.Prepare(row.Packet);
        if(protection is not null) await WorkstationProtectionState.StoreAsync(db,tx,sourceAgent.ToString("D"),entity,adComputer,protection,ct);
    }
    private static async Task StoreAsync(NpgsqlConnection db,NpgsqlTransaction tx,WorkstationObservation observation,string agent,long entity,long? ad,CancellationToken ct)
    {
        const string sql="""
            insert into sli_plugin_workstations.observations(id,agent_key,entity_id,ad_computer_id,family,event_id,observed_at,observation,observation_sha256,source_xml)
            values(@id,@agent,@entity,@ad,@family,@event,@observed,@observation,@hash,@xml)
            on conflict(id) do nothing returning id
            """;
        await using var command=new NpgsqlCommand(sql,db,tx);
        command.Parameters.AddWithValue("id",observation.Id);command.Parameters.AddWithValue("agent",agent);command.Parameters.AddWithValue("entity",entity);
        if(!JsonRead.TryInteger(observation.Document["event_id"],out var eventId) || eventId<int.MinValue || eventId>int.MaxValue) throw new InvalidDataException();
        command.Parameters.AddWithValue("event",(int)eventId);
        var family=Text(observation.Document["family"]);if(family is not ("protection" or "usb" or "logons" or "processes")) throw new InvalidDataException();command.Parameters.AddWithValue("family",family);
        command.Parameters.AddWithValue("ad",NpgsqlDbType.Bigint,ad is null?DBNull.Value:ad.Value);command.Parameters.AddWithValue("observed",observation.ObservedAt);
        command.Parameters.AddWithValue("observation",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(observation.Document));command.Parameters.AddWithValue("hash",observation.Hash);command.Parameters.AddWithValue("xml",observation.SourceXml);
        if(await command.ExecuteScalarAsync(ct) is not null) return;
        await using var check=new NpgsqlCommand("select observation_sha256,observation::text from sli_plugin_workstations.observations where id=@id",db,tx);check.Parameters.AddWithValue("id",observation.Id);
        await using var reader=await check.ExecuteReaderAsync(ct);
        if(!await reader.ReadAsync(ct)) throw new InvalidDataException();
        var existing=JsonNode.Parse(reader.GetString(1))!.AsObject();
        if(reader.GetString(0)!=Packets.Digest(existing) || Text(existing["source_sha256"])!=Text(observation.Document["source_sha256"])) throw new InvalidDataException();
    }
    private static void WriteDiagnostic(AdDcProjectionFailure failures,JsonObject diagnostic,CancellationToken ct)
    {
        try { if (failures.CountAndAllow(diagnostic)) Console.Error.WriteLine(diagnostic.ToJsonString()); }
        catch(OperationCanceledException) when(ct.IsCancellationRequested) { throw; }
        catch(Exception) { /* A failed diagnostic must not change the packet outcome. */ }
    }
    // Only current server/agent configuration shared by every packet of the pair.
    // Binding mismatches and channel lookup from the packet header are packet-specific.
    private static bool IsConfigurationPending(string? code) => AdDcProjectionFailure.IsStorageIssue(code) || code is
        "agent_ad_dc_source_not_configured" or
        "agent_eventlog_source_not_configured" or
        "agent_disabled" or "agent_module_not_assigned" or "agent_identity_unavailable" or "agent_plugin_disabled" or
        "agent_nps_source_not_configured" or "agent_nps_import_disabled" or "agent_nps_import_config_invalid" or
        "file_audit_source_not_configured" or "file_audit_workstation_not_assigned";
    private sealed class DirectAdDcPending(string code,JsonObject? diagnostic=null,bool permanent=false) : Exception(code) {
        internal JsonObject? Diagnostic { get; }=diagnostic;
        internal bool Permanent { get; }=permanent;
    }
    private static string Text(JsonNode? value)=>JsonRead.TryString(value,out var result)?result:throw new InvalidDataException();
}

