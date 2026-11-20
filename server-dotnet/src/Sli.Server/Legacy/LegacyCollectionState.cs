using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Semantic;

namespace Sli.Server.Legacy;

// Summary/import receipts belong to the acquisition that actually published the events.
public sealed partial record LegacyCollectionSummary(string Server, string StartedAt, JsonObject Summary, JsonObject ImportStats);

public interface ILegacyCollectionState
{
    Task<JsonObject?> BlockAsync(CancellationToken ct);
    Task ActivateAsync(string code, string action, string worker, string? server, int? job, JsonObject evidence, CancellationToken ct);
    Task ClearAsync(string server, string actor, CancellationToken ct);
    Task StartAsync(string run, string worker, LegacyJobInput input, CancellationToken ct);
    Task FinishAsync(string run, JsonObject result, CancellationToken ct);
}

public sealed class LegacyCollectionState(ISemanticDatabase database) : ILegacyCollectionState
{
    static string? Text(JsonNode? value) => value?.ToString();
    static long? Number(JsonNode? value) => long.TryParse(Text(value), out long n) ? n : null;
    static bool IsTrue(JsonNode? value) => value is JsonValue v && v.TryGetValue<bool>(out bool b) && b;
    static bool IsFalse(JsonNode? value) => value is JsonValue v && v.TryGetValue<bool>(out bool b) && !b;

    internal static Task UpdateAsync(ISemanticSession session, LegacyCollectionSummary receipt,
        long? jobId, string? traceId, CancellationToken ct, bool requireQueryExhaustion = false)
    {
        throw new InvalidOperationException("module_disabled");
    }

    public async Task<JsonObject?> BlockAsync(CancellationToken ct)
    {
        try {
            await using var db = await database.OpenAsync(false, ct);
            var rows = await db.QueryAsync("select reason_code,operator_action,observed_count from runtime_collection_blocks where singleton_id=1 and active", ct);
            return rows.Count == 0 ? null : (JsonObject)rows[0]!.DeepClone();
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return new() { ["reason_code"] = "runtime_collection_block_contract_unavailable",
            ["operator_action"] = "Состояние блокировки сбора недоступно; сбор остановлен до восстановления PostgreSQL." }; }
    }
    public async Task ActivateAsync(string code, string action, string worker, string? server, int? job, JsonObject evidence, CancellationToken ct)
    {
        // Never persist raw exception text, credentials or Windows identity values.
        var safe = new JsonObject();
        foreach (string key in new[] { "failure_code", "failure_scope", "collector_backend", "marker" })
            if (evidence[key] is {} value) safe[key] = value.DeepClone();
        await using var db = await database.OpenAsync(true, ct);
        await db.QueryAsync("""
            insert into runtime_collection_blocks(singleton_id,active,reason_code,retry_policy,operator_action,
              source_worker_id,source_job_id,source_server,evidence_json)
            values(1,true,$1,'operator_recovery_required',$2,$3,$4,$5,$6)
            on conflict(singleton_id) do update set active=true,reason_code=excluded.reason_code,
              retry_policy=excluded.retry_policy,operator_action=excluded.operator_action,source_worker_id=excluded.source_worker_id,
              source_job_id=excluded.source_job_id,source_server=excluded.source_server,evidence_json=excluded.evidence_json,
              observed_count=runtime_collection_blocks.observed_count+1,last_seen_at=now(),cleared_at=null,cleared_by=null,updated_at=now()
            """, ct, code, action, worker, job, server, safe);
        await db.CommitAsync(ct);
    }
    public async Task ClearAsync(string server, string actor, CancellationToken ct)
    {
        await using var db = await database.OpenAsync(true, ct);
        // Lock and recheck: an unrelated block may have replaced the one just probed.
        var rows = await db.QueryAsync("select active,reason_code from runtime_collection_blocks where singleton_id=1 for update", ct);
        if (rows.Count == 0) throw new InvalidOperationException("active collection block was not found");
        var row = rows[0]!;
        if (row["active"]!.GetValue<bool>()) {
            if (row["reason_code"]!.GetValue<string>() is not (LegacyCollectionFailurePolicy.SecurityContext or "windows_event_log_access_denied"))
                throw new InvalidOperationException("active collection block cannot be cleared by Windows preflight");
            await db.QueryAsync("""
                update runtime_collection_blocks set active=false,last_probe_at=now(),last_probe_result='success',
                  cleared_at=now(),cleared_by=$1,updated_at=now(),
                  evidence_json=evidence_json || jsonb_build_object('successful_probe_server',$2::text)
                where singleton_id=1 and active
                """, ct, actor, server);
        }
        await db.CommitAsync(ct);
    }
    public async Task StartAsync(string run, string worker, LegacyJobInput input, CancellationToken ct)
    {
        await using var db = await database.OpenAsync(true, ct);
        await db.QueryAsync("""
            insert into runtime_collection_runs(run_id,worker_id,status,phase,hours,max_events_per_channel,servers_json,started_at)
            values($1,$2,'running','admission',$3,$4,$5,now())
            """, ct, run, worker, input.Hours, input.MaxEvents, JsonSerializer.SerializeToNode(input.Servers));
        await db.CommitAsync(ct);
    }
    public async Task FinishAsync(string run, JsonObject result, CancellationToken ct)
    {
        var errors = result["errors"]?.DeepClone() ?? new JsonArray();
        if (errors.AsArray().Count == 0 && result["status"]?.GetValue<string>() is "blocked" or "failed" && result["reason"] is {} reason)
            errors.AsArray().Add(reason.DeepClone());
        await using var db = await database.OpenAsync(true, ct);
        await db.QueryAsync("""
            update runtime_collection_runs set status=$2,phase=$3,job_id=$4,duration_ms=$5,errors_json=$6,finished_at=now(),updated_at=now()
            where run_id=$1
            """, ct, run, result["status"]!.GetValue<string>(), result["phase"]?.GetValue<string>() ?? "done",
            result["job_id"]?.GetValue<int>(), result["duration_ms"]?.GetValue<long>(), errors);
        await db.CommitAsync(ct);
    }
}

public sealed class LegacyCollectionPreflight(ILegacyWindowsContext windows, ILegacyCollectionState state)
{
    public async Task<JsonObject> RunAsync(string server, string worker, CancellationToken ct)
    {
        string[] reasons = windows.IdentityReasons();
        JsonObject result;
        if (reasons.Length != 0) result = new() { ["status"] = "failed", ["failure_code"] = LegacyCollectionFailurePolicy.SecurityContext };
        else {
            var block = await state.BlockAsync(ct);
            if (block?["reason_code"]?.GetValue<string>() is {} code && LegacyCollectionFailurePolicy.CredentialCodes.Contains(code))
                return new() { ["status"] = "failed", ["reason"] = code, ["operator_action"] = block["operator_action"]?.DeepClone(), ["server"] = server };
            result = windows.Probe(server);
        }
        if (result["status"]?.GetValue<string>() == "ok") {
            var block = await state.BlockAsync(ct);
            if (block is not null) {
                if (block["reason_code"]?.GetValue<string>() is not (LegacyCollectionFailurePolicy.SecurityContext or "windows_event_log_access_denied"))
                    throw new InvalidOperationException("active collection block cannot be cleared by Windows preflight");
                await state.ClearAsync(server, "worker-preflight:" + Environment.UserName, ct);
            }
            return result;
        }
        string failure = result["failure_code"]?.GetValue<string>() ?? "windows_context_preflight_failed";
        var decision = LegacyCollectionFailurePolicy.Classify([failure]);
        string action = decision.OperatorAction ?? "Запустите worker в интерактивной Windows-сессии точной учётной записи с подтверждённым правом чтения журналов DC.";
        if (decision.Blocked) await state.ActivateAsync(failure, action, worker, server, null, new() {
            ["failure_code"] = failure, ["failure_scope"] = "worker_identity", ["collector_backend"] = "dotnet",
            ["identity_reasons"] = JsonSerializer.SerializeToNode(reasons) }, ct);
        result["reason"] = failure; result["operator_action"] = action; result["server"] = server;
        return result;
    }
}