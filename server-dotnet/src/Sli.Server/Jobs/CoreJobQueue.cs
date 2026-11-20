using System.Data;
using System.Text.Json.Nodes;
using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;

namespace Sli.Server.Jobs;

public interface ICoreJobSession : IAsyncDisposable
{
    ValueTask IAsyncDisposable.DisposeAsync() => ValueTask.CompletedTask;
    Task<object?> CallAsync(string function, object?[] args, CancellationToken ct);
    Task BeginAsync(CancellationToken ct);
    Task CommitAsync(CancellationToken ct);
    Task RollbackAsync(CancellationToken ct);
}

// Dedicated direct identity per purpose/profile, never SET ROLE or a runtime/admin pool.
public sealed class PostgresCoreJobSession(NpgsqlConnection connection) : ICoreJobSession
{
    public ValueTask DisposeAsync() => connection.DisposeAsync();
    internal bool IsDisconnected => connection.State is ConnectionState.Closed or ConnectionState.Broken;
    private NpgsqlTransaction? transaction;
    private static readonly IReadOnlyDictionary<string, string> Statements = new Dictionary<string, string>
    {
        ["enqueue_core_job_v1"] = "select public.enqueue_core_job_v1($1::jsonb)",
        ["claim_core_job_v1"] = "select public.claim_core_job_v1($1,$2,$3::jsonb)",
        ["heartbeat_core_job_v1"] = "select public.heartbeat_core_job_v1($1,$2,$3)",
        ["fail_core_job_v1"] = "select public.fail_core_job_v1($1,$2,$3,$4,$5)",
        ["begin_core_job_result_v1"] = "select public.begin_core_job_result_v1($1,$2,$3,$4)",
        ["finish_core_job_result_v1"] = "select public.finish_core_job_result_v1($1,$2,$3,$4,$5::jsonb,$6::jsonb)",
        ["clock_timestamp"] = "select clock_timestamp()",
        ["radius_host_lock"] = "select pg_try_advisory_lock(hashtext('sli.remote-access:radius-session-observation:host:v1'))"
    };
    public async Task<object?> CallAsync(string function, object?[] args, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(Statements[function], connection, transaction);
        foreach (var arg in args)
        {
            if (arg is JsonNode json) command.Parameters.Add(new() { NpgsqlDbType = NpgsqlDbType.Jsonb, Value = CanonicalJson.Serialize(json) });
            else command.Parameters.Add(new() { Value = arg ?? DBNull.Value });
        }
        var result = await command.ExecuteScalarAsync(ct);
        if (result is DBNull) return null;
        if (function == "claim_core_job_v1" && result is string text) return JsonNode.Parse(text)!.AsObject();
        return result;
    }
    public async Task BeginAsync(CancellationToken ct) => transaction = await connection.BeginTransactionAsync(ct);
    public async Task CommitAsync(CancellationToken ct)
    { await transaction!.CommitAsync(ct); await transaction.DisposeAsync(); transaction = null; }
    public async Task RollbackAsync(CancellationToken ct)
    { if (transaction is null) return; await transaction.RollbackAsync(ct); await transaction.DisposeAsync(); transaction = null; }
}

public sealed class CoreJobQueue(ICoreJobSession session)
{
    private static object?[] Fence(JsonObject job) => [Guid.Parse(job.Text("job_id")), Guid.Parse(job.Text("lease_token")), job["lease_generation"]!.Deserialize<long>()];
    public static string IdempotencyKey(JsonObject spec, JsonObject pinned)
    {
        var value = CoreJobJson.Pick(spec, "plugin_id", "handler_id", "handler_version", "manifest_sha256", "source_instance_id", "partition_key", "input_contract", "input_sha256");
        foreach (var item in CoreJobJson.Pick(pinned, "generation", "input_range", "policy_revision", "continuation")) value[item.Key] = item.Value?.DeepClone();
        return CoreJobJson.Digest(value);
    }
    public async Task<string> EnqueueAsync(JsonObject spec, CancellationToken ct)
        => (await session.CallAsync("enqueue_core_job_v1", [spec], ct))?.ToString() ?? throw new CoreJobConflict();
    public async Task<JsonObject?> ClaimAsync(string profile, string executor, JsonArray identities, CancellationToken ct)
    {
        if (!CoreJobRegistry.Profiles.ContainsKey(profile)) throw new CoreJobContractException("executor_profile_invalid");
        return (JsonObject?)await session.CallAsync("claim_core_job_v1", [profile, executor, identities], ct);
    }
    public async Task HeartbeatAsync(JsonObject job, CancellationToken ct)
    { if (await session.CallAsync("heartbeat_core_job_v1", Fence(job), ct) is not true) throw new CoreJobLeaseLost(); }
    public async Task FailAsync(JsonObject job, string code, bool permanent, CancellationToken ct)
    { if (await session.CallAsync("fail_core_job_v1", [.. Fence(job), code, permanent], ct) is not true) throw new CoreJobLeaseLost(); }

    // A draining projection commits effects/receipts in short transactions while
    // retaining the same lease. Only PublishAsync may finish the job/result.
    public async Task ApplyBatchAsync(JsonObject job, JsonObject batch, Func<CancellationToken, Task> apply, CancellationToken ct)
    {
        string hash = CoreJobJson.Digest(batch);
        await session.BeginAsync(ct);
        try
        {
            if (await session.CallAsync("begin_core_job_result_v1", [.. Fence(job), hash], ct) is not "publish") throw new CoreJobLeaseLost();
            await apply(ct);
            // Include the commit boundary in the fence check, even for batches
            // with no writes (and hence no publication guard trigger).
            if (await session.CallAsync("begin_core_job_result_v1", [.. Fence(job), hash], ct) is not "publish") throw new CoreJobLeaseLost();
            await session.CommitAsync(ct);
        }
        catch { await session.RollbackAsync(CancellationToken.None); throw; }
    }

    public async Task<string> PublishAsync(JsonObject job, JsonObject result, Func<CancellationToken, Task> apply, CancellationToken ct)
    {
        var envelope = CoreJobJson.Pick(job, "job_id", "lease_token", "lease_generation", "plugin_id", "plugin_version", "handler_id", "handler_version");
        envelope["contract_id"] = "sli.core-job-result.v1";
        envelope["status"] = result["status"]?.DeepClone(); envelope["output_contract"] = job["result_contract"]?.DeepClone();
        envelope["output_refs"] = new JsonArray("core-job:" + job.Text("job_id"));
        envelope["evidence_refs"] = result["evidence_refs"]?.DeepClone() ?? new JsonArray();
        envelope["continuation"] = result["continuation"]?.DeepClone();
        envelope["coverage_state"] = result["coverage_state"]?.DeepClone() ?? JsonValue.Create("not_proven");
        envelope["error_code"] = result["error_code"]?.DeepClone();
        string hash = CoreJobJson.Digest(new JsonObject { ["envelope"] = envelope.DeepClone(), ["output"] = result.DeepClone() });
        envelope["result_sha256"] = hash;
        CoreJobJson.Validate(envelope, CoreJobRegistry.Schema["$defs"]!["result"]!.AsObject(), CoreJobRegistry.Schema);
        if (CanonicalJson.Length(new JsonObject { ["envelope"] = envelope.DeepClone(), ["output"] = result.DeepClone() }) > job["budget"]!["max_result_bytes"]!.GetValue<long>()) throw new CoreJobContractException("job_result_budget_exceeded");
        await session.BeginAsync(ct);
        try
        {
            string? state = (string?)await session.CallAsync("begin_core_job_result_v1", [.. Fence(job), hash], ct);
            if (state is "duplicate" or "conflict") { await session.CommitAsync(ct); return state; }
            if (state != "publish") throw new CoreJobLeaseLost();
            await apply(ct);
            if (await session.CallAsync("finish_core_job_result_v1", [.. Fence(job), hash, envelope, result], ct) is not true) throw new CoreJobLeaseLost();
            await session.CommitAsync(ct);
            return "committed";
        }
        catch { await session.RollbackAsync(CancellationToken.None); throw; }
    }
}
