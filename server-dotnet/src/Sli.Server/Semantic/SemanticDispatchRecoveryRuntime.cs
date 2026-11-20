using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic.Password;

namespace Sli.Server.Semantic;

// Each admin operation owns its transaction; worker replay uses a separate NOINHERIT login.
internal sealed class SemanticDispatchRecoveryRuntime(string adminDsn)
{
    private async Task<NpgsqlConnection> Open(CancellationToken ct)
    {
        var builder = new NpgsqlConnectionStringBuilder(adminDsn) { Pooling = false, Multiplexing = false, CommandTimeout = 0, IncludeErrorDetail = false };
        var db = new NpgsqlConnection(builder.ConnectionString);
        try { await db.OpenAsync(ct); return db; } catch { await db.DisposeAsync(); throw; }
    }
    private async Task<T> Read<T>(Func<ISemanticSession, Task<T>> read, CancellationToken ct)
    {
        await using var db = await Open(ct); await using var tx = await db.BeginTransactionAsync(System.Data.IsolationLevel.RepeatableRead, ct);
        var session = new SemanticSession(db, tx); await session.ExecuteAsync("set transaction read only", ct); return await read(session);
    }
    internal Task<JsonArray> Snapshot(CancellationToken ct) => Read(s => SemanticDispatchRecovery.SnapshotAsync(s, ct), ct);
    internal Task<JsonObject> Baseline(CancellationToken ct) => Read(async s => (await s.QueryAsync(SemanticDispatchRecoverySql.Baseline, ct, SemanticDispatchRecovery.Jobs.Keys.ToArray(), SemanticDispatchRecovery.Jobs.Keys.ToArray())).Single()!.AsObject(), ct);
    internal async Task<JsonObject> Plan(CancellationToken ct) => SemanticDispatchRecovery.BuildPlan(await Snapshot(ct), await Baseline(ct));

    internal async Task<(string Role, string Dsn)> CreateLogin(CancellationToken ct)
    {
        string role = "adlog_semantic_l1_" + Guid.NewGuid().ToString("N"), password = Convert.ToHexString(RandomNumberGenerator.GetBytes(36));
        await using var db = await Open(ct); await using var tx = await db.BeginTransactionAsync(ct);
        var session = new SemanticSession(db, tx); using var quote = new NpgsqlCommandBuilder();
        // Both interpolated values are generated locally, and identifiers are quoted.
        await session.ExecuteAsync($"create role {quote.QuoteIdentifier(role)} login noinherit nosuperuser nocreatedb nocreaterole nobypassrls noreplication password '{password}'", ct);
        await session.ExecuteAsync($"grant adlog_semantic_worker to {quote.QuoteIdentifier(role)}; grant connect on database {quote.QuoteIdentifier(db.Database)} to {quote.QuoteIdentifier(role)}", ct);
        await tx.CommitAsync(ct);
        return (role, new NpgsqlConnectionStringBuilder(adminDsn) { Username = role, Password = password, Pooling = false, Multiplexing = false, CommandTimeout = 0 }.ConnectionString);
    }
    internal async Task DropLogin(string role)
    {
        if (!System.Text.RegularExpressions.Regex.IsMatch(role, @"\Aadlog_semantic_l1_[a-f0-9]{32}\z")) throw new InvalidOperationException("refusing unexpected ephemeral role name");
        await using var db = await Open(CancellationToken.None); await using var tx = await db.BeginTransactionAsync();
        var session = new SemanticSession(db, tx); using var quote = new NpgsqlCommandBuilder(); string id = quote.QuoteIdentifier(role);
        await session.ExecuteAsync($"revoke adlog_semantic_worker from {id}; revoke connect on database {quote.QuoteIdentifier(db.Database)} from {id}; drop role {id}", CancellationToken.None);
        await tx.CommitAsync();
    }
    internal Task<JsonObject> Dispatch(Guid[] ids, DateTimeOffset boundary, CancellationToken ct) => SemanticDispatchRecovery.DispatchAsync(ids, boundary,
        () => CreateLogin(ct), DropLogin, async (_, scope) => {
            await using var runtime = PasswordProducerRuntime.Create(scope.Configuration, _ => throw new InvalidOperationException("recovery forbids credential file reads"));
            await using var db = await runtime.OpenAsync(ct);
            await using (var tx = await db.BeginTransactionAsync(ct)) {
                await SemanticProduction.GuardAsync(new SemanticSession(db, tx), scope.Mode, ct); await tx.CommitAsync(ct);
            }
            // This entrypoint executes dispatch only and has no source/archive/producer/risk dependency.
            return await SemanticProduction.RecoverDispatchAsync(runtime, db, scope, ct);
        }, Environment.GetEnvironmentVariable);

    internal async Task<JsonObject> Apply(JsonObject plan, Func<Task<int?>> guard, string auditPath, CancellationToken ct)
    {
        string digest = plan.Text("plan_digest")!;
        try {
            await using var control = await Open(ct);
            var locks = new List<string>();
            try {
                foreach (string name in new[] { "semantic_dispatch_partition_recovery_controller_v1", "ad_log_reports_runtime_semantic_production_worker" }) {
                    await using var cmd = new NpgsqlCommand("select pg_try_advisory_lock(hashtextextended($1,0))", control) { CommandTimeout = 0 }; cmd.Parameters.AddWithValue(name);
                    if (await cmd.ExecuteScalarAsync(ct) is not true) throw new InvalidOperationException("semantic dispatch recovery advisory lock is busy");
                    locks.Add(name);
                }
                if (await SemanticDispatchRecovery.WorkerIsLiveAsync(guard)) throw new InvalidOperationException("semantic dispatch recovery refuses a live dispatcher");
                var rows = await Snapshot(ct); Guid[] remaining = SemanticDispatchRecovery.ValidateRows(rows);
                if (remaining.Length == 0) return SemanticDispatchRecovery.WriteAtomicAudit(auditPath, new JsonObject { ["status"] = "already_complete", ["plan_digest"] = digest, ["production_changed"] = false });
                if (!JsonNode.DeepEquals(SemanticDispatchRecovery.PlanJobs(rows), plan["jobs"]) || !JsonNode.DeepEquals(await Baseline(ct), plan["baseline"])) throw new InvalidOperationException("semantic dispatch recovery plan changed before any write");
                await using (var db = await Open(ct)) {
                    await using var tx = await db.BeginTransactionAsync(ct); var session = new SemanticSession(db, tx);
                    await session.ExecuteAsync("set local role adlog_storage_worker", ct);
                    await SemanticDispatchRecovery.RequeueAsync(session, remaining, ct); await tx.CommitAsync(ct);
                }
                var dispatch = await Dispatch(remaining, SemanticQuery.Time(plan.Text("normalized_before")!, "UTC", "invalid_boundary"), ct);
                if (dispatch.Number("failed") != 0 || dispatch.Number("completed") != remaining.Length) throw new InvalidOperationException("semantic dispatch recovery processing failed or was incomplete");
                var finalRows = await Snapshot(ct); var baseline = await Baseline(ct);
                if (SemanticDispatchRecovery.ValidateRows(finalRows).Length != 0 || !JsonNode.DeepEquals(baseline, plan["baseline"])) throw new InvalidOperationException("semantic dispatch recovery acceptance verification failed");
                return SemanticDispatchRecovery.WriteAtomicAudit(auditPath, new JsonObject { ["status"] = "complete", ["plan_digest"] = digest, ["production_changed"] = true, ["dispatch"] = dispatch,
                    ["verification"] = new JsonObject { ["completed"] = true, ["relations_exact"] = true, ["scenario_evidence_added"] = 0, ["unrelated_status_unchanged"] = true } });
            }
            finally {
                foreach (string name in locks.AsEnumerable().Reverse()) {
                    await using var cmd = new NpgsqlCommand("select pg_advisory_unlock(hashtextextended($1,0))", control) { CommandTimeout = 0 }; cmd.Parameters.AddWithValue(name); await cmd.ExecuteScalarAsync(CancellationToken.None);
                }
            }
        }
        catch (Exception e) {
            SemanticDispatchRecovery.WriteAtomicAudit(auditPath, new JsonObject { ["status"] = "failed_closed", ["plan_digest"] = digest, ["error_type"] = e.GetType().Name }); throw;
        }
    }
}
