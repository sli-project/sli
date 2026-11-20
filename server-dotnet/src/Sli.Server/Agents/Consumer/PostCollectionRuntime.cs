using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Radius;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Infrastructure;

namespace Sli.Server.Agents.Consumer;

internal sealed class PostCollectionRuntime(NpgsqlConnection processLock, IPostgresConnectionFactory connections, AgentWorkstationInboxConsumer consumer,
    Func<string, Func<JsonObject, CancellationToken, Task>, CancellationToken, Task<Sli.Server.Legacy.LegacyPostResult>>? legacy = null,
    Func<CancellationToken, Task>? cleanup = null)
{
    private readonly SnapshotCycleConsumer snapshots = new();
    private readonly RadiusInboxConsumer accounting = new();
    private readonly Stopwatch clock = Stopwatch.StartNew();
    private readonly string worker = $"post-collection-{Environment.MachineName}-{Environment.ProcessId}";
    private readonly DateTime started = DateTime.UtcNow;
    private JsonObject? activeJob;

    public Task<int> RunAsync(AgentImportOptions options, CancellationToken ct) => new PostCollectionLoop(
        async token => {
            await CheckProcessSessionAsync(token);
            var result = await consumer.RunOnceAsync(16, token, CheckProcessSessionAsync);
            return new(result.Scanned, result.Imported, result.PendingReasons, result.Quarantined) { Cursor = consumer.Cursor, Skipped = result.Skipped };
        },
        async token => {
            await CheckProcessSessionAsync(token);
            await using var pending = new NpgsqlCommand("select exists(select 1 from sli_agent_snapshot_cycles where transport_state='pending' or publication_state='pending')", processLock);
            if (await pending.ExecuteScalarAsync(token) is not true) return PostCollectionBatch.Empty;
            if (!GpoWorkerConfiguration.TryCreate(Environment.GetEnvironmentVariable, ReadBounded, out var dsn))
                return new(0, 0, new Dictionary<string, int> { ["agent_snapshot_import_unavailable"] = 1 });
            return await snapshots.RunOnceAsync(dsn!, token);
        },
        async token => {
            await CheckProcessSessionAsync(token);
            string[] keys = ["SLI_NPS_AGENT_IMPORT_ENABLED", "SLI_NPS_AGENT_WORKER_DSN", "SLI_NPS_AGENT_WORKER_DSN_FILE", "SLI_NPS_AGENT_WORKER_PASSWORD", "SLI_NPS_AGENT_WORKER_PASSWORD_FILE", "ADLOG_RADIUS_COLLECTION_ROUTES_PATH", "ADLOG_RADIUS_SOURCE_NAME", "ADLOG_RADIUS_SOURCE_INSTANCE_ID", "ADLOG_RADIUS_OWNER_CONFIRMED_IP", "ADLOG_RADIUS_ACCOUNTING_SHARE_UNC", "ADLOG_DATA_DIR", "SLI_DATA_DIR"];
            var values = keys.ToDictionary(k => k, Environment.GetEnvironmentVariable);
            var configuration = RadiusWorkerConfiguration.Parse(values);
            return configuration.Enabled ? await accounting.RunUnderProcessLockAsync(configuration.WorkerDsn!, configuration.Binding!, Math.Clamp(options.Limit, 1, 10), token) : PostCollectionBatch.Empty;
        },
        (status, phase, details, token) => HeartbeatAsync(status, phase, options.PollSeconds, details, token),
        () => clock.Elapsed, Task.Delay,
        result => { result["worker_id"] = worker; Console.WriteLine(CanonicalJson.Serialize(result, false)); }, legacy is null ? null : async token => {
            await CheckProcessSessionAsync(token);
            try {
                return await legacy(worker, (current, cancellation) => {
                    activeJob = (JsonObject)current.DeepClone();
                    return HeartbeatAsync("running", current["phase"]?.GetValue<string>() ?? "processing", 30,
                        new JsonObject { ["limit"] = options.Limit, ["active_job"] = current.DeepClone() }, cancellation);
                }, token);
            }
            finally { activeJob = null; }
        }, cleanup is null ? null : async token => {
            await CheckProcessSessionAsync(token);
            await cleanup(token);
        }).RunAsync(options, ct);

    private async Task CheckProcessSessionAsync(CancellationToken ct)
    {
        await using var check = new NpgsqlCommand("select 1", processLock);
        await check.ExecuteScalarAsync(ct);
    }

    private static byte[] ReadBounded(string path)
    {
        using var input = File.OpenRead(path);
        byte[] bytes = new byte[65537]; int count = 0, read;
        while (count < bytes.Length && (read = input.Read(bytes, count, bytes.Length - count)) > 0) count += read;
        if (count > 65536) throw new ArgumentException();
        return bytes[..count];
    }

    private async Task HeartbeatAsync(string status, string phase, int interval, JsonObject details, CancellationToken ct)
    {
        // A replacement monitor session cannot prove ownership of the process
        // lock. Losing that original session must stop the next iteration.
        if (phase == "poll") await CheckProcessSessionAsync(ct);
        if (phase == "legacy_post_collection" && activeJob is { } current) {
            phase = current["phase"]?.GetValue<string>() ?? phase;
            details["active_job"] = current.DeepClone();
        }
        try
        {
            // The process lock session stays dedicated to ownership checks.
            // Imports and monitoring borrow separate pooled connections.
            await using var monitoring = await connections.OpenAsync(ct);
            details["cursors"] = new JsonObject { ["events"] = consumer.Cursor?.DeepClone(),
                ["snapshots"] = snapshots.Cursor?.DeepClone(), ["accounting"] = accounting.Cursor?.DeepClone() };
            await using var command = new NpgsqlCommand("""
                insert into runtime_worker_heartbeats(worker_name,worker_id,process_pid,status,phase,expected_interval_seconds,details_json,started_at,heartbeat_at,updated_at)
                values('post_collection',@worker,@pid,@status,@phase,@interval,@details,@started,now(),now())
                on conflict(worker_name) do update set worker_id=excluded.worker_id,process_pid=excluded.process_pid,status=excluded.status,
                  phase=excluded.phase,expected_interval_seconds=excluded.expected_interval_seconds,details_json=excluded.details_json,
                  started_at=case when runtime_worker_heartbeats.worker_id=excluded.worker_id then runtime_worker_heartbeats.started_at else excluded.started_at end,
                  heartbeat_at=now(),updated_at=now()
                """, monitoring);
            command.CommandTimeout = 0;
            command.Parameters.AddWithValue("worker", worker); command.Parameters.AddWithValue("pid", Environment.ProcessId);
            command.Parameters.AddWithValue("status", status); command.Parameters.AddWithValue("phase", phase);
            command.Parameters.AddWithValue("interval", Math.Clamp(interval, 1, 300)); command.Parameters.AddWithValue("started", started);
            command.Parameters.AddWithValue("details", NpgsqlDbType.Jsonb, CanonicalJson.Serialize(details, false));
            await command.ExecuteNonQueryAsync(ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (NpgsqlException error) when (error is not PostgresException) { throw; }
        catch (Exception) { if (processLock.State != System.Data.ConnectionState.Open) throw; }
    }
}
