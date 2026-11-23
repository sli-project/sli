using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Agents.SnapshotPublication;

namespace Sli.Server.Storage.Lifecycle;

internal sealed class LifecycleRuntime : ILifecycleSession
{
    readonly NpgsqlDataSource source;
    readonly string databaseMeasurementConnection;
    readonly Func<string, string?> get;
    readonly LifecycleFiles files;
    NpgsqlConnection? locked;
    NpgsqlDataSource? maintenance;
    readonly HashSet<string> locks = new(StringComparer.Ordinal);
    readonly string workerId = $"storage-lifecycle-{Environment.MachineName}-{Environment.ProcessId}";
    readonly DateTime started = DateTime.UtcNow;
    string? lastSuccess;
    int waitingForLock;
    void WaitingForLock(bool value) => Volatile.Write(ref waitingForLock,value ? 1 : 0);
    internal LifecycleRuntime(Func<string, string?> get, LifecycleFiles files)
    {
        this.get = get; this.files = files;
        if (!GpoWorkerConfiguration.TryCreateNamed(get, ReadSecret, "ADLOG_PG_DSN", "ADLOG_PG_PASSWORD", "sli_storage_lifecycle", 180, out string? dsn)) throw new LifecycleBlocked("postgres_dsn_not_configured");
        var cs = new NpgsqlConnectionStringBuilder(dsn!) { Pooling = false, Multiplexing = false,
            CommandTimeout = 0, Options = "-c role=adlog_storage_lifecycle_worker -c statement_timeout=0 -c lock_timeout=0" };
        source = NpgsqlDataSource.Create(cs.ConnectionString);
        // The native login owns CONNECT. The retention role selected on the pinned
        // connection does not. Sample under the same login on a separate read-only connection.
        cs.ApplicationName = "sli_storage_database_usage";
        cs.Timeout = 5;
        cs.CommandTimeout = 5;
        cs.Options = "-c default_transaction_read_only=on -c statement_timeout=5000";
        databaseMeasurementConnection = cs.ConnectionString;
    }
    public async Task<long> ReadDatabaseSizeAsync(CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        await using var connection = new NpgsqlConnection(databaseMeasurementConnection);
        await connection.OpenAsync(deadline.Token);
        await using var command = new NpgsqlCommand("select pg_catalog.pg_database_size(pg_catalog.current_database())", connection);
        return await command.ExecuteScalarAsync(deadline.Token) is long bytes && bytes >= 0
            ? bytes : throw new InvalidDataException("database_usage_unavailable");
    }

    internal static byte[] ReadSecret(string path)
    {
        using var stream = File.OpenRead(path); byte[] bytes = new byte[65537]; int n = 0, read;
        while (n < bytes.Length && (read = stream.Read(bytes, n, bytes.Length - n)) > 0) n += read;
        if (n > 65536) throw new ArgumentException("secret_too_large"); return bytes[..n];
    }
    internal static string? Secret(Func<string, string?> get, string name)
    {
        string? path = get(name + "_FILE"), value = get(name);
        if (path is null) return value;
        if (string.IsNullOrEmpty(path) || !string.IsNullOrEmpty(value)) throw new ArgumentException("secret_configuration_invalid");
        string result = new UTF8Encoding(false, true).GetString(ReadSecret(path)).TrimEnd('\r', '\n');
        if (result.Length == 0 || result.Contains('\0')) throw new ArgumentException("secret_configuration_invalid"); return result;
    }
    NpgsqlDataSource Maintenance()
    {
        if (maintenance is not null) return maintenance;
        if (!GpoWorkerConfiguration.TryCreateNamed(get, ReadSecret, "ADLOG_STORAGE_LIFECYCLE_DELETE_DSN", "ADLOG_STORAGE_LIFECYCLE_DELETE_PASSWORD", "sli_storage_lifecycle_delete", 180, out string? dsn))
            throw new LifecycleBlocked("storage_lifecycle_delete_credentials_required");
        var cs = new NpgsqlConnectionStringBuilder(dsn!) { Pooling = false, Multiplexing = false,
            CommandTimeout = 0, Options = "-c role=adlog_storage_lifecycle_delete -c statement_timeout=0 -c lock_timeout=0" };
        maintenance = NpgsqlDataSource.Create(cs.ConnectionString); return maintenance;
    }
    public async Task<bool> TryLockAsync(string name, CancellationToken ct)
    {
        if (locked is not null) await EnsureLocksAsync(ct);
        if (locks.Contains(name)) return true;
        locked ??= await source.OpenConnectionAsync(ct);
        if (!await LifecyclePostgres.Lock(locked, name, ct)) return false;
        locks.Add(name); return true;
    }
    public Task EnsureLocksAsync(CancellationToken ct) => VerifyLocksAsync(locked, locks, ct);
    internal static async Task VerifyLocksAsync(NpgsqlConnection? connection, IReadOnlyCollection<string> names, CancellationToken ct)
    {
        if (connection?.State != System.Data.ConnectionState.Open || names.Count == 0)
            throw new LifecycleBlocked("storage_lifecycle_lock_lost");
        try
        {
            // Probe the original pinned backend and its locks; never reacquire on a replacement connection.
            await using var command = new NpgsqlCommand("""
                select count(*)=@count from pg_locks
                where locktype='advisory' and pid=pg_backend_pid() and granted and objsubid=1
                  and ((classid::bigint << 32) | objid::bigint) in (select hashtext(name)::bigint from unnest(@names::text[]) name)
                """, connection) { CommandTimeout = 0 };
            command.Parameters.AddWithValue("count", names.Count);
            command.Parameters.AddWithValue("names", names.ToArray());
            if (await command.ExecuteScalarAsync(ct) is not true) throw new LifecycleBlocked("storage_lifecycle_lock_lost");
        }
        catch (Exception error) when (error is NpgsqlException or InvalidOperationException || error is OperationCanceledException && !ct.IsCancellationRequested)
        { throw new LifecycleBlocked("storage_lifecycle_lock_lost"); }
    }
    public async Task ReleaseLockAsync(string name, CancellationToken ct)
    {
        if (!locks.Remove(name)) return;
        if (locked?.State != System.Data.ConnectionState.Open) return;
        await using var cmd = new NpgsqlCommand("select pg_advisory_unlock(hashtext(@name))", locked); cmd.Parameters.AddWithValue("name", name);
        try { if (await cmd.ExecuteScalarAsync(ct) is not true) throw new LifecycleBlocked("storage_lifecycle_lock_lost"); }
        catch (NpgsqlException) { /* A disconnected backend has already released its session locks. */ }
    }
    public async Task HeartbeatAsync(string status, string phase, int interval, JsonObject result, CancellationToken ct)
    {
        if (phase == "sleep" && LifecycleJson.Text(result, "status") is "ok" or "disabled") lastSuccess = result["ended_at_utc"]?.ToString();
        var details = new JsonObject {
            ["policy"] = "postgres_partitions",
            ["process_status"] = "running", ["lifecycle_phase"] = phase == "processing" ? "processing" : LifecycleJson.Text(result, "phase") == "completed" ? "not_due" : LifecycleJson.Text(result, "phase"),
            ["last_cycle_status"] = LifecycleJson.Text(result, "status") is "ok" or "disabled" ? "success" : result["status"]?.DeepClone(),
            ["last_cycle_reason"] = (result["reason"] ?? result["warning_reason"])?.DeepClone(), ["last_cycle_started_at"] = result["started_at_utc"]?.DeepClone(),
            ["last_cycle_completed_at"] = result["ended_at_utc"]?.DeepClone(), ["last_result_digest"] = result["result_digest"]?.DeepClone(), ["last_result_phase"] = result["phase"]?.DeepClone(),
            ["last_success_at"] = lastSuccess, ["last_error_type"] = result["error_type"]?.DeepClone(),
            ["last_blocked_phase"] = result["blocked_phase"]?.DeepClone(), ["last_blocked_step"] = result["blocked_step"]?.DeepClone(),
            ["last_successful_watermark"] = result["last_successful_watermark"]?.DeepClone(), ["watermark_updated_at"] = result["watermark_updated_at"]?.DeepClone(),
            ["active_phase"] = result["active_phase"]?.DeepClone(),
            ["file_audit_retention"] = result["file_audit_retention"]?.DeepClone(),
            ["file_audit_observations_selected_count"] = result["file_audit_observations_selected_count"]?.DeepClone(),
            ["file_audit_observations_copied_count"] = result["file_audit_observations_copied_count"]?.DeepClone(),
            ["file_audit_observations_deleted_count"] = result["file_audit_observations_deleted_count"]?.DeepClone(),
            ["file_audit_observations_held_count"] = result["file_audit_observations_held_count"]?.DeepClone(),
            ["agent_inbox_retention"] = result["agent_inbox_retention"]?.DeepClone(),
            ["inbox_retention_batches"] = result["inbox_retention_batches"]?.DeepClone(),
            ["inbox_rows_scanned"] = result["inbox_rows_scanned"]?.DeepClone(),
            ["inbox_rows_deleted"] = result["inbox_rows_deleted"]?.DeepClone(),
            ["inbox_rows_held"] = result["inbox_rows_held"]?.DeepClone(),
            ["inbox_payloads_cleared"] = result["inbox_payloads_cleared"]?.DeepClone(),
            ["agent_receipt_retention"] = result["agent_receipt_retention"]?.DeepClone(),
            ["receipt_retention_batches"] = result["receipt_retention_batches"]?.DeepClone(),
            ["receipt_rows_scanned"] = result["receipt_rows_scanned"]?.DeepClone(),
            ["receipt_rows_deleted"] = result["receipt_rows_deleted"]?.DeepClone(),
            ["receipt_rows_held"] = result["receipt_rows_held"]?.DeepClone(),
            ["semantic_outbox_retention"] = result["semantic_outbox_retention"]?.DeepClone(),
            ["outbox_retention_batches"] = result["outbox_retention_batches"]?.DeepClone(),
            ["outbox_rows_scanned"] = result["outbox_rows_scanned"]?.DeepClone(),
            ["outbox_rows_deleted"] = result["outbox_rows_deleted"]?.DeepClone(),
            ["outbox_rows_held"] = result["outbox_rows_held"]?.DeepClone(),
            ["retention_retained_reasons"] = result["retention_retained_reasons"]?.DeepClone(),
            ["partitions"] = result["partitions"]?.DeepClone(),
            ["capacity_evidence"] = Capacity()
        };
        if (DateTime.TryParse(result["ended_at_utc"]?.ToString(), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var ended)) details["result_age_seconds"] = Math.Max(0, (long)(DateTime.UtcNow - ended).TotalSeconds);
        if (Volatile.Read(ref waitingForLock) != 0) {
            phase = "waiting_for_lock";
            details["lifecycle_phase"] = phase;
        }
        await using var db = await source.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("""
            insert into runtime_worker_heartbeats(worker_name,worker_id,process_pid,status,phase,expected_interval_seconds,details_json,started_at,heartbeat_at,updated_at)
            values('storage_lifecycle',@worker,@pid,@status,@phase,@interval,@details,@started,now(),now())
            on conflict(worker_name) do update set worker_id=excluded.worker_id,process_pid=excluded.process_pid,status=excluded.status,
              phase=excluded.phase,expected_interval_seconds=excluded.expected_interval_seconds,details_json=excluded.details_json,
              started_at=case when runtime_worker_heartbeats.worker_id=excluded.worker_id then runtime_worker_heartbeats.started_at else excluded.started_at end,
              heartbeat_at=now(),updated_at=now()
            """, db);
        cmd.Parameters.AddWithValue("worker", workerId); cmd.Parameters.AddWithValue("pid", Environment.ProcessId); cmd.Parameters.AddWithValue("status", status); cmd.Parameters.AddWithValue("phase", phase);
        cmd.Parameters.AddWithValue("interval", interval); cmd.Parameters.AddWithValue("details", NpgsqlDbType.Jsonb, LifecycleJson.Canonical(details)); cmd.Parameters.AddWithValue("started", started);
        await cmd.ExecuteNonQueryAsync(ct);
    }
    JsonObject Capacity()
    {
        try {
            var drive = new DriveInfo(Path.GetPathRoot(files.Root)!);
            return new JsonObject { ["status"] = "known", ["read_only"] = true, ["disk_free_bytes"] = drive.AvailableFreeSpace, ["free_bytes"] = drive.AvailableFreeSpace, ["total_bytes"] = drive.TotalSize, ["free_percent"] = 100.0 * drive.AvailableFreeSpace / drive.TotalSize };
        } catch { return new JsonObject { ["status"] = "unknown", ["reason"] = "capacity_evidence_unavailable" }; }
    }
    public async Task<JsonObject> ExpirePartitionsAsync(DateTime now, CancellationToken ct)
    {
        int Days(string name, int fallback) {
            string raw = get("Sli:Storage:" + name) ?? get("Sli__Storage__" + name) ?? fallback.ToString(CultureInfo.InvariantCulture);
            return int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out int days) && days > 0
                ? days : throw new LifecycleBlocked("storage_retention_days_invalid");
        }
        var day = now.ToUniversalTime().Date;
        int hot = Days("HotRetentionDays", 14), cold = Days("ColdRetentionDays", 365);
        if (cold < hot) throw new LifecycleBlocked("storage_retention_days_invalid");
        await using var reader = await source.OpenConnectionAsync(ct);
        var setting = await LifecyclePostgres.Rows(reader, null, "select value from public.storage_lifecycle_setting_v319", ct);
        string configured = setting.Count > 0 ? LifecycleJson.Text(setting[0], "value") : get("SLI_AD_SNAPSHOT_HISTORY_DAYS") ?? "365";
        if (!int.TryParse(configured, NumberStyles.None, CultureInfo.InvariantCulture, out int snapshots) || snapshots is < 7 or > 3650)
            throw new LifecycleBlocked("ad_snapshot_history_days_must_be_7_to_3650");
        await using var db = await Maintenance().OpenConnectionAsync(ct);
        var result = await LifecyclePostgres.Rows(db, null,
            "select * from public.expire_short_storage_partitions342(@hot,@cold,@snapshots)", ct,
            ("hot", day.AddDays(-hot)), ("cold", day.AddDays(-cold)), ("snapshots", day.AddDays(-snapshots)));
        return result.Single();
    }
    public Task<JsonObject> RetainInboxAsync(DateTime cutoff, DateTime afterReceivedAt, Guid after, int limit, CancellationToken ct) =>
        new InboxRetention(Maintenance(), files, WaitingForLock).RunAsync(cutoff, after, limit, ct, afterReceivedAt);
    public Task<JsonObject> RetainReceiptsAsync(DateTime cutoff, Guid after, int limit, CancellationToken ct) =>
        new ReceiptRetention(Maintenance(), files, WaitingForLock).RunAsync(cutoff, after, limit, ct);
    public Task<JsonObject> RetainOutboxAsync(DateTime cutoff, Guid after, int limit, CancellationToken ct) =>
        new SemanticOutboxRetention(Maintenance(), files, get("ADLOG_SEMANTIC_RUNTIME_MODE")?.Trim() is { Length: > 0 } mode ? mode : Sli.Server.Semantic.SemanticRuntimeSettings.FindingsMode, WaitingForLock).RunAsync(cutoff, after, limit, ct);
    public async ValueTask DisposeAsync()
    {
        if (locked is not null) await locked.DisposeAsync();
        await source.DisposeAsync(); if (maintenance is not null) await maintenance.DisposeAsync();
    }
}
