using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Globalization;
using System.Runtime.InteropServices;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Operations;

namespace Sli.Server.Legacy;

public interface ILegacyEnvironment
{
    Task<string[]> TargetsAsync(CancellationToken ct);
    Task<JsonObject> DiskGuardAsync(CancellationToken ct);
    Task<string?> CollectionBlockAsync(CancellationToken ct);
}

public sealed class LegacyEnvironment(IPostgresConnectionFactory connections, LegacySettings settings, IConfiguration configuration) : ILegacyEnvironment
{
    public async Task<string[]> TargetsAsync(CancellationToken ct)
    {
        var authority = new DomainControllerTargets(ReadTargetRowsAsync, new OperationsFiles(configuration));
        return (await authority.VerifyConfiguredAsync(ct)).OfType<JsonObject>().Select(t => t["hostname"]!.GetValue<string>()).ToArray();
    }

    async Task<JsonArray> ReadTargetRowsAsync(CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct);
        await using var command = new NpgsqlCommand(DomainControllerTargets.Query, db) { CommandTimeout = 0 };
        await using var reader = await command.ExecuteReaderAsync(ct);
        var rows = new JsonArray();
        while (await reader.ReadAsync(ct)) rows.Add(new JsonObject {
            ["hostname"] = reader.GetString(0), ["connect_address"] = reader.GetString(1),
            ["owner_confirmed_ip"] = reader.IsDBNull(2) ? null : reader.GetString(2), ["enabled"] = reader.GetBoolean(3)
        });
        return rows;
    }

    public Task<JsonObject> DiskGuardAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try {
            string path = settings.DataDirectory;
            while (!Directory.Exists(path)) path = Path.GetDirectoryName(path) ?? throw new IOException();
            var drive = new DriveInfo(Path.GetPathRoot(path)!);
            int Read(string name, int fallback) => int.TryParse(settings.Get(name), out var value) ? value : fallback;
            int warn = Read("ADLOG_MIN_FREE_DISK_PERCENT", 15), stop = Read("ADLOG_STOP_COLLECTION_IF_FREE_DISK_PERCENT_BELOW", 10),
                critical = Read("ADLOG_CRITICAL_FREE_DISK_PERCENT", 5);
            bool valid = critical > 0 && critical < stop && stop < warn && warn < 100;
            if (!valid) { warn = 15; stop = 10; critical = 5; }
            long bytes = Math.Max(1, long.TryParse(settings.Get("ADLOG_STOP_COLLECTION_IF_FREE_DISK_BYTES_BELOW"), out var b) ? b : 10L * 1024 * 1024 * 1024);
            return Task.FromResult(DiskDecision(drive.AvailableFreeSpace, drive.TotalSize, warn, stop, critical, bytes, valid));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException) {
            return Task.FromResult(new JsonObject { ["status"] = "blocked", ["collection_allowed"] = false,
                ["reason"] = "collection_guard_error", ["error_type"] = error.GetType().Name });
        }
    }

    internal static JsonObject DiskDecision(long freeBytes, long totalBytes, int warn, int stop, int critical, long minimumBytes, bool valid, double? observedPercent = null)
    {
        double percent = observedPercent ?? (totalBytes > 0 ? Math.Round(100.0 * freeBytes / totalBytes, 2, MidpointRounding.ToEven) : 0);
        bool bytesBlocked = freeBytes < minimumBytes, percentBlocked = percent < stop;
        string condition = bytesBlocked && percentBlocked ? "free_bytes_and_percent_below_stop" : bytesBlocked ? "free_bytes_below_stop"
            : percentBlocked ? "free_percent_below_stop" : percent < warn ? "warning_only" : "none";
        string? reason = bytesBlocked && percentBlocked ? $"Свободное место ниже обоих порогов остановки сбора: {Human(freeBytes)} < {Human(minimumBytes)}; {N(percent)}% < {stop}%"
            : bytesBlocked ? $"Свободное место ниже фиксированного порога сбора: {Human(freeBytes)} < {Human(minimumBytes)}"
            : percentBlocked ? $"Свободное место ниже процентного порога остановки сбора: {N(percent)}% < {stop}%"
            : percent < warn ? $"Свободное место ниже рекомендованного уровня: {N(percent)}% < {warn}%; сбор разрешён, пороги остановки — {Human(minimumBytes)} или {stop}%."
            : !valid ? "Некорректные storage thresholds; применены безопасные значения 15/10/5." : null;
        return new() { ["status"] = bytesBlocked || percentBlocked ? "blocked" : percent < warn || !valid ? "warn" : "ok",
            ["collection_allowed"] = !bytesBlocked && !percentBlocked, ["reason"] = reason,
            ["disk"] = new JsonObject { ["free_bytes"] = freeBytes, ["total_bytes"] = totalBytes, ["free_percent"] = percent },
            ["blocking_threshold"] = new JsonObject { ["mode"] = "free_bytes_or_percent", ["condition"] = condition,
                ["free_bytes"] = minimumBytes, ["free_human"] = Human(minimumBytes), ["free_percent"] = stop },
            ["threshold_validation"] = new JsonObject { ["status"] = valid ? "ok" : "warn", ["source"] = valid ? "configured" : "safe_defaults",
                ["effective"] = new JsonObject { ["warn_free_percent"] = warn, ["stop_free_percent"] = stop, ["critical_free_percent"] = critical } } };
    }
    private static string N(double value) => value.ToString("0.0#", CultureInfo.InvariantCulture);
    private static string Human(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = bytes; int unit = 0;
        while (value >= 1024 && unit < units.Length - 1) { value /= 1024; unit++; }
        return value.ToString("0.0", CultureInfo.InvariantCulture) + " " + units[unit];
    }

    public async Task<string?> CollectionBlockAsync(CancellationToken ct)
    {
        try {
            await using var db = await connections.OpenAsync(ct);
            await using var command = new NpgsqlCommand("select reason_code from runtime_collection_blocks where singleton_id=1 and active", db);
            return await command.ExecuteScalarAsync(ct) as string;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return "runtime_collection_block_contract_unavailable"; }
    }
}

public interface ILegacyAudit
{
    Task AppendAsync(string action, string status, JsonObject job, CancellationToken ct);
}

public sealed class LegacyAudit(LegacySettings settings, ILogger<LegacyAudit>? logger = null) : ILegacyAudit
{
    [DllImport("libc", EntryPoint = "flock", SetLastError = true)]
    private static extern int Flock(int fileDescriptor, int operation);
    private static readonly SemaphoreSlim Gate = new(1, 1);
    public async Task AppendAsync(string action, string status, JsonObject job, CancellationToken ct)
    {
        try { await AppendCoreAsync(action,status,job,ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch {
            // append_jsonl_bounded in the reference is best effort. Failed audit
            // I/O must not change admission or strand an accepted job.
            logger?.LogWarning("legacy_audit_write_failed");
        }
    }
    private async Task AppendCoreAsync(string action, string status, JsonObject job, CancellationToken ct)
    {
        var row = new JsonObject { ["ts"] = DateTimeOffset.UtcNow.ToString("O"), ["level"] = "INFO",
            ["component"] = "audit", ["event"] = "operator_action", ["action"] = action, ["status"] = status,
            ["pid"] = Environment.ProcessId, ["thread"] = "legacy-jobs" };
        foreach (string key in new[] { "hours", "max_events_per_channel", "servers" }) row[key] = job[key]?.DeepClone();
        if (job["id"] is { } id) row["job_id"] = id.DeepClone();
        if (job["mode"]?.GetValue<string>() == "runtime_guard") row["runtime_guard"] = job["skipped_reason"]?.DeepClone();
        if (job["reason"] is { } reason) row["reason"] = reason.DeepClone();
        string directory = Path.Combine(settings.DataDirectory, "logs");
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "audit-actions.log");
        await Gate.WaitAsync(ct);
        try {
            // Cross-process append lock, compatible with Python's byte-zero lock.
            await using var fileLock = new FileStream(path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite);
            if (fileLock.Length == 0) fileLock.WriteByte(0);
            bool acquired = false;
            try {
                for (int attempt = 0; attempt < 40; attempt++) {
                    ct.ThrowIfCancellationRequested();
                    try {
                        if (OperatingSystem.IsWindows()) fileLock.Lock(0, 1);
                        else if (OperatingSystem.IsLinux()) { if (Flock(fileLock.SafeFileHandle.DangerousGetHandle().ToInt32(), 2 | 4) != 0) throw new IOException("audit_lock_busy"); }
                        else throw new PlatformNotSupportedException("audit_lock_platform_unsupported");
                        acquired = true; break;
                    }
                    catch (IOException) { await Task.Delay(50, ct); }
                }
                if (!acquired) throw new IOException("audit_lock_timeout");
                string line = row.ToJsonString(new JsonSerializerOptions { WriteIndented = false }) + "\n";
                if (File.Exists(path) && new FileInfo(path).Length > 0 && new FileInfo(path).Length + Encoding.UTF8.GetByteCount(line) > 10_000_000) {
                    for (int n = 4; n >= 1; n--) if (File.Exists(path + "." + n)) File.Move(path + "." + n, path + "." + (n + 1), true);
                    File.Move(path, path + ".1", true);
                }
                await File.AppendAllTextAsync(path, line, new UTF8Encoding(false), ct);
            }
            finally { if (acquired) {
                if (OperatingSystem.IsWindows()) fileLock.Unlock(0, 1);
                else if (OperatingSystem.IsLinux()) _ = Flock(fileLock.SafeFileHandle.DangerousGetHandle().ToInt32(), 8);
            } }
        }
        finally { Gate.Release(); }
    }
}
