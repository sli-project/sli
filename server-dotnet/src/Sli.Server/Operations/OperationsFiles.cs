using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Operations;

// Only fixed operational files are read. No caller supplied path, command,
// directory traversal, DNS lookup or remote probe is accepted by these APIs.
public partial class OperationsFiles
{
    private readonly object storageLock = new();
    private JsonObject? storageCache;
    private DateTimeOffset storageCaptured;
    private bool storageRefreshing;
    private string? storageError;
    private readonly SemaphoreSlim healthLock = new(1, 1);
    private JsonObject? healthCache;
    private long healthCaptured;
    public string Root { get; }
    public string DataRoot { get; }
    private readonly IConfiguration config;
    private readonly Storage.Lifecycle.LifecycleConfiguration legacyConfig;
    public OperationsFiles(IConfiguration config)
    {
        this.config = config;
        Root = Path.GetFullPath(config["Sli:ProjectRoot"] ?? FindRoot());
        legacyConfig = new(Root, name => config["Sli:Operations:" + name] ?? Environment.GetEnvironmentVariable(name));
        string sibling = Path.Combine(Directory.GetParent(Root)?.FullName ?? Root, "sli_data");
        string raw = config["Sli:DataDirectory"] ?? Setting("ADLOG_DATA_DIR", Setting("SLI_DATA_DIR", Directory.Exists(sibling) ? sibling : Path.Combine(Root, "data")));
        DataRoot = Path.GetFullPath(raw, Root);
    }
    static string FindRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (Directory.Exists(Path.Combine(directory.FullName, "config"))) return directory.FullName;
        return AppContext.BaseDirectory;
    }
    public string Setting(string name, string fallback = "") => legacyConfig.Get(name) ?? fallback;
    internal string? PostgresConnectionString => config.GetConnectionString("Sli") ?? config["Sli:PostgresConnectionString"] ?? Setting("ADLOG_PG_DSN");
    public bool Flag(string name) => Setting(name).Trim().ToLowerInvariant() is "1" or "true" or "yes" or "on";
    internal JsonObject CapacityProfile() => Storage.Lifecycle.StorageCapacityProfiles.Read(new Storage.Lifecycle.LifecycleConfiguration(Root, name => Setting(name)).Get);
    internal string Resolve(string relative)
    {
        string portable = relative.Replace('\\', '/');
        return Path.GetFullPath(portable.StartsWith("data/", StringComparison.Ordinal)
            ? Path.Combine(DataRoot, portable[5..]) : Path.Combine(Root, portable));
    }
    public virtual JsonObject? Json(string relative, int maxBytes = 2097152) => ReadJson(Resolve(relative), maxBytes);
    internal static JsonObject? ReadJson(string path, int maxBytes)
    {
        try
        {
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (file.Length > maxBytes) return null;
            byte[] bytes = new byte[maxBytes + 1]; int count = 0, n;
            while (count < bytes.Length && (n = file.Read(bytes, count, bytes.Length - count)) > 0) count += n;
            return count > maxBytes ? null : JsonNode.Parse(Encoding.UTF8.GetString(bytes, 0, count).TrimStart('\uFEFF')) as JsonObject;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or ArgumentException) { return null; }
    }
    public virtual JsonObject? PluginHeartbeat(string component) => ReadJson(Path.Combine(Setting("SLI_PLUGIN_HEARTBEAT_DIR", Path.Combine(DataRoot, "runtime")), "plugin-" + component + ".json"), 65536);
    public virtual JsonObject? NativeHeartbeat(string name) => ReadJson(Path.Combine(DataRoot, "runtime", "native-" + name + ".json"), 65536);
    public virtual JsonArray LogTail(string name, int lines)
    {
        string directory = config["Sli:LogDirectory"] ?? Setting("ADLOG_LOG_DIR", Path.Combine(DataRoot, "logs"));
        try
        {
            using var file = new FileStream(Path.Combine(directory, name), FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            long start = Math.Max(0, file.Length - 262144); file.Seek(start, SeekOrigin.Begin);
            using var reader = new StreamReader(file, Encoding.UTF8, true);
            if (start > 0) reader.ReadLine();
            string text = reader.ReadToEnd();
            var matches = Regex.Matches(text, @"[^\r\n]*(?:\r?\n|\z)").Select(m => m.Value).Where(s => s.Length > 0).TakeLast(lines);
            return new JsonArray(matches.Select(s => JsonValue.Create(Redact(s))).ToArray());
        }
        catch (FileNotFoundException) { return new(); }
        catch (DirectoryNotFoundException) { return new(); }
    }
    // Collector diagnostics consume structured records, never the redacted UI
    // tail (redaction can change JSON syntax). Only derived counters leave here.
    internal virtual IEnumerable<string> CollectorLogLines()
    {
        string directory = config["Sli:LogDirectory"] ?? Setting("ADLOG_LOG_DIR", Path.Combine(DataRoot, "logs"));
        StreamReader reader;
        try { reader = new(new FileStream(Path.Combine(directory, "adlog-monitor.log"), FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete), Encoding.UTF8, true); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { yield break; }
        using (reader)
        {
            while (true)
            {
                string? line;
                try { line = reader.ReadLine(); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { yield break; }
                if (line is null) yield break;
                yield return line;
            }
        }
    }
    internal static string Redact(string line)
    {
        string result = Regex.Replace(line, @"(?i)postgres(?:ql)?://[^\s]+", "[redacted]", RegexOptions.CultureInvariant);
        result = Regex.Replace(result, "(?i)(?:[\"']?)(password|passwd|secret|token|authorization|credential)(?:[\"']?)\\s*[:=]\\s*(?:\"[^\"]*\"|'[^']*'|[^\\s,;]+)", "$1=[redacted]", RegexOptions.CultureInvariant);
        return Regex.Replace(result, @"(?i)\bBearer\s+[^\s,;]+", "Bearer [redacted]", RegexOptions.CultureInvariant);
    }

    public virtual JsonObject Footprint(DateTimeOffset now)
    {
        const string relative = "artifacts/operations/project-storage-latest.json";
        var data = Json(relative);
        int maxAge = int.TryParse(Setting("ADLOG_OPERATIONS_STORAGE_MAX_AGE_SECONDS", "86400"), out var age) ? Math.Clamp(age, 300, 604800) : 86400;
        if (data is null || S(data["schema"]) != "sli.operations-storage-footprint.v1" || data["components"] is not JsonArray { Count: <= 100 })
            return new() { ["schema"] = "sli.operations-storage-footprint.v1", ["status"] = "unavailable", ["generated_at_utc"] = null,
                ["components"] = new JsonArray(), ["totals"] = new JsonObject(), ["backups"] = BackupSummary(now),
                ["warnings"] = new JsonArray("Complete storage footprint snapshot is unavailable."), ["read_only"] = true,
                ["snapshot"] = new JsonObject { ["path"] = Path.Combine(Root, relative), ["age_seconds"] = null, ["max_age_seconds"] = maxAge, ["stale"] = false, ["available"] = false } };
        double? seconds = Time(data["generated_at_utc"]) is {} time ? Math.Max(0, Math.Floor((now - time).TotalSeconds)) : null;
        bool stale = seconds is null || seconds > maxAge;
        data["backups"] = BackupSummary(now);
        var spool = data["raw_spool"] as JsonObject;
        bool valid = spool is not null && S(spool["status"]) is "ok" or "partial" or "unavailable" && spool["scan"] is JsonObject && spool["thresholds"] is JsonObject;
        if (!valid || S(spool?["status"]) == "unavailable" && (spool?["bytes"] is not null || spool?["batch_count"] is not null))
        {
            data["raw_spool"] = new JsonObject { ["status"] = "unavailable", ["path"] = null, ["bytes"] = null, ["human"] = null, ["batch_count"] = null,
                ["oldest_batch_at_utc"] = null, ["oldest_batch_age_seconds"] = null, ["thresholds"] = new JsonObject(), ["scan"] = new JsonObject { ["complete"] = false, ["errors"] = 1, ["error"] = spool is null ? "raw_spool_missing" : "raw_spool_contract_invalid" } };
            if (spool is not null) data["status"] = "unavailable";
        }
        else if (S(spool!["status"]) == "ok" && !B(spool["scan"]?["complete"])) spool["status"] = "partial";
        if (S(data["raw_spool"]?["status"]) is "partial" or "unavailable" && S(data["status"]) == "ok")
        { data["status"] = "partial"; (data["warnings"] as JsonArray ?? (JsonArray)(data["warnings"] = new JsonArray())!).Add("RAW spool measurements are incomplete or unavailable."); }
        data["snapshot"] = new JsonObject { ["path"] = Path.Combine(Root, relative), ["age_seconds"] = seconds, ["max_age_seconds"] = maxAge, ["stale"] = stale, ["available"] = true };
        if (OperationsStorage.ProjectScanWarning(data) is {} scanWarning)
        {
            if (S(data["status"]) == "ok") data["status"] = "partial";
            (data["warnings"] as JsonArray ?? (JsonArray)(data["warnings"] = new JsonArray())!).Add(scanWarning);
        }
        if (stale) { data["status"] = "stale"; (data["warnings"] as JsonArray ?? (JsonArray)(data["warnings"] = new JsonArray())!).Add("Storage footprint snapshot is stale; run the documented read-only refresh."); }
        return data;
    }
    JsonObject BackupSummary(DateTimeOffset now)
    {
        string fallback = Setting("SLI_DEPLOYMENT_MODE") == "native" ? "/var/lib/sli/backup-status/summary.json" : "/run/sli-backup-status/summary.json";
        var data = ReadJson(Setting("SLI_BACKUP_SUMMARY_PATH", fallback), 4096);
        var result = new JsonObject { ["last_backup_at_utc"] = null, ["last_verified_at_utc"] = null, ["capacity_days"] = null };
        foreach (string key in new[] { "last_backup_at_utc", "last_verified_at_utc" }) if (Time(data?[key]) is {} time) result[key] = Stamp(time);
        if (Time(data?["observed_at_utc"]) is {} observed && (now - observed).TotalSeconds <= 172800 && data?["capacity_days"] is JsonValue v && v.TryGetValue<long>(out long days) && days >= 0) result["capacity_days"] = days;
        return result;
    }
    public virtual JsonObject DiskPressure()
    {
        try
        {
            var disk = ReadDiskSpace();
            double percent = disk.Total > 0 ? disk.Free * 100d / disk.Total : 0;
            return Storage.Lifecycle.StorageCapacityProfiles.Pressure(new JsonObject { ["total_bytes"] = disk.Total, ["free_bytes"] = disk.Free, ["used_bytes"] = disk.Total - disk.Free, ["free_percent"] = Math.Round(percent, 2) }, CapacityProfile()["effective_policy"]!.AsObject());
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException) { return Unavailable(e); }
    }
    protected virtual (long Free, long Total) ReadDiskSpace()
    {
        var disk = new DriveInfo(Path.GetPathRoot(Root)!);
        return (disk.AvailableFreeSpace, disk.TotalSize);
    }
    internal JsonObject RecentRawGrowth(DateTimeOffset now)
    {
        var scan = Scan("data/raw", 20000, TimeSpan.FromSeconds(2), now.AddHours(-24));
        return new() { ["bytes"] = Copy(scan["bytes"]), ["human"] = Copy(scan["human"]), ["files"] = Copy(scan["files"]), ["lookback_hours"] = 24, ["scan"] = Copy(scan["scan"]) };
    }
    internal virtual JsonObject Scan(string relative, int maxEntries, TimeSpan budget, DateTimeOffset? modifiedSince = null)
    {
        var started = Stopwatch.StartNew(); long bytes = 0; int files = 0, entries = 0, errors = 0; bool complete = true;
        var pending = new Stack<string>(); string path = Resolve(relative);
        if (File.Exists(path)) pending.Push(path); else if (Directory.Exists(path)) pending.Push(path);
        while (pending.TryPop(out string? current))
        {
            if (entries >= maxEntries || started.Elapsed > budget) { complete = false; break; }
            try
            {
                var info = new FileInfo(current);
                if ((info.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                if ((info.Attributes & FileAttributes.Directory) == 0)
                {
                    entries++;
                    if (modifiedSince is null || info.LastWriteTimeUtc >= modifiedSince.Value.UtcDateTime) { bytes += info.Length; files++; }
                }
                else foreach (var child in Directory.EnumerateFileSystemEntries(current))
                {
                    if (++entries >= maxEntries || started.Elapsed > budget) { complete = false; break; }
                    pending.Push(child);
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { errors++; }
        }
        return new() { ["bytes"] = bytes, ["human"] = Human(bytes), ["files"] = files,
            ["scan"] = new JsonObject { ["complete"] = complete && errors == 0, ["errors"] = errors, ["entries"] = entries, ["duration_ms"] = started.ElapsedMilliseconds } };
    }
    internal virtual IReadOnlyList<FileInfo> Inventory(string relative, int maxEntries, TimeSpan budget)
    {
        var timer = Stopwatch.StartNew(); var result = new List<FileInfo>(); var pending = new Stack<string>(); string path = Resolve(relative);
        if (!Directory.Exists(path)) return result; pending.Push(path); int entries = 0;
        while (pending.TryPop(out string? directory) && entries < maxEntries && timer.Elapsed < budget)
        {
            foreach (var name in Directory.EnumerateFileSystemEntries(directory))
            {
                if (++entries > maxEntries || timer.Elapsed > budget) break;
                var info = new FileInfo(name);
                if ((info.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                if ((info.Attributes & FileAttributes.Directory) != 0) pending.Push(name); else result.Add(info);
            }
        }
        return result;
    }
    internal JsonObject PurgeRuns()
    {
        try
        {
            string directory = Resolve("data/runtime/purge-runs");
            var rows = new JsonArray();
            if (Directory.Exists(directory)) foreach (string path in Directory.EnumerateFiles(directory, "*.json").OrderDescending(StringComparer.Ordinal).Take(50))
            {
                var receipt = ReadJson(path, 65536);
                if (receipt is null || S(receipt["contract"]) != "sli.purge-run.v1") throw new InvalidDataException();
                rows.Add(receipt);
            }
            return new() { ["status"] = "ok", ["runs"] = rows, ["limit"] = 50 };
        }
        catch (Exception e) when (e is IOException or InvalidDataException or UnauthorizedAccessException) { return new() { ["status"] = "unavailable", ["reason"] = "purge_receipts_unreadable", ["runs"] = new JsonArray() }; }
    }
    internal async Task<JsonObject> SystemHealthAsync(bool force, TimeProvider clock, Func<Task<JsonObject>> build, CancellationToken ct)
    {
        int ttl = int.TryParse(Setting("ADLOG_SYSTEM_HEALTH_CACHE_SECONDS", "30"), out int value) ? Math.Clamp(value, 0, 300) : 30;
        await healthLock.WaitAsync(ct);
        try
        {
            double age = clock.GetElapsedTime(healthCaptured).TotalMilliseconds;
            if (!force && ttl > 0 && healthCache is not null && age <= ttl * 1000)
            {
                var cached = (JsonObject)healthCache.DeepClone();
                cached["cache"] = new JsonObject { ["hit"] = true, ["ttl_seconds"] = ttl, ["age_ms"] = (long)Math.Max(0, age) };
                return cached;
            }
            var result = await build();
            result["cache"] = new JsonObject { ["hit"] = false, ["ttl_seconds"] = ttl, ["age_ms"] = 0 };
            var snapshot = result["runtime_storage"]?["snapshot"];
            if (!B(snapshot?["refreshing"]) && S(snapshot?["status"]) is "ready" or "incomplete")
            {
                healthCache = (JsonObject)result.DeepClone();
                healthCaptured = clock.GetTimestamp();
            }
            else healthCache = null;
            return result;
        }
        finally { healthLock.Release(); }
    }
    public virtual JsonObject RuntimeStorage(bool force, DateTimeOffset now)
    {
        if (force)
        {
            var built = BuildRuntimeStorage(now);
            lock (storageLock) { storageCache = (JsonObject)built.DeepClone(); storageCaptured = now; storageError = null; }
            return RuntimeStorageResponse(built, 0, false, false, false);
        }
        lock (storageLock)
        {
            double age = Math.Max(0, (now - storageCaptured).TotalSeconds);
            if (storageCache is not null && age < 300) return RuntimeStorageResponse((JsonObject)storageCache.DeepClone(), age, false, storageRefreshing, true);
            if (!storageRefreshing)
            {
                storageRefreshing = true;
                _ = Task.Run(() => {
                    try { var built = BuildRuntimeStorage(DateTimeOffset.UtcNow); lock (storageLock) { storageCache = built; storageCaptured = DateTimeOffset.UtcNow; storageError = null; } }
                    catch (Exception e) { lock (storageLock) storageError = e.GetType().Name; }
                    finally { lock (storageLock) storageRefreshing = false; }
                });
            }
            if (storageCache is not null) return RuntimeStorageResponse((JsonObject)storageCache.DeepClone(), age, true, true, true);
            return new() { ["generated_at_utc"] = Stamp(now), ["sizes"] = new JsonObject(), ["counts"] = new JsonObject(), ["disk"] = new JsonObject(),
                ["warnings"] = new JsonArray(storageError is null ? "Полный снимок хранилища формируется; частичные размеры не показываются" : "Полный снимок хранилища пока недоступен: " + storageError),
                ["scan"] = new JsonObject { ["mode"] = "single_pass", ["scope"] = "project_tree", ["complete_project_tree"] = false, ["status"] = "warming", ["files_seen"] = null, ["errors"] = null },
                ["snapshot"] = new JsonObject { ["status"] = storageError is null ? "warming" : "unavailable", ["scope"] = "complete_project_tree", ["generated_at_utc"] = null, ["age_ms"] = null, ["ttl_seconds"] = 300, ["cache_hit"] = false, ["stale"] = false, ["refreshing"] = true, ["last_error"] = storageError } };
        }
    }
    static JsonObject RuntimeStorageResponse(JsonObject payload, double age, bool stale, bool refreshing, bool hit)
    {
        payload["snapshot"] = new JsonObject { ["status"] = B(payload["scan"]?["complete_project_tree"]) ? "ready" : "incomplete", ["scope"] = "complete_project_tree", ["generated_at_utc"] = Copy(payload["generated_at_utc"]), ["age_ms"] = (long)(age * 1000), ["ttl_seconds"] = 300, ["cache_hit"] = hit, ["stale"] = stale, ["refreshing"] = refreshing, ["last_error"] = null };
        return payload;
    }
    internal virtual IEnumerable<string> RuntimeEntries(string directory) => Directory.EnumerateFileSystemEntries(directory);
    JsonObject BuildRuntimeStorage(DateTimeOffset now)
    {
        var timer = Stopwatch.StartNew(); var sizes = new Dictionary<string, long> { ["project"] = 0, ["data"] = 0, ["raw"] = 0, ["raw_archive"] = 0, ["storage_v2_archives"] = 0, ["processed"] = 0, ["reports"] = 0, ["logs"] = 0, ["backups"] = 0, ["maintenance"] = 0, ["artifacts"] = 0, ["archive"] = 0, ["venv"] = 0, ["frontend_node_modules"] = 0, ["sqlite"] = 0 };
        var countKeys = new Dictionary<string, string> { ["raw"] = "raw_files", ["raw_archive"] = "raw_archive_files", ["processed"] = "processed_files", ["reports"] = "report_files", ["logs"] = "log_files", ["backups"] = "backup_files", ["maintenance"] = "maintenance_files" };
        var counts = countKeys.Values.ToDictionary(key => key, _ => 0L); int errors = 0, seen = 0;
        var errorPaths = new JsonArray();
        string spoolRoot = Path.GetFullPath(Resolve("data/raw/pilot")); bool spoolExists = Directory.Exists(spoolRoot);
        long spoolBytes = 0, spoolBatches = 0; int spoolErrors = 0; DateTimeOffset? oldestBatch = null;
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        bool InSpool(string path) => path.Equals(spoolRoot, comparison) || path.StartsWith(spoolRoot + Path.DirectorySeparatorChar, comparison);
        var pending = new Stack<string>(); pending.Push(Root);
        bool dataOutside = !DataRoot.StartsWith(Root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) && DataRoot != Root;
        if (dataOutside && Directory.Exists(DataRoot)) pending.Push(DataRoot);
        while (pending.TryPop(out var directory))
        {
            try
            {
                foreach (string name in RuntimeEntries(directory))
                {
                    var info = new FileInfo(name);
                    if ((info.Attributes & FileAttributes.ReparsePoint) != 0) { if (InSpool(name)) spoolErrors++; continue; }
                    if ((info.Attributes & FileAttributes.Directory) != 0)
                    {
                        if (info.Name is "agent-ca-offline" or "stand-keys" or ".ssh" or ".net-local" or "pytest-runs" || info.Name.StartsWith("pytest-", StringComparison.Ordinal) || info.Name.StartsWith("pytest_", StringComparison.Ordinal)) continue;
                        if (directory.Equals(spoolRoot, comparison))
                        {
                            spoolBatches++; var modified = new DateTimeOffset(info.LastWriteTimeUtc);
                            if (oldestBatch is null || modified < oldestBatch) oldestBatch = modified;
                        }
                        pending.Push(name); continue;
                    }
                    seen++; long bytes = info.Length; sizes["project"] += bytes;
                    if (InSpool(name)) spoolBytes += bytes;
                    bool inData = name.StartsWith(DataRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
                    string relative = Path.GetRelativePath(inData ? DataRoot : Root, name).Replace('\\', '/');
                    if (inData)
                    {
                        sizes["data"] += bytes; string key = relative.Split('/')[0];
                        if (sizes.ContainsKey(key) && key != "data") { sizes[key] += bytes; counts[key + "_files"] = counts.GetValueOrDefault(key + "_files") + 1; }
                        if (countKeys.TryGetValue(key, out string? countKey) && countKey != key + "_files") counts[countKey]++;
                        // Historical artifact inventory only; never opened as a database.
                        if (relative == "processed/ad_logs.sqlite") sizes["sqlite"] += bytes;
                    }
                    else
                    {
                        string key = relative.Split('/')[0]; if (sizes.ContainsKey(key) && key != "project") sizes[key] += bytes;
                        if (key == "backups") counts["backup_files"]++;
                        if (relative.StartsWith(".venv/", StringComparison.Ordinal)) sizes["venv"] += bytes;
                        if (relative.StartsWith("frontend/node_modules/", StringComparison.Ordinal)) sizes["frontend_node_modules"] += bytes;
                    }
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { errors++; errorPaths.Add(directory); if (InSpool(directory)) spoolErrors++; }
        }
        var sizeJson = new JsonObject(); foreach (var pair in sizes) sizeJson[pair.Key] = new JsonObject { ["bytes"] = pair.Value, ["human"] = Human(pair.Value) };
        var countJson = new JsonObject(); foreach (var pair in counts) countJson[pair.Key] = pair.Value;
        var warnings = new JsonArray(); if (errors > 0) warnings.Add("Полный снимок хранилища неполон: не удалось прочитать все объекты.");
        if (sizes["raw"] > 1073741824) warnings.Add("data/raw больше 1 ГБ — высокий приоритет обслуживания");
        var disk = DiskPressure(); if (S(disk["status"]) != "ok") warnings.Add(S(disk["reason"], "Disk pressure unavailable"));
        bool spoolComplete = spoolExists && spoolErrors == 0;
        return new() { ["generated_at_utc"] = Stamp(now), ["sizes"] = sizeJson, ["counts"] = countJson, ["disk"] = Copy(disk["disk"]) ?? new JsonObject(), ["warnings"] = warnings, ["last_raw_cleanup"] = Json("data/maintenance/raw_cleanup_last.json"),
            ["raw_spool"] = new JsonObject { ["status"] = spoolComplete ? "ok" : spoolExists ? "partial" : "unavailable", ["path"] = spoolRoot,
                ["bytes"] = spoolExists ? spoolBytes : null, ["human"] = spoolExists ? Human(spoolBytes) : null, ["batch_count"] = spoolExists ? spoolBatches : null,
                ["oldest_batch_at_utc"] = oldestBatch is {} oldest ? Stamp(oldest) : null, ["timestamp_basis"] = "direct_batch_directory_mtime_utc",
                ["scan"] = new JsonObject { ["complete"] = spoolComplete, ["errors"] = spoolErrors, ["follow_symlinks"] = false },
                ["thresholds"] = new JsonObject { ["bytes_warning"] = 524288000, ["bytes_critical"] = 1073741824, ["batch_count_warning"] = 1000, ["oldest_age_warning_seconds"] = 172800,
                    ["basis"] = "existing_raw_size_cleanup_candidate_and_retention_policy_boundaries" } },
            ["scan"] = new JsonObject { ["mode"] = "single_pass", ["scope"] = "project_tree", ["complete_project_tree"] = errors == 0, ["files_seen"] = seen, ["errors"] = errors, ["error_paths"] = errorPaths, ["follow_symlinks"] = false, ["duration_ms"] = timer.ElapsedMilliseconds } };
    }
}
