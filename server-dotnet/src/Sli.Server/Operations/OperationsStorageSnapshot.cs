using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Operations;

internal sealed record StorageSnapshotOptions
{
    public string? ExternalArchive { get; init; }
    public string? EvidenceRoot { get; init; }
    public string? PlatformDependencies { get; init; }
    public string? PostgresData { get; init; }
    public string? PostgresBin { get; init; }
    public string? SliData { get; init; }
    public string? PnpmStore { get; init; }
    public string ClickHouseContainer { get; init; } = "sli-warm-tier-step1";
    public string? HistoryContainer { get; init; }
    public bool IncludeDocker { get; init; } = true;
}

// Producer runs outside HTTP. Only filesystem metadata and read-only database
// metrics are measured; nested rows and shared image layers never inflate totals.
internal sealed class OperationsStorageSnapshot(OperationsFiles files,
    Func<CancellationToken, Task<JsonObject>> postgres)
{
    internal const string Schema = "sli.operations-storage-footprint.v1";
    internal async Task<JsonObject> BuildAsync(StorageSnapshotOptions options, DateTimeOffset now, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var project = files.RuntimeStorage(true, now);
        var spool = project["raw_spool"]?.DeepClone().AsObject() ?? new JsonObject { ["status"] = "unavailable" };
        long? oldestAge = null;
        if (spool["oldest_batch_at_utc"] is not null)
        {
            if (Time(spool["oldest_batch_at_utc"]) is {} oldest) oldestAge = (long)Math.Max(0, (now - oldest).TotalSeconds);
            else { spool["status"] = "partial"; (spool["scan"] as JsonObject ?? (JsonObject)(spool["scan"] = new JsonObject())!)["complete"] = false; }
        }
        spool["oldest_batch_age_seconds"] = oldestAge;
        var warnings = new JsonArray(); string rawStatus = S(spool["status"]);
        if (rawStatus == "unavailable") warnings.Add("RAW spool is unavailable; bytes, batch count and oldest age are unknown.");
        else if (rawStatus == "partial" || !B(spool["scan"]?["complete"])) warnings.Add("RAW spool scan is incomplete; measured bytes and batch count are lower bounds.");
        if (rawStatus is "ok" or "partial")
        {
            var thresholds = spool["thresholds"];
            if (spool["bytes"] is not null && N(spool["bytes"]) >= N(thresholds?["bytes_critical"])) warnings.Add("RAW spool bytes exceed the explicit critical threshold.");
            else if (spool["bytes"] is not null && N(spool["bytes"]) >= N(thresholds?["bytes_warning"])) warnings.Add("RAW spool bytes exceed the explicit warning threshold.");
            if (spool["batch_count"] is not null && N(spool["batch_count"]) >= N(thresholds?["batch_count_warning"])) warnings.Add("RAW spool batch count exceeds the explicit warning threshold.");
            if (oldestAge is {} age && age >= N(thresholds?["oldest_age_warning_seconds"])) warnings.Add("Oldest RAW spool batch exceeds the explicit age warning threshold; this is not cleanup authorization.");
        }
        string externalPath = options.ExternalArchive ?? Path.Combine(Directory.GetParent(files.Root)!.FullName, Path.GetFileName(files.Root) + "_obsolete");
        string evidencePath = options.EvidenceRoot ?? @"C:\SLI";
        var external = TreeSize(externalPath, ct); var evidence = TreeSize(evidencePath, ct);
        JsonObject pg;
        try { pg = await postgres(ct); }
        catch (Exception e) when (!ct.IsCancellationRequested) { pg = Unavailable(e); pg["available"] = false; }
        long? pgBytes = B(pg["available"]) ? N(pg["database"]?["database_bytes"]) : null;
        var components = new JsonArray();
        void Add(string key, string label, long? bytes, string? path, string method, bool included = false, string? parent = null, string status = "ok", string? note = null) =>
            components.Add(new JsonObject { ["key"] = key, ["label"] = label, ["bytes"] = bytes, ["human"] = bytes is {} n ? Human(n) : null,
                ["path"] = path, ["method"] = method, ["included_in_accounted_total"] = included, ["parent"] = parent, ["status"] = status, ["note"] = note });
        void Tree(string key, string label, string path, JsonObject measured, bool included, string? parent = null) =>
            Add(key, label, measured["bytes"] is null ? null : N(measured["bytes"]), path, S(measured["method"], "not_measured"), included && measured["bytes"] is not null, parent, S(measured["status"]));
        Add("project_root", "Каталог проекта", N(project["sizes"]?["project"]?["bytes"]), files.Root, "single_pass_file_size_sum", true);
        foreach (var (key, size, relative, parent) in new[] {
            ("project_data", "data", "data", "project_root"), ("project_raw", "raw", "data/raw", "project_data"),
            ("project_raw_archive", "raw_archive", "data/raw_archive", "project_data"), ("storage_v2_archive", "storage_v2_archives", "data/storage_v2_archives", "project_data"),
            ("project_processed", "processed", "data/processed", "project_data"), ("project_reports", "reports", "data/reports", "project_data"),
            ("project_logs", "logs", "data/logs", "project_data"), ("project_maintenance", "maintenance", "data/maintenance", "project_data"),
            ("project_backups", "backups", "backups", "project_root"), ("project_artifacts", "artifacts", "artifacts", "project_root"),
            ("project_archive", "archive", "archive", "project_root"), ("project_venv", "venv", ".venv", "project_root"), ("frontend_dependencies", "frontend_node_modules", "frontend/node_modules", "project_root") })
            Add(key, size, N(project["sizes"]?[size]?["bytes"]), files.Resolve(relative), "project_scan_subtotal", parent: parent);
        Tree("external_archive", "Внешний архив проекта", externalPath, external, true);
        Tree("evidence_root", "Сырьё и evidence", evidencePath, evidence, true);
        bool deps = Directory.Exists(options.PlatformDependencies), physicalPg = Directory.Exists(options.PostgresData);
        foreach (var (key, label, path) in new[] { ("platform_dependencies", "Внешние зависимости и среды", options.PlatformDependencies),
            ("postgres_physical_cluster", "Физический кластер PostgreSQL", options.PostgresData), ("postgres_server_install", "Установка сервера PostgreSQL", options.PostgresBin),
            ("sli_data_root", "Рабочие данные и логи", options.SliData), ("pnpm_store", "Глобальное хранилище пакетов pnpm", options.PnpmStore) })
            if (Directory.Exists(path)) Tree(key, label, path!, TreeSize(path!, ct), true);
        if (deps)
            foreach (var (key, directory) in new[] { ("deps_docker_data", "docker-data"), ("deps_docker_desktop", "DockerDesktop"), ("deps_postgres_18", "postgresql-18"),
                ("deps_pgadmin", "pgAdmin4"), ("deps_playwright", "playwright-browsers"), ("deps_installers", "installers"), ("deps_python", "python"), ("deps_npm_cache", "npm-cache") })
            {
                string path = Path.Combine(options.PlatformDependencies!, directory);
                if (Directory.Exists(path)) Tree(key, directory, path, TreeSize(path, ct), false, "platform_dependencies");
            }
        if (Directory.Exists(options.SliData))
            foreach (string directory in new[] { "runtime", "logs", "reports" })
            {
                string path = Path.Combine(options.SliData!, directory);
                if (Directory.Exists(path)) Tree("sli_data_" + directory, directory, path, TreeSize(path, ct), false, "sli_data_root");
            }
        Add("postgres_database", "PostgreSQL database", pgBytes, null, "pg_database_size_current_database", !physicalPg && pgBytes is not null,
            physicalPg ? "postgres_physical_cluster" : null, pgBytes is null ? "unavailable" : "ok");
        if (pgBytes is null && !physicalPg) warnings.Add("PostgreSQL database footprint is unavailable.");
        if (S(external["status"]) == "partial" || S(evidence["status"]) == "partial" || !B(project["scan"]?["complete_project_tree"])) warnings.Add("At least one filesystem tree scan is incomplete.");
        var included = components.OfType<JsonObject>().Where(c => B(c["included_in_accounted_total"]) && c["bytes"] is not null).ToArray();
        long accounted = included.Sum(c => N(c["bytes"])), physical = included.Where(c => S(c["key"]) != "postgres_database").Sum(c => N(c["bytes"]));
        return new() { ["schema"] = Schema, ["generated_at_utc"] = Stamp(now), ["status"] = warnings.Count > 0 ? "partial" : "ok", ["components"] = components,
            ["totals"] = new JsonObject { ["accounted_bytes"] = accounted, ["accounted_human"] = Human(accounted), ["known_physical_bytes"] = physical, ["known_physical_human"] = Human(physical),
                ["postgres_proxy_included"] = !physicalPg && pgBytes is not null, ["accounting_quality"] = physicalPg ? "measured" : pgBytes is not null ? "estimated" : "partial" },
            ["disk"] = Copy(project["disk"]) ?? new JsonObject(), ["postgres"] = new JsonObject { ["status"] = Copy(pg["status"]), ["database"] = Copy(pg["database"]) ?? new JsonObject() },
            ["external_archive"] = external, ["evidence_root"] = evidence,
            ["project_scan"] = Copy(project["scan"]), ["raw_spool"] = spool, ["warnings"] = warnings, ["read_only"] = true,
            ["accounting_notes"] = new JsonArray("Nested project rows are excluded from the total.", "PostgreSQL contributes physical cluster or pg_database_size.") };
    }

    static JsonObject TreeSize(string path, CancellationToken ct)
    {
        var timer = Stopwatch.StartNew(); long bytes = 0, count = 0; int errors = 0; var pending = new Stack<string>();
        if (!Directory.Exists(path)) return new() { ["status"] = "missing", ["path"] = path, ["bytes"] = null, ["human"] = null, ["files"] = 0, ["errors"] = 0 };
        pending.Push(path);
        while (pending.TryPop(out string? directory))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (string child in Directory.EnumerateFileSystemEntries(directory))
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        var info = new FileInfo(child); if ((info.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                        if ((info.Attributes & FileAttributes.Directory) != 0) pending.Push(child);
                        else { bytes += info.Length; count++; }
                    }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException) { errors++; }
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { errors++; }
        }
        return new() { ["status"] = errors == 0 ? "ok" : "partial", ["path"] = path, ["bytes"] = bytes, ["human"] = Human(bytes), ["files"] = count,
            ["errors"] = errors, ["duration_ms"] = timer.ElapsedMilliseconds, ["method"] = "single_pass_file_size_sum" };
    }

    internal static void WriteAtomic(string path, object payload)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var options = new JsonSerializerOptions { WriteIndented = true };
        options.Converters.Add(new UtcDatetime()); options.Converters.Add(new UtcOffset());
        string temporary = path + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(payload, options) + "\n", new System.Text.UTF8Encoding(false));
        File.Move(temporary, path, true);
    }
    sealed class UtcDatetime : JsonConverter<DateTime>
    {
        public override DateTime Read(ref Utf8JsonReader reader, Type type, JsonSerializerOptions options) => reader.GetDateTime();
        public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options) => writer.WriteStringValue(Stamp(new DateTimeOffset(value.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(value, DateTimeKind.Utc) : value)));
    }
    sealed class UtcOffset : JsonConverter<DateTimeOffset>
    {
        public override DateTimeOffset Read(ref Utf8JsonReader reader, Type type, JsonSerializerOptions options) => reader.GetDateTimeOffset();
        public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options) => writer.WriteStringValue(Stamp(value));
    }
}
