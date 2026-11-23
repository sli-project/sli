using System.Text.Json.Nodes;
using Sli.Server.Storage.Lifecycle;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Operations;

internal static class OperationsStorage
{
    internal static string? ProjectScanWarning(JsonObject overview)
    {
        if (overview["scan"] is not JsonObject scan || scan.Count == 0) return null;
        long errors = N(scan["errors"]);
        return B(scan["complete_project_tree"]) && errors == 0 ? null : $"полный обход проекта неполон: ошибок чтения {errors}";
    }
    internal static JsonObject Thresholds(OperationsFiles files)
    {
        var policy = files.CapacityProfile()["effective_policy"]!;
        int warn = (int)N(policy["min_free_disk_percent"]), stop = (int)N(policy["stop_collection_if_free_disk_percent_below"]), critical = (int)N(policy["critical_free_disk_percent"]);
        bool valid = critical > 0 && critical < stop && stop < warn && warn < 100;
        return new() { ["status"] = valid ? "ok" : "warn", ["source"] = valid ? "configured" : "safe_defaults",
            ["configured"] = new JsonObject { ["warn_free_percent"] = warn, ["stop_free_percent"] = stop, ["critical_free_percent"] = critical },
            ["effective"] = new JsonObject { ["warn_free_percent"] = valid ? warn : 15, ["stop_free_percent"] = valid ? stop : 10, ["critical_free_percent"] = valid ? critical : 5 },
            ["issues"] = valid ? new JsonArray() : new JsonArray("threshold ordering must be critical < stop < warn") };
    }
    internal static readonly string[] ManagedFields = ["database_bytes", "raw_bytes", "raw_archive_bytes", "backups_bytes", "logs_bytes", "reports_bytes", "artifacts_bytes"];
    internal static readonly string[] OperationalFields = ["database_bytes", "raw_bytes", "raw_archive_bytes", "logs_bytes", "reports_bytes"];
    internal static JsonObject Growth(JsonObject? current, JsonObject? previous)
    {
        if (current is null) return new() { ["status"] = "pending", ["quality"] = "no_baseline", ["reason"] = "no snapshots recorded" };
        if (previous is null || Time(previous["captured_at"]) is not {} start || Time(current["captured_at"]) is not {} end)
            return new() { ["status"] = "pending", ["quality"] = "baseline_only", ["reason"] = "a second snapshot is required for measured growth", ["elapsed_hours"] = 0 };
        double seconds = Math.Max(1, (end - start).TotalSeconds), hours = seconds / 3600, days = seconds / 86400; var components = new JsonObject();
        foreach (string key in ManagedFields.Append("disk_used_bytes"))
        {
            long delta = N(current[key]) - N(previous[key]), perDay = (long)Math.Round(delta / days);
            components[key] = new JsonObject { ["delta_bytes"] = delta, ["delta_human"] = Human(Math.Abs(delta)), ["direction"] = Direction(delta), ["bytes_per_day"] = perDay, ["per_day_human"] = Human(Math.Abs(perDay)) };
        }
        long total = ManagedFields.Sum(k => N(current[k]) - N(previous[k])), operational = OperationalFields.Sum(k => N(current[k]) - N(previous[k]));
        long totalDay = (long)Math.Round(total / days), operationalDay = (long)Math.Round(operational / days);
        return new() { ["status"] = "ok", ["quality"] = hours is >= 20 and <= 36 ? "measured_24h" : "measured_partial", ["from"] = Stamp(start), ["to"] = Stamp(end), ["elapsed_hours"] = Math.Round(hours, 2), ["components"] = components,
            ["managed_total_delta_bytes"] = total, ["managed_total_delta_human"] = Human(Math.Abs(total)), ["managed_bytes_per_day"] = totalDay, ["managed_per_day_human"] = Human(Math.Abs(totalDay)),
            ["operational_delta_bytes"] = operational, ["operational_delta_human"] = Human(Math.Abs(operational)), ["operational_bytes_per_day"] = operationalDay, ["operational_per_day_human"] = Human(Math.Abs(operationalDay)), ["direction"] = Direction(operational) };
    }
    static string Direction(long n) => n > 0 ? "growth" : n < 0 ? "reduction" : "stable";
    internal static JsonObject Forecast(JsonObject? current, long growth, JsonObject thresholds)
    {
        if (current is null) return new() { ["status"] = "pending" };
        var items = new JsonObject();
        foreach (string key in new[] { "warn", "stop", "critical" })
        {
            long percent = N(thresholds["effective"]?[key + "_free_percent"]), reserve = (long)(N(current["disk_total_bytes"]) * percent / 100d), usable = Math.Max(0, N(current["disk_free_bytes"]) - reserve);
            items[key] = new JsonObject { ["free_percent"] = percent, ["reserve_bytes"] = reserve, ["reserve_human"] = Human(reserve), ["current_headroom_bytes"] = usable, ["current_headroom_human"] = Human(usable), ["estimated_days"] = growth > 0 ? Math.Round(usable / (double)growth, 2) : null };
        }
        return new() { ["status"] = growth > 0 ? "ok" : "stable_or_unknown", ["growth_bytes_per_day_used"] = growth, ["growth_per_day_human"] = Human(Math.Abs(growth)), ["thresholds"] = items };
    }
}

public sealed partial class OperationsService
{
    // Storage reads the existing measurements only. The full overview also reads
    // collection/workers and pg_database_size; none belongs on this request path.
    internal JsonObject StorageOverview()
    {
        var now = Now;
        var footprint = files.Footprint(now);
        var sample = files.Json("data/runtime/" + StorageLifecycleWorker.DatabaseUsageFile, maxBytes: 1024);
        var database = DatabaseMeasurement(sample?["database_bytes"], sample?["observed_at_utc"], now);
        var manualComponent = (footprint["components"] as JsonArray ?? []).OfType<JsonObject>()
            .FirstOrDefault(row => S(row["key"]) == "postgres_database");
        var manual = S(footprint["status"]) == "stale" ? null : DatabaseMeasurement(manualComponent?["bytes"],
            footprint["postgres"]?["database"]?["checked_at"] ?? footprint["generated_at_utc"], now);
        if (manual is { } fallback && (database is null || fallback.ObservedAt > database.Value.ObservedAt))
            database = fallback;

        var components = new JsonArray();
        if (database is { } measured)
            components.Add(new JsonObject { ["key"] = "postgres_database", ["human"] = Human(measured.Bytes),
                ["bytes"] = measured.Bytes, ["observed_at_utc"] = Stamp(measured.ObservedAt) });
        var disk = files.DiskPressure()["disk"] as JsonObject;
        var measurements = new JsonObject();
        foreach (string name in new[] { "used", "free" })
            if (disk?[name + "_bytes"] is {} bytes)
            { measurements[name + "_bytes"] = Copy(bytes); measurements[name + "_human"] = Human(N(bytes)); }
        return new() { ["api_version"] = "v1", ["generated_at_utc"] = Generated, ["read_only"] = true,
            ["storage"] = new JsonObject {
                ["agent_inbox_capacity"] = inboxLimits?.CapacityStatus(),
                ["retired_clickhouse_data"] = OperatingSystem.IsLinux() && Directory.Exists("/srv/sli-db/clickhouse"),
                ["postgres_volume"] = files.PostgresVolume(),
                ["disk_pressure"] = new JsonObject { ["disk"] = measurements },
                ["footprint"] = new JsonObject { ["components"] = components,
                    ["backups"] = new JsonObject { ["last_backup_at_utc"] = Copy(footprint["backups"]?["last_backup_at_utc"]),
                        ["same_disk_as_postgres"] = Copy(footprint["backups"]?["same_disk_as_postgres"]) } } } };
    }

    static (long Bytes, DateTimeOffset ObservedAt)? DatabaseMeasurement(JsonNode? size, JsonNode? observed, DateTimeOffset now)
    {
        if (size is not JsonValue value || !value.TryGetValue<long>(out long bytes) || bytes < 0
            || Time(observed) is not { } recorded || recorded > now || now - recorded > TimeSpan.FromDays(1))
            return null;
        return (bytes, recorded);
    }

    internal async Task<JsonObject> PostgresAsync(int limit, CancellationToken ct)
    {
        JsonObject database;
        try { database = (JsonObject)(await queries.ReadAsync("select current_database() as database_name,pg_database_size(current_database()) as database_bytes,now() as checked_at", ct)).OfType<JsonObject>().First().DeepClone(); }
        catch (Exception e) when (!ct.IsCancellationRequested)
        { return new() { ["status"] = "failed", ["backend"] = "postgres", ["available"] = false, ["connectivity_status"] = "unavailable", ["metrics_status"] = "unavailable", ["generated_at_utc"] = Generated, ["error_type"] = e.GetType().Name, ["tables"] = new JsonArray(), ["long_running_queries"] = new JsonArray(), ["warnings"] = new JsonArray("PostgreSQL operations metrics could not be read.") }; }
        var limitations = new JsonArray(); JsonArray tables, longQueries; var warnings = new JsonArray();
        try { tables = await queries.ReadAsync("""
            select stats.relname as table_name,stats.n_live_tup::bigint as live_rows,stats.n_dead_tup::bigint as dead_rows,
              (greatest(c.relpages,0)::bigint * current_setting('block_size')::bigint) as total_bytes,
              stats.last_analyze,stats.last_autoanalyze,stats.last_vacuum,stats.last_autovacuum
            from pg_stat_user_tables stats join pg_class c on c.oid=stats.relid
            order by c.relpages desc,stats.relname limit @limit
            """, ct, ("limit", limit)); }
        catch (Exception e) when (!ct.IsCancellationRequested) { tables = []; limitations.Add(new JsonObject { ["metric"] = "table_statistics", ["error_type"] = e.GetType().Name }); warnings.Add("PostgreSQL table statistics are temporarily unavailable."); }
        try { longQueries = await queries.ReadAsync("""
            select pid,usename as user_name,application_name,state,
              extract(epoch from (now()-query_start))::bigint as duration_seconds,left(query,500) as query_preview
            from pg_stat_activity where datname=current_database() and pid<>pg_backend_pid() and state<>'idle'
              and query_start is not null and now()-query_start >= interval '60 seconds' order by query_start limit 20
            """, ct); }
        catch (Exception e) when (!ct.IsCancellationRequested) { longQueries = []; limitations.Add(new JsonObject { ["metric"] = "long_running_queries", ["error_type"] = e.GetType().Name }); warnings.Add("PostgreSQL long-running query metrics are temporarily unavailable."); }
        foreach (var row in longQueries.OfType<JsonObject>())
        {
            string text = S(row["query_preview"]); text = text[..Math.Min(500, text.Length)];
            text = System.Text.RegularExpressions.Regex.Replace(text, "'(?:''|[^'])*'", "'<redacted>'");
            row["query_preview"] = System.Text.RegularExpressions.Regex.Replace(text, @"\b\d{5,}\b", "<number>");
        }
        foreach (var row in tables.OfType<JsonObject>())
        {
            long live = N(row["live_rows"]), dead = N(row["dead_rows"]); double ratio = live + dead > 0 ? dead / (double)(live + dead) : 0;
            row["total_human"] = Human(N(row["total_bytes"])); row["dead_row_ratio"] = Math.Round(ratio, 4);
            if (dead >= 100000 && ratio >= .2) warnings.Add($"{S(row["table_name"])}: high dead tuple ratio {ratio:P1} ({dead} rows)");
        }
        if (longQueries.Count > 0) warnings.Add($"Long-running PostgreSQL queries: {longQueries.Count}");
        database["database_human"] = Human(N(database["database_bytes"]));
        return new() { ["status"] = warnings.Count > 0 ? "warn" : "ok", ["backend"] = "postgres", ["available"] = true, ["connectivity_status"] = "ready", ["metrics_status"] = limitations.Count > 0 ? "partial" : "complete",
            ["generated_at_utc"] = Generated, ["database"] = database, ["tables"] = tables, ["long_running_queries"] = longQueries, ["thresholds"] = new JsonObject { ["table_limit"] = limit, ["long_query_seconds"] = 60 },
            ["warnings"] = warnings, ["limitations"] = limitations, ["backup_tools"] = BackupTools(), ["safety"] = new JsonObject { ["read_only"] = true, ["vacuum_executed"] = false, ["analyze_executed"] = false, ["backup_executed"] = false } };
    }
    JsonObject BackupTools()
    {
        string suffix = OperatingSystem.IsWindows() ? ".exe" : "";
        var directories = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator).Append(files.Setting("ADLOG_PG_BIN_DIR")).Where(p => p.Length > 0).ToArray();
        string? Find(string name) => directories.Select(d => Path.Combine(d, name + suffix)).FirstOrDefault(File.Exists);
        string? dump = Find("pg_dump"), restore = Find("pg_restore"); bool available = dump is not null && restore is not null;
        return new() { ["pg_dump"] = dump, ["pg_restore"] = restore, ["available"] = available, ["status"] = available ? "ready" : "not_ready", ["searched"] = new JsonArray("PATH", files.Setting("ADLOG_PG_BIN_DIR")), ["executed"] = false, ["runbook"] = "docs/POSTGRES_OPERATIONS_RUNBOOK.md" };
    }
    internal JsonObject StorageSummary(JsonObject postgres)
    {
        var pressure = files.DiskPressure(); var footprint = files.Footprint(Now); var warnings = new JsonArray();
        if (S(pressure["status"]) is "warn" or "blocked" or "critical" or "unavailable") warnings.Add(S(pressure["reason"], "Disk pressure could not be read."));
        if (!B(postgres["available"])) warnings.Add("PostgreSQL database size is unavailable.");
        foreach (var warning in footprint["warnings"] as JsonArray ?? []) warnings.Add(Copy(warning));
        return new() { ["generated_at_utc"] = Generated, ["status"] = S(pressure["status"]) == "critical" ? "critical" : warnings.Count > 0 ? "warn" : "ok", ["warnings"] = warnings, ["disk_pressure"] = pressure,
            ["project_overview"] = new JsonObject { ["database_bytes"] = Copy(postgres["database"]?["database_bytes"]), ["database_human"] = Copy(postgres["database"]?["database_human"]), ["total_bytes"] = Copy(footprint["totals"]?["accounted_bytes"]), ["total_human"] = Copy(footprint["totals"]?["accounted_human"]), ["scope"] = "deduplicated_known_project_footprint", ["complete"] = S(footprint["status"]) == "ok" },
            ["footprint"] = footprint, ["limitations"] = new JsonArray("PostgreSQL is represented by pg_database_size rather than a measured physical data directory.", "Docker image raw sizes are shown separately and excluded from the total because layers may be shared.", "Refresh the footprint with scripts/maintenance/operations_storage_snapshot.py; the HTTP endpoint never starts a scan."), ["read_only"] = true };
    }
    internal const string StorageGrowthSql = """
        select captured_at,database_bytes,raw_bytes,raw_archive_bytes,backups_bytes,logs_bytes,reports_bytes,artifacts_bytes,
          disk_total_bytes,disk_used_bytes,disk_free_bytes
        from storage_lifecycle_snapshots order by captured_at desc limit @limit
        """;
    internal async Task<JsonObject> LifecycleAsync(int limit, CancellationToken ct, bool storageView = false)
    {
        try
        {
            var rows = await queries.ReadAsync(storageView ? StorageGrowthSql : "select * from storage_lifecycle_snapshots order by captured_at desc limit @limit", ct, ("limit", limit));
            var current = rows.OfType<JsonObject>().FirstOrDefault(); JsonObject? previous = null;
            if (Time(current?["captured_at"]) is {} now)
            {
                var eligible = rows.OfType<JsonObject>().Skip(1).Select(r => (Row: r, Hours: Time(r["captured_at"]) is {} t ? (now - t).TotalHours : 0)).Where(p => p.Hours > 0).ToArray();
                var preferred = eligible.Where(p => p.Hours >= 20).ToArray(); previous = (preferred.Length > 0 ? preferred : eligible).OrderBy(p => Math.Abs(p.Hours - 24)).FirstOrDefault().Row;
            }
            var thresholds = OperationsStorage.Thresholds(files); var measured = OperationsStorage.Growth(current, previous);
            if (storageView)
            {
                var components = new JsonObject();
                foreach (string key in new[] { "database_bytes", "disk_used_bytes" })
                    if (current?[key] is not null && previous?[key] is not null && measured["components"]?[key] is {} component)
                        components[key] = new JsonObject { ["bytes_per_day"] = Copy(component["bytes_per_day"]), ["per_day_human"] = Copy(component["per_day_human"]) };
                bool known = S(measured["status"]) == "ok" && N(current?["disk_total_bytes"]) > 0 && current?["disk_free_bytes"] is not null
                    && OperationsStorage.OperationalFields.All(k => current?[k] is not null && previous?[k] is not null);
                var compactForecast = known ? OperationsStorage.Forecast(current, N(measured["operational_bytes_per_day"]), thresholds) : null;
                return new() { ["measured_growth"] = new JsonObject { ["components"] = components },
                    ["forecast"] = new JsonObject { ["estimated_days"] = Copy(compactForecast?["thresholds"]?["stop"]?["estimated_days"]) } };
            }
            var profile = files.CapacityProfile(); var capacityPolicy = profile["effective_policy"]!.AsObject();
            var recommendation = Storage.Lifecycle.StorageCapacityProfiles.Recommend(rows.OfType<JsonObject>(), S(profile["selected_profile"]) is { Length: > 0 } selected ? selected : null, capacityPolicy);
            var disk = files.DiskPressure()["disk"] as JsonObject;
            var capacityEvidence = disk is null ? new JsonObject { ["status"] = "unknown", ["reason"] = "capacity_evidence_unavailable", ["read_only"] = true }
                : Storage.Lifecycle.StorageCapacityProfiles.RuntimeEvidence(rows.OfType<JsonObject>(), Now, disk, capacityPolicy);
            var estimate = current is null ? null : FallbackEstimate(current);
            long growth = S(measured["status"]) == "ok" ? N(measured["operational_bytes_per_day"]) : N(estimate?["estimated_managed_bytes_per_day"]);
            var forecast = OperationsStorage.Forecast(current, growth, thresholds); forecast["source"] = Copy(S(measured["status"]) == "ok" ? measured["quality"] : estimate?["quality"]);
            var backup = files.Json("data/maintenance/postgres_backup_restore_last.json"); var bloat = new JsonArray();
            if (current is not null)
            {
                foreach (string name in new[] { "database", "raw", "raw_archive", "disk_free" }) current[name + "_human"] = Human(N(current[name + "_bytes"]));
                long total = OperationsStorage.ManagedFields.Sum(k => N(current[k])); current["managed_total_bytes"] = total; current["managed_total_human"] = Human(total);
                foreach (var table in (current["table_stats_json"] as JsonArray ?? []).OfType<JsonObject>())
                {
                    long dead = N(table["dead_rows"]), live = N(table["live_rows"]); double ratio = dead / (double)Math.Max(1, live + dead);
                    if (dead >= 100000 && ratio >= .2) bloat.Add(new JsonObject { ["table_name"] = Copy(table["table_name"]), ["dead_rows"] = dead, ["dead_ratio"] = Math.Round(ratio, 4), ["action"] = "observe_only" });
                }
            }
            string status = current is null ? "pending" : "ok"; var reasons = new JsonArray();
            if (current is null) reasons.Add("record the first storage snapshot");
            if (S(thresholds["status"]) != "ok") { status = "warn"; foreach (var issue in thresholds["issues"]!.AsArray()) reasons.Add(Copy(issue)); }
            if (backup is null || S(backup["status"]) is not ("ok" or "verified")) { if (status == "ok") status = "pending"; reasons.Add("successful PostgreSQL backup/restore rehearsal evidence is not recorded yet"); }
            if (S(measured["quality"]) != "measured_24h") { if (status == "ok") status = "pending"; reasons.Add("24-hour measured growth window is not complete yet"); }
            return new() { ["status"] = status, ["backend"] = "postgres", ["generated_at_utc"] = Generated, ["schema"] = new JsonObject { ["status"] = "ok", ["table"] = "storage_lifecycle_snapshots", ["migration_version"] = 7 }, ["thresholds"] = thresholds,
                ["latest_snapshot"] = Copy(current), ["snapshot_count"] = rows.Count, ["measured_growth"] = measured, ["fallback_estimate"] = estimate, ["forecast"] = forecast, ["backup_restore_rehearsal"] = backup ?? new JsonObject { ["status"] = "not_run" },
                ["capacity_profile"] = profile, ["capacity_recommendation"] = recommendation, ["runtime_capacity_evidence"] = capacityEvidence,
                ["bloat_observation"] = new JsonObject { ["status"] = bloat.Count > 0 ? "warn" : "ok", ["warnings"] = bloat, ["automatic_vacuum"] = false, ["automatic_reindex"] = false, ["automatic_drop"] = false }, ["reasons"] = reasons,
                ["safety"] = new JsonObject { ["measurement_read_only"] = true, ["raw_archive_first"] = true, ["vacuum_automatic"] = false, ["reindex_automatic"] = false, ["drop_production_objects"] = false } };
        }
        catch (Exception e) when (!ct.IsCancellationRequested) { var result = Unavailable(e); result["backend"] = "postgres"; result["generated_at_utc"] = Generated; return result; }
    }
    JsonObject FallbackEstimate(JsonObject current)
    {
        long rows = Math.Max(1, Math.Max(N(current["events_estimated_rows"]), N(current["events_max_id"]))), events = N(current["events_last_24h"]);
        double perEvent = N(current["database_bytes"]) / (double)rows; long databaseEstimate = (long)Math.Round(events * perEvent);
        var raw = files.RecentRawGrowth(Now); long total = databaseEstimate + N(raw["bytes"]);
        return new() { ["status"] = "ok", ["quality"] = "estimated_until_24h_history", ["database"] = new JsonObject { ["events_last_24h"] = events, ["estimated_bytes_per_event"] = Math.Round(perEvent, 2), ["estimated_bytes_per_day"] = databaseEstimate, ["estimated_per_day_human"] = Human(databaseEstimate) },
            ["raw"] = raw, ["estimated_managed_bytes_per_day"] = total, ["estimated_managed_per_day_human"] = Human(total), ["limitations"] = new JsonArray("PostgreSQL growth is estimated from current database bytes per estimated event row until two storage snapshots exist.", "Raw growth uses file modification times in the last 24 hours.") };
    }
}
