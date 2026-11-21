using System.Diagnostics;
using System.Text.Json.Nodes;
using Sli.Server.Workspace;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Operations;

public sealed partial class OperationsService
{
    internal const string ArchiveRootAvailabilitySql = "select case when to_regclass('public.storage_v2_runtime_authorizations') is null then false else has_table_privilege(current_user,'public.storage_v2_runtime_authorizations','SELECT') end as available";
    internal const string ArchiveRootSql = "select archive_root from public.storage_v2_runtime_authorizations where singleton=true";
    async Task<JsonObject?> ArchiveRootStatusAsync(CancellationToken ct)
    {
        try {
            var available = await queries.ReadAsync(ArchiveRootAvailabilitySql, ct);
            if (!B(available.FirstOrDefault()?["available"])) return null;
            var row = (await queries.ReadAsync(ArchiveRootSql, ct)).SingleOrDefault();
            if (row is null) return null;
            return new() { ["status"] = Storage.Archive.ArchiveObjectStore.SupportsRoot(S(row["archive_root"])) ? "ok" : "invalid_root" };
        }
        catch (Exception) when (!ct.IsCancellationRequested) { return new() { ["status"] = "unavailable" }; }
    }
    static readonly string[] ExpectedTables = ["schema_migrations", "log_sources", "collection_channel_state", "collector_channel_runs", "collector_stage_metrics", "events", "findings", "ai_api_runs"];
    async Task<JsonObject> DbStatusAsync(bool connect, CancellationToken ct)
    {
        var started = Stopwatch.StartNew();
        string? dsn = files.PostgresConnectionString;
        bool configured = !string.IsNullOrEmpty(dsn);
        var checks = new JsonObject { ["dsn"] = configured ? new JsonObject { ["status"] = "ok" } : new JsonObject { ["status"] = "warn", ["reason"] = "PostgreSQL DSN is not set" }, ["npgsql"] = new JsonObject { ["status"] = "ok", ["module"] = "Npgsql" } };
        var result = new JsonObject { ["status"] = "ok", ["mode"] = "db0_readiness", ["duration_ms"] = 0, ["active_backend"] = "postgres",
            ["postgres"] = new JsonObject { ["configured"] = configured, ["dsn"] = PostgresDsn.Redact(dsn), ["connect_timeout_seconds"] = 3 },
            ["safety"] = new JsonObject { ["backend_switched"] = false, ["migration_running"] = false, ["cursor_or_watermark_changed"] = false }, ["checks"] = checks, ["release_metadata"] = files.Release.ToJson() };
        if (!configured) result["status"] = "warn";
        if (!connect || !configured) checks["connection"] = new JsonObject { ["status"] = "skipped", ["reason"] = !connect ? "connect=false" : "PostgreSQL DSN is not set" };
        else try
        {
            var identity = (await queries.ReadAsync("select version() as version,current_database() as database,current_user as user", ct)).OfType<JsonObject>().First().DeepClone(); identity["status"] = "ok"; checks["connection"] = identity;
            var tables = await queries.ReadAsync("select table_name from information_schema.tables where table_schema='public' order by table_name", ct);
            var names = tables.OfType<JsonObject>().Select(t => S(t["table_name"])).ToHashSet();
            var missing = ExpectedTables.Where(t => !names.Contains(t)).ToArray();
            var migrations = names.Contains("schema_migrations") ? await queries.ReadAsync("select version,name from schema_migrations order by version", ct) : new JsonArray();
            checks["schema"] = new JsonObject { ["status"] = missing.Length > 0 ? "warn" : "ok", ["tables_seen"] = tables.Count, ["missing_tables"] = new JsonArray(missing.Select(m => JsonValue.Create(m)).ToArray()), ["schema_migrations"] = migrations };
            if (missing.Length > 0) result["status"] = "warn";
        }
        catch (Exception e) when (!ct.IsCancellationRequested) { result["status"] = "failed"; checks["connection"] = new JsonObject { ["status"] = "failed", ["error_type"] = e.GetType().Name }; }
        result["duration_ms"] = started.ElapsedMilliseconds; return result;
    }
    async Task<JsonObject> PostgresReadinessAsync(bool connect, CancellationToken ct)
    {
        var result = await DbStatusAsync(connect, ct);
        result["package_type"] = "POSTGRES_READINESS";
        result["stage"] = "DB-0.1";
        result["safety"] = new JsonObject { ["switch_backend"] = false, ["migrate_data"] = false, ["move_cursor_or_watermark"] = false, ["create_schema_requires_explicit_flag"] = true };
        string schema = Path.Combine(files.Root, "config", "postgres_schema.sql");
        bool exists = File.Exists(schema);
        result["schema_file"] = new JsonObject { ["path"] = schema, ["exists"] = exists };
        result["checks"]!["schema_file"] = exists ? new JsonObject { ["status"] = "ok" } : new JsonObject { ["status"] = "failed", ["error"] = "config/postgres_schema.sql is missing" };
        if (!exists) result["status"] = "failed";
        return result;
    }
    async Task<JsonObject> StorageHealthAsync(bool deep, CancellationToken ct)
    {
        var postgres = await PostgresAsync(deep ? 30 : 15, ct); var lifecycle = await LifecycleAsync(deep ? 72 : 48, ct); var summary = StorageSummary(postgres);
        var runtimeStorage = files.RuntimeStorage(false, Now);
        summary["project_overview"]!["project_files_human"] = Copy(runtimeStorage["sizes"]?["project"]?["human"]);
        summary["project_overview"]!["scan"] = Copy(runtimeStorage["scan"]);
        var sizes = new JsonObject();
        foreach (var (name, directory) in new[] { ("raw", "data/raw"), ("raw_archive", "data/raw_archive"), ("processed", "data/processed"), ("backups", "data/backups"), ("legacy_backups", "backups"), ("logs", "data/logs"), ("reports", "data/reports"), ("diagnostics", "data/diagnostics"), ("handoff", "data/handoff"), ("artifacts", "artifacts") })
            sizes[name] = files.Scan(directory, deep ? 20000 : 5000, TimeSpan.FromSeconds(deep ? 3 : 1));
        var warnings = summary["warnings"]!.AsArray();
        foreach (var warning in runtimeStorage["warnings"] as JsonArray ?? []) warnings.Add(Copy(warning));
        if (S(lifecycle["status"]) is "warn" or "unavailable") warnings.Add("Storage lifecycle status requires operator attention");
        if (sizes.Any(p => !B(p.Value?["scan"]?["complete"]))) warnings.Add("Filesystem inventory is incomplete; measured bytes are lower bounds.");
        summary["status"] = S(summary["status"]) == "critical" ? "critical" : warnings.Count > 0 ? "warn" : "ok";
        summary["sizes"] = sizes; summary["policy"] = StoragePolicy(); summary["postgres_operations"] = postgres; summary["storage_lifecycle"] = lifecycle;
        var cleanup = await CleanupPreviewAsync(ct, compact: true); summary["cleanup_preview"] = cleanup;
        summary["last_cleanup"] = files.Json("data/maintenance/storage_cleanup_last.json");
        var capacity = CapacityPlan(summary["disk_pressure"]?["disk"] as JsonObject ?? new());
        summary["capacity_plan"] = capacity;
        double? days = capacity["days_until_full"]?.GetValue<double>();
        var scale = Copy(capacity["server_model"])!.AsArray();
        foreach (var item in scale.OfType<JsonObject>()) item["capacity_ready"] = item["projected_days_until_full"] is null || item["projected_days_until_full"]!.GetValue<double>() >= 14;
        summary["capacity_state"] = new JsonObject { ["status"] = days is null ? "unknown" : days < 2 ? "critical" : days < 7 ? "high" : days < 14 ? "warn" : "ok", ["days_until_full"] = days, ["scale_readiness"] = scale, ["minimum_ready_days"] = 14 };
        summary["purge_runs"] = files.PurgeRuns();
        summary["operator_guidance"] = new JsonArray("Review storage pressure, lifecycle and cleanup preview before applying maintenance.");
        return summary;
    }
    JsonObject StoragePolicy()
    {
        return (JsonObject)files.CapacityProfile()["effective_policy"]!.DeepClone();
    }
    JsonObject CapacityPlan(JsonObject disk)
    {
        var raw = files.RecentRawGrowth(Now); long total = N(raw["bytes"]);
        foreach (string directory in new[] { "data/processed", "data/logs" }) total += N(files.Scan(directory, 10000, TimeSpan.FromSeconds(3), Now.AddHours(-24))["bytes"]);
        double gb = Math.Round(total / Math.Pow(1024, 3), 2); long free = N(disk["free_bytes"]);
        int current = int.TryParse(files.Setting("ADLOG_CAPACITY_CURRENT_SERVERS", "2"), out int n) ? n : 2;
        var model = new JsonArray();
        foreach (int servers in new[] { 2, 5, 10 })
        {
            double projected = gb * servers / Math.Max(1, current);
            model.Add(new JsonObject { ["servers"] = servers, ["projected_gb_per_day"] = Math.Round(projected, 2), ["projected_days_until_full"] = projected > 0 ? Math.Round(free / Math.Pow(1024, 3) / projected, 1) : null });
        }
        return new() { ["disk"] = disk.DeepClone(), ["observed_growth"] = new JsonObject { ["lookback_hours"] = 24, ["bytes"] = total, ["human"] = Human(total), ["gb_per_day"] = gb }, ["days_until_full"] = gb > 0 ? Math.Round(free / Math.Pow(1024, 3) / gb, 1) : null, ["server_model"] = model, ["policy"] = StoragePolicy() };
    }
    internal async Task<JsonObject> CleanupPreviewAsync(CancellationToken ct, bool compact = false)
    {
        var policy = StoragePolicy(); long bytes = 0; int count = 0; var warnings = new JsonArray();
        var actions = new JsonArray(); var excluded = new JsonObject(); bool confirmationAvailable = true;
        void Exclude(string reason) => excluded[reason] = N(excluded[reason]) + 1;
        void Candidate(FileInfo file, string action, string category)
        {
            long size = file.Length; bytes += size; count++;
            actions.Add(new JsonObject { ["path"] = file.FullName, ["action"] = action, ["category"] = category, ["size_bytes"] = size, ["size_human"] = Human(size) });
        }
        try
        {
            var raw = files.Inventory("data/raw", 5000, TimeSpan.FromSeconds(2.5));
            var variants = raw.Select(f => f.FullName.ToLowerInvariant()).Distinct().ToArray(); var confirmed = new HashSet<string>(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
            if (variants.Length > 0) try
            {
                var imported = await queries.ReadAsync("""
                    select raw_path as file_path from (
                        select distinct on(lower(raw_path)) raw_path,import_outcome,cursor_outcome,expected_channels,committed_channels,cleanup_outcome
                        from raw_batch_lifecycle where lower(raw_path)=any(@paths) order by lower(raw_path),updated_at desc,batch_identity
                    ) latest where import_outcome='succeeded' and cursor_outcome='committed'
                        and expected_channels>0 and committed_channels=expected_channels and cleanup_outcome in ('retained','delete_authorized')
                    """, ct, ("paths", variants));
                foreach (var row in imported.OfType<JsonObject>()) confirmed.Add(S(row["file_path"]));
            }
            catch (Exception) when (!ct.IsCancellationRequested) { confirmationAvailable = false; warnings.Add("Raw import confirmation is unavailable; raw files remain protected."); }
            static bool Marker(FileInfo f) => File.Exists(f.FullName + ".keep") || File.Exists(f.FullName + ".evidence");
            bool Old(FileInfo f, long days) => (Now - f.LastWriteTimeUtc).TotalDays >= Math.Max(0, days);
            foreach (var f in raw.OrderBy(f => f.FullName, StringComparer.Ordinal))
            {
                string relative = Path.GetRelativePath(files.Resolve("data/raw"), f.FullName).Replace('\\', '/').ToLowerInvariant();
                if (!Old(f, N(policy["raw_retention_days"]))) { Exclude("recent"); continue; }
                if (Marker(f) || new[] { "failed", "partial", "error", "retry", "evidence", "finding", "investigation", "keep" }.Any(relative.Contains)) { Exclude("protected"); continue; }
                if (!confirmationAvailable) { Exclude("import_confirmation_unavailable"); continue; }
                if (!confirmed.Contains(f.FullName)) { Exclude("not_confirmed_imported"); continue; }
                Candidate(f, !B(policy["raw_archive_enabled"]) ? "delete_file" : B(policy["raw_archive_compress"]) ? "archive_zip" : "archive_move", "raw");
            }
            foreach (var (directory, key, category) in new[] { ("data/raw_archive", "warm_retention_days", "archive"), ("data/backups", "backup_retention_days", "backup"), ("backups", "backup_retention_days", "backup"), ("data/logs", "log_retention_days", "logs"), ("artifacts", "artifact_retention_days", "artifacts") })
            {
                if (category == "archive" && !B(policy["raw_archive_enabled"])) continue;
                foreach (var f in files.Inventory(directory, 3000, TimeSpan.FromSeconds(1.5)).OrderBy(f => f.FullName, StringComparer.Ordinal))
                {
                    if (!Old(f, N(policy[key]))) continue;
                    if (category == "logs" && new[] { "adlog-monitor.log", "internal-errors.log", "performance-events.log", "self-test.log", "release-check.log", "audit-actions.log" }.Contains(f.Name)) continue;
                    string relative = Path.GetRelativePath(files.Resolve(directory), f.FullName).Replace('\\', '/').ToLowerInvariant();
                    if (category == "artifacts" && (Marker(f) || new[] { "acceptance", "evidence", "baseline", "handoff", "incident", "investigation" }.Any(relative.Contains))) continue;
                    Candidate(f, "delete_file", category);
                }
            }
            var result = new JsonObject { ["status"] = warnings.Count > 0 ? "partial" : "ok", ["mode"] = "dry-run", ["generated_at_utc"] = Generated, ["total_candidates"] = count, ["total_bytes"] = bytes, ["total_human"] = Human(bytes), ["warnings"] = warnings, ["actions"] = actions,
                ["scan"] = new JsonObject { ["raw"] = new JsonObject { ["excluded"] = excluded, ["import_confirmation"] = new JsonObject { ["status"] = confirmationAvailable ? "ok" : "unavailable", ["backend"] = "postgres" } } },
                ["safety"] = new JsonObject { ["dry_run_default"] = true, ["failed_partial_raw_preserved"] = true, ["evidence_raw_preserved"] = true, ["vacuum_automatic"] = false, ["apply_requires_confirm_apply"] = true, ["raw_delete_automatic"] = false, ["archive_verified_before_source_remove"] = true, ["raw_requires_confirmed_postgres_import"] = true, ["acceptance_evidence_artifacts_preserved"] = true } };
            if (!compact) return result;
            var summary = OperationsStorageCompact.Cleanup(result);
            summary["warnings"] = warnings.DeepClone(); return summary;
        }
        catch (Exception e) when (!ct.IsCancellationRequested)
        { var unavailable = Unavailable(e); unavailable["mode"] = "dry-run"; unavailable["total_candidates"] = null; unavailable["total_bytes"] = null; unavailable["total_human"] = null; return unavailable; }
    }
    // Compatibility with the retired age-only retention entry point. Planning
    // shares the operational preview; only the verified lifecycle may delete.
    public async Task<JsonObject> ApplyRetentionAsync(bool apply = false, CancellationToken ct = default)
    {
        var plan = await CleanupPreviewAsync(ct);
        if (apply) plan["status"] = "blocked";
        plan["mode"] = apply ? "blocked" : "dry_run";
        plan["apply_supported"] = false;
        plan["legacy_planner_retired"] = true;
        plan["replacement"] = "storage-lifecycle";
        plan["deleted"] = new JsonArray();
        plan["errors"] = apply ? new JsonArray(new JsonObject {
            ["code"] = "legacy_retention_apply_disabled",
            ["error"] = "Legacy retention apply is disabled; use the verified storage cleanup workflow." }) : new JsonArray();
        return plan;
    }
    Task<JsonObject> SystemAsync(bool force, CancellationToken ct) => files.SystemHealthAsync(force, clock, () => BuildSystemAsync(force, ct), ct);
    async Task<JsonObject> BuildSystemAsync(bool force, CancellationToken ct)
    {
        var timer = Stopwatch.StartNew(); var collector = await CollectorAsync(ct); var runtimeStorage = files.RuntimeStorage(force, Now);
        var warnings = A(runtimeStorage["warnings"] as JsonArray ?? []);
        if (N(collector["summary"]?["security_high"]) > 0) warnings.Add("Есть высокий риск качества сбора Security");
        var inventory = await queries.ReadAsync("""
            with database_size as materialized (
                select pg_database_size(current_database())::bigint as database_size_bytes
            )
            select c.relname as table_name,coalesce(partitions.estimated_rows,greatest(c.reltuples,0)::bigint) as estimated_rows,
                database_size.database_size_bytes
            from pg_class c join pg_namespace n on n.oid=c.relnamespace cross join database_size
            left join lateral (select sum(greatest(leaf.reltuples,0)::bigint)::bigint as estimated_rows
                from pg_partition_tree(c.oid) tree join pg_class leaf on leaf.oid=tree.relid where tree.isleaf) partitions on c.relkind='p'
            where n.nspname=current_schema() and c.relname in ('event_hot','servers','findings')
            """, ct);
        long databaseBytes = N(inventory.FirstOrDefault()?["database_size_bytes"]);
        var sizes = new JsonObject { ["source"] = "full_project_runtime_storage_snapshot" };
        var db = new JsonObject { ["backend"] = "postgres", ["path"] = "PostgreSQL current_database()", ["size_bytes"] = databaseBytes, ["size_human"] = Human(databaseBytes), ["counts_are_estimates"] = true, ["count_source"] = "pg_class.reltuples" };
        foreach (var (key, table) in new[] { ("events", "event_hot"), ("servers", "servers"), ("findings", "findings") }) db[key] = N(inventory.OfType<JsonObject>().FirstOrDefault(r => S(r["table_name"]) == table)?["estimated_rows"]);
        bool hasValues = S(runtimeStorage["snapshot"]?["status"]) is "ready" or "incomplete";
        foreach (string name in new[] { "data", "reports", "logs" })
        {
            var component = runtimeStorage["sizes"]?[name];
            sizes[name + "_dir_bytes"] = hasValues ? Copy(component?["bytes"]) : null; sizes[name + "_dir_human"] = hasValues ? S(component?["human"], "—") : "—";
        }
        var cleanup = await CleanupPreviewAsync(ct, compact: true);
        if (N(cleanup["total_candidates"]) > 0) warnings.Add("Есть кандидаты на очистку по retention");
        var password = await queries.ReadAsync("select public.password_catchup_status388() as progress", ct);
        warnings = A(warnings.Select(w => S(w)).Distinct().Select(w => JsonValue.Create(w)));
        var health = new JsonObject { ["status"] = (runtimeStorage["warnings"] as JsonArray)?.Count > 0 ? "warn" : "ok", ["warnings"] = Copy(runtimeStorage["warnings"]) ?? new JsonArray(),
            ["disk_pressure"] = new JsonObject { ["free_percent"] = Copy(runtimeStorage["disk"]?["free_percent"]), ["free_bytes"] = Copy(runtimeStorage["disk"]?["free_bytes"]), ["free_human"] = Copy(runtimeStorage["disk"]?["free_human"]) }, ["source"] = "runtime_storage_single_pass", ["detail_endpoint"] = "/api/storage/health", ["deep_diagnostics_deferred"] = true };
        return new() { ["generated_at_utc"] = Generated, ["status"] = warnings.Count > 0 ? "warn" : "ok", ["warnings"] = warnings,
            ["password_catchup"] = Copy(password.FirstOrDefault()?["progress"]),
            ["release_metadata"] = files.Release.ToJson(),
            ["config"] = new JsonObject { ["db_backend"] = "postgres", ["retention"] = StoragePolicy() }, ["db"] = db, ["storage"] = sizes, ["runtime_storage"] = runtimeStorage, ["storage_health"] = health,
            ["retention"] = new JsonObject { ["candidates"] = Copy(cleanup["total_candidates"]), ["bytes"] = Copy(cleanup["total_bytes"]), ["bytes_human"] = Copy(cleanup["total_human"]) }, ["collector_summary"] = Copy(collector["summary"]),
            ["performance"] = new JsonObject { ["total_duration_ms"] = timer.ElapsedMilliseconds, ["component_duration_ms"] = new JsonObject(), ["bounded_db_timeout_ms"] = 3000 }, ["cache"] = new JsonObject { ["hit"] = false, ["ttl_seconds"] = 0, ["age_ms"] = 0 } };
    }
    async Task<JsonObject> DiagnosticsAsync(bool runChecks, CancellationToken ct)
    {
        var logs = new JsonObject();
        foreach (var (name, file) in new[] { ("internal_errors_tail", "internal-errors.log"), ("self_test_tail", "self-test.log"), ("release_check_tail", "release-check.log"), ("performance_tail", "performance-events.log") })
            logs[name] = string.Concat(files.LogTail(file, 20).Select(n => S(n)));
        var checks = new JsonObject(); var parsed = new JsonObject(); var warnings = new JsonArray();
        if (runChecks)
        {
            var db = await DbStatusAsync(true, ct); var workers = await WorkersAsync(ct);
            parsed["runtime_watchdog"] = new JsonObject { ["status"] = S(workers["status"]) != "ok" || workers["items"]!.AsArray().Any(w => S(w?["state"]) is "stale" or "warning" or "blocked" or "not_registered") ? "warn" : "ok", ["workers"] = workers };
            parsed["self_test_offline"] = OfflineCheck();
            parsed["release_check"] = await ReleaseCheckAsync(db, ct);
            parsed["ui_nav_check"] = NavigationCheck();
            foreach (var check in parsed)
            {
                string status = S(check.Value?["status"]); checks[check.Key] = new JsonObject { ["command"] = "in-process", ["exit_code"] = status == "ok" ? 0 : 1, ["timed_out"] = false };
                if (status != "ok") warnings.Add($"{check.Key}: status={status}");
            }
        }
        var errors = InternalErrors(S(logs["internal_errors_tail"]), string.Concat(files.LogTail("adlog-monitor.log", 1000).Select(n => S(n))), Now);
        if (N(errors["active_count"]) > 0) warnings.Add($"internal-errors.log has {N(errors["active_count"])} active errors in the last 30 minutes");
        return new() { ["status"] = warnings.Count > 0 ? "warn" : "ok", ["release_metadata"] = files.Release.ToJson(), ["checks"] = checks, ["parsed_checks"] = parsed, ["logs"] = logs, ["internal_errors"] = errors, ["warnings"] = warnings };
    }
    internal static JsonObject InternalErrors(string text, string activity, DateTimeOffset now)
    {
        int parsed = 0, malformed = 0, recoveredCount = 0, ignored = 0; var active = new List<string>();
        var recoveries = new List<(DateTimeOffset Time, string Server, string Channel)>();
        static JsonObject? Parse(string line) { try { return JsonNode.Parse(line) as JsonObject; } catch (System.Text.Json.JsonException) { return null; } }
        foreach (string line in activity.Split('\n').Where(l => !string.IsNullOrWhiteSpace(l)))
        {
            var row = Parse(line); if (row is null || Time(row["ts"]) is not {} time) continue;
            bool success = S(row["status"]).ToLowerInvariant() is "ok" or "completed" or "success" or "succeeded";
            bool collection = S(row["event"]) is "import_completed" or "server_collection_completed" or "collection_completed" || S(row["event"]) == "stage_completed" && S(row["stage"]) is "collection_backend_command" or "evt_next_read" or "render_parse_write_jsonl";
            if (success && collection) recoveries.Add((time, S(row["server"]), S(row["channel"])));
        }
        foreach (string line in text.Split('\n').Where(l => !string.IsNullOrWhiteSpace(l)))
        {
            var row = Parse(line);
            if (row is null || Time(row["ts"]) is not {} time) { malformed++; active.Add(line); continue; }
            parsed++; if (time < now.AddMinutes(-30)) continue;
            string level = S(row["level"]).ToUpperInvariant();
            if (level.Length > 0 && level is not ("ERROR" or "CRITICAL")) { ignored++; continue; }
            string server = S(row["server"]), channel = S(row["channel"]);
            if (server.Length > 0 && recoveries.Any(r => r.Time > time && r.Server == server && (channel.Length == 0 || r.Channel.Length == 0 || r.Channel == channel))) { recoveredCount++; continue; }
            active.Add(line);
        }
        return new() { ["active"] = active.Count > 0, ["active_count"] = active.Count, ["active_text"] = string.Join('\n', active), ["parsed_count"] = parsed, ["malformed_count"] = malformed, ["recovered_count"] = recoveredCount, ["ignored_non_error_count"] = ignored, ["freshness_minutes"] = 30 };
    }
    JsonObject OfflineCheck()
    {
        var issues = new JsonArray(); var packs = catalog.Packs();
        var adapters = OperationsCatalog.Adapters().OfType<JsonObject>().Select(a => S(a["adapter_id"])).ToHashSet();
        var ids = new HashSet<string>();
        foreach (var pack in packs.OfType<JsonObject>())
        {
            if (!ids.Add(S(pack["pack_id"]))) issues.Add("source_pack_id_duplicate");
            if ((pack["adapters"] as JsonArray ?? []).Any(a => !adapters.Contains(S(a)))) issues.Add("source_pack_adapter_unknown");
            if (S(pack["manifest_sha256"]).Length != 64) issues.Add("source_pack_hash_invalid");
        }
        var completeness = catalog.Completeness();
        if (N(completeness["entry_count"]) == 0) issues.Add("event_catalog_empty");
        return new() { ["status"] = issues.Count == 0 ? "ok" : "failed", ["issues"] = issues, ["catalog_completeness"] = completeness, ["source_pack_count"] = packs.Count, ["network_actions"] = new JsonArray(), ["database_actions"] = new JsonArray() };
    }
    async Task<JsonObject> ReleaseCheckAsync(JsonObject database, CancellationToken ct)
    {
        var issues = new JsonArray();
        foreach (string assembly in new[] { typeof(OperationsService).Assembly.Location, typeof(Npgsql.NpgsqlConnection).Assembly.Location })
            if (!File.Exists(assembly)) issues.Add("runtime_assembly_missing");
        if (!File.Exists(Path.Combine(files.Root, "config", "postgres_schema.sql"))) issues.Add("postgres_schema_missing");
        var roleViews = JsonNode.Parse(WorkspaceJson.ReadResource("role-view-templates.json"))!.AsArray();
        var cleanup = await CleanupPreviewAsync(ct, compact: true);
        int exitCode = S(cleanup["status"]) is "ok" or "warn" ? 0 : 1;
        if (exitCode != 0) issues.Add("storage_cleanup_preview_unavailable");
        return new() { ["status"] = issues.Count == 0 && S(database["status"]) == "ok" ? "ok" : "warn", ["issues"] = issues, ["database"] = database, ["release_metadata"] = files.Release.ToJson(),
            ["role_views"] = new JsonArray(roleViews.Select(view => view!["id"]!.DeepClone()).ToArray()),
            ["storage_cleanup_dry_run"] = new JsonObject { ["exit_code"] = exitCode, ["stdout_tail"] = cleanup.ToJsonString(), ["timed_out"] = false } };
    }
    JsonObject NavigationCheck()
    {
        var issues = new JsonArray();
        // Validate the actual shipped SPA shell and its script references. This
        // check never executes JavaScript, follows external URLs or calls DNS.
        string[] candidates = [Path.Combine(files.Root, "web", "app", "index.html"), Path.Combine(AppContext.BaseDirectory, "wwwroot", "index.html")];
        string? index = candidates.FirstOrDefault(File.Exists);
        if (index is null) issues.Add("spa_index_missing");
        else
        {
            using var input = new FileStream(index, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (input.Length > 2097152) issues.Add("spa_index_size_invalid");
            else
            {
                using var reader = new StreamReader(input); string text = reader.ReadToEnd();
                foreach (System.Text.RegularExpressions.Match match in System.Text.RegularExpressions.Regex.Matches(text, "<script[^>]+src=[\"']([^\"']+)[\"']"))
                {
                    string asset = match.Groups[1].Value;
                    if (asset.StartsWith("http", StringComparison.OrdinalIgnoreCase) || asset.StartsWith("//", StringComparison.Ordinal)) { issues.Add("spa_external_script"); continue; }
                    string root = Path.GetDirectoryName(index)!; string resolved = Path.GetFullPath(Path.Combine(root, asset.TrimStart('/').Split('?')[0]));
                    if (!resolved.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) || !File.Exists(resolved)) issues.Add("spa_asset_missing");
                }
            }
        }
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["Sli:ProjectRoot"] = files.Root, ["Sli:DataDirectory"] = files.DataRoot }).Build();
        var result = Workspace.LegacyWorkspaceModels.NavigationCheck(configuration, Path.Combine(files.DataRoot, "reports"));
        result["issues"] = issues;
        foreach (var issue in issues) result["warnings"]!.AsArray().Add(issue!.DeepClone());
        if (issues.Count > 0) result["status"] = "warn";
        return result;
    }
}
