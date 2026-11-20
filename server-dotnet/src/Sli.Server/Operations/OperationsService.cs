using System.Diagnostics;
using System.Text.Json.Nodes;
using Sli.Server.Storage;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Operations;

// The legacy HTTP job registry is process-local in the reference too. Reading
// it never creates or recovers work. Manual job producers can share this store.
public sealed class OperationsJobs(Sli.Server.Legacy.LegacyJobStore? legacy = null)
{
    private readonly Dictionary<long, JsonObject> jobs = new();
    public JsonArray List() { lock (jobs) return A((legacy?.List().OfType<JsonObject>() ?? []).Concat(jobs.Values)
        .GroupBy(j => N(j["id"])).Select(g => g.First()).OrderByDescending(j => N(j["id"]))); }
    public JsonObject? Get(long id) { lock (jobs) return (id is >= int.MinValue and <= int.MaxValue ? legacy?.Get((int)id) : null)
        ?? (jobs.TryGetValue(id, out var row) ? (JsonObject)row.DeepClone() : null); }
    public void Record(JsonObject job) { lock (jobs) jobs[N(job["id"])] = (JsonObject)job.DeepClone(); }
}

public sealed partial class OperationsService(IOperationsQueries queries, OperationsFiles files, OperationsCatalog catalog, OperationsJobs jobs, TimeProvider clock,
    ILogger<OperationsService>? logger = null, Sli.Server.Agents.Ingress.AgentInboxLimits? inboxLimits = null)
{
    DateTimeOffset Now => clock.GetUtcNow();
    string Generated => Stamp(Now);
    public JsonObject? Job(long id) => jobs.Get(id);
    public async Task<JsonNode> ReadAsync(string path, Dictionary<string, string[]> query, CancellationToken ct)
    {
        switch (path)
        {
            case "/api/v1/source-packs": return new JsonObject { ["api_version"] = "v1", ["items"] = catalog.PublicPacks() };
            case "/api/v1/source-adapters": return new JsonObject { ["api_version"] = "v1", ["items"] = OperationsCatalog.Adapters() };
            case "/api/v1/operations/overview":
                if (query.TryGetValue("view", out var view) && view.SequenceEqual(["storage"])) return StorageOverview();
                if (view is not null && view.SequenceEqual(["workers"])) return new JsonObject {
                    ["api_version"] = "v1", ["generated_at_utc"] = Generated,
                    ["workers"] = await WorkersAsync(ct, includeQueues: false), ["read_only"] = true };
                if (view is not null && view.SequenceEqual(["storage-growth"])) return await LifecycleAsync(48, ct, storageView: true);
                return await OverviewAsync(view is not null && view.SequenceEqual(["readiness"]), ct);
            case "/api/v1/operations/administrative-activity": return await JournalAsync(query, ct);
            case "/api/sources": return new JsonObject { ["items"] = await SourcesAsync(ct) };
            case "/api/domain-controllers": return new JsonObject { ["items"] = new JsonArray((await TargetsAsync(ct)).OfType<JsonObject>().Select(r => JsonValue.Create(S(r["hostname"]))).ToArray()) };
            case "/api/jobs": return new JsonObject { ["items"] = jobs.List() };
            case "/api/runtime/status": return await RuntimeAsync(ct);
            case "/api/logs/tail": return new JsonObject { ["items"] = files.LogTail("adlog-monitor.log", 100) };
            case "/api/autocollection/status": return await AutoCollectionAsync(ct);
            case "/api/collector/health": return await CollectorAsync(ct);
            case "/api/health/details":
                var runtime = await RuntimeAsync(ct);
                var payload = new JsonObject { ["status"] = "ok", ["service"] = "ad-log-reports", ["mode"] = "real-readonly-archive-collector", ["runtime_identity"] = Copy(runtime["identity"]), ["runtime"] = runtime };
                if (OperationsEndpoints.Flag(query, "deep"))
                {
                    var archive = await queries.ReadAsync("select server_hostname,channel,last_successful_collection_utc,last_event_time_utc,last_event_record_id,backfill_completed from collection_channel_state order by server_hostname,channel", ct);
                    var setting = await queries.ReadAsync("select value from archive_settings where key='archive_start_utc'", ct);
                    payload["archive_start_utc"] = Copy(setting.FirstOrDefault()?["value"]);
                    payload["archive_channel_states"] = archive;
                    payload["archive_backend"] = "postgres";
                }
                return payload;
            case "/api/db/status": return OperationsEndpoints.First(query, "view", "") == "readiness"
                ? await PostgresReadinessAsync(OperationsEndpoints.Flag(query, "connect", "1"), ct)
                : await DbStatusAsync(OperationsEndpoints.Flag(query, "connect", "1"), ct);
            case "/api/system/health": return await SystemAsync(OperationsEndpoints.Flag(query, "force"), ct);
            case "/api/storage/health":
                var health = await StorageHealthAsync(OperationsEndpoints.Flag(query, "deep"), ct);
                return OperationsEndpoints.Flag(query, "summary_only") ? OperationsStorageCompact.Health(health) : health;
            case "/api/storage/lifecycle":
                string raw = OperationsEndpoints.First(query, "limit", "48");
                if (!int.TryParse(raw, out int limit)) throw new OperationsInputException("invalid literal for int() with base 10: '" + raw[..Math.Min(raw.Length, 64)] + "'");
                return await LifecycleAsync(Math.Clamp(limit, 2, 200), ct);
            case "/api/diagnostics/overview": return await DiagnosticsAsync(OperationsEndpoints.Flag(query, "run_checks"), ct);
            default: throw new OperationsInputException("not_found", 404);
        }
    }
    async Task<JsonNode> JournalAsync(Dictionary<string, string[]> query, CancellationToken ct)
    {
        string[] allowed = ["limit", "category", "before_activity_id"];
        if (query.Any(p => !allowed.Contains(p.Key) || p.Value.Length != 1)
            || !int.TryParse(OperationsEndpoints.First(query, "limit", "50"), out int limit) || limit is < 1 or > 200
            || query.ContainsKey("before_activity_id") && (!long.TryParse(query["before_activity_id"][0], out long before) || before < 1))
            throw new OperationsInputException("administrative_activity_query_invalid");
        using var stream = typeof(OperationsService).Assembly.GetManifestResourceStream("Sli.Server.Auth.Lifecycle.Security.administrative-activity-v1.json")!;
        var contract = JsonNode.Parse(stream)!;
        string? category = query.TryGetValue("category", out var values) ? values[0].Trim() : null;
        if (category == "") category = null;
        if (category is not null && !contract["categories"]!.AsArray().Any(n => S(n) == category)) throw new OperationsInputException("administrative_activity_query_invalid");
        if (!B(contract["runtime_read_enabled"])) throw new OperationsInputException("administrative_activity_reader_runtime_disabled", 503);
        var rows = await queries.ReadAsync("select * from read_administrative_activity_v1(@before::bigint,@limit::integer,@category::text)", ct,
            ("before", query.ContainsKey("before_activity_id") ? long.Parse(query["before_activity_id"][0]) : null), ("limit", limit + 1), ("category", category));
        var items = A(rows.Take(limit));
        foreach (var row in items.OfType<JsonObject>())
        {
            if (N(row["activity_id"]) < 1 || row["details_json"] is not JsonObject || new[] { "content_hash_hex", "previous_record_hash_hex", "record_hash_hex" }.Any(k => !System.Text.RegularExpressions.Regex.IsMatch(S(row[k]), "\\A[0-9a-f]{64}\\z"))) throw new OperationsInputException("administrative_activity_query_invalid");
            foreach (string key in new[] { "occurred_at_utc", "recorded_at_utc" }) row[key] = Time(row[key]) is {} t ? Stamp(t) : throw new OperationsInputException("administrative_activity_query_invalid");
        }
        bool more = rows.Count > limit;
        return new JsonObject { ["contract_id"] = "sli.administrative-activity-reader.v1", ["status"] = "ok", ["items"] = items,
            ["page"] = new JsonObject { ["limit"] = limit, ["has_more"] = more, ["next_before_activity_id"] = more && items.Count > 0 ? Copy(items[^1]!["activity_id"]) : null },
            ["filters"] = new JsonObject { ["category"] = category }, ["bounded"] = true, ["contains_sensitive_details"] = false };
    }
    public async Task<JsonObject> PreflightAsync(JsonObject candidate, CancellationToken ct) => catalog.Preflight(candidate, (await TargetsAsync(ct)).OfType<JsonObject>().Select(r => S(r["hostname"])));
    internal Task<JsonArray> TargetsAsync(CancellationToken ct) => new DomainControllerTargets(queries, files).ConfiguredAsync(ct);

    async Task<JsonObject> RuntimeAsync(CancellationToken ct)
    {
        var targets = await TargetsAsync(ct);
        return new() { ["status"] = "ok", ["active_backend"] = "postgres", ["postgres_dsn_present"] = true,
            ["storage_v2"] = StorageSettings(), ["identity"] = Hosting.HealthHosting.RuntimeIdentity(),
            ["scheduler"] = Scheduler(targets), ["collection"] = await CollectionAsync(ct) };
    }
    bool LegacyDisabled => files.Setting("SLI_LEGACY_COLLECTION_DISABLED", "0").Trim() != "0";
    bool ContinuousRecovery => files.Setting("ADLOG_CONTINUOUS_RECOVERY", "true").Trim().ToLowerInvariant() is not ("0" or "false" or "no" or "off");
    string PostCollectionMode => LegacyDisabled ? "disabled" : files.Flag("ADLOG_EXTERNAL_POST_COLLECTION_WORKER") ? "external" : files.Flag("ADLOG_ENABLE_INPROCESS_POST_COLLECTION") ? "in_process" : "disabled";
    JsonObject Scheduler(JsonArray targets)
    {
        bool postgresEnabled = files.Flag("ADLOG_ENABLE_POSTGRES_COLLECTION") || files.Flag("ADLOG_POSTGRES_RUNTIME_COLLECTION");
        bool canary = files.Flag("ADLOG_SCHEDULER_CANARY") || files.Flag("ADLOG_POSTGRES_SCHEDULER_CANARY"), archive = files.Flag("ADLOG_CANARY_ARCHIVE");
        int Read(string key, int fallback, int min) => Math.Max(min, int.TryParse(files.Setting(key, fallback.ToString()), out int value) ? value : fallback);
        string profile = files.Setting("ADLOG_SCHEDULER_PROFILE").Trim().ToLowerInvariant(); if (profile.Length == 0) profile = canary ? "canary" : "standard";
        bool skip = files.Setting("ADLOG_SCHEDULER_SKIP_REPORT", canary ? "1" : "0").Trim().ToLowerInvariant() is "1" or "true" or "yes" or "on";
        string collectionMode = files.Setting("ADLOG_CANARY_COLLECTION_MODE", "current").Trim().ToLowerInvariant(); if (collectionMode.Length == 0) collectionMode = "current";
        int requested = Read("ADLOG_CANARY_MAX_EVENTS", 1000, 1), cap = Read("ADLOG_CANARY_MAX_EVENTS_CAP", 5000, 1);
        string? reason = LegacyDisabled ? "legacy_collection_disabled" : !files.Flag("ADLOG_ENABLE_INPROCESS_COLLECTION_SCHEDULER") ? "inprocess_scheduler_requires_ADLOG_ENABLE_INPROCESS_COLLECTION_SCHEDULER" : files.Flag("ADLOG_DISABLE_SCHEDULER") ? "scheduler_disabled_by_ADLOG_DISABLE_SCHEDULER" : !postgresEnabled ? "postgres_runtime_collection_guard" : null;
        var canaryConfig = new JsonObject { ["enabled"] = canary, ["profile"] = profile, ["channels"] = new JsonArray(files.Setting("ADLOG_CANARY_CHANNELS", "Security").Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(s => JsonValue.Create(s)).ToArray()),
            ["requested_max_events_per_channel"] = requested, ["max_events_cap"] = cap, ["max_events_capped"] = requested > cap, ["max_events_per_channel"] = Math.Min(requested, cap), ["hours"] = Read("ADLOG_CANARY_HOURS", 1, 1),
            ["archive_enabled"] = archive, ["watermark_enabled"] = archive, ["archive_watermark_canary"] = archive && canary, ["collection_mode"] = collectionMode, ["skip_report"] = skip,
            ["channel_timeout_seconds"] = Read("ADLOG_CANARY_CHANNEL_TIMEOUT_SECONDS", 120, 30), ["command_timeout_seconds"] = Read("ADLOG_CANARY_COMMAND_TIMEOUT_SECONDS", 240, 60) };
        return new() { ["active_backend"] = "postgres", ["scheduler_enabled"] = reason is null, ["scheduler_started"] = false, ["disabled_reason"] = reason,
            ["postgres_collection_enabled"] = postgresEnabled, ["disable_scheduler_env"] = files.Flag("ADLOG_DISABLE_SCHEDULER"), ["inprocess_scheduler_opt_in"] = files.Flag("ADLOG_ENABLE_INPROCESS_COLLECTION_SCHEDULER"),
            ["continuous_recovery_enabled"] = ContinuousRecovery, ["scheduler_canary_enabled"] = canary, ["scheduler_profile"] = profile, ["scheduler_skip_report"] = skip,
            ["post_collection_worker_mode"] = PostCollectionMode, ["scheduler_canary"] = canaryConfig, ["scheduler_archive_watermark_canary_enabled"] = archive && canary, ["domain_controller_targets"] = Copy(targets) };
    }
    async Task<JsonObject> CollectionAsync(CancellationToken ct)
    {
        bool postgresEnabled = files.Flag("ADLOG_ENABLE_POSTGRES_COLLECTION") || files.Flag("ADLOG_POSTGRES_RUNTIME_COLLECTION");
        string? reason = files.Setting("SLI_LEGACY_COLLECTION_DISABLED", "0").Trim() != "0" ? "legacy_collection_disabled"
            : files.Setting("SLI_AD_DC_AGENT_IMPORT_ENABLED", "0") is not ("0" or "1") ? "agent_ad_dc_import_config_invalid"
            : files.Setting("SLI_AD_DC_AGENT_IMPORT_ENABLED", "0") == "1" ? "ad_dc_agent_collection_owner"
            : files.Flag("ADLOG_DISABLE_COLLECTION") ? "collection_disabled_by_ADLOG_DISABLE_COLLECTION"
            : !postgresEnabled ? "postgres_runtime_collection_guard" : null;
        var result = new JsonObject { ["active_backend"] = "postgres", ["collection_enabled"] = reason is null, ["collection_block_reason"] = reason,
            ["postgres_collection_enabled"] = postgresEnabled, ["disable_collection_env"] = files.Flag("ADLOG_DISABLE_COLLECTION"),
            ["continuous_recovery_enabled"] = ContinuousRecovery, ["post_collection_worker_mode"] = PostCollectionMode };
        try
        {
            var rows = await queries.ReadAsync("select reason_code,retry_policy,operator_action,observed_count,first_seen_at,last_seen_at from runtime_collection_blocks where singleton_id=1 and active=true", ct);
            if (rows.FirstOrDefault() is JsonObject block && reason is not ("legacy_collection_disabled" or "ad_dc_agent_collection_owner"))
            { result["collection_block"] = Copy(block); result["collection_block_reason"] = S(block["reason_code"], "runtime_collection_block_active"); result["collection_enabled"] = false; }
        }
        catch (Exception) when (!ct.IsCancellationRequested)
        { if (reason is not ("legacy_collection_disabled" or "ad_dc_agent_collection_owner")) { result["collection_block_reason"] = "runtime_collection_block_contract_unavailable"; result["collection_enabled"] = false; } }
        try
        {
            await queries.ReadAsync("select 1 as ok", ct); result["postgres_importer_available"] = true; result["postgres_pipeline_status"] = "ready";
        }
        catch (Exception e) when (!ct.IsCancellationRequested) { result["postgres_importer_available"] = false; result["postgres_pipeline_status"] = "failed"; result["postgres_pipeline_error_type"] = e.GetType().Name; }
        return result;
    }
    JsonObject StorageSettings() => StorageV2Settings.Load(files.Setting).PublicValues();
    async Task<JsonObject> AutoCollectionAsync(CancellationToken ct)
    {
        var list = jobs.List().OfType<JsonObject>().ToArray();
        var active = list.FirstOrDefault(j => S(j["status"]) == "running");
        var last = list.FirstOrDefault(j => S(j["status"]) == "completed" && S(j["kind"]).StartsWith("collect_all_dc_logs", StringComparison.Ordinal));
        var runtime = await RuntimeAsync(ct);
        var states = await queries.ReadAsync("select server_hostname,channel,last_successful_collection_utc,last_event_time_utc,last_event_record_id,backfill_completed from collection_channel_state order by server_hostname,channel", ct);
        var channels = new JsonArray();
        foreach (var row in states.OfType<JsonObject>())
        {
            if (S(row["channel"]).Length == 0) continue;
            var item = new JsonObject { ["server"] = Copy(row["server_hostname"]), ["stale_reason"] = S(row["channel"]) == "Security" ? null : "non-security channel can be included by fairness collector" };
            foreach (string key in new[] { "channel", "last_successful_collection_utc", "last_event_time_utc", "last_event_record_id", "backfill_completed" }) item[key] = Copy(row[key]);
            channels.Add(item);
        }
        var skipped = list.Where(j => S(j["status"]) == "skipped" && S(j["skipped_reason"]) == "overlap").OrderBy(j => S(j["created_at"])).ToArray();
        var overlap = new JsonObject { ["count"] = skipped.Length, ["reason"] = skipped.Length > 0 ? "previous collection still running" : null, ["first_at"] = Copy(skipped.FirstOrDefault()?["created_at"]), ["last_at"] = Copy(skipped.LastOrDefault()?["created_at"]) };
        if (skipped.Length > 0) { overlap["normal"] = true; overlap["message"] = "Пропущены плановые запуски, потому что активный сбор уже выполнялся."; }
        var errorJob = list.FirstOrDefault(j => (j["errors"] as JsonArray)?.Count > 0);
        var error = errorJob is null ? null : new JsonObject { ["job_id"] = Copy(errorJob["id"]), ["status"] = Copy(errorJob["status"]), ["error"] = Copy(errorJob["errors"]!.AsArray()[^1]), ["updated_at"] = Copy(errorJob["updated_at"]) };
        return new() { ["status"] = active is null ? "idle" : "running", ["mode"] = "fast", ["duration_ms"] = 0,
            ["runtime"] = new JsonObject { ["scheduler"] = Copy(runtime["scheduler"]), ["collection"] = Copy(runtime["collection"]) },
            ["active_job"] = Copy(active), ["last_successful_cycle"] = Copy(last), ["last_error"] = error,
            ["skipped_overlap_summary"] = overlap,
            ["collector_health"] = new JsonObject { ["status"] = "skipped", ["mode"] = "fast", ["reason"] = "full collector health is skipped in fast autocollection status" },
            ["performance"] = new JsonObject { ["status"] = "skipped", ["mode"] = "fast", ["reason"] = "performance SQL is skipped in fast autocollection status", ["stages"] = new JsonArray() },
            ["channels"] = channels, ["explanation"] = new JsonObject { ["skipped_overlap"] = "Это не ошибка: плановый запуск пропускается, если предыдущий сбор еще выполняется.", ["fairness"] = "Во время Security recovery не-Security журналы периодически включаются в read-only сбор, если они устарели." } };
    }
}
