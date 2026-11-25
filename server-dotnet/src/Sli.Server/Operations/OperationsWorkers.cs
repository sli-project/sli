using System.Text.Json.Nodes;
using Npgsql;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Operations;

internal sealed record OperationsComponent(string Name, string Label, int Interval, string? Plugin = null);

public sealed partial class OperationsService
{
    internal async Task<JsonObject> WorkersAsync(CancellationToken ct, bool includeQueues = true)
    {
        var rows = new JsonArray(); string? errorType = null;
        try { rows = await queries.ReadAsync("select worker_name,worker_id,process_pid,status,phase,expected_interval_seconds,details_json,started_at,heartbeat_at from runtime_worker_heartbeats order by worker_name", ct); }
        catch (Exception e) when (!ct.IsCancellationRequested) { errorType = e.GetType().Name; }
        var items = new JsonArray();
        var declared = Components.ToList();
        // New .NET roles can publish the same durable contract without being
        // hidden until another web release adds a label to the registry.
        foreach (var row in rows.OfType<JsonObject>())
            if (!declared.Any(c => c.Name == S(row["worker_name"])) && !Retired.Contains(S(row["worker_name"])))
                declared.Add(new(S(row["worker_name"]), S(row["worker_name"]), (int)Math.Max(1, N(row["expected_interval_seconds"]))));
        foreach (var component in declared)
        {
            bool plugin = component.Plugin is not null;
            var row = plugin ? files.PluginHeartbeat(component.Plugin!) : rows.OfType<JsonObject>().FirstOrDefault(r => S(r["worker_name"]) == component.Name);
            bool native = false;
            var observed = NativeRoles.Contains(component.Name) ? files.NativeHeartbeat(component.Name) : null;
            // The independent process timer cannot refresh cycle/result evidence.
            // A terminal observation may supersede a fresh cycle, never a stale one.
            var durableTime = Time(row?[plugin ? "heartbeat_at_utc" : "heartbeat_at"]);
            long durableInterval = Math.Max(1, N(row?["expected_interval_seconds"], component.Interval));
            bool durableFresh = durableTime is {} durable && (Now - durable).TotalSeconds <= Math.Max(60, durableInterval * 2 + 30);
            if (observed is not null && (row is null
                || durableFresh && S(observed["status"]) is "stopped" or "failed" && Time(observed["heartbeat_at_utc"]) >= durableTime))
            { row = observed; native = true; }
            if (row is null && OptionalRoles.Contains(component.Name)) continue;
            bool enabled = component.Name != "storage_lifecycle" || row is not null;
            if (row is null)
            {
                items.Add(new JsonObject { ["worker_name"] = component.Name, ["label"] = component.Label, ["state"] = enabled ? "not_registered" : "disabled", ["status"] = enabled ? "not_observed" : "disabled", ["feature_enabled"] = enabled, ["heartbeat_at"] = null }); continue;
            }
            var heartbeat = Time(row[plugin || native ? "heartbeat_at_utc" : "heartbeat_at"]);
            long? age = heartbeat is {} t ? Math.Max(0, (long)(Now - t).TotalSeconds) : null;
            long expected = Math.Max(1, N(row["expected_interval_seconds"], component.Interval));
            bool fresh = age is not null && age <= Math.Max(60, expected * 2 + 30);
            string reported = S(row["status"], "unknown");
            string state = reported == "blocked" ? "blocked" : (plugin || native && !OptionalRoles.Contains(component.Name) || component.Name == "semantic") && reported == "stopped" ? "disabled" : !fresh ? "stale" : reported is "partial" or "warning" or "failed" or "error" or "stopped" ? "warning" : native && reported != "running" ? "unknown" : "active";
            // Only a plugin, a cleanly exited process and the semantic worker (explicit stop request) are intentionally off;
            // any other worker that reports stopped is a service that is not running and must not read as disabled.
            // Report the latest actual launch independently of cycle health.
            var started = Time(row["started_at"]);
            if (Time(observed?["started_at"]) is {} processStarted && (started is null || processStarted > started)) started = processStarted;
            var item = new JsonObject { ["worker_name"] = component.Name, ["label"] = component.Label, ["state"] = state, ["status"] = reported,
                ["feature_enabled"] = enabled, ["execution_owner"] = plugin ? "plugin_host" : component.Name == "semantic" ? "external_worker" : "runtime_worker",
                ["worker_id"] = Copy(row[plugin || native ? "worker_instance_id" : "worker_id"]), ["process_pid"] = Copy(row["process_pid"]), ["phase"] = Copy(row["phase"]),
                ["expected_interval_seconds"] = expected, ["heartbeat_age_seconds"] = age, ["heartbeat_at"] = heartbeat is {} time ? Stamp(time) : null,
                ["started_at"] = started is {} launch ? Stamp(launch) : null, ["details"] = plugin || native ? new JsonObject { ["last_result"] = Copy(row["last_result"]) } : Copy(row["details_json"]) ?? new JsonObject() };
            if (native) { item["observation_source"] = "native_process_heartbeat"; item["service_outcome"] = "unknown"; }
            if (observed is not null) item["details"]!.AsObject()["process_observation"] = Copy(observed);
            if (component.Name == "storage_lifecycle") AddLifecycleOutcome(item, fresh, expected, Now);
            items.Add(item);
        }
        var result = new JsonObject { ["status"] = errorType is null ? "ok" : "unavailable", ["source"] = "postgres_runtime_worker_heartbeats", ["error_type"] = errorType, ["items"] = items };
        if (includeQueues) result["semantic_queues"] = await QueuesAsync(ct);
        else
        {
            var semantic = items.OfType<JsonObject>().FirstOrDefault(item => S(item["worker_name"]) == "semantic");
            bool semanticStopped = S(semantic?["status"]) == "stopped";
            bool semanticStale = S(semantic?["state"]) == "stale";
            result["password_detection"] = await PasswordDetectionAsync(semanticStopped, semanticStale, ct);
        }
        return result;
    }

    // The ordinary web role supplies its active domain inventory. Only the
    // projection owner reads the protected checkpoint and native-event tables.
    internal const string PasswordLiveStatusSql = """
        select rule_id,state,observed_at from public.read_password_live_status400(
            array(select d.id::bigint from public.domains d where not d.is_archived))
        """;
    private const string PasswordThresholdStatusSql = """
        select rule_id,state,observed_at from public.read_password_threshold_status418(
            array(select d.id::bigint from public.domains d where not d.is_archived))
        """;

    private async Task<JsonObject> PasswordDetectionAsync(bool semanticStopped, bool semanticStale, CancellationToken ct)
    {
        static JsonObject UnavailableStatus() => new() { ["status"] = "unavailable", ["items"] = new JsonArray() };
        try
        {
            JsonArray rows;
            try { rows = await queries.ReadAsync(PasswordThresholdStatusSql, ct); }
            catch (PostgresException error) when (error.SqlState == PostgresErrorCodes.UndefinedFunction)
            { rows = await queries.ReadAsync(PasswordLiveStatusSql, ct); }
            var items = new JsonArray();
            var rules = new HashSet<string>(StringComparer.Ordinal);
            foreach (var node in rows)
            {
                if (node is not JsonObject row) return UnavailableStatus();
                string rule = S(row["rule_id"]), state = S(row["state"]);
                if (rule is not ("qw.password-brute-force" or "qw.password-spray") || !rules.Add(rule)
                    || state is not ("failed" or "behind" or "catching_up" or "history_pending" or "recovered" or "current" or "quiet" or "unknown" or "disabled"))
                    return UnavailableStatus();
                var observed = Time(row["observed_at"]);
                if (state is not ("unknown" or "disabled" or "history_pending") && observed is null) return UnavailableStatus();
                if (state == "behind" && (semanticStopped || semanticStale) || state == "catching_up" && semanticStopped)
                    state = "stalled";
                if (state == "current" && (semanticStopped || semanticStale)) state = "stalled";
                items.Add(new JsonObject { ["rule_id"] = rule, ["state"] = state,
                    ["observed_at"] = observed is {} at ? Stamp(at) : null });
            }
            return items.Count == 2 ? new() { ["status"] = "ok", ["items"] = items } : UnavailableStatus();
        }
        catch (Exception) when (!ct.IsCancellationRequested)
        {
            return UnavailableStatus();
        }
    }

    static readonly HashSet<string> Retired = ["ad_context_snapshot", "ad_snapshot_projection", "computers_v5_snapshot", "computers_v6_snapshot", "computers_v6_source", "users_v2_snapshot", "storage_v2_outbox", "collection", "agent_import", "gpo_snapshot", "password_producer", "password_risk", "smtp_delivery", "telegram_delivery"];
    static readonly HashSet<string> NativeRoles = ["post_collection", "entity_state", "what_where_when_projection", "semantic", "ad_snapshot_manifest_coordinator", "plugin_radius_session_observation", "notification_delivery", "core_job_executor_light", "core_job_executor_heavy", "core_job_executor_long", "radius_accounting"];
    // Extra executor profiles run only when the install enabled them: shown from a heartbeat row or file, hidden otherwise, and a stopped one is a failure.
    static readonly HashSet<string> OptionalRoles = ["core_job_executor_heavy", "core_job_executor_long"];
    internal static void AddLifecycleOutcome(JsonObject item, bool fresh, long expected, DateTimeOffset now)
    {
        var details = item["details"] as JsonObject ?? new(); long bound = Math.Max(60, expected * 2 + 30);
        var completed = Time(details["last_cycle_completed_at"]); var watermark = Time(details["watermark_updated_at"]);
        long? age = completed is {} t ? Math.Max(0, (long)(now - t).TotalSeconds) : null;
        bool? stale = age is null ? null : age > bound;
        string status = S(details["last_cycle_status"], "unknown"), phase = S(details["lifecycle_phase"]);
        bool valid = status == "success" && S(details["last_result_phase"]) == "completed" && System.Text.RegularExpressions.Regex.IsMatch(S(details["last_result_digest"]), "\\A[0-9a-fA-F]{64}\\z") && S(details["last_successful_watermark"]).Length > 0;
        bool stalled = fresh && phase != "not_due" && S(details["last_successful_watermark"]).Length > 0 && watermark is {} w && (now - w).TotalSeconds > bound;
        string outcome = status == "success" ? fresh && phase == "not_due" && valid || valid && watermark is {} u && (now - u).TotalSeconds <= bound || stale == false ? "ok" : "degraded" : status is "failed" or "partial" or "blocked" ? "degraded" : "unknown";
        if (stale == true || stalled) outcome = "degraded";
        item["process_status"] = fresh ? "up" : "stale"; item["service_outcome"] = outcome; item["result_age_seconds"] = age; item["result_is_stale"] = stale; item["progress_is_stalled"] = stalled;
        item["lifecycle_progress_status"] = status == "failed" ? "failed" : stalled ? "stalled" : phase == "not_due" ? "not_due" : status == "success" ? "completed" : "unknown";
    }
    async Task<JsonObject> QueuesAsync(CancellationToken ct)
    {
        try
        {
            var rows = await queries.ReadAsync(OperationsSql.Queues, ct); var stages = new JsonArray();
            foreach (string name in new[] { "processing", "dispatch", "risk" })
            {
                var stage = rows.OfType<JsonObject>().Where(r => S(r["queue_name"]) == name).ToArray();
                var pending = stage.Where(r => S(r["queue_status"]) is "queued" or "failed" or "leased").ToArray();
                stages.Add(new JsonObject { ["queue_name"] = name, ["depth"] = pending.Sum(r => N(r["depth"])), ["oldest_pending_age_seconds"] = pending.Select(r => N(r["oldest_pending_age_seconds"])).DefaultIfEmpty().Max(), ["completed_last_hour"] = stage.Sum(r => N(r["completed_last_hour"])) });
            }
            foreach (var row in rows.OfType<JsonObject>()) { row.Remove("oldest_pending_age_seconds"); row.Remove("completed_last_hour"); }
            return new() { ["status"] = "ok", ["contains_event_payload"] = false, ["window_seconds"] = 3600, ["warning_thresholds"] = new JsonObject { ["depth"] = 1000, ["oldest_pending_age_seconds"] = 900 }, ["stages"] = stages, ["items"] = rows };
        }
        catch (Exception e) when (!ct.IsCancellationRequested) { var result = Unavailable(e); result["contains_event_payload"] = false; result["items"] = new JsonArray(); return result; }
    }
    async Task<JsonObject> OverviewAsync(bool readiness, CancellationToken ct)
    {
        var postgres = await PostgresAsync(10, ct); var workers = await WorkersAsync(ct);
        var output = new JsonObject { ["api_version"] = "v1", ["generated_at_utc"] = Generated, ["workers"] = workers, ["postgres"] = postgres,
            ["storage"] = StorageSummary(postgres), ["agent_collection"] = await AgentHealthAsync(ct), ["read_only"] = true };
        if (readiness)
        {
            workers["items"] = A(workers["items"]!.AsArray().Where(w => S(w?["worker_name"]) != "collection"));
            output["archive"] = await ArchiveRootStatusAsync(ct);
            return output;
        }
        var collector = await CollectorAsync(ct); var collection = await CollectionAsync(ct);
        var worker = workers["items"]!.AsArray().OfType<JsonObject>().FirstOrDefault(w => S(w["worker_name"]) == "collection");
        bool external = worker is not null && B(worker["feature_enabled"]) && S(worker["state"]) is "active" or "warning";
        bool localOnly = external && S(collection["collection_block_reason"]) == "collection_disabled_by_ADLOG_DISABLE_COLLECTION";
        collection["operational_collection_enabled"] = localOnly || B(collection["collection_enabled"]);
        collection["operational_collection_block_reason"] = localOnly ? null : Copy(collection["collection_block_reason"]);
        collection["collection_execution_owner"] = external ? "external_worker" : "server_process";
        collection["local_runtime_guard_only"] = localOnly;
        var progress = OperationsCollector.Progress(collector, worker, collection, Now);
        collector = OperationsCollector.ApplyProgress(collector, progress);
        if (!B(collection["operational_collection_enabled"]))
            foreach (var item in collector["items"]!.AsArray().OfType<JsonObject>())
            {
                var last = new[] { Time(item["last_successful_collection_utc"]), Time(item["last_event_time_utc"]) }.Where(t => t is not null).Max();
                if (last is {} t && t < Now.AddDays(-7) && N(item["inserted_24h"]) == 0) item["usage_state"] = "unused";
            }
        output["collection"] = collection; output["collection_progress"] = progress; output["collector_health"] = collector;
        output["catalog_completeness"] = catalog.Completeness();
        output["plugin_pilots"] = new JsonObject { ["vpn_radius"] = await RadiusOperationsAsync(ct) };
        return output;
    }
    async Task<JsonObject> RadiusOperationsAsync(CancellationToken ct)
    {
        try
        {
            var rows = await queries.ReadAsync("select * from radius_vpn_operations_v1 order by source_instance_id limit 20", ct);
            foreach (var row in rows.OfType<JsonObject>())
            {
                long projected = N(row["projected_session_count"]), unresolved = N(row["identity_unresolved_count"]) + N(row["timestamp_unresolved_count"]) + N(row["quarantined_delivery_count"]);
                row["plugin_id"] = "sli.remote-access"; row["plugin_state"] = "bundled_supervised_production";
                row["source_state"] = S(row["source_activation"]) == "disabled" ? "disabled" : S(row["subscription_activation"]) == "disabled" ? "subscription_disabled" : "manual_enabled";
                row["worker_state"] = B(row["manual_worker_session_exists"]) ? "active_manual" : B(row["ephemeral_login_exists"]) ? "attention" : "manual_idle";
                row["queue_state"] = N(row["failed_delivery_count"]) > 0 || N(row["leased_delivery_count"]) > 0 || N(row["quarantined_delivery_count"]) > 0 ? "attention" : N(row["queued_delivery_count"]) > 0 ? "pending_manual" : "drained";
                row["dataset_state"] = projected == 0 && unresolved > 0 ? "identity_incomplete" : projected > 0 && unresolved > 0 ? "partial" : projected > 0 ? "available" : "not_collected";
                row["access_state"] = N(row["direct_capability_assignment_count"]) == 0 && N(row["package_capability_mapping_count"]) == 0 ? "owner_only" : "assigned";
                row["resource_profile"] = OperationsCatalog.ResourceProfile(S(row["resource_profile_id"]).Trim());
            }
            return new() { ["contract_id"] = "sli.radius-vpn-operations.v1", ["status"] = "ok", ["items"] = rows, ["limits"] = new JsonObject { ["source_instances"] = 20 }, ["contains_identity_or_event_payload"] = false };
        }
        catch (Exception e) when (!ct.IsCancellationRequested) { var result = Unavailable(e); result["contract_id"] = "sli.radius-vpn-operations.v1"; result["items"] = new JsonArray(); result["contains_identity_or_event_payload"] = false; return result; }
    }
    // Retired/manual rollback components are intentionally absent.
    internal static readonly OperationsComponent[] Components = [
        new("ad_snapshot_manifest_coordinator", "Canonical координатор manifest-снимка AD (06:00/18:00 Asia/Novosibirsk)", 43200, null),
        new("storage_lifecycle", "Жизненный цикл хранения", 21600, null),
        new("post_collection", "Постобработка", 10, null),
        new("entity_state", "Состояния сущностей", 30, null),
        new("what_where_when_projection", "Проекция отчёта «что где когда»", 30, null),
        new("plugin_radius_acquisition", "Сбор RADIUS-событий", 300, "radius-acquisition"),
        new("plugin_radius_session_observation", "Наблюдение RADIUS-сессий", 30, "radius-session-observation"),
        new("semantic", "Семантический анализ", 30, null),
        new("notification_delivery", "Доставка уведомлений", 30),
        new("core_job_executor_light", "Исполнение задач light", 30),
        new("core_job_executor_heavy", "Исполнение задач heavy", 30),
        new("core_job_executor_long", "Исполнение задач long", 30),
        new("radius_accounting", "Обработка RADIUS Accounting", 30)
    ];
}
