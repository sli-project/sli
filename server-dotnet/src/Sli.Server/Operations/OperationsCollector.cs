using System.Text.Json.Nodes;
using System.Text.Json;
using System.Text.RegularExpressions;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Operations;

internal static partial class OperationsCollector
{
    internal static Dictionary<(string Server, string Channel), JsonObject> LogStats(IEnumerable<string> lines, DateTimeOffset now)
    {
        var stats = new Dictionary<(string, string), JsonObject>();
        var cutoff = now.AddHours(-24);
        foreach (string line in lines)
        {
            JsonObject? record;
            try { record = JsonNode.Parse(line) as JsonObject; }
            catch (JsonException) { continue; }
            if (record is null) continue;
            var time = Time(record["ts"]);
            if (time < cutoff) continue;
            string server = S(record["server"]);
            if (server.Length == 0) server = Regex.Match(S(record["command"]), @"--server\s+(\S+)").Groups[1].Value;
            if (server.Length == 0) continue;
            string text = string.Join('\n', new[] { "stdout_tail", "stderr_tail", "message", "error" }.Select(key => S(record[key])));
            JsonObject Bucket(string channel)
            {
                var key = (server, channel);
                if (!stats.TryGetValue(key, out var bucket))
                    stats[key] = bucket = new() { ["timeouts_24h_available"] = null, ["timeouts_24h"] = 0L, ["partial_timeouts_24h"] = 0L, ["inserted"] = 0L, ["skipped"] = 0L, ["last_partial_count"] = 0L, ["last_status"] = null };
                return bucket;
            }
            void Status(string channel, string status, long count)
            {
                var bucket = Bucket(channel.Trim());
                bucket["last_status"] = status;
                bucket["timeouts_24h_available"] = time is not null && time >= cutoff && time <= now && !(bucket["timeouts_24h_available"] is JsonValue value && value.TryGetValue<bool>(out bool available) && !available);
                if (status is "timeout" or "partial_timeout") bucket["timeouts_24h"] = N(bucket["timeouts_24h"]) + 1;
                if (status == "partial_timeout")
                {
                    bucket["partial_timeouts_24h"] = N(bucket["partial_timeouts_24h"]) + 1;
                    bucket["last_partial_count"] = Math.Max(N(bucket["last_partial_count"]), count);
                }
            }
            foreach (Match match in Regex.Matches(text, @"Timed out channel: (.+?) after \d+s(?: partial_count=(\d+))?"))
            {
                long count = long.TryParse(match.Groups[2].Value, out long n) ? n : 0;
                Status(match.Groups[1].Value, count > 0 ? "partial_timeout" : "timeout", count);
            }
            foreach (Match match in Regex.Matches(text, @"Completed channel: (.+?) count=(\d+)")) Status(match.Groups[1].Value, "completed", 0);
            foreach (Match match in Regex.Matches(text, @"([A-Za-z0-9_.-]+)\.jsonl: inserted=(\d+), skipped=(\d+)"))
            {
                string safe = match.Groups[1].Value;
                string[] channels = ["Security", "System", "Directory Service", "DNS Server", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-TaskScheduler/Operational"];
                string channel = channels.FirstOrDefault(c => Regex.Replace(c, "[\\\\/:*?\"<>| ]+", "_") == safe) ?? safe.Replace('_', ' ');
                var bucket = Bucket(channel);
                if (long.TryParse(match.Groups[2].Value, out long inserted)) bucket["inserted"] = N(bucket["inserted"]) + inserted;
                if (long.TryParse(match.Groups[3].Value, out long skipped)) bucket["skipped"] = N(bucket["skipped"]) + skipped;
            }
        }
        return stats;
    }
    internal static readonly HashSet<string> Errors = ["failed", "error", "timeout", "unavailable", "blocked", "access_denied"];
    internal static long? Lag(JsonNode? value, DateTimeOffset now) => Time(value) is {} t ? Math.Max(0, (long)(now - t).TotalMinutes) : null;
    internal static string Check(string status, long? lag) => Errors.Contains(status.ToLowerInvariant()) ? "error" : lag is null or > 20 ? "stale" : lag > 5 ? "lagging" : "current";
    internal static JsonObject Freshness(JsonArray items, DateTimeOffset now, string? selected = null)
    {
        var relevant = items.OfType<JsonObject>().Where(r => selected is null || S(r["server"]).Equals(selected, StringComparison.OrdinalIgnoreCase)).ToArray();
        var lags = relevant.Select(r => Lag(r["last_successful_collection_utc"], now)).Where(n => n is not null).ToArray();
        int failed = relevant.Count(r => Errors.Contains(S(r["last_status"]).ToLowerInvariant()));
        long? worst = lags.Length > 0 ? lags.Max() : null;
        var oldest = relevant.Select(r => Time(r["last_successful_collection_utc"])).Where(t => t is not null).Min();
        var latest = relevant.Select(r => Time(r["last_event_time_utc"])).Where(t => t is not null).Max();
        string state = failed > 0 && failed < relevant.Length ? "partial" : failed > 0 ? "error" : worst is null or > 20 || lags.Length != relevant.Length ? "stale" : worst > 5 ? "lagging" : "current";
        return new() { ["state"] = state, ["label"] = state switch { "partial" => "Частичный сбор", "error" => "Ошибка сбора", "stale" => "Данные сильно устарели", "lagging" => "Есть отставание", _ => "Данные актуальны" },
            ["worst_lag_minutes"] = worst, ["checked_at_utc"] = oldest is {} o ? Stamp(o).Replace("+00:00", "Z") : null, ["latest_event_utc"] = latest is {} e ? Stamp(e).Replace("+00:00", "Z") : null,
            ["worst_event_lag_minutes"] = relevant.Select(r => Lag(r["last_event_time_utc"], now)).Where(n => n is not null).Max(),
            ["collection_error"] = failed > 0, ["channels_failed"] = failed, ["channels_total"] = relevant.Length, ["channels_checked"] = lags.Length, ["basis"] = "last_successful_collection" };
    }
    internal static JsonObject Channel(JsonObject row, JsonObject stats, JsonObject? cursor, DateTimeOffset now)
    {
        long? eventLag = Lag(row["last_event_time_utc"] ?? row["latest_event_time_utc"], now), checkLag = Lag(row["last_successful_collection_utc"], now);
        string status = S(stats["last_status"], row["last_successful_collection_utc"] is null ? "unknown" : eventLag > 120 ? "stale" : "completed"), channel = S(row["channel"]);
        long inserted = N(stats["inserted"]), skipped = N(stats["skipped"]); bool recovery = B(row["recovery_mode"]) || N(row["recovery_mode"]) != 0;
        string check = Check(status, checkLag);
        string severity = status is "timeout" or "failed" ? channel == "Security" ? "high" : "warn" : channel == "Security" && eventLag > 120 ? "high" : channel == "Security" && eventLag > 30 || status == "stale" || eventLag > 120 || status != "completed" && skipped > Math.Max(inserted * 3, 100) || status == "partial_timeout" ? "warn" : "ok";
        var warnings = new JsonArray();
        if (status is "timeout" or "partial_timeout") warnings.Add("channel timeout");
        if (channel == "Security" && eventLag > 120) warnings.Add("Security lag > 2h"); else if (channel == "Security" && eventLag > 30) warnings.Add("Security lag > 30m"); else if (channel != "Security" && eventLag > 120) warnings.Add("channel data stale");
        if (status != "completed" && skipped > Math.Max(inserted * 3, 100)) warnings.Add("possible repeated backlog read");
        if (S(cursor?["decision"]) == "rejected") { warnings.Add(S(cursor?["reason"], "cursor commit rejected")); severity = channel == "Security" ? "high" : "warn"; }
        string label = check switch { "error" => "ошибка проверки", "stale" => "проверка сильно отстаёт", "lagging" => "есть задержка проверки", _ => "проверка актуальна" };
        var result = new JsonObject { ["server"] = Copy(row["server_hostname"]), ["channel"] = Copy(row["channel"]), ["collection_lag_minutes"] = checkLag,
            ["last_event_time_utc"] = Copy(row["last_event_time_utc"] ?? row["latest_event_time_utc"]), ["last_event_record_id"] = Copy(row["last_event_record_id"] ?? row["latest_event_record_id"]),
            ["last_status"] = status, ["failure_reason"] = Errors.Contains(status) ? S(stats["backend_reason"], status) : null,
            ["display_status"] = channel == "Security" && eventLag > 30 && status == "completed" ? "сбор завершён, данные ещё догоняются" : status == "stale" ? "данные устарели" : StatusLabel(status),
            ["timeouts_24h"] = TimeoutCount(stats["timeouts_24h"]) ?? 0, ["timeouts_24h_available"] = CounterAvailable(stats), ["partial_timeouts_24h"] = N(stats["partial_timeouts_24h"]),
            ["last_partial_count"] = N(stats["last_partial_count"]), ["inserted_24h"] = inserted, ["skipped_24h"] = skipped, ["inserted_skipped_ratio"] = $"{inserted}/{skipped}", ["event_count"] = N(row["event_count"]),
            ["lag_minutes"] = eventLag, ["severity"] = severity, ["warnings"] = warnings,
            ["target_state"] = eventLag is null ? "unknown" : recovery || eventLag > 120 ? "catching_up" : eventLag > 30 ? "near_current" : "current",
            ["adaptive_limit"] = Copy(row["current_limit"]), ["recovery_mode"] = recovery, ["adaptive_action"] = Copy(row["last_action"]),
            ["collection_state"] = check, ["collection_label"] = label, ["collection_severity"] = check is "error" or "stale" ? "high" : check == "lagging" ? "warn" : "ok",
            ["cycle_status_label"] = status switch { "completed" => "сбор завершен", "partial_timeout" => "частичный сбор", "timeout" => "таймаут", "failed" => "ошибка сбора", "stale" => "последний сбор был давно", _ => StatusLabel(status) },
            ["freshness_label"] = eventLag is null ? "нет данных о свежести" : channel == "Security" && recovery && eventLag > 30 ? "сбор успешен, догоняет backlog" : eventLag > 120 ? "данные сильно отстают" : eventLag > 30 ? "данные отстают" : "данные актуальны",
            ["event_observation_label"] = check == "error" ? "состояние событий не подтверждено" : check == "stale" ? "нужна новая проверка канала" : channel == "Security" && recovery && eventLag > 30 ? "события догоняются" : channel == "Security" && (eventLag is null or > 30) ? "события отстают" : eventLag is null or > 30 ? "новых событий не обнаружено" : "события актуальны",
            ["event_observation_severity"] = check == "error" ? "high" : check == "stale" ? "warn" : channel == "Security" && eventLag is null or > 30 ? recovery ? "warn" : "high" : "good",
            ["state_explanation"] = label };
        foreach (string key in new[] { "last_collection_start_utc", "last_successful_collection_utc" }) result[key] = Copy(row[key]);
        foreach (string key in new[] { "query_duration_ms", "import_duration_ms", "import_queue_wait_ms", "import_retry_count", "total_duration_ms", "events_per_second", "last_record_id_delta", "lag_delta_minutes", "collection_mode", "requested_collection_mode", "cursor_strategy", "cursor_fallback_reason", "collector_backend", "backend_reason" }) result[key] = Copy(stats[key]);
        foreach (var (target, source) in new[] { ("cursor_commit_decision", "decision"), ("cursor_commit_reason", "reason"), ("cursor_old_record_id", "old_record_id"), ("cursor_proposed_record_id", "proposed_record_id"), ("cursor_new_record_id", "new_record_id"), ("cursor_audit_id", "id"), ("cursor_trace_id", "trace_id") }) result[target] = Copy(cursor?[source]);
        double delta = double.TryParse(S(stats["lag_delta_minutes"]), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var d) ? d : 0;
        result["backlog_eta_minutes"] = eventLag is > 30 && delta < 0 && N(stats["total_duration_ms"]) > 0 ? (long)Math.Ceiling(eventLag.Value / -delta * N(stats["total_duration_ms"]) / 60000d) : null;
        return result;
    }
    static string StatusLabel(string status) => Sli.Server.Reporting.UiLabels.Status(status);
    internal static JsonObject Summary(JsonArray items)
    {
        var rows = items.OfType<JsonObject>().ToArray();
        var result = new JsonObject { ["channels_total"] = rows.Length, ["servers_total"] = rows.Select(r => S(r["server"])).Where(s => s.Length > 0).Distinct().Count(), ["timeouts_24h"] = rows.Sum(r => N(r["timeouts_24h"])), ["partial_timeouts_24h"] = rows.Sum(r => N(r["partial_timeouts_24h"])) };
        foreach (string severity in new[] { "high", "warn" }) { result[severity] = rows.Count(r => S(r["severity"]) == severity); result["security_" + severity] = rows.Count(r => S(r["channel"]) == "Security" && S(r["severity"]) == severity); }
        foreach (string state in new[] { "current", "near_current", "catching_up" }) result["target_" + state] = rows.Count(r => S(r["target_state"]) == state);
        result["cursor_rejected"] = rows.Count(r => S(r["cursor_commit_decision"]) == "rejected"); return result;
    }
    internal static JsonObject Progress(JsonObject collector, JsonObject? worker, JsonObject collection, DateTimeOffset now)
    {
        var job = worker?["details"]?["active_job"] as JsonObject; var items = new JsonArray();
        foreach (var channel in collector["items"]!.AsArray().OfType<JsonObject>())
        {
            string check = S(Freshness(A([channel]), now)["state"]);
            bool boundary = !B(channel["recovery_mode"]) && (S(channel["last_status"]) == "completed" || S(channel["adaptive_action"]).StartsWith("exit_recovery:source_boundary_reached", StringComparison.Ordinal));
            var item = new JsonObject { ["check_state"] = check, ["boundary_reached"] = boundary, ["boundary_checked_at_utc"] = boundary ? Copy(channel["last_successful_collection_utc"]) : null };
            foreach (string key in new[] { "server", "channel", "recovery_mode", "last_status", "failure_reason", "last_event_record_id", "last_event_time_utc", "last_successful_collection_utc" }) item[key] = Copy(channel[key]);
            item["current_limit"] = Copy(channel["adaptive_limit"]); item["last_action"] = Copy(channel["adaptive_action"]); items.Add(item);
        }
        int boundaries = items.Count(i => B(i?["boundary_reached"])); var recovery = A(items.Where(i => B(i?["recovery_mode"])));
        string workerStatus = S(worker?["status"], "unknown"), jobStatus = S(job?["status"]), freshness = S(Freshness(collector["items"]!.AsArray(), now)["state"]);
        var block = collection.ContainsKey("operational_collection_block_reason") ? collection["operational_collection_block_reason"] : collection["collection_block_reason"];
        bool blocked = S(block).Length > 0;
        string status = blocked ? "blocked" : items.Any(i => S(i?["check_state"]) == "error") ? "failed" : workerStatus is "failed" or "error" or "blocked" ? workerStatus == "blocked" ? "blocked" : "failed" : workerStatus == "running" || jobStatus == "running" ? "running"
            : items.Count > 0 && recovery.Count == 0 && boundaries == items.Count && freshness == "current" ? "completed" : recovery.Count > 0 ? "partial" : items.Count > 0 && freshness is "stale" or "lagging" ? freshness : "unknown";
        return new() { ["status"] = status, ["check_state"] = freshness, ["block_reason"] = Copy(block), ["blocked_since_utc"] = blocked ? Copy(collection["collection_block"]?["first_seen_at"]) : null,
            ["source"] = "postgres_adaptive_state_and_worker_heartbeat", ["channels_total"] = items.Count, ["boundaries_reached"] = boundaries, ["channels_in_recovery"] = recovery.Count,
            ["worker_id"] = Copy(worker?["worker_id"]), ["worker_status"] = workerStatus, ["worker_phase"] = Copy(worker?["phase"]), ["heartbeat_at"] = Copy(worker?["heartbeat_at"]),
            ["job_id"] = Copy(job?["job_id"]), ["job_status"] = jobStatus, ["job_phase"] = Copy(job?["phase"]), ["items"] = items, ["recovery_items"] = recovery };
    }
    internal static JsonObject ApplyProgress(JsonObject collector, JsonObject progress)
    {
        if (S(progress["status"]) is "failed" or "blocked" || S(progress["worker_status"]) is "failed" or "blocked") return collector;
        var result = (JsonObject)collector.DeepClone();
        bool live = S(progress["status"]) == "running" || S(progress["worker_status"]) == "running" || S(progress["job_status"]) == "running";
        foreach (var item in result["items"]!.AsArray().OfType<JsonObject>())
        {
            var bounded = progress["items"]!.AsArray().FirstOrDefault(p => S(p?["server"]) == S(item["server"]) && S(p?["channel"]) == S(item["channel"]));
            if (bounded is null) continue;
            if (B(bounded["boundary_reached"]) && S(bounded["check_state"]) == "current") { item["collection_label"] = "граница прочитана при последней успешной проверке"; item["collection_severity"] = "ok"; item["state_explanation"] = "Чтение границы подтверждено актуальной проверкой канала."; }
            else if (B(bounded["boundary_reached"]) || S(bounded["check_state"]) == "error") continue;
            else if (B(bounded["recovery_mode"])) { item["collection_label"] = live ? "канал догоняет границу" : "канал ожидает следующую bounded-порцию"; item["collection_severity"] = "warn"; item["state_explanation"] = live ? "Bounded recovery активен; канал догоняет известную границу." : "Recovery не завершён; worker продолжит его следующей bounded-порцией."; }
            else if (live) { item["collection_label"] = "проверяется текущая граница"; item["collection_severity"] = "warn"; item["state_explanation"] = "Живой collection worker проверяет текущую source boundary."; }
        }
        return result;
    }
}

public sealed partial class OperationsService
{
    internal async Task<JsonObject> CollectorAsync(CancellationToken ct)
    {
        var history = await queries.ReadAsync(OperationsSql.CollectorHistory, ct, ("cutoff", Stamp(Now.AddHours(-24))));
        var logStats = OperationsCollector.LogStats(files.CollectorLogLines(), Now);
        var states = await queries.ReadAsync(OperationsSql.CollectorState, ct);
        JsonArray cursors;
        try { cursors = await queries.ReadAsync("select distinct on (server,channel) * from collector_cursor_audit order by server,channel,id desc", ct); }
        catch (Exception) when (!ct.IsCancellationRequested) { cursors = []; }
        var latest = states.OfType<JsonObject>().GroupBy(r => (S(r["server_hostname"]).ToLowerInvariant(), S(r["channel"]).ToLowerInvariant())).Select(g => g.OrderByDescending(r => new[] { Time(r["last_successful_collection_utc"]), Time(r["updated_at"]), Time(r["last_collection_start_utc"]) }.Max()).First());
        var items = new JsonArray();
        foreach (var row in latest)
        {
            bool Same(JsonObject other) => S(other["server"]) == S(row["server_hostname"]) && S(other["channel"]) == S(row["channel"]);
            var stats = OperationsCollector.MergeStats(history.OfType<JsonObject>().FirstOrDefault(Same) ?? new(), logStats.GetValueOrDefault((S(row["server_hostname"]), S(row["channel"]))) ?? new());
            items.Add(OperationsCollector.Channel(row, stats, cursors.OfType<JsonObject>().FirstOrDefault(Same), Now));
        }
        var summary = OperationsCollector.Summary(items);
        JsonObject post, runtimeHistory, outbox;
        try
        {
            var rows = await queries.ReadAsync("select status,count(*) as count from post_collection_jobs group by status", ct);
            var postSummary = new JsonObject(); foreach (var row in rows.OfType<JsonObject>()) postSummary[S(row["status"])] = N(row["count"]);
            var postItems = await queries.ReadAsync("select * from post_collection_jobs order by id desc limit 10", ct);
            int staleMinutes = int.TryParse(files.Setting("ADLOG_POST_COLLECTION_STALE_MINUTES", "15"), out var threshold) ? Math.Max(1, threshold) : 15;
            foreach (var row in postItems.OfType<JsonObject>())
            {
                long? age = OperationsCollector.Lag(row["heartbeat_at"] ?? row["updated_at"] ?? row["started_at"], Now);
                row["heartbeat_age_minutes"] = age; row["stale_running"] = S(row["status"]) == "running" && age >= staleMinutes;
            }
            postSummary["stale_running"] = postItems.Count(r => B(r?["stale_running"]));
            post = new() { ["backend"] = "postgres", ["status"] = "ok", ["summary"] = postSummary, ["items"] = postItems, ["generated_at_utc"] = Generated, ["stale_threshold_minutes"] = staleMinutes };
        }
        catch (Exception e) when (!ct.IsCancellationRequested)
        {
            logger?.LogWarning("post_collection_overview_unavailable error_type={ErrorType}", e.GetType().Name);
            post = Unavailable(e);
            post["backend"] = "postgres"; post["summary"] = new JsonObject(); post["items"] = new JsonArray();
        }
        summary["stale_post_collection"] = N(post["summary"]?["stale_running"]);
        try
        {
            var cycles = await queries.ReadAsync(OperationsSql.ChannelCycles, ct, ("limit", 3));
            foreach (var row in cycles.OfType<JsonObject>())
            {
                var channels = row["channels_json"] as JsonArray ?? [];
                row["servers_json"] = new JsonArray(Copy(row["server"])); row.Remove("server");
                row["phase"] = channels.Count == 1 ? S(channels[0]) : $"{channels.Count} каналов"; row.Remove("channels_json");
            }
            runtimeHistory = new() { ["status"] = "ok", ["source"] = "effective_collector", ["active_items"] = new JsonArray(), ["channel_items"] = Copy(cycles), ["items"] = cycles };
        }
        catch (Exception e) when (!ct.IsCancellationRequested)
        {
            logger?.LogWarning("runtime_collection_history_unavailable error_type={ErrorType}", e.GetType().Name);
            runtimeHistory = Unavailable(e);
        }
        try
        {
            var rows = await queries.ReadAsync(OperationsSql.Outbox, ct); var all = new JsonObject();
            foreach (var row in rows.OfType<JsonObject>()) all[S(row["state"])] = new JsonObject { ["batches"] = N(row["batches"]), ["events"] = N(row["events"]) };
            outbox = new() { ["status"] = "ok", ["states"] = all.DeepClone() };
            outbox["states"]!.AsObject().Remove("completed");
            foreach (string key in new[] { "batches", "events" })
            {
                outbox[key] = new[] { "ready", "delayed", "leased" }.Sum(s => N(all[s]?[key]));
                outbox["expired_lease_" + key] = N(all["expired_lease"]?[key]); outbox["completed_" + key] = N(all["completed"]?[key]);
            }
        }
        catch (Exception e) when (!ct.IsCancellationRequested)
        {
            logger?.LogWarning("storage_v2_outbox_unavailable error_type={ErrorType}", e.GetType().Name);
            outbox = Unavailable(e);
        }
        return new() { ["generated_at_utc"] = Generated, ["lookback_hours"] = 24, ["backend"] = "postgres", ["summary"] = summary, ["items"] = items, ["post_collection"] = post,
            ["cursor_audit"] = new JsonObject { ["latest"] = cursors }, ["operations_slo"] = CollectorSlo(items, summary, post), ["collection_freshness"] = OperationsCollector.Freshness(items, Now), ["runtime_history"] = runtimeHistory, ["storage_v2_outbox"] = outbox };
    }
    internal JsonObject CollectorSlo(JsonArray items, JsonObject summary, JsonObject post)
    {
        var security = items.OfType<JsonObject>().Where(i => S(i["channel"]) == "Security").ToArray();
        var checks = security.Select(i => (Lag: OperationsCollector.Lag(i["last_successful_collection_utc"], Now), Status: S(i["last_status"]))).ToArray();
        int current = checks.Count(i => OperationsCollector.Check(i.Status, i.Lag) == "current"), unknown = checks.Count(i => i.Lag is null && OperationsCollector.Check(i.Status, i.Lag) != "error"), breached = checks.Count(i => OperationsCollector.Check(i.Status, i.Lag) == "error" || i.Lag is not null && OperationsCollector.Check(i.Status, i.Lag) == "stale");
        int warning = security.Length - current - unknown - breached;
        bool known = security.Length > 0 && security.All(OperationsCollector.CounterAvailable);
        long? consumed = known ? security.Sum(i => OperationsCollector.TimeoutCount(i["timeouts_24h"])!.Value) : null;
        long interval = Math.Max(60, long.TryParse(files.Setting("ADLOG_COLLECTION_INTERVAL_SECONDS", "600"), out long n) ? n : 600);
        long expected = security.Length * Math.Max(1, 86400 / interval), allowed = security.Length == 0 ? 0 : Math.Max(1, (long)Math.Floor(expected * (1 - .99)));
        string status = security.Length == 0 || unknown == security.Length ? "unknown" : breached > 0 ? "breached" : warning > 0 || unknown > 0 || N(summary["timeouts_24h"]) > 0 || N(summary["partial_timeouts_24h"]) > 0 || N(summary["stale_post_collection"]) > 0 || !known ? "attention" : "met";
        return new() { ["status"] = status, ["label"] = status switch { "unknown" => "Недостаточно данных", "breached" => "Требует вмешательства", "attention" => "Требует внимания", _ => "В норме" }, ["basis"] = "last_successful_collection", ["security_channels"] = security.Length,
            ["freshness_current"] = current, ["freshness_warning"] = warning, ["freshness_breached"] = breached, ["freshness_unknown"] = unknown, ["warning_minutes"] = 5, ["breach_minutes"] = 20,
            ["timeouts_24h"] = Copy(summary["timeouts_24h"]), ["partial_timeouts_24h"] = Copy(summary["partial_timeouts_24h"]), ["stale_post_collection"] = Copy(summary["stale_post_collection"]), ["analysis_queued"] = N(post["summary"]?["queued"]), ["analysis_running"] = N(post["summary"]?["running"]),
            ["error_budget"] = new JsonObject { ["window_hours"] = 24, ["objective"] = .99, ["schedule_interval_seconds"] = interval, ["expected_security_checks"] = expected, ["allowed_errors"] = allowed, ["consumed_errors"] = consumed,
                ["remaining_errors"] = consumed is null ? null : Math.Max(0, allowed - consumed.Value), ["consumed_percent"] = consumed is null ? null : Math.Round(100d * consumed.Value / Math.Max(1, allowed), 2), ["status"] = consumed is null ? "unknown" : consumed > allowed ? "exhausted" : consumed > 0 ? "attention" : "available", ["method"] = "scheduled_security_checks_model" } };
    }
}
