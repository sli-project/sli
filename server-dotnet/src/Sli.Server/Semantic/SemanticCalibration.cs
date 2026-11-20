using System.Text.Json.Nodes;

namespace Sli.Server.Semantic;

public sealed partial class SemanticWorkspace
{
    private static async Task<JsonObject> CalibrationAsync(ISemanticSession session, JsonObject execution, int hours, CancellationToken ct)
    {
        bool ready = execution.Number("semantic_schema_marker") == 29;
        var jobs = ready ? await session.QueryAsync(SemanticReadSql.job_rows, ct, hours) : new JsonArray();
        var results = ready ? await session.QueryAsync(SemanticReadSql.result_rows, ct, hours) : new JsonArray();
        var policies = ready ? await session.QueryAsync(SemanticReadSql.policy_rows, ct) : new JsonArray();
        var control = ready ? await session.QueryAsync(SemanticReadSql.control_rows, ct, hours) : new JsonArray();
        var coverage = ready ? await session.QueryAsync(SemanticReadSql.coverage_rows, ct, hours) : new JsonArray();
        var quality = ready ? (await session.QueryAsync(SemanticReadSql.quality_rows, ct, hours)).FirstOrDefault() : null;
        bool reviewReady = ready && execution.Flag("analyst_review_schema_ready");
        var reviews = reviewReady ? await session.QueryAsync(SemanticReadSql.review_rows, ct, hours) : new JsonArray();
        long total = jobs.Sum(x => x.Number("job_count"));
        var flags = new JsonObject();
        foreach (string name in new[] { "missing_actor_sid", "unresolved_actor", "unresolved_target", "missing_source_ip", "unknown_event_mapping" }) flags[name] = quality.Number(name);
        JsonObject Counts(JsonArray rows) => new() { ["total"] = rows.Sum(x => x.Number("item_count")), ["by_status"] = new JsonObject(rows.Select(x => KeyValuePair.Create<string, JsonNode?>(x.Text("coverage_status")!, JsonValue.Create(x.Number("item_count"))))) };
        var time = new JsonObject { ["observed"] = quality.Number("normalized") };
        foreach (string name in new[] { "future_clock_skew", "delayed_ingest", "average_ingest_delay_seconds", "max_ingest_delay_seconds" }) time[name] = quality?[name].Copy() ?? JsonValue.Create(0);
        var readiness = new JsonObject
        {
            ["control_health"] = Counts(control), ["coverage"] = Counts(coverage),
            ["execution_reliability"] = new JsonObject { ["jobs"] = total, ["completed"] = jobs.Where(x => x.Text("evaluation_status") == "completed").Sum(x => x.Number("job_count")),
                ["failed"] = jobs.Where(x => x.Text("evaluation_status") == "failed").Sum(x => x.Number("job_count")), ["quarantined"] = jobs.Where(x => x.Text("evaluation_status") == "quarantined").Sum(x => x.Number("job_count")),
                ["retries"] = Math.Max(0, jobs.Sum(x => x.Number("attempts")) - total) },
            ["source_quality"] = new JsonObject { ["normalized"] = quality.Number("normalized"), ["flags"] = flags }, ["time_provenance"] = time,
            ["source_coverage_integrity"] = ready ? await IntegrityAsync(session, hours, ct) : new JsonObject { ["state"] = "schema_unavailable", ["channels"] = new JsonObject { ["total"] = 0, ["by_status"] = new JsonObject(), ["items"] = new JsonArray() }, ["cursor_integrity"] = new JsonObject(), ["run_integrity"] = new JsonObject(), ["gap_detection"] = new JsonObject(), ["surveyed_servers_contacted"] = false, ["payload_read"] = false },
            ["false_positive_rate"] = ReviewSummary(reviews, reviewReady)
        };
        return new JsonObject { ["api_version"] = "v1", ["generated_at_utc"] = SemanticJson.Stamp(DateTimeOffset.UtcNow), ["read_only"] = true, ["execution"] = execution.Copy(),
            ["window_hours"] = hours, ["state"] = !ready ? "schema_unavailable" : jobs.Count + results.Count + policies.Count > 0 ? "available" : "empty", ["jobs"] = jobs, ["results"] = results, ["policies"] = policies,
            ["calibration_readiness"] = readiness, ["limits"] = new JsonObject { ["window_hours_max"] = 168, ["payload"] = false, ["legacy_findings"] = false } };
    }
    internal static JsonObject ReviewSummary(JsonArray rows, bool ready, int minimumSample = 10)
    {
        var by = rows.ToDictionary(x => x.Text("verdict")!, x => x.Number("item_count"));
        long confirmed = by.GetValueOrDefault("confirmed_security"), fp = by.GetValueOrDefault("false_positive"), decisive = confirmed + fp;
        string state = !ready || decisive == 0 ? "not_measurable" : decisive < minimumSample ? "insufficient_sample" : "measured";
        string reason = !ready ? "analyst_review_schema_unavailable" : decisive == 0 ? "decisive_analyst_labels_not_available" : decisive < minimumSample ? $"minimum_{minimumSample}_decisive_labels_required" : "decisive_analyst_sample_available";
        return new JsonObject { ["state"] = state, ["reason"] = reason, ["reviewed_scenarios"] = by.Values.Sum(), ["decisive_labels"] = decisive, ["false_positive_labels"] = fp,
            ["rate_percent"] = decisive > 0 ? Math.Round(100.0 * fp / decisive, 2) : null, ["minimum_decisive_sample"] = minimumSample,
            ["by_verdict"] = new JsonObject(by.Select(x => KeyValuePair.Create<string, JsonNode?>(x.Key, JsonValue.Create(x.Value)))) };
    }
    private static async Task<JsonObject> IntegrityAsync(ISemanticSession session, int hours, CancellationToken ct)
    {
        var states = await session.QueryAsync(SemanticReadSql.Integrity_state_rows, ct);
        var runs = (await session.QueryAsync(SemanticReadSql.Integrity_run_rows, ct, hours)).FirstOrDefault();
        var audits = (await session.QueryAsync(SemanticReadSql.Integrity_audit_rows, ct, hours)).FirstOrDefault();
        var items = new JsonArray(); var counts = new Dictionary<string, long>();
        foreach (var row in states)
        {
            long? age = row.Text("last_successful_collection_utc") is { } stamp ? Math.Max(0, (long)(DateTimeOffset.UtcNow - SemanticQuery.Time(stamp, "UTC", "collection_time_invalid")).TotalMinutes) : null;
            string status, reason, last = row.Text("last_status") ?? "not_observed";
            if (age is null or >= 120) { status = "unavailable"; reason = "successful_collection_not_recent"; }
            else if (!row.Flag("backfill_completed")) { status = "partial"; reason = "backfill_not_completed"; }
            else if (last is "failed" or "error" or "timeout" or "partial_timeout") { status = "partial"; reason = "latest_run_" + last; }
            else if (age >= 30) { status = "partial"; reason = "successful_collection_outside_attention_budget"; }
            else { status = "complete"; reason = "successful_collection_inside_attention_budget"; }
            counts[status] = counts.GetValueOrDefault(status) + 1;
            items.Add(new JsonObject { ["server"] = row.Text("server_hostname") ?? "", ["channel"] = row.Text("channel") ?? "", ["status"] = status, ["reason"] = reason, ["last_status"] = last, ["collection_age_minutes"] = age, ["backfill_completed"] = row.Flag("backfill_completed") });
        }
        long actionable = audits.Number("actionable_rollbacks"), inserted = runs.Number("inserted"), skipped = runs.Number("skipped");
        var cursor = new JsonObject(); foreach (string key in new[] { "audits", "committed", "no_change", "rejected_rollbacks", "stale_empty_proposals", "actionable_rollbacks" }) cursor[key] = audits.Number(key);
        cursor["reset_or_rollover_classification"] = actionable > 0 ? "unclassified" : "not_observed";
        return new JsonObject { ["state"] = counts.GetValueOrDefault("unavailable") > 0 || actionable > 0 ? "attention_required" : counts.GetValueOrDefault("partial") > 0 ? "partial" : "observed_complete", ["window_hours"] = hours,
            ["channels"] = new JsonObject { ["total"] = items.Count, ["by_status"] = new JsonObject(counts.Select(x => KeyValuePair.Create<string, JsonNode?>(x.Key, JsonValue.Create(x.Value)))), ["items"] = items }, ["cursor_integrity"] = cursor,
            ["run_integrity"] = new JsonObject { ["runs"] = runs.Number("runs"), ["noncomplete_runs"] = runs.Number("noncomplete_runs"), ["inserted"] = inserted, ["replay_skipped"] = skipped, ["replay_skip_percent"] = Math.Round(100.0 * skipped / Math.Max(1, inserted + skipped), 4) },
            ["gap_detection"] = new JsonObject { ["state"] = actionable > 0 ? "uncertain" : "bounded_metadata_only", ["remote_sequence_scan_performed"] = false, ["reason"] = actionable > 0 ? "actionable cursor rollback requires reset/rollover investigation" : "local metadata shows no actionable rollback but cannot prove remote record continuity" }, ["surveyed_servers_contacted"] = false, ["payload_read"] = false };
    }
}
