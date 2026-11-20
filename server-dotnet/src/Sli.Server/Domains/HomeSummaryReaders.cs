using System.Text.Json.Nodes;
using Sli.Server.Access;
using static Sli.Server.Domains.HomeJson;

namespace Sli.Server.Domains;

public sealed class HomeSummaryReaders(IHomeSummaryRepository repository, Sli.Server.Agents.Registry.AgentLinkHistory? links = null)
{
    internal Sli.Server.Agents.Registry.AgentLinkHistory? Links => links;
    // This reader is request-scoped. The aggregate home summary is followed by
    // per-domain summaries; reuse complete inventory reads for those subsets.
    private readonly List<(string Sql, string? Sections, long[] Ids, IReadOnlyList<JsonObject> Rows)> inventory = [];
    internal async Task<IReadOnlyList<JsonObject>> Read(string sql, CancellationToken ct, params (string Key, object? Value)[] values)
    {
        ct.ThrowIfCancellationRequested();
        var parameters = values.ToDictionary(v => v.Key, v => v.Value);
        bool reusable = sql == HomeSummarySql.Sections || sql == HomeSummarySql.Entities || sql == HomeComputerReader.Sources;
        if (!reusable || parameters.GetValueOrDefault("ids") is not long[] ids)
            return await repository.ReadAsync(sql, parameters, ct);
        string? sections = parameters.GetValueOrDefault("sections") as string;
        var cached = inventory.FirstOrDefault(c => c.Sql == sql && c.Sections == sections && ids.All(c.Ids.Contains));
        if (cached.Rows is not null)
            return cached.Rows.Where(r => ids.Contains(r.Number("domain_id"))).Select(r => r.DeepClone().AsObject()).ToArray();
        var rows = await repository.ReadAsync(sql, parameters, ct);
        // A truncated aggregate may have omitted every row of one domain.
        // Such a result cannot answer that domain's independent request.
        int limit = sections == "directory_accounts" ? 10001 : 5001;
        if (sql != HomeSummarySql.Entities || rows.Count < limit)
            inventory.Add((sql, sections, ids.ToArray(), rows.Select(r => r.DeepClone().AsObject()).ToArray()));
        return rows;
    }

    internal static string Runtime(JsonObject? heartbeat, DateTimeOffset now)
    {
        var details = heartbeat?["details_json"];
        var mode = details.Text("runtime_mode");
        if (mode is not ("facts-v1" or "investigation-v1" or "findings-v1")) return "unknown";
        if (mode != "findings-v1") return "inactive";
        var at = heartbeat.Stamp("heartbeat_at");
        if (at is null || (now - at.Value).TotalSeconds > Math.Max(60, Math.Max(1, heartbeat.Number("expected_interval_seconds") is 0 ? 30 : heartbeat.Number("expected_interval_seconds")) * 2 + 30)) return "stale";
        return Semantic.SemanticProduction.WorkerActive(heartbeat) && details.Boolean("manual_runtime") == false ? "active" : "inactive";
    }

    internal static JsonObject Metric(string key, string label, long? value, string? tone = null, object? filter = null) =>
        Object(new { key, label, value, tone = tone ?? "neutral", filter });
    internal static JsonObject Result(string state, IEnumerable<JsonObject>? items = null, IEnumerable<JsonObject>? metrics = null,
        JsonObject? coverage = null, string? reason = null)
    {
        coverage ??= new();
        var rows = (items ?? []).ToArray();
        var missingSources = coverage["missing_sources"]?.DeepClone() as JsonArray ?? new();
        var missingDomains = coverage["missing_domains"]?.DeepClone() as JsonArray ?? new();
        var issues = new JsonArray();
        foreach (var domain in (coverage["domains"] as JsonArray ?? []).OfType<JsonObject>())
        {
            var statuses = new[] { domain.Text("run_status"), domain.Text("section_status"), domain.Text("state") };
            if (statuses.Any(s => s is "failed" or "cancelled" or "error" or "unavailable" or "timeout" or "denied" or "partial" or "skipped" or "not_collected")
                || domain.ContainsKey("run_status") && domain["run_status"] is null)
            {
                var id = domain.Number("domain_id"); var section = domain.Text("section_name");
                if (!missingDomains.Any(d => d?.ToString() == id.ToString(System.Globalization.CultureInfo.InvariantCulture))) missingDomains.Add(id);
                if (section is not null && !missingSources.Any(s => s?.ToString() == section)) missingSources.Add(section);
                issues.Add(new JsonObject { ["source"] = id + (section is null ? "" : ":" + section), ["source_name"] = domain["domain_name"].Copy(),
                    ["reason"] = statuses.Contains("denied") ? "access_denied" : statuses.Any(s => s is "failed" or "cancelled" or "error" or "unavailable" or "timeout") ? "source_failed"
                        : statuses.Contains("partial") ? "source_partial" : "source_missing", ["since_utc"] = null });
            }
        }
        foreach (var (key, why) in new[] { ("failed", "source_failed"), ("partial", "source_partial"), ("missing", "source_missing"), ("stale", "snapshot_old") })
            foreach (var source in (coverage[key] as JsonArray ?? []).Select(s => s?.ToString()))
                if (!issues.Any(i => i.Text("source") == source)) issues.Add(Object(new { source, reason = why, since_utc = (string?)null }));
        foreach (var source in missingSources.Select(s => s?.ToString()))
            if (!issues.Any(i => i.Text("source") == source || i.Text("source")?.Split(':').LastOrDefault() == source))
                issues.Add(Object(new { source, reason = "source_missing", since_utc = (string?)null }));
        if (state is not ("denied" or "error" or "not_collected"))
        {
            state = coverage.Text("state") switch
            {
                "failed" or "error" or "unavailable" => "error", "not_collected" => rows.Length > 0 ? "partial" : "not_collected",
                "processing" => "processing", "stale" when state is "ok" or "empty" or "stale" => "stale",
                "partial" or "unknown" or "inactive" when state is "ok" or "empty" => "partial", _ => state
            };
            if (state is "ok" or "empty" && (missingSources.Count > 0 || missingDomains.Count > 0)) state = "partial";
        }
        var whyState = state switch { "ok" => "query_completed", "empty" => "query_completed_zero_rows", "denied" => "access_denied",
            "not_collected" => "collection_not_confirmed", "partial" => "coverage_incomplete", "processing" => "import_or_projection_pending",
            "stale" => "freshness_exceeded", _ => "source_or_storage_error" };
        var result = new JsonObject
        {
            ["state"] = state, ["items"] = Array(rows), ["metrics"] = Array(metrics ?? []),
            ["coverage"] = coverage, ["reason"] = reason
        };
        if (state != "denied" && reason is null) result["state_details"] = new JsonObject {
            ["reason"] = whyState, ["source"] = null, ["stage"] = "query", ["limitations"] = new JsonArray(),
            ["missing_sources"] = missingSources, ["missing_domains"] = missingDomains,
            ["observed_at_utc"] = coverage["observed_at_utc"].Copy(), ["stale_since_utc"] = null, ["source_issues"] = issues };
        return result;
    }

    internal static JsonObject Limitations(JsonObject result, params (string Code, string Text)[] notes)
    {
        result["limitation"] = notes.FirstOrDefault().Text;
        if (result["state_details"] is JsonObject details) details["limitations"] = Array(notes.Select(n => new { code = n.Code, text = n.Text }));
        return result;
    }

    internal async Task<JsonObject> Problems(long[] ids, HomeSummaryQuery query, CancellationToken ct, bool identity = true, bool technical = true)
    {
        var parameters = new Dictionary<string, object?> { ["ids"] = ids, ["from"] = query.Period?.From, ["to"] = query.Period?.To, ["all_statuses"] = query.Contract == "v1" };
        IReadOnlyList<JsonObject> rows = (await repository.ReadAsync(HomeSummarySql.Problems, parameters, ct)).Select(row => row.DeepClone().AsObject()).ToArray();
        foreach (var row in rows) {
            var view = HomePresentation.Finding(row, query.Language, identity, technical);
            foreach (var (field, presentation) in new[] { ("title", "title"), ("summary", "what"), ("why_it_matters", "why"), ("recommended_action", "next_step") })
                row[field] = view[presentation].Copy();
        }
        var counts = await repository.ReadAsync(HomeSummarySql.Counts, parameters, ct);
        var heartbeat = (await Read(HomeSummarySql.Heartbeat, ct)).FirstOrDefault();
        var runtime = Runtime(heartbeat, query.Now);
        var state = runtime == "stale" ? "stale" : runtime != "active" ? "partial" : rows.Count > 0 ? "ok" : "empty";
        if (ids.Length > 0)
        {
            var password = (await Read(HomeSummarySql.PasswordCoverage, ct, ("ids", ids))).FirstOrDefault()?["coverage"];
            bool incomplete = password.Text("availability") != "observed" || password.Boolean("has_more") == true
                || password?["rows"] is not JsonArray list || list.Count == 0 || list.Any(r => r.Text("policy_state") is "unknown" or "disabled_last_known"
                    || r?["frozen_episode_count"]?.ToString() != "0" || r.Text("policy_state") == "enabled" && r.Text("status") != "healthy");
            if (incomplete && state is "ok" or "empty") state = "partial";
        }
        long Count(params string[] statuses) => counts.Where(row => statuses.Contains(row.Text("status"))).Sum(row => row.Number("count"));
        var count = Count("new", "confirmed", "repeated");
        var progress = Count("active", "review"); var closed = Count("false_positive", "closed");
        var result = Result(state, rows.Take(5), [
            Metric("open", HomePresentation.Text("reports.v2.security.problems.metrics.open.label"), count + progress, count + progress > 0 ? "warning" : "neutral"),
            Metric("attention", HomePresentation.Text("reports.v2.security.problems.metrics.attention.label"), count, count > 0 ? "danger" : "neutral", new { population = "attention" }),
            Metric("progress", HomePresentation.Text("reports.v2.security.problems.metrics.progress.label"), progress, "accent", new { status = "active" }),
            Metric("closed", HomePresentation.Text("reports.v2.security.problems.metrics.closed.label"), closed, "success", new { status = "closed" })],
            new() { ["state"] = runtime, ["event_at_utc"] = rows.Select(r => r.Text("last_seen_utc")).Where(t => t is not null).OrderDescending().FirstOrDefault(),
                ["published_at_utc"] = rows.Select(r => r.Text("published_at_utc")).Where(t => t is not null).OrderDescending().FirstOrDefault(),
                ["worker_checked_at_utc"] = heartbeat?["heartbeat_at"].Copy() });
        result["has_more"] = rows.Count > 5;
        if (runtime == "stale") Limitations(result, ("problems_0", "Нет свежего подтверждения работы проверки; проблемы показаны по сохранённым данным, а полнота текущего состояния не подтверждена."));
        else if (runtime is "inactive" or "unknown") Limitations(result, ("problems_0", "Работа проверки сейчас не подтверждена; отсутствие новых результатов нельзя считать отсутствием проблем."));
        return result;
    }

    internal async Task<JsonObject> Directory(long[] ids, HomeSummaryQuery query, CancellationToken ct)
    {
        var sections = await Read(HomeSummarySql.Sections, ct, ("ids", ids), ("sections", "domain_posture,domain_health"));
        var rows = await Read(HomeSummarySql.Entities, ct, ("ids", ids), ("sections", "domain_posture,domain_health"));
        var coverage = SectionCoverage(sections, query.Now, false);
        var controls = HomeDirectoryControls.Build(rows.Take(5000), ids.Length > 1);
        long Count(string qualification) => controls.Count(c => c.Text("qualification") == qualification);
        var state = coverage.Text("state")!;
        if (rows.Count > 5000) state = "partial";
        if (state == "ok" && controls.Count == 0) state = "empty";
        return Limitations(Result(state, controls.OrderBy(c => c.Text("qualification") switch { "failed" => 0, "not_evaluated" => 1, "policy_not_defined" => 2, _ => 3 })
            .ThenBy(c => c.Text("entity_name"), StringComparer.Ordinal).ThenBy(c => c.Text("label"), StringComparer.Ordinal),
            new[] { ("failed", "Не пройдено", "danger"), ("not_evaluated", "Не оценено", "warning"),
                ("policy_not_defined", "Требование не задано", "neutral"), ("passed", "Пройдено", "success") }
                .Select(m => Metric(m.Item1, m.Item2, Count(m.Item1), Count(m.Item1) == 0 && m.Item1 is "failed" or "not_evaluated" ? "neutral" : m.Item3,
                    new { qualification = m.Item1 })), coverage), ("unknown_not_safe", "Отсутствующие и недоступные параметры не считаются безопасным нулём: «Не оценено» — не «Пройдено»."));
    }

    internal static JsonObject SectionCoverage(IReadOnlyList<JsonObject> sections, DateTimeOffset now, bool computers)
    {
        var missing = sections.Where(s => s.Stamp("observed_at_utc") is null).ToArray();
        var stale = sections.Where(s => s.Stamp("observed_at_utc") is not { } at || at < now.AddDays(-1)).ToArray();
        var failed = sections.Where(s => s.Text("run_status") is "failed" or "cancelled" || s.Text("section_status") == "failed").ToArray();
        var partial = sections.Where(s => s.Text("run_status") == "partial" || s.Text("section_status") == "partial").ToArray();
        var complete = sections.Count(s => s.Text("run_status") == "completed" && s.Text("section_status") == "complete");
        string state = computers
            ? sections.Count == 0 || complete + failed.Length + partial.Length == 0 ? "not_collected"
                : failed.Length == sections.Count ? "error" : complete == sections.Count ? stale.Length > 0 ? "stale" : "ok" : "partial"
            : sections.Count == 0 ? "not_collected" : failed.Length + partial.Length + missing.Length > 0 ? "partial" : stale.Length > 0 ? "stale" : "ok";
        string Source(JsonObject s) => s.Number("domain_id") + ":" + s.Text("section_name");
        return new() { ["state"] = state, ["domains"] = Array(sections), ["missing"] = Array(missing.Select(Source)),
            ["stale"] = Array(stale.Select(Source)), ["failed"] = Array(failed.Select(Source)), ["partial"] = Array(partial.Select(Source)),
            ["missing_sources"] = Array(missing.Concat(failed).Concat(partial).Select(Source)),
            ["observed_at_utc"] = sections.Select(s => s.Text("observed_at_utc")).Where(t => t is not null).Order().FirstOrDefault() };
    }

    internal async Task<JsonObject> Changes(long[] ids, HomeSummaryQuery query, CancellationToken ct)
    {
        if (!query.WindowComplete) return Result("partial", reason: "home_window_incomplete");
        var counts = (await Read(HomeSummarySql.Changes, ct, ("ids", ids), ("current", query.Current.From), ("before", query.Previous.From), ("end", query.Current.To))).FirstOrDefault();
        var history = await Read(HomeSummarySql.ChangeHistory, ct, ("ids", ids), ("end", query.Current.To));
        var observed = history.Select(h => h.Text("observed_at_utc")).Where(s => s is not null).Order().FirstOrDefault();
        var metric = Metric("privileged_changes", "", history.Count > 0 ? counts.Number("current_count") : null);
        metric["previous_value"] = null;
        if (history.Count > 0 && history.Select(h => h.Number("domain_id")).SequenceEqual(ids.Order()) && history.All(h => h.Stamp("history_from") < query.Previous.From))
            metric["previous_value"] = counts.Number("previous_count");
        var result = Result(history.Count > 0 ? "partial" : "not_collected", metrics: [metric], coverage: new()
        { ["observed_at_utc"] = observed, ["domain_ids"] = Array(history.Select(h => h.Number("domain_id"))),
            ["missing_domains"] = Array(ids.Except(history.Select(h => h.Number("domain_id")))) });
        result["comparison_coverage"] = Object(new { complete = false, domains = history.Select(h => h.Number("domain_id")), kind = "snapshot_observations" });
        result["previous_coverage"] = result["comparison_coverage"].Copy();
        return Limitations(result, ("snapshot_observations", "Изменения — наблюдения импортированной истории членства; время изменения в AD и непрерывное покрытие событий не подтверждены. Первоначальный состав не считается изменением."));
    }

    internal async Task<JsonObject> Vpn(long domain, HomeSummaryQuery query, CancellationToken ct)
    {
        if (!query.WindowComplete) return Result("partial", reason: "home_window_incomplete");
        var plugin = (await Read("select enabled from read_plugin_states_v1() where plugin_id='sli.remote-access'", ct)).FirstOrDefault();
        if (plugin.Boolean("enabled") != true) return Result(plugin.Boolean("enabled") == false ? "not_collected" : "error",
            reason: plugin.Boolean("enabled") == false ? "plugin_disabled" : "plugin_state_unknown");
        var coverage = (await Read(HomeSummarySql.VpnCoverage, ct, ("domain", domain))).FirstOrDefault();
        if (coverage.Number("total_delivery_count") == 0) return Result("not_collected");
        var pending = new[] { "queued_delivery_count", "leased_delivery_count", "failed_delivery_count" }.Sum(k => coverage.Number(k));
        var unresolved = new[] { "identity_unresolved_count", "timestamp_unresolved_count", "quarantined_delivery_count" }.Sum(k => coverage.Number(k));
        var state = pending > 0 ? "processing" : unresolved > 0 ? "partial" : "ok";
        var aggregate = (await Read(HomeSummarySql.VpnCounts, ct, ("domain", domain), ("current", query.Current.From),
            ("before", query.Previous.From), ("end", query.Current.To))).FirstOrDefault();
        var metric = Metric("closed", "", aggregate.Number("current_count"));
        metric["previous_value"] = null;
        if (coverage.Stamp("history_available_from_utc") <= query.Previous.From) metric["previous_value"] = aggregate.Number("previous_count");
        var result = Result(state, metrics: [metric], coverage: new() { ["observed_at_utc"] = coverage?["history_available_to_utc"].Copy() });
        JsonObject Fingerprint(HomeWindow window) => Object(new { domains = new[] { domain }, state = state == "ok" ? "available" : state,
            complete = state == "ok" && coverage.Stamp("history_available_from_utc") <= window.From
                && coverage.Stamp("history_available_to_utc") >= window.To });
        result["comparison_coverage"] = Fingerprint(query.Current);
        result["previous_coverage"] = Fingerprint(query.Previous);
        result["comparison_complete"] = result["comparison_coverage"].Boolean("complete") == true
            && result["previous_coverage"].Boolean("complete") == true;
        return result;
    }
}
