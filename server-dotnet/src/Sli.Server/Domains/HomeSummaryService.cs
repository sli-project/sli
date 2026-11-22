using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Gpo;
using static Sli.Server.Domains.HomeJson;

namespace Sli.Server.Domains;

public sealed class HomeSummaryService(IHomeSummaryAccess access, IDomainRepository domains, HomeSummaryReaders reads,
    IGpoReadStore? gpo = null, IConfiguration? configuration = null)
{
    public async Task<JsonObject> BuildAsync(Principal principal, HomeSummaryQuery query, CancellationToken ct)
    {
        var reports = await access.LoadAsync(principal, ct);
        // v3 resolves its selector against queue grants, never against the workspace union.
        var queue = reports.FirstOrDefault(r => r.Key == "security.problems");
        var domainGrants = reports.Where(r => r.Registered && r.Rule.Scope == "domain" && r.Available()).Select(r => r.Grant).ToArray();
        var permitted = query.Contract == "v3" ? queue?.Grant ?? DomainGrant.None
            : domainGrants.Any(g => g.Kind == DomainGrantKind.All) ? DomainGrant.All : DomainGrant.Scoped(domainGrants.SelectMany(g => g.DomainIds));
        if (query.Contract == "v3" && permitted.Kind == DomainGrantKind.None)
            return await new HomeDecisionSummary(reads).Build(null, [], principal, query, ct);
        if (query.Domain is { } domain)
        {
            if (permitted.Kind == DomainGrantKind.None || permitted.Kind == DomainGrantKind.Scoped && !permitted.DomainIds.Contains(domain))
                throw new HomeQueryException("domain_scope_denied", 403);
            if (query.Contract != "v4") permitted = DomainGrant.Scoped([domain]);
        }
        var selected = await domains.ReadAsync(permitted, ct);
        if (query.Domain is { } selectedId && !selected.Any(d => d.Id == selectedId)) throw new HomeQueryException("domain_scope_denied", 403);
        if (query.Contract == "v3") return await new HomeDecisionSummary(reads).Build(queue, selected, principal, query, ct);
        if (query.Contract == "v4") return await new HomePeriodSummary(reads, gpo, configuration).Build(reports, selected, query, ct);
        var payload = await Build(reports, selected, query, ct);
        payload["domain_scope"] = Object(new { mode = query.Domain.HasValue ? "domain" : "accessible", domain_id = query.Domain,
            domain_ids = selected.Select(d => d.Id), state = selected.Count > 0 ? "available" : "no_domains" });
        var domainRows = new JsonArray();
        foreach (var item in selected)
        {
            var summary = selected.Count == 1 ? payload : await Build(reports, [item], query with { Domain = item.Id }, ct);
            var embedded = new JsonObject();
            foreach (var key in new[] { "metrics", "kpis", "freshness", "readers", "problems_found", "observation_health" })
                if (summary.ContainsKey(key)) embedded[key] = summary[key].Copy();
            var row = Object(item); row["summary"] = embedded; domainRows.Add(row);
        }
        payload["domains"] = domainRows;
        return payload;
    }

    private static bool Readable(string? state) => state is "ok" or "partial" or "stale" or "processing";
    private static JsonObject Scope(long[] ids, string mode = "restricted") => Object(new { mode, domain_ids = ids });
    private async Task<JsonObject> Safe(Func<Task<JsonObject>> reader, CancellationToken ct)
    {
        try { ct.ThrowIfCancellationRequested(); return await reader(); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (UnauthorizedAccessException) { return HomeSummaryReaders.Result("denied"); }
        catch (Exception e) when (e is OperationCanceledException or TimeoutException || e is Npgsql.PostgresException { SqlState: "57014" })
        { return HomeSummaryReaders.Result("error", reason: "read_timeout"); }
        catch { return HomeSummaryReaders.Result("error", reason: "reader_failed"); }
    }

    private async Task<JsonObject> Build(IReadOnlyList<HomeReport> catalog, IReadOnlyList<DomainItem> selected,
        HomeSummaryQuery query, CancellationToken ct)
    {
        bool v2 = query.Contract == "v2";
        var reports = new JsonArray(); var freshness = new JsonArray(); var readers = new JsonArray();
        var deviations = new List<JsonObject>(); var attention = new List<JsonObject>(); var metrics = new JsonArray(); var kpis = new JsonArray();
        var measured = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
        string queueState = "denied"; long? decisionCount = null; bool hasMore = false;
        var queueItems = new JsonArray();
        foreach (var report in catalog.Where(r => r.Registered && r.Order.HasValue).OrderBy(r => r.Order).ThenBy(r => r.Key, StringComparer.Ordinal))
        {
            var filters = query.Contract == "v1" && query.Domain is null ? new Dictionary<string, object?>() : query.Filters(report.Key);
            var href = HomeSummaryQuery.Href(report.Key, filters);
            reports.Add(Object(new { key = report.Key, title = report.Title, href = HomeSummaryQuery.Href(report.Key) }));
            if (report.Key is not ("security.problems" or "ad.infrastructure" or "ad.computers.v6")) continue;
            reports[^1]!["href"] = href;
            var ids = report.Intersect(selected.Where(d => query.Domain.HasValue || !d.IsArchived || report.Key == "security.problems"));
            var data = HomeSummaryReaders.Result("denied");
            if (ids is { Length: > 0 } && report.Available())
            {
                data = report.RequiresDomain && query.Domain is null ? HomeSummaryReaders.Result("not_collected", reason: "domain_required")
                    : await Safe(() => report.Reader is not null ? report.Reader(reads, ids, query, ct) : report.Key switch
                {
                    "security.problems" => reads.Problems(ids, query, ct, report.Fields(ids, "identity_basic"), report.Fields(ids, "technical")), "ad.infrastructure" => reads.Directory(ids, query, ct),
                    _ => new HomeComputerReader(reads).Read(ids, query, ct)
                }, ct);
                data["scope"] = Scope(ids);
                ProjectMetrics(report, data, ids);
            }
            measured[report.Key] = data;
            var state = data.Text("state")!;
            var coverage = data["coverage"];
            var fresh = Object(new { key = report.Key, title = report.Title, href, state, reason = data.Text("reason") ?? data["state_details"].Text("reason"),
                last_successful_check_utc = coverage.Text("last_successful_check_utc") ?? coverage.Text("last_successful_collection_utc"),
                observed_at_utc = coverage.Text("observed_at_utc"), event_at_utc = coverage.Text("event_at_utc"),
                snapshot_at_utc = coverage.Text("snapshot_at_utc"), published_at_utc = coverage.Text("published_at_utc"),
                state_details = data["state_details"].Copy(), limitation = data.Text("limitation")
                    ?? (data["limitations"] as JsonArray)?.FirstOrDefault(n => !string.IsNullOrEmpty(n.Text("text"))).Text("text") });
            freshness.Add(fresh);
            if (v2)
            {
                var reader = fresh.DeepClone().AsObject(); reader["period_kind"] = report.Key == "security.problems" && query.Period is not null ? "observations" : "snapshot";
                reader["scope"] = data["scope"].Copy(); reader["message_code"] = "home.state." + state; readers.Add(reader);
                AddAttention(attention, report, data, filters, ids, query);
            }
            metrics.Add(new JsonObject { ["report_key"] = report.Key, ["state"] = state, ["items"] = data["metrics"].Copy() });
            if (Readable(state))
            {
                foreach (var metric in (data["metrics"] as JsonArray ?? []).OfType<JsonObject>().Where(m => m.Text("tone") is "danger" or "warning" && m.Number("value") > 0))
                {
                    var link = new Dictionary<string, object?>(filters);
                    if (metric["filter"] is JsonObject f) foreach (var p in f) link[p.Key] = p.Value?.ToString();
                    deviations.Add(Object(new { report_key = report.Key, key = metric.Text("key"), report_title = report.Title,
                        label = metric.Text("label"), value = metric.Number("value"), tone = metric.Text("tone"), href = HomeSummaryQuery.Href(report.Key, link) }));
                }
            }
            if (report.Key == "security.problems")
            {
                queueState = state;
                if (Readable(state) || state == "empty")
                {
                    var countMetric = (data["metrics"] as JsonArray)?.FirstOrDefault(m => m.Text("key") == "attention");
                    decisionCount = countMetric?["value"] is null ? null : countMetric.Number("value");
                }
                var activeRows = state is "ok" or "partial" or "stale" ? (data["items"] as JsonArray ?? []).OfType<JsonObject>()
                    .Where(row => row.Text("status") is "new" or "confirmed" or "repeated" or "active" or "review").ToArray() : [];
                hasMore = data.Boolean("has_more") == true || activeRows.Length > 5;
                foreach (var row in activeRows.Take(5))
                {
                    var view = HomePresentation.Finding(row, query.Language, report.Fields(ids, "identity_basic"), report.Fields(ids, "technical"));
                    queueItems.Add(new JsonObject { ["id"] = row["id"].Copy(), ["title"] = view["title"].Copy(), ["severity"] = row["severity"].Copy(),
                        ["assigned_to"] = ids is not null && report.Fields(ids, "identity_basic") ? row["assigned_to"].Copy() : null,
                        ["href"] = HomeSummaryQuery.Href(report.Key, new Dictionary<string, object?>(filters) { ["status"] = row.Text("status"), ["severity"] = row.Text("severity") ?? "" }) });
                }
            }
        }
        if (v2)
        {
            foreach (var (report, entry) in catalog.Where(r => r.Registered).SelectMany(r => r.Contributions.Select(e => (Report: r, Entry: e)))
                .OrderBy(p => p.Entry.Order).ThenBy(p => p.Entry.Key, StringComparer.Ordinal))
            {
                var reportKey = report.Key;
                var periodKind = entry.PeriodKind;
                var ids = report.Intersect(selected.Where(d => query.Domain.HasValue || !d.IsArchived));
                var data = HomeSummaryReaders.Result("denied");
                if (ids is { Length: > 0 } && report.Available() && report.Fields(ids, entry.RequiredFields.ToArray()))
                {
                    if (periodKind == "observations" && !query.WindowComplete)
                        data = HomeSummaryReaders.Result("partial", reason: "home_window_incomplete");
                    else if (entry.Reader is null && measured.TryGetValue(reportKey, out var snapshot)) data = snapshot;
                    else
                    {
                        data = await Safe(async () =>
                        {
                            if (entry.Availability is not null && entry.Availability() is var availability && availability != "enabled")
                                return HomeSummaryReaders.Result(availability == "disabled" ? "not_collected" : "error",
                                    reason: availability == "disabled" ? "plugin_disabled" : "plugin_state_unknown");
                            if (report.RequiresDomain && query.Domain is null) return HomeSummaryReaders.Result("not_collected", reason: "domain_required");
                            if (entry.Key == "vpn_closed" && query.Domain is not null
                                && report.Capabilities?.DecideForResourceGroups("vpn.sessions.view", [[new AccessResource("domain", query.Domain.Value)]]).Allowed != true)
                                return HomeSummaryReaders.Result("denied");
                            var reader = entry.Reader ?? report.Reader;
                            return reader is null ? HomeSummaryReaders.Result("not_collected", reason: "reader_unavailable") : await reader(reads, ids, query, ct);
                        }, ct);
                        if (data.Text("state") != "denied") data["scope"] = Scope(ids, report.Rule.Scope == "delegated" ? "delegated" : "restricted");
                        ProjectMetrics(report, data, ids);
                    }
                }
                var filters = query.Filters(reportKey);
                if (periodKind == "observations" && query.WindowComplete)
                { filters["period"] = "custom"; filters["from"] = HomeWindow.Iso(query.Current.From); filters["to"] = HomeWindow.Iso(query.Current.To); }
                foreach (var filter in entry.Filters) filters[filter.Key] = filter.Value;
                var href = HomeSummaryQuery.Href(reportKey, filters);
                var kpi = Kpi(data, query, reportKey, entry, href);
                kpis.Add(kpi);
                if (entry.Reader is not null) readers.Add(new JsonObject { ["key"] = reportKey, ["contribution_key"] = entry.Key, ["title"] = report.Title,
                    ["href"] = href, ["state"] = data["state"].Copy(), ["reason"] = data["reason"].Copy(), ["observed_at_utc"] = kpi["observed_at_utc"].Copy(),
                    ["limitation"] = data.Text("limitation"), ["period_kind"] = periodKind, ["scope"] = kpi["scope"].Copy(), ["message_code"] = kpi["message_code"].Copy(), ["health"] = entry.Health });
                if (entry.Reader is not null && !reports.Any(r => r.Text("key") == reportKey))
                    reports.Add(Object(new { key = reportKey, title = report.Title, href }));
                if (entry.Attention is not null && (Readable(data.Text("state")) || data.Text("state") == "empty"))
                {
                    try { attention.AddRange(entry.Attention(data, href).ToArray()); }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                    catch { /* Optional presentation hooks cannot discard successful measurements. */ }
                }
            }
        }
        var pinned = new JsonArray();
        foreach (var report in catalog.Where(r => r.Decision.Allowed && r.Preference.Get("pinned").ValueKind == System.Text.Json.JsonValueKind.True)
            .OrderByDescending(r => r.Preference.Get("updated_at").ToString(), StringComparer.Ordinal).Take(8))
        {
            var href = report.Registered ? HomeSummaryQuery.Href(report.Key) : report.Definition.Get("definition_json").Object().Text("target_path", "/app/reports");
            if ((href.StartsWith("/report/", StringComparison.Ordinal) || href.StartsWith("/reports", StringComparison.Ordinal)) && !href.EndsWith(".html", StringComparison.Ordinal)) href = "/app" + href;
            pinned.Add(Object(new { key = report.Key, title = report.Title, href }));
        }
        var payload = new JsonObject { ["contract_id"] = "sli.home-summary.v1", ["freshness"] = freshness,
            ["deviations"] = Array(deviations.OrderBy(d => d.Text("tone") != "danger").ThenByDescending(d => d.Number("value"))
                .ThenBy(d => d.Text("report_key"), StringComparer.Ordinal).ThenBy(d => d.Text("key"), StringComparer.Ordinal).Take(5)),
            ["metrics"] = metrics, ["action_queue"] = new JsonObject { ["state"] = queueState, ["items"] = queueItems, ["has_more"] = hasMore },
            ["reports"] = reports, ["pinned"] = pinned };
        if (!v2) return payload;
        var relevant = readers.OfType<JsonObject>().Where(r => r.Text("state") != "denied" && r.Boolean("health") != false).ToArray();
        var health = new[] { "error", "not_collected", "processing", "stale", "partial" }.FirstOrDefault(s => relevant.Any(r => r.Text("state") == s))
            ?? (relevant.Length > 0 && relevant.All(r => r["observed_at_utc"] is not null) ? "ok" : "unknown");
        var attentionState = attention.Count > 0 && queueState is "empty" or "denied" ? queueState == "empty" && health == "ok" ? "ok" : "partial" : queueState;
        payload["contract_id"] = "sli.home-summary.v2"; payload["context"] = Object(query.Context(selected.Select(d => d.Id).ToArray()));
        payload["generated_at_utc"] = HomeSummaryQuery.Iso(query.Now); payload["readers"] = readers; payload["kpis"] = kpis;
        payload["observation_health"] = Object(new { state = health, message_code = "home.observation." + health });
        payload["problems_found"] = Object(new { state = queueState, count = decisionCount, message_code = decisionCount.HasValue ? "home.problems.known" : "home.problems.unknown",
            href = HomeSummaryQuery.Href("security.problems", new Dictionary<string, object?>(query.Filters("security.problems")) { ["population"] = "attention" }) });
        payload["action_queue"] = Object(new { state = attentionState, items = attention.OrderBy(i => i, AttentionComparer.Instance).Take(5), has_more = attention.Count > 5 || hasMore });
        return payload;
    }

    private static void ProjectMetrics(HomeReport report, JsonObject data, long[] ids)
    {
        if (data["metrics"] is not JsonArray metrics) return;
        for (var i = metrics.Count - 1; i >= 0; i--)
            if (report.MetricCategories.TryGetValue(metrics[i].Text("key") ?? "", out var fields) && !report.Fields(ids, fields.ToArray()))
                metrics.RemoveAt(i);
    }

    private static JsonObject Kpi(JsonObject data, HomeSummaryQuery query, string reportKey, HomeContribution entry, string href)
    {
        var kind = entry.PeriodKind;
        var metric = (data["metrics"] as JsonArray)?.FirstOrDefault(m => m.Text("key") == entry.MetricKey);
        var state = data.Text("state");
        var value = (Readable(state) || state == "empty") && (state != "partial" || data["scope"] is not null) ? metric?["value"].Copy() : null;
        if (!HomeTrends.Numeric(value, out _)) value = null;
        JsonObject Measurement(JsonNode? number, JsonNode? coverage, HomeWindow window) => new()
        {
            ["value"] = number.Copy(), ["scope"] = data["scope"].Copy(), ["time_zone"] = query.TimeZone,
            ["unit"] = entry.UnitCode, ["definition_version"] = entry.DefinitionVersion, ["coverage"] = coverage.Copy(),
            ["window"] = kind == "observations" && query.WindowComplete ? Object(window.Json()) : null
        };
        var comparison = HomeTrends.Compare(
            Measurement(value, data["comparison_coverage"] ?? data["coverage"], query.Current),
            Measurement(metric?["previous_value"], data["previous_coverage"], query.Previous),
            entry.Key == "attention" && entry.Meaning == "neutral" ? "lower_is_better" : entry.Meaning);
        return new JsonObject { ["key"] = entry.Key, ["report_key"] = reportKey, ["label_code"] = entry.LabelCode, ["unit_code"] = entry.UnitCode,
            ["value"] = value, ["state"] = state, ["message_code"] = data.Text("reason") switch { "plugin_disabled" => "home.plugin.disabled", "plugin_state_unknown" => "home.plugin.unknown",
                "home_window_incomplete" => "home.comparison.incomplete", _ => "home.state." + state },
            ["href"] = value is null ? null : href, ["period_kind"] = kind, ["window"] = kind == "observations" && query.WindowComplete ? Object(query.Current.Json()) : null,
            ["scope"] = state == "denied" ? null : data["scope"].Copy(), ["observed_at_utc"] = state == "denied" ? null : data["coverage"]?["observed_at_utc"].Copy(),
            ["definition_version"] = entry.DefinitionVersion, ["comparison"] = comparison };
    }

    private static void AddAttention(List<JsonObject> items, HomeReport report, JsonObject data, Dictionary<string, object?> filters, long[]? ids, HomeSummaryQuery query)
    {
        var state = data.Text("state");
        if (report.Key == "security.problems" && Readable(state))
            foreach (var row in (data["items"] as JsonArray ?? []).OfType<JsonObject>().Where(r => r.Text("status") is "new" or "confirmed" or "repeated"))
            {
                var view = HomePresentation.Finding(row, query.Language, ids is not null && report.Fields(ids, "identity_basic"), ids is not null && report.Fields(ids, "technical"));
                var identity = ids is not null && report.Fields(ids, "identity_basic");
                var obj = identity ? row.Text("target") : null;
                items.Add(new JsonObject { ["id"] = "problem:" + row.Number("id"), ["problem_id"] = row.Number("id"), ["kind"] = "problem",
                    ["priority_group"] = row.Text("severity") is "critical" or "high" ? 0 : 2, ["severity"] = row["severity"].Copy(),
                    ["needs_decision"] = true, ["repeat_count"] = row.Number("repeat_count"), ["repeated"] = row.Text("status") == "repeated" || row.Number("repeat_count") > 0,
                    ["observed_at_utc"] = row["last_seen_utc"].Copy(), ["title"] = view["title"].Copy(), ["what"] = view["what"].Copy(),
                    ["object"] = obj, ["why"] = view["why"].Copy(), ["next_step"] = view["next_step"].Copy(),
                    ["presentation_code"] = view["presentation_code"].Copy(), ["message_code"] = "home.attention.problem", ["title_code"] = view["title_code"].Copy(),
                    ["what_code"] = view["what_code"].Copy(), ["why_code"] = view["why_code"].Copy(), ["next_step_code"] = view["next_step_code"].Copy(),
                    ["object_code"] = obj is null ? "home.attention.object_unknown" : null,
                    ["href"] = HomeSummaryQuery.Href(report.Key, new Dictionary<string, object?>(filters) { ["id"] = row.Number("id") }) });
            }
        var unconfirmed = report.Key == "security.problems" && data["coverage"].Text("state") is "inactive" or "unknown";
        var broken = state == "partial" && (unconfirmed || new[] { "missing_sources", "missing_domains", "failed", "partial" }.Any(k => data["coverage"]?[k] is JsonArray a && a.Count > 0));
        if ((state is "not_collected" or "processing" or "stale" || broken) && data.Text("reason") != "domain_required")
        {
            var code = unconfirmed ? "home.attention.analysis_unconfirmed" : "home.attention." + state;
            items.Add(new JsonObject { ["id"] = "observation:" + report.Key, ["kind"] = "observation", ["priority_group"] = 1, ["severity"] = null,
                ["needs_decision"] = false, ["repeat_count"] = 0, ["observed_at_utc"] = data["coverage"]?["observed_at_utc"].Copy(), ["message_code"] = code,
                ["object"] = Object(new { report_key = report.Key }), ["what_code"] = code, ["why_code"] = "home.attention.observation_why",
                ["next_step_code"] = "home.attention.observation_next", ["href"] = HomeSummaryQuery.Href(report.Key, filters) });
        }
        if (report.Key == "ad.infrastructure" && Readable(state))
            foreach (var row in (data["items"] as JsonArray ?? []).OfType<JsonObject>().Where(r => r.Text("qualification") == "failed"))
                items.Add(new JsonObject { ["id"] = "ad-check:" + row.Text("row_id"), ["kind"] = "ad_check", ["priority_group"] = 3, ["severity"] = row["severity"].Copy(),
                    ["needs_decision"] = false, ["repeat_count"] = 0, ["observed_at_utc"] = row["observed_at_utc"].Copy(), ["title"] = row["label"].Copy(),
                    ["object"] = ids is not null && report.Fields(ids, "identity_basic") ? row["entity_name"].Copy() : null,
                    ["what"] = row["actual_text"].Copy(), ["why"] = row["basis"].Copy(), ["next_step"] = row["expected_condition"].Copy(),
                    ["title_code"] = "reports.v2.ad.infrastructure.controls." + row.Text("control_id") + ".label", ["next_step_code"] = "home.attention.ad_next",
                    ["message_code"] = "home.attention.ad_check", ["href"] = HomeSummaryQuery.Href(report.Key, new Dictionary<string, object?>(filters) { ["row_id"] = row.Text("row_id") }) });
    }

    private sealed class AttentionComparer : IComparer<JsonObject>
    {
        internal static AttentionComparer Instance { get; } = new();
        public int Compare(JsonObject? x, JsonObject? y)
        {
            if (x is null || y is null) return 0;
            int Severity(JsonObject i) => i.Text("severity") switch { "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4 };
            foreach (var (a, b) in new[] { (x.Number("priority_group"), y.Number("priority_group")), (Severity(x), Severity(y)),
                (x.Boolean("needs_decision") == true ? 0 : 1, y.Boolean("needs_decision") == true ? 0 : 1),
                (x.Boolean("repeated") == true ? 0 : 1, y.Boolean("repeated") == true ? 0 : 1), (-x.Number("repeat_count"), -y.Number("repeat_count")) })
                if (a != b) return a.CompareTo(b);
            var at = x.Stamp("observed_at_utc") ?? DateTimeOffset.MinValue; var bt = y.Stamp("observed_at_utc") ?? DateTimeOffset.MinValue;
            if (at != bt) return bt.CompareTo(at);
            return x["problem_id"] is not null && y["problem_id"] is not null ? y.Number("problem_id").CompareTo(x.Number("problem_id"))
                : StringComparer.Ordinal.Compare(x.Text("id"), y.Text("id"));
        }
    }
}
