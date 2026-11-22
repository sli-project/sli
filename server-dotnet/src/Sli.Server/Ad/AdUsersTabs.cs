using System.Text.Json.Nodes;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

// Legacy slices remain internal to the inventory reader.
internal static class AdUsersTabs
{
    internal static readonly string[] Tabs = ["all", "active", "disabled", "privileged", "risk", "semantic"];
    static readonly HashSet<string> RiskKeys = ["password_not_required", "kerberos_no_preauth", "spn_privileged", "spn_old_password", "privileged_password_never_expires", "password_age", "inactive_threshold", "sensitive_uac_flag"];
    internal static bool IsRisk(JsonObject row) => row["reason_keys"]!.AsArray().Any(k => RiskKeys.Contains(k!.ToString()));
    internal static string SemanticState(JsonObject? heartbeat, DateTimeOffset? now = null)
    {
        string? mode = heartbeat?["details_json"].Text("runtime_mode");
        if (mode is not ("facts-v1" or "investigation-v1" or "findings-v1")) return "unknown";
        if (mode != "findings-v1") return "inactive";
        long expected = Math.Max(1, heartbeat.Int("expected_interval_seconds") is > 0 and var interval ? interval : 30);
        if (AdInventoryRows.Date(heartbeat?["heartbeat_at"]) is not {} at || Math.Max(0, ((now ?? DateTimeOffset.UtcNow) - at).TotalSeconds) > Math.Max(60, expected * 2 + 30)) return "stale";
        return heartbeat.Text("status") is "running" or "idle" && AdInventoryRows.Bool(heartbeat?["details_json"]?["manual_runtime"]) == false ? "active" : "inactive";
    }
    internal static string State(string? state) => state switch
    {
        "observed" or "complete" or "completed" or "ok" => "ok",
        "failed" or "unavailable" or "error" => "error",
        "not_collected" => "not_collected", "processing" => "processing", "denied" => "denied", "stale" => "stale", _ => "partial"
    };
    static string DirectoryState(JsonObject source)
    {
        var metadata = source["snapshot"]?["metadata"];
        return State(metadata?["coverage"].Text("state")
            ?? (metadata?["sources"] as JsonArray ?? []).FirstOrDefault(s => s.Text("name") == "directory").Text("status")
            ?? metadata.Text("collection_status") ?? source.Text("source_state") ?? "not_collected");
    }
    internal static JsonArray DirectMemberships(JsonObject raw) => Array((raw["memberships"]?["direct"] as JsonArray ?? [])
        .Where(group => group.Text("id") is not null && group.Text("name") is not null)
        .Select(group => new { id = group.Text("id"), name = group.Text("name") }));

    internal static void SetPrivileges(JsonObject row, JsonObject raw, bool includePaths = true)
    {
        var grants = (raw["privilegedMemberships"] as JsonArray ?? []).OfType<JsonObject>()
            .Where(g => g.Text("relation") == "direct" && (g.Text("group") is not null || g.Int("group_id") > 0)).ToArray();
        var effective = (raw["memberships"]?["effective"] as JsonArray ?? []).OfType<JsonObject>()
            .Where(g => AdInventoryRows.Bool(g["watchGroup"]) == true).ToArray();
        var direct = grants.Select(g => g.Text("group") ?? g.Int("group_id").ToString())
            .Concat(effective.Where(g => g.Text("relation") is "direct" or "primary").Select(g => g.Text("name") ?? g.Text("id")))
            .Distinct(StringComparer.OrdinalIgnoreCase);
        row["privilege_basis"] = Array(direct);
        row["nested_privilege_groups"] = Array(effective.Where(g => g.Text("relation") == "nested").Select(g => g.Text("name")));
        if (!includePaths) return;
        var identifiedGrants = grants.Where(g => g.Int("group_id") > 0).ToArray();
        var targets = effective.Select(g => g.Text("id")).Concat(identifiedGrants.Select(g => "group:" + g.Int("group_id"))).ToHashSet();
        var paths = (raw["memberships"]?["paths"] as JsonArray ?? []).OfType<JsonObject>()
            .Where(p => targets.Contains(p.Text("groupId"))).Select(p => p.DeepClone().AsObject()).ToList();
        string? primary = raw["memberships"]?["primary"].Text("id");
        foreach (var path in paths)
            if (primary is not null && (path["nodes"] as JsonArray)?.Skip(1).FirstOrDefault().Text("id") == primary)
                path["first_relation"] = "primary";
        foreach (var grant in identifiedGrants)
        {
            string groupId = "group:" + grant.Int("group_id");
            if (paths.Any(p => p.Text("groupId") == groupId) || grant.Text("group") is not {} name) continue;
            paths.Add(Obj(new { groupId, relation = "direct", nodes = new[] {
                new { id = raw.Text("id"), name = raw.Text("samAccountName") },
                new { id = (string?)groupId, name = (string?)name }
            } }));
        }
        row["privilege_paths"] = Array(paths);
    }

    internal static JsonObject Query(AdV2Request request, List<JsonObject> sources, JsonObject policy,
        Func<IEnumerable<string>, bool> fields, JsonObject? exceptions = null,
        IReadOnlyDictionary<(long, string), JsonObject>? workplaces = null,
        IReadOnlyDictionary<long, long>? findings = null, string semanticState = "active")
    {
        var coverage = new JsonObject { ["domains"] = AdV2Store.Coverage(sources)["domains"]!.DeepClone() };
        if (!fields(request.Tab == "privileged" ? ["security", "privilege"] : ["security"])) return Result("denied");
        foreach (var source in sources)
            foreach (var (key, value) in source["snapshot"]?["metadata"]?["coverage"] as JsonObject ?? new())
                if (key is "missing_sources" or "missing_domains")
                {
                    if (coverage[key] is not JsonArray) coverage[key] = new JsonArray();
                    foreach (var item in value as JsonArray ?? [])
                        if (!coverage[key]!.AsArray().Any(n => JsonNode.DeepEquals(n, item))) coverage[key]!.AsArray().Add(item?.DeepClone());
                }
        var states = sources.Select(DirectoryState).ToArray();
        string state = new[] { "denied", "error", "processing", "stale", "partial", "not_collected" }.FirstOrDefault(states.Contains) ?? "ok";
        if (sources.Count == 0) state = "not_collected";
        if (!sources.Any(s => s["snapshot"] is not null)) return Result(state is "denied" or "not_collected" or "processing" or "error" ? state : "error");
        if (state == "not_collected" && states.Contains("ok")) state = "partial";
        coverage["state"] = state;
        if (state is "denied" or "error" or "not_collected") return Result(state);
        var limitations = new JsonArray();
        var rows = new List<JsonObject>(); var allRows = new List<JsonObject>(); var groups = new Dictionary<string, string>(); int unknown = 0;
        foreach (var source in sources.Where(s => s["snapshot"] is not null))
        {
            var snapshot = source["snapshot"]!; string observed = snapshot["metadata"].Text("observed_at")!;
            foreach (var group in fields(["privilege"]) ? snapshot["groups"] as JsonArray ?? [] : [])
                if (group.Text("id") is {} id) groups[id] = group.Text("name") ?? id;
            foreach (var node in snapshot["users"] as JsonArray ?? [])
            {
                var raw = (JsonObject)node!.DeepClone(); AdInventoryRows.RedactUser(raw, fields);
                var row = AdInventoryRows.User(raw, raw["sourceStates"]?["directory"].Text("observed_at") ?? observed, policy, exceptions);
                row["domain_id"] = raw["domainId"]?.DeepClone() ?? source["domain_id"]?.DeepClone();
                row["domain_name"] = raw["domainName"]?.DeepClone() ?? source["fqdn"]?.DeepClone();
                row["observed_at_utc"] = raw["sourceStates"]?["directory"]?["observed_at"]?.DeepClone() ?? JsonValue.Create(observed);
                if (fields(["privilege"]))
                {
                    bool historical = request.Params["as_of"] is not null;
                    SetPrivileges(row, raw, historical);
                    if (historical) row["direct_memberships"] = DirectMemberships(raw);
                    row["membership_paths"] = raw["memberships"]?["paths"]?.DeepClone();
                }
                if (fields(["security", "technical"])) row["last_workplace"] = workplaces?.GetValueOrDefault((source.Int("domain_id"), raw.Text("sid")?.ToLowerInvariant() ?? ""))?.DeepClone();
                if (request.QualifyNames)
                {
                    string name = row.Text("domain_name") ?? source.Int("domain_id").ToString();
                    row["account_display_name"] = row["display_name"]?.DeepClone();
                    row["display_name"] = name + "\\" + (row.Text("sam") ?? row.Text("display_name"));
                    if (row.Text("sam") is {} sam) row["sam"] = name + "\\" + sam;
                }
                if (request.Tab == "privileged")
                {
                    var effective = (raw["memberships"]?["effective"] as JsonArray ?? []).Where(g => AdInventoryRows.Bool(g?["watchGroup"]) == true).ToArray();
                    unknown += raw["privilegedMemberships"] is null ? 1 : 0;
                    foreach (var group in raw["privilegedMemberships"] as JsonArray ?? [])
                        if (group.Text("relation") == "direct" && group.Int("group_id") > 0) groups["group:" + group.Int("group_id")] = group.Text("group") ?? group.Int("group_id").ToString();
                    foreach (var group in effective) if (group.Text("id") is {} id) groups[id] = group.Text("name") ?? id;
                }
                if (request.Tab == "semantic")
                { row["finding_count"] = findings?.GetValueOrDefault(row.Int("entity_id")) ?? 0; row["queue_entity_id"] = row["entity_id"]?.DeepClone(); }
                if (request.Tab is "active" or "disabled") unknown += AdInventoryRows.Bool(raw["enabled"]) is null ? 1 : 0;
                // Unknown policy facts use the same search/filter scope, before the risk population predicate.
                if (request.Tab == "risk" && new[] { row.Text("password_age_policy"), row.Text("inactivity_policy") }.Contains("unknown")
                    && AdInventoryRows.Matches(request with { Tab = "all" }, raw, row, true)) unknown++;
                allRows.Add(row);
                if (AdInventoryRows.Matches(request, raw, row, true)
                    && (request.Tab != "privileged" || row["privilege_basis"]!.AsArray().Count + row["nested_privilege_groups"]!.AsArray().Count > 0)
                    && (request.Tab != "semantic" || row.Int("finding_count") > 0)) rows.Add(row);
            }
        }
        if (unknown > 0) Partial("unknown_accounts", $"Недостаточно данных для классификации: {unknown}.");
        if (request.Tab == "privileged" && sources.Any(s => s["snapshot"]?["metadata"]?["coverage"].Text("privilege_state") != "complete"))
            Partial("privilege_incomplete", "Полнота привилегированного членства не подтверждена; показаны известные прямые, основные и вложенные связи.");
        if (request.Tab == "semantic" && semanticState != "active")
        {
            if (semanticState == "stale" || state == "stale") state = "stale";
            Partial("semantic_incomplete", "Актуальность семантического анализа не подтверждена; ноль находок не означает отсутствие проблем.");
        }
        coverage["observed_at_utc"] = sources.Select(s => s["snapshot"]?["metadata"].Text("observed_at")).Where(s => s is not null).Order().FirstOrDefault();
        coverage["tab"] = request.Tab; coverage["population"] = allRows.Count; coverage["unknown_accounts"] = unknown;
        coverage["as_of"] = request.Tab == "privileged" ? request.Params["as_of"]?.DeepClone() : null;
        coverage["disabled_privileged"] = request.Tab == "privileged" ? JsonValue.Create(rows.Count(r => AdInventoryRows.Bool(r["enabled"]) == false)) : null;
        coverage["truncated"] = false;
        if (request.Tab == "all")
        {
            coverage["privileged_accounts"] = fields(["privilege", "security"]) ? JsonValue.Create(rows.Count(r =>
                r["privilege_basis"] is JsonArray { Count: > 0 } || r["nested_privilege_groups"] is JsonArray { Count: > 0 })) : null;
        }
        coverage["hygiene_policy"] = request.Tab == "risk" ? policy.DeepClone() : null;
        if (request.Tab == "risk")
        {
            coverage["risk_accounts"] = rows.Count;
            limitations.Add(Obj(new { code = "hygiene_policy", text = $"Пороги политики: пароль > {policy.Int("password_age")} дней; неактивность > {policy.Int("inactivity")} дней. lastLogonTimestamp — приблизительный реплицируемый атрибут; это не доказательство отсутствия входов." }));
        }
        var result = Result(state == "ok" && rows.Count == 0 ? "empty" : state);
        result["limitations"] = limitations;
        result["metrics"] = Array(new[] { Obj(new { key = "attention", label = "Подтверждённые причины проверки", value = rows.Count(r => r["reasons"] is JsonArray { Count: > 0 }) }), Obj(new { key = "information", label = "С ограничениями сведений", value = rows.Count(r => r["information_limitations"] is JsonArray { Count: > 0 }) }) });
        if (request.Tab == "risk") result["metrics"]!.AsArray().Add(Obj(new { key = "unknown", label = "Оценка по политике неизвестна", value = unknown }));
        foreach (string key in new[] { "department", "company", "ou" }) result["filter_options"]![key] = Array(allRows.Select(r => r.Text(key)).Where(v => v is not null).Distinct().Order(StringComparer.Ordinal).Select(v => new { value = v, label = v }));
        result["filter_options"]!["group"] = Array(groups.Select(g => new { value = g.Key, label = g.Value }));
        result["filter_options"]!["reason"] = Array(rows.SelectMany(r => r["reasons"]!.AsArray()).DistinctBy(r => r.Text("key")).OrderBy(r => r.Int("order")).Select(r => new { value = r.Text("key"), label = r.Text("label") }));
        AdV2Store.Page(result, request with { Sort = request.Sort ?? "name" }, rows);
        AdV2Result.Finish(result);
        return result;

        JsonObject Result(string value) => AdV2Store.Result(request.Key, value, coverage: coverage);
        void Partial(string code, string text) { if (state == "ok") state = "partial"; limitations.Add(Obj(new { code, text })); }
    }
}
