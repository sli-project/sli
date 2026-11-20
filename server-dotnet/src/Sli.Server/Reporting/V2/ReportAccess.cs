using System.Text.Json.Nodes;
using Sli.Server.Access;
namespace Sli.Server.Reporting.V2;

public sealed class ReportAccess
{
    private readonly ReportDefinition definition;
    private readonly AccessDecision access;
    private readonly string action;
    public ReportScope Scope { get; }
    public ReportAccess(ReportDefinition definition, AccessDecision access, string action = "view")
    {
        this.definition = definition; this.access = access; this.action = action;
        if (definition.ScopeKind == "delegated")
        {
            var report = access.Reports.FirstOrDefault(r => r.ReportKey == definition.AccessKey && r.Allowed);
            if (!definition.Rule.Flag("accepts_generic_scope") && report?.Grants.Any(g => g.Scope.ValueKind == System.Text.Json.JsonValueKind.Object && g.Scope.TryGetProperty("mode", out _)) == true)
                throw new ReportRequestException("report_scope_not_executable", 403);
            Scope = ReportScope.None;
        }
        else
        {
            Scope = Resolve(definition.Rule);
            if (definition.ScopeKind == "domain") Scope.DomainIds();
        }
    }
    private ReportScope Resolve(JsonObject rule)
    {
        var report = access.Reports.FirstOrDefault(r => r.ReportKey == rule.Text("report_key") && r.Allowed);
        var required = rule.Strings("required_fields");
        string role = rule.Text("required_role");
        if (role.Length > 0 && role != access.CoarseRole || report is null || !report.Grants.Any(g => g.AllowedActions.Contains(action))
            || !rule.Strings("required_capabilities").IsSubsetOf(access.Capabilities.Capabilities)
            || rule.Flag("global_scope_only") && rule.Strings("required_capabilities").Any(c => !access.Capabilities.Decide(c).Allowed))
            throw new ReportRequestException("report_access_denied", 403);
        var eligible = report.Grants.Where(g => g.AllowedActions.Contains(action) && required.IsSubsetOf(g.FieldCategories)).ToArray();
        if (eligible.Length == 0) throw new ReportRequestException("report_field_categories_not_allowed", 403);
        var scopes = eligible.Select(g => ReportScope.FromGrant(g.Scope)).ToArray();
        if (scopes.Any(s => s.Mode == "all")) return ReportScope.All;
        if (rule.Flag("global_scope_only")) throw new ReportRequestException("report_scope_not_executable", 403);
        var scope = ReportScope.Merge(scopes.SelectMany(s => s.Clauses));
        if (scope.Mode == "none") throw new ReportRequestException("report_scope_not_executable", 403);
        return scope;
    }
    internal ReportScope ResolveScope() => Resolve(definition.Rule);
    public bool FieldsAllowed(IEnumerable<string> fields)
    {
        var required = fields.ToHashSet(StringComparer.Ordinal);
        if (required.Count == 0) return true;
        required.UnionWith(definition.Rule.Strings("required_fields"));
        var rule = definition.Rule.Copy(); rule["required_fields"] = Strings(required);
        try { return Resolve(rule).Covers(definition.ScopeKind == "delegated" ? ReportScope.All : Scope); }
        catch (ReportRequestException e) when (e.Status == 403) { return false; }
    }
    private JsonObject RuleDecision(JsonObject? rule)
    {
        if (rule is null) return new() { ["allowed"] = true };
        rule = rule.Copy();
        var fields = rule.Strings("required_fields");
        if (rule.Text("report_key") == definition.AccessKey) fields.UnionWith(definition.Rule.Strings("required_fields"));
        rule["required_fields"] = Strings(fields);
        try
        {
            if (!Resolve(rule).Covers(definition.ScopeKind == "delegated" ? ReportScope.All : Scope)) throw new ReportRequestException("report_scope_not_executable", 403);
            return new() { ["allowed"] = true };
        }
        catch (ReportRequestException e) when (e.Status == 403)
        {
            if (rule.Text("report_key") == definition.AccessKey) fields.ExceptWith(definition.Rule.Strings("required_fields"));
            return new() { ["allowed"] = false, ["reason"] = e.Message, ["hidden_categories"] = Strings(e.Message == "report_field_categories_not_allowed" ? fields : []) };
        }
    }
    public void Validate(IQueryCollection query, string? tab, string? sort, bool detail)
    {
        foreach (var param in definition.Params)
            if (query[param.Text("key")].Count > 0 && !FieldsAllowed(param.Strings("field_categories"))) throw new ReportRequestException("report_field_categories_not_allowed", 403);
        foreach (var column in definition.Columns)
            if (sort == column.Text("key") && !FieldsAllowed(column.Strings("field_categories"))) throw new ReportRequestException("report_field_categories_not_allowed", 403);
        tab = string.IsNullOrEmpty(tab) ? definition.Views.FirstOrDefault()?.Text("key") : tab;
        var view = definition.Views.FirstOrDefault(v => v.Text("key") == tab);
        var rules = new List<JsonObject?> { view?["access_rule"] as JsonObject };
        if (detail) rules.Add(definition.Detail?["access_rule"] as JsonObject);
        foreach (var rule in rules)
        {
            var decision = RuleDecision(rule);
            if (!decision.Flag("allowed")) throw new ReportRequestException(decision.Text("reason"), 403);
        }
    }
    public ReportDefinition VisibleDefinition()
    {
        var json = definition.Declaration.Copy();
        json["params"] = new JsonArray(definition.Params.Where(p => FieldsAllowed(p.Strings("field_categories"))).Select(p => (JsonNode?)p.DeepClone()).ToArray());
        return new(json);
    }
    public JsonObject Declaration()
    {
        var payload = VisibleDefinition().Declaration;
        payload["access"] = Summary();
        JsonArray Columns(IEnumerable<JsonObject> columns) => new(columns.Where(c => FieldsAllowed(c.Strings("field_categories"))).Select(c => (JsonNode?)c.DeepClone()).ToArray());
        payload["columns"] = Columns(definition.Columns);
        foreach (var param in payload.Objects("params"))
        {
            param.Remove("field_categories");
            if (param.Text("kind") != "text" || param["max_length"]?.GetValue<int>() == 256) param.Remove("max_length");
        }
        var visibleParams = payload.Objects("params").Select(p => p.Text("key")).ToHashSet(StringComparer.Ordinal);
        payload["presets"] = new JsonArray(payload.Objects("presets").Where(p => (p["params"] as JsonObject ?? []).All(v => visibleParams.Contains(v.Key))).Select(p => (JsonNode?)p.DeepClone()).ToArray());
        foreach (var view in payload.Objects("views"))
        {
            view["access"] = RuleDecision(view["access_rule"] as JsonObject);
            if (view.ContainsKey("columns")) view["columns"] = Columns(view.Objects("columns"));
        }
        if (payload["detail"] is JsonObject detail)
        {
            detail["access"] = RuleDecision(detail["access_rule"] as JsonObject);
            detail["columns"] = Columns(detail.Objects("columns"));
        }
        return payload;
    }
    public ReportScope Restrict(JsonObject parameters)
    {
        var clause = new JsonObject();
        foreach (var (key, dimension) in new[] { ("plugin_id", "plugin_ids"), ("source_instance_id", "source_instance_ids"), ("device_id", "device_ids"), ("entity_id", "entity_ids") })
        {
            if (key == "entity_id" && definition.ScopeKind == "domain") continue;
            if (parameters[key] is { } value) clause[dimension] = value is JsonArray ? value.DeepClone() : new JsonArray(value.DeepClone());
        }
        if (parameters["domain"] is { } domain) clause["collection_scope_ids"] = new JsonArray("ad-domain:" + domain);
        if (clause.Count > 0 && ReportScopeResolver.ParseScope(System.Text.Json.JsonSerializer.SerializeToElement(new { mode = "restricted", clauses = new[] { clause } })).Invalid)
            throw new ReportRequestException("invalid_scope_dimension");
        var scope = clause.Count > 0 ? Scope.Intersect(new("restricted", [clause])) : Scope;
        if (scope.Mode == "none" && definition.ScopeKind != "delegated") throw new ReportRequestException("report_scope_not_executable", 403);
        return scope;
    }
    public JsonObject Summary()
    {
        var dependencies = definition.Columns.Concat(definition.Params).Concat(definition.Views.SelectMany(v => v.Objects("columns")))
            .Concat(definition.Detail?.Objects("columns") ?? []).Select(c => c.Strings("field_categories")).ToList();
        foreach (string key in new[] { "metric_categories", "row_categories", "series_categories" })
            dependencies.AddRange((definition.Declaration[key] as JsonObject ?? []).Select(p => ((JsonArray)p.Value!).Select(n => n!.GetValue<string>()).ToHashSet()));
        var denied = dependencies.Where(d => !FieldsAllowed(d)).ToArray();
        var hidden = denied.SelectMany(d => d).Where(c => !FieldsAllowed([c])).ToHashSet();
        if (hidden.Count == 0) hidden.UnionWith(denied.SelectMany(d => d));
        return new() { ["allowed"] = true, ["hidden_categories"] = Strings(hidden), ["reason"] = hidden.Count > 0 ? "report_field_categories_not_allowed" : null };
    }
    private static JsonArray Strings(IEnumerable<string> values) => new(values.Order(StringComparer.Ordinal).Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
    private IEnumerable<string> Categories(string map, string key) => ((definition.Declaration[map] as JsonObject)?[key] as JsonArray)?.Select(n => n!.GetValue<string>()) ?? [];
    private JsonArray Rows(JsonArray? rows, IEnumerable<JsonObject> columns, bool main = false)
    {
        var denied = columns.Where(c => !FieldsAllowed(c.Strings("field_categories"))).Select(c => c.Text("path", c.Text("key"))).ToHashSet();
        if (main)
            foreach (var path in definition.Declaration["row_categories"] as JsonObject ?? [])
                if (!FieldsAllowed(Categories("row_categories", path.Key))) denied.Add(path.Key);
        var copy = (JsonArray?)(rows?.DeepClone()) ?? [];
        foreach (var row in copy) foreach (string path in denied) ReportJson.Remove(row, path);
        return copy;
    }
    public JsonObject Project(JsonObject data, bool detail = false)
    {
        var payload = data.Copy();
        if (!ReportResult.States.Contains(payload.Text("state"))) payload = ReportResult.Create(definition.Key, "error", coverage: new() { ["reason"] = "report_state_unknown" });
        payload["access"] = Summary();
        if (payload.Text("state") == "denied")
        {
            string reason = payload.Text("reason");
            if (reason is not ("report_access_denied" or "report_field_categories_not_allowed" or "report_scope_not_executable")) reason = "report_access_denied";
            foreach (string key in new[] { "items", "metrics", "limitations" }) payload[key] = new JsonArray();
            foreach (string key in new[] { "series", "collections", "filter_options", "coverage", "window" }) payload[key] = new JsonObject();
            payload["reason"] = reason; payload["filtered_count"] = null; payload["has_more"] = false; payload["next_cursor"] = null;
            payload["state_details"] = new JsonObject { ["reason"] = reason, ["missing_sources"] = new JsonArray(), ["missing_domains"] = new JsonArray(), ["observed_at_utc"] = null, ["stale_since_utc"] = null };
            var summary = Summary(); summary["allowed"] = false; summary["reason"] = reason; payload["access"] = summary;
            return payload;
        }
        var columns = detail ? definition.Detail?.Objects("columns") ?? [] : definition.Columns.Concat(definition.Views.Where(v => v.Text("source") == "items").SelectMany(v => v.Objects("columns")));
        if (payload.ContainsKey("items")) payload["items"] = Rows(payload["items"] as JsonArray, columns, !detail);
        if (!detail && definition.Detail is { } drill && drill.Text("inline") is { Length: > 0 } inline)
            foreach (var row in payload["items"] as JsonArray ?? [])
            {
                if (!RuleDecision(drill["access_rule"] as JsonObject).Flag("allowed")) ReportJson.Remove(row, inline);
                else
                {
                    JsonNode? parent = row; var parts = inline.Split('.');
                    foreach (string part in parts[..^1]) parent = (parent as JsonObject)?[part];
                    if (parent is JsonObject obj && obj.ContainsKey(parts[^1])) obj[parts[^1]] = Rows(obj[parts[^1]] as JsonArray, drill.Objects("columns"));
                }
            }
        var visibleParams = definition.Params.Where(p => FieldsAllowed(p.Strings("field_categories"))).Select(p => p.Text("key")).ToHashSet();
        var visibleOptions = definition.Params.Where(p => visibleParams.Contains(p.Text("key"))).Select(p => p.Text("options_from", p.Text("key"))).ToHashSet();
        if (payload["filter_options"] is JsonObject options) foreach (string key in options.Select(p => p.Key).ToArray()) if (!visibleOptions.Contains(key)) options.Remove(key);
        if (payload["metrics"] is JsonArray metrics) payload["metrics"] = new JsonArray(metrics.OfType<JsonObject>().Where(m => FieldsAllowed(Categories("metric_categories", m.Text("key"))) && ((m["filter"] as JsonObject)?.Select(p => p.Key) ?? []).All(visibleParams.Contains)).Select(m => (JsonNode?)m.DeepClone()).ToArray());
        if (payload["series"] is JsonObject series) foreach (string key in series.Select(p => p.Key).ToArray()) if (!FieldsAllowed(Categories("series_categories", key))) series.Remove(key);
        if (payload["collections"] is JsonObject collections)
        {
            var projected = new JsonObject();
            foreach (var view in definition.Views)
                if (collections[view.Text("source")] is JsonArray rows && RuleDecision(view["access_rule"] as JsonObject).Flag("allowed")) projected[view.Text("source")] = Rows(rows, view.Objects("columns"));
            payload["collections"] = projected;
        }
        return payload;
    }
    internal JsonObject[] VisibleColumns => definition.Columns.Where(c => FieldsAllowed(c.Strings("field_categories"))).ToArray();
}
