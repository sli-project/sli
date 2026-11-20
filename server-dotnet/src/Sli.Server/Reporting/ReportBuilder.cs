using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static Sli.Server.Reporting.ReportJson;

namespace Sli.Server.Reporting;

public static class ReportBuilder
{
    internal static readonly string[] Executable = ["entities.v2", "ad.audit.snapshot", "events.v2", "security.problems", "ad.accounts.privileged", "ad.accounts.vpn", "ad.gpo.governance"];
    private static readonly string[] UnsafeKeys = ["sql", "raw_sql", "query", "expression", "where", "having", "join"];
    internal static bool Unsafe(JsonNode? node) => node switch
    {
        JsonObject obj => obj.Any(p => UnsafeKeys.Contains(p.Key.Trim().ToLowerInvariant()) || Unsafe(p.Value)),
        JsonArray list => list.Any(Unsafe), _ => false
    };
    public static JsonObject Preview(JsonObject payload, JsonObject dataset, IReadOnlySet<string> capabilities)
    {
        Require(capabilities.Contains("reports.design"), "reports_design_required", 403);
        Require(!Unsafe(payload), "arbitrary_sql_or_unsafe_definition_rejected");
        string key = dataset.Text("dataset_key");
        Require(dataset.Count > 0, "unknown_dataset");
        Require(Executable.Contains(key), "report_dataset_not_executable");
        var fields = dataset.Array("fields_json").OfType<JsonObject>().ToDictionary(f => f.Text("key"));
        var selected = payload.Strings("fields");
        Require(selected.Length > 0 && selected.All(fields.ContainsKey), "unknown_or_empty_field_selection");
        Require(payload["filters"] is null or JsonArray, "invalid_filter");
        Require(payload["sort"] is null or JsonArray, "invalid_sort");
        Require(payload["actions"] is null or JsonArray, "unknown_action");
        var filters = payload.Array("filters");
        var knownFilters = dataset.Array("filters_json").OfType<JsonObject>().ToDictionary(f => f.Text("key"), f => f.Strings("ops"));
        foreach (var raw in filters)
        {
            Require(raw is JsonObject, "invalid_filter");
            string field = raw.Text("field"), op = raw.Text("op");
            Require(knownFilters.TryGetValue(field, out var ops) && ops.Contains(op), "unknown_filter_or_operator");
            Require(FilterExpression(key, field) is not null, "report_filter_not_executable");
            _ = FilterValue(key, field, raw?["value"], op == "in");
        }
        var sort = payload.Array("sort");
        foreach (var raw in sort)
        {
            Require(raw is JsonObject, "invalid_sort");
            Require(fields.ContainsKey(raw.Text("field")) && raw.Text("direction").ToLowerInvariant() is "asc" or "desc", "unknown_sort_field_or_direction");
            Require(SortExpression(key, raw.Text("field")) is not null, "report_sort_not_executable");
        }
        string[] actions = payload.Strings("actions");
        Require(actions.All(dataset.Strings("actions_json").Contains), "unknown_action");
        string[] categories = Sorted(selected.Select(f => fields[f].Text("category", "identity_basic")));
        string[] required = Sorted(categories.Select(c => c == "raw_evidence" ? "evidence.exact" : "field." + c)
            .Concat(actions.Select(a => a switch { "export" => "reports.export", "start_case" => "investigations.manage", "create_task" => "tasks.create", "grant_access" => "access.manage", _ => "" }).Where(c => c.Length > 0)));
        string[] missing = required.Except(capabilities).ToArray();
        return new JsonObject
        {
            ["api_version"] = "v4", ["status"] = missing.Length == 0 ? "accepted" : "gated",
            ["dataset"] = new JsonObject { ["key"] = key, ["version"] = dataset.Number("version", 1), ["name"] = dataset.Text("name") },
            ["fields"] = Nodes(selected.Select(f => fields[f])), ["filters"] = filters.DeepClone(), ["sort"] = sort.DeepClone(),
            ["actions"] = Nodes(actions), ["required_capabilities"] = Nodes(required), ["missing_capabilities"] = Nodes(missing),
            ["required_field_categories"] = Nodes(categories), ["arbitrary_sql_allowed"] = false,
            ["dashboard_metrics"] = Metrics(payload["dashboard_metrics"]), ["sample_rows"] = new JsonArray(), ["sample_state"] = "not_requested_no_data_disclosure"
        };
    }

    internal static string? FilterExpression(string dataset, string field) => ReportDatasetCatalog.Data["RUNTIME_FILTER_FIELDS"]?[dataset]?[field]?.GetValue<string>();
    internal static string? SortExpression(string dataset, string field) => ReportDatasetCatalog.Data["RUNTIME_SORT_FIELDS"]?[dataset]?[field]?.GetValue<string>();

    internal static object FilterValue(string dataset, string field, JsonNode? value, bool many)
    {
        string[] values = many ? (value is JsonArray arr ? arr.Select(v => v?.ToString() ?? "").ToArray() : (value?.ToString() ?? "").Split(','))
            .Select(v => v.Trim()).Where(v => v.Length > 0).ToArray() : [value?.ToString().Trim() ?? ""];
        Require(value is not JsonObject && (many || value is not JsonArray) && values.Length is > 0 and <= 100 && values.All(v => v.Length is > 0 and <= 512), "invalid_filter_value");
        if ((dataset == "events.v2" && field == "event_id") || (dataset == "ad.gpo.governance" && field == "link_count"))
        {
            var result = values.Select(v => long.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out long n) ? n : throw new ReportException("invalid_filter_value")).ToArray();
            return many ? result : result[0];
        }
        if (dataset == "ad.accounts.vpn" && field is "enabled" or "privileged_overlap")
        {
            var result = values.Select(v => v.ToLowerInvariant() switch { "1" or "true" or "yes" or "on" => true, "0" or "false" or "no" or "off" => false, _ => throw new ReportException("invalid_filter_value") }).ToArray();
            return many ? result : result[0];
        }
        return many ? values : values[0];
    }

    internal static JsonArray Metrics(JsonNode? value)
    {
        if (value is null || value.ToJsonString() == "\"\"") return [];
        Require(value is JsonArray && value.AsArray().Count <= 24, "invalid_dashboard_metrics");
        var result = new JsonArray(); var keys = new HashSet<string>(); int required = 0;
        foreach (var item in value!.AsArray())
        {
            Require(item is JsonObject, "invalid_dashboard_metrics");
            string key = item.Text("key").Trim(), label = item.Text("label").Trim(), caption = item.Text("caption").Trim(), kind = item.Text("kind").Trim().ToLowerInvariant();
            string path = item.Text("value_path").Trim(), freshness = item.Text("freshness_path").Trim(), unit = item.Text("unit").Trim();
            string icon = item.Text("icon", "report").Trim(), tone = item.Text("tone", "accent").Trim(), target = item.Text("target_path").Trim();
            var priority = item?["priority"] ?? JsonValue.Create(100)!; var defaultSelected = item?["default_selected"] ?? JsonValue.Create(false)!;
            var filters = item?["filters"] ?? new JsonObject();
            Require(Regex.IsMatch(key, "\\A[a-z0-9][a-z0-9_.-]{1,79}\\z") && keys.Add(key) && label.Length is > 0 and <= 120 && caption.Length <= 240
                && kind is "required" or "optional" && Regex.IsMatch(path, "\\A(?:summary\\.[a-z0-9_]{1,80}|items\\.count)\\z")
                && (freshness.Length == 0 || Regex.IsMatch(freshness, "\\Asummary\\.[a-z0-9_]{1,80}\\z")) && unit.Length <= 32
                && Regex.IsMatch(icon, "\\A[a-z][a-z0-9_-]{1,39}\\z") && tone is "accent" or "good" or "warn" or "bad" or "neutral"
                && target.StartsWith('/') && !target.StartsWith("//") && target.Length <= 300
                && priority is JsonValue pv && pv.TryGetValue<int>(out int p) && p is >= 0 and <= 999
                && defaultSelected is JsonValue dv && dv.TryGetValue<bool>(out _) && filters is JsonObject fo && fo.Count <= 12
                && fo.All(f => Regex.IsMatch(f.Key, "\\A[a-z0-9_]{1,80}\\z") && f.Value is not (JsonObject or JsonArray) && (f.Value?.ToString().Length ?? 4) <= 256), "invalid_dashboard_metrics");
            if (kind == "required") required++;
            result.Add(new JsonObject { ["key"] = key, ["label"] = label, ["caption"] = caption, ["kind"] = kind, ["value_path"] = path,
                ["freshness_path"] = freshness.Length == 0 ? null : freshness, ["unit"] = unit.Length == 0 ? null : unit, ["icon"] = icon,
                ["tone"] = tone, ["priority"] = priority.DeepClone(), ["target_path"] = target, ["default_selected"] = defaultSelected.DeepClone(), ["filters"] = filters.DeepClone() });
        }
        Require(required <= 4, "required_dashboard_metric_capacity_exceeded");
        return result;
    }

    public static bool SecurityExpands(JsonObject previous, JsonObject current)
    {
        foreach (string key in new[] { "columns", "field_categories", "actions", "required_capabilities" })
        {
            string[] Before(JsonObject obj) => obj.Array(key).Select(v => v is JsonObject ? v.Text("key") : v?.ToString() ?? "").ToArray();
            if (Before(current).Except(Before(previous)).Any()) return true;
        }
        return new[] { "filters", "sort", "target_path", "export_policy", "dashboard_metrics" }.Any(k => !JsonNode.DeepEquals(previous[k], current[k]));
    }
}
