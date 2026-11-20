using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using static Sli.Server.Reporting.ReportJson;

namespace Sli.Server.Reporting;

internal sealed class ReportQuery
{
    internal readonly List<object?> Values = [];
    internal readonly List<string> Predicates = [];
    internal string Order = "";
    internal string Parameter(object? value) { string key = "@p" + Values.Count; Values.Add(value); return key; }
    internal void Add(string expression, object? value) => Predicates.Add(expression + Parameter(value));
    internal static string DefaultOrder(string dataset) => ReportDatasetCatalog.Data["DEFAULT_ORDERS"]![dataset]!.GetValue<string>();
    internal static string Inactivity(string attributes, string observed, long days)
    {
        Require(days is >= 1 and <= 3650, "value_must_be_days_1_3650");
        string raw = "(" + attributes + "->>'last_logon_utc')";
        return $"(case when {raw} ~ 'T.*(Z|[+-][0-9]{{2}}:[0-9]{{2}})$' and pg_input_is_valid({raw},'timestamp with time zone') then case when {observed} is not null and {raw}::timestamptz <= {observed} then {raw}::timestamptz < {observed} - interval '{days} days' end end)";
    }
    internal static string Resolve(string sql, long days) => sql.Replace("{inactive_account}", Inactivity("account.attributes_json->'attributes'", "account.last_observed_at_utc", days)).Replace("{inactivity_days}", days.ToString(CultureInfo.InvariantCulture));
    internal void Definition(string dataset, JsonObject definition, long days)
    {
        Require(definition["filters"] is null or JsonArray, "invalid_report_definition_filters");
        foreach (var item in definition.Array("filters"))
        {
            Require(item is JsonObject, "invalid_report_definition_filters");
            if (item!["field"] is null && item["value"] is null) continue;
            string field = item.Text("field"), op = item.Text("op").ToLowerInvariant();
            string? expression = ReportBuilder.FilterExpression(dataset, field);
            Require(expression is not null && op is "eq" or "in" or "contains" or "gte" or "lte", "report_filter_not_executable");
            var value = ReportBuilder.FilterValue(dataset, field, item["value"], op == "in");
            string parameter = Parameter(op == "contains" ? "%" + value + "%" : value);
            if (dataset == "events.v2" && field == "time_created_utc") parameter += op == "in" ? "::timestamptz[]" : "::timestamptz";
            Predicates.Add(Resolve(expression!, days) + (op switch { "eq" => "=" + parameter, "in" => "=any(" + parameter + ")", "contains" => " ilike " + parameter, "gte" => ">=" + parameter, _ => "<=" + parameter }));
        }
        var sort = definition["sort"] ?? definition["default_sort"] ?? new JsonArray();
        Require(sort is JsonArray && sort.AsArray().Count <= 5, "invalid_report_definition_sort");
        var parts = new List<string>();
        foreach (var item in sort.AsArray())
        {
            Require(item is JsonObject, "invalid_report_definition_sort");
            string? expression = ReportBuilder.SortExpression(dataset, item.Text("field")); string direction = item.Text("direction").ToLowerInvariant();
            Require(expression is not null && direction is "asc" or "desc", "report_sort_not_executable");
            parts.Add(expression + " " + direction);
        }
        Order = parts.Count > 0 ? string.Join(',', parts) : DefaultOrder(dataset);
    }
    internal void Interactive(string dataset, IReadOnlyDictionary<string, string> query, long days)
    {
        string field = query.GetValueOrDefault("sort", "").Trim(), direction = query.GetValueOrDefault("direction", "").Trim().ToLowerInvariant();
        if (field.Length > 0 || direction.Length > 0)
        {
            Require(field.Length > 0 && direction.Length > 0, "incomplete_report_sort");
            string? expression = ReportBuilder.SortExpression(dataset, field);
            Require(expression is not null && direction is "asc" or "desc", "report_sort_not_executable");
            Order = dataset == "ad.accounts.vpn" && field == "object_id" && direction == "asc" ? "source_entity.id asc" : expression + " " + direction + " nulls last," + Order;
        }
        var filters = query.Where(p => p.Key is not ("sort" or "direction")).ToDictionary();
        string[] allowed = dataset switch { "events.v2" => ["q", "server", "time_from", "time_to", "cursor", "view"], "ad.audit.snapshot" => ["entity_type"],
            "ad.accounts.vpn" => ["q", "activity_state", "privileged_overlap", "cursor"], "ad.gpo.governance" => ["q", "application_state", "link_count", "has_executable_components"], _ => [] };
        Require(!filters.Keys.Except(allowed).Any(), "unknown_report_query_filter");
        string Get(string key) => filters.GetValueOrDefault(key, "").Trim();
        string search = Get("q"); Require(search.Length <= 256 && Get("server").Length <= 256, "invalid_report_query_filter");
        if (dataset == "events.v2")
        {
            string view = Get("view").ToLowerInvariant();
            if (view.Length > 0 && view != "all")
            {
                Require(EventViews.ContainsKey(view), "invalid_report_query_filter");
                string ids = Parameter(EventViews[view]);
                Predicates.Add(view == "tasks" ? "(lower(coalesce(channel.value,'')) like '%taskscheduler%' or event.event_id=any(" + ids + "))" : "event.event_id=any(" + ids + ")");
            }
            if (search.Length > 0)
            {
                var accounts = new List<string> { search };
                if (search.Contains('\\')) accounts.Add(search.Split('\\')[^1]);
                if (search.Contains('@')) accounts.Add(search.Split('@')[0]);
                var clauses = new List<string>();
                foreach (string column in new[] { "event.subject_user_name", "event.target_user_name" })
                    foreach (string value in accounts.Where(v => v.Length > 0).Distinct()) {
                        clauses.Add("lower(coalesce(" + column + ",''))=lower(" + Parameter(value) + ")");
                        clauses.Add("lower(split_part("+column+",E'\\\\',2))=lower("+Parameter(value)+")");
                    }
                foreach (string column in new[] { "event.ip_address", "event.workstation_name", "event.logon_id" }) clauses.Add("lower(coalesce(" + column + ",''))=lower(" + Parameter(search) + ")");
                if (long.TryParse(search, out long id)) clauses.Add("event.event_id=" + Parameter(id));
                Predicates.Add("(" + string.Join(" or ", clauses) + ")");
            }
            if (Get("server").Length > 0) Predicates.Add("lower(server.hostname)=lower(" + Parameter(Get("server")) + ")");
            foreach (string key in new[] { "time_from", "time_to" }) if (Get(key).Length > 0) {
                if(key=="time_from") {
                    string stamp=Parameter(Timestamp(Get(key)));
                    Predicates.Add($"(case when event.day is null then event.time_created_utc>={stamp} else event.day>=({stamp} at time zone 'UTC')::date end)");
                }
                else Add("event.time_created_utc" + (key == "time_from" ? ">=" : "<"), Timestamp(Get(key)));
            }
            if (Get("cursor").Length > 0)
            {
                Require(Order == DefaultOrder(dataset), "report_cursor_requires_default_sort");
                var cursor = DecodeCursor(Get("cursor"));
                bool daily = cursor.Text("group") is { Length:64 } group && group.All(Uri.IsHexDigit);
                Require((cursor.Number("id") > 0 || daily && cursor.Number("id") == 0) && cursor.Text("time").Length is > 0 and <= 64, "invalid_report_cursor");
                string time = Parameter(Timestamp(cursor.Text("time"))), id = Parameter(cursor.Number("id"));
                Predicates.Add($"(event.time_created_utc,coalesce(event.id,0),event.summary_key)<({time},{id},{Parameter(cursor.Text("group"))})");
            }
        }
        if (dataset == "ad.audit.snapshot" && Get("entity_type").Length > 0)
        {
            string type = Get("entity_type").ToLowerInvariant(); Require(type is "ad_user" or "ad_computer", "invalid_report_query_filter"); Add("entity_type.value=", type);
        }
        if (dataset == "ad.accounts.vpn")
        {
            if (search.Length > 0) Predicates.Add("strpos(lower(concat_ws(' ',source_entity.display_name,source_entity.natural_key)),lower(" + Parameter(search) + "))>0");
            if (Get("activity_state").Length > 0)
            {
                string state = Get("activity_state").ToLowerInvariant(); Require(state is "active" or "disabled" or "inactive" or "unknown", "invalid_report_query_filter");
                Add(Resolve(ReportBuilder.FilterExpression(dataset, "activity_state")!, days) + "=", state);
            }
            if (Get("privileged_overlap").Length > 0) Add(ReportBuilder.FilterExpression(dataset, "privileged_overlap") + "=", ReportBuilder.FilterValue(dataset, "privileged_overlap", JsonValue.Create(Get("privileged_overlap")), false));
            // VPN cursor is appended after the filtered count by the reader.
            if (Get("cursor").Length > 0)
            {
                Require(Order == "source_entity.id asc", "report_cursor_requires_default_sort");
                string id = DecodeCursor(Get("cursor")).Text("object_id");
                Require(id.All(char.IsAsciiDigit) && long.TryParse(id, out long parsed) && parsed > 0, "invalid_report_cursor");
            }
        }
        if (dataset == "ad.gpo.governance")
        {
            string state = Get("application_state").ToLowerInvariant();
            if (state.Length > 0)
            {
                Require(state is "both_enabled" or "computer_only" or "user_only" or "disabled" or "partial", "invalid_report_query_filter");
                string exp = ReportBuilder.FilterExpression(dataset, "application_state")!;
                if (state == "partial") Predicates.Add(exp + " in ('computer_only','user_only')"); else Add(exp + "=", state);
            }
            if (Get("link_count").Length > 0)
            {
                Require(long.TryParse(Get("link_count"), out long links) && links is >= 0 and <= 1000000, "invalid_report_query_filter");
                Add(ReportBuilder.FilterExpression(dataset, "link_count") + "=", links);
            }
            string executable = Get("has_executable_components").ToLowerInvariant();
            if (executable.Length > 0)
            {
                Require(executable is "true" or "false", "invalid_report_query_filter");
                Predicates.Add("(" + ReportDatasetCatalog.Data.Text("GPO_EXECUTABLE_COUNT_SQL") + ")" + (executable == "true" ? ">0" : "=0"));
            }
            if (search.Length > 0)
            {
                string parameter = Parameter("%" + search + "%");
                Predicates.Add("(" + string.Join(" or ", new[] { "entity.display_name", "entity.natural_key", "version.attributes_json->'attributes'->>'gpo_wmi_filter_id'", "version.attributes_json->'attributes'->'links'::text", "version.attributes_json->'attributes'->'gpo_security_filtering_sids'::text", "version.attributes_json->'attributes'->'gpo_settings'::text" }.Select(e => "coalesce(" + e + ",'') ilike " + parameter)) + ")");
            }
        }
    }
    private static DateTimeOffset Timestamp(string value)
    {
        Require(value.Length <= 64 && System.Text.RegularExpressions.Regex.IsMatch(value, @"(Z|[+-][0-9]{2}:[0-9]{2})$")
            && DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out _), "invalid_report_time_filter");
        return DateTimeOffset.Parse(value, CultureInfo.InvariantCulture).ToUniversalTime();
    }
    internal static JsonObject DecodeCursor(string value)
    {
        Require(value.Length is > 0 and <= 512, "invalid_report_cursor");
        try { string b64 = value.Replace('-', '+').Replace('_', '/'); return JsonNode.Parse(Convert.FromBase64String(b64.PadRight((b64.Length + 3) / 4 * 4, '=')))!.AsObject(); }
        catch (Exception e) when (e is FormatException or System.Text.Json.JsonException or InvalidOperationException) { throw new ReportException("invalid_report_cursor"); }
    }
    internal static string Cursor(JsonObject payload) => Convert.ToBase64String(Encoding.UTF8.GetBytes(payload.ToJsonString())).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    internal static readonly IReadOnlyDictionary<string, long[]> EventViews = LoadViews();
    private static IReadOnlyDictionary<string, long[]> LoadViews()
    {
        // Generated from the same frozen catalog as the event search reference.
        return (ReportDatasetCatalog.Data["event_views"] as JsonObject ?? []).ToDictionary(p => p.Key, p => p.Value!.AsArray().Select(v => v!.GetValue<long>()).ToArray());
    }
}
