using System.Text.Json.Nodes;

namespace Sli.Server.Compatibility;

// Native port of event_search_projection and the catalogue machine contract.
// The JSON declarations are copied from the frozen AD normalizer, not inferred
// from Event IDs by the HTTP layer.
internal static partial class LegacySemantics
{
    static JsonNode Resource(string name)
    {
        using var stream = typeof(LegacySemantics).Assembly.GetManifestResourceStream(name)
            ?? throw new InvalidDataException("legacy_declarations_missing");
        return JsonNode.Parse(stream)!;
    }
    static readonly JsonNode Declarations = Resource("Sli.Server.Compatibility.legacy-declarations.json");
    static readonly JsonObject[] Entries = new[] {
        "Sli.Server.Semantic.Risk.event_catalog.json", "Sli.Server.Compatibility.file_audit_event_catalog.json",
        "Sli.Server.Compatibility.radius_event_catalog.json", "Sli.Server.Compatibility.workstations_event_catalog.json"
    }.SelectMany(name => Resource(name)["entries"]!.AsArray().OfType<JsonObject>()).ToArray();
    internal static JsonArray Groups => (JsonArray)Declarations["groups"]!.DeepClone();
    internal static int[] Family(string key) => Declarations["families"]?[key]?.AsArray().Select(n => int.Parse(n!.ToString())).ToArray() ?? [];
    internal static int[] AccountIds => Declarations["accounts"]!.AsObject().Select(p => int.Parse(p.Key)).Order().ToArray();
    internal static string Label(int id) => EventLabel(id, "ru") ?? "Событие журнала";
    internal static string AccountCategory(int id) => Declarations["accounts"]?[id.ToString()]?[1]?.ToString() ?? "";
    internal static string AccountSeverity(int id) => Declarations["accounts"]?[id.ToString()]?[2]?.ToString() ?? "info";
    internal static string TimelineLabel(int id) => Declarations["accounts"]?[id.ToString()]?[0]?.ToString() ?? Label(id);
    internal static string Text(JsonNode? obj, string key, string fallback = "") => obj?[key]?.ToString() ?? fallback;
    internal static long Number(JsonNode? obj, string key) => long.TryParse(Text(obj, key), out long n) ? n : 0;
    internal static JsonObject Object(JsonNode? value)
    {
        if (value is JsonObject obj) return (JsonObject)obj.DeepClone();
        try { return JsonNode.Parse(value?.ToString() ?? "{}") as JsonObject ?? new(); }
        catch (System.Text.Json.JsonException) { return new(); }
    }
    internal static JsonObject? Entry(JsonObject row)
    {
        int id = (int)Number(row, "event_id");
        string channel = Text(row, "channel").Trim().ToLowerInvariant(), provider = Text(row, "provider_name").Trim().ToLowerInvariant();
        return Entries.Where(e => Number(e, "event_id") == id &&
            (Text(e, "channel").Length == 0 || Text(e, "channel").ToLowerInvariant() == channel) &&
            (Text(e, "provider_name").Length == 0 || Text(e, "provider_name").ToLowerInvariant() == provider))
            .OrderByDescending(e => (Text(e, "channel").Length > 0 ? 2 : 0) + (Text(e, "provider_name").Length > 0 ? 1 : 0)).FirstOrDefault(e =>
                // The catalogue index uses the last declaration of one identity.
                !Entries.Any(other => !ReferenceEquals(e, other) && Array.IndexOf(Entries, other) > Array.IndexOf(Entries, e) &&
                    Number(other, "event_id") == id && Text(other, "channel") == Text(e, "channel") && Text(other, "provider_name") == Text(e, "provider_name")));
    }
    static string FirstValue(JsonObject row, JsonNode? names)
    {
        var data = Object(row["event_data"] ?? row["event_data_json"]);
        foreach (var name in names as JsonArray ?? [])
        {
            string key = name!.ToString(), text = (row.ContainsKey(key) ? row[key] : data[key])?.ToString().Trim() ?? "";
            if (text is not ("" or "-" or "—")) return text;
        }
        return "";
    }
    static bool Matches(JsonObject rule, JsonObject row, Dictionary<string, string> roles)
    {
        foreach (var condition in rule["all"] as JsonArray ?? [])
        {
            string value = roles.GetValueOrDefault(Text(condition, "role"), "");
            if (value.Length == 0) value = FirstValue(row, condition?["fields"]);
            value = value.ToLowerInvariant();
            if (condition?["microsoft_namespace"]?.ToString() == "true" && !value.StartsWith("\\microsoft\\windows\\")) return false;
            if (condition?["machine_or_system"]?.ToString() == "true" && !(value.EndsWith('$') || value is "system" or "nt authority\\system")) return false;
            if (condition?["dc"]?.ToString() == "true" && !Text(row, "server").StartsWith("dc", StringComparison.OrdinalIgnoreCase)) return false;
            if (condition?["contains_any"] is JsonArray { Count: > 0 } tokens)
            {
                string haystack = string.Join(" ", Object(row["event_data"] ?? row["event_data_json"]).Select(p => p.Value?.ToString())).ToLowerInvariant();
                if (!tokens.Any(t => haystack.Contains(t!.ToString().ToLowerInvariant()))) return false;
            }
        }
        return true;
    }
    static string Risk(string raw) => raw.ToLowerInvariant() switch { "important" or "warning" or "warn" => "medium", "critical" or "high" or "medium" or "low" or "info" or "unknown" => raw.ToLowerInvariant(), _ => "unknown" };
    internal static JsonObject Summary(JsonObject row)
    {
        var entry = Entry(row); var card = entry?["card"] as JsonObject ?? new(); bool known = entry is not null;
        var roles = (card["field_roles"] as JsonObject ?? new()).ToDictionary(p => p.Key, p => FirstValue(row, p.Value));
        string[] missing = (card["expected_roles"] as JsonArray ?? []).Select(n => n!.ToString()).Where(r => roles.GetValueOrDefault(r, "").Length == 0).ToArray();
        int matched = -1; JsonObject? rule = null;
        foreach (var candidate in card["risk_rules"] as JsonArray ?? [])
        { matched++; if (Matches(candidate!.AsObject(), row, roles)) { rule = candidate.AsObject(); break; } }
        if (rule is null) matched = -1;
        string baseRisk = known ? Risk(Text(entry, "base_risk", Text(entry, "severity"))) : "unknown";
        string risk = known ? Risk(Text(rule, "severity", Text(entry, "severity", "info"))) : "unknown";
        string tier = Text(rule, "tier", Text(card, "tier", risk is "critical" or "high" ? "critical" : risk == "medium" ? "important" : "technical"));
        string confidence = !known ? "low" : card.Count == 0 ? "unknown" : missing.Length > 0 ? "medium" : "high";
        confidence = Text(rule, "confidence", Text(card, "confidence", confidence));
        string confidenceLabel = confidence switch { "low" => "низкая", "medium" => "средняя", "high" => "высокая", _ => confidence };
        string category = Text(card, "category", Text(entry, "category", known ? "other" : "unknown"));
        if (category is "other" or "unknown" && known)
        {
            category = new[] { "authentication", "account_management", "privilege_management", "policy_change" }.FirstOrDefault(f => Family(f).Contains((int)Number(row, "event_id")))
                ?? (Text(row, "channel").Contains("taskscheduler", StringComparison.OrdinalIgnoreCase) || Text(row, "provider_name").Contains("task scheduler", StringComparison.OrdinalIgnoreCase) ||
                    Family("service_task").Contains((int)Number(row, "event_id")) && (Text(row, "channel").Equals("system", StringComparison.OrdinalIgnoreCase) || Text(row, "provider_name").Contains("service control manager", StringComparison.OrdinalIgnoreCase)) ? "service_task" : "operations");
        }
        var reasons = new List<string> { known ? "catalog_rule_matched" : "catalog_rule_missing" };
        if (matched >= 0) reasons.Add("contextual_rule_matched:" + matched);
        reasons.AddRange(missing.Select(r => "expected_role_missing:" + r));
        var fields = new List<string>();
        foreach (var (role, names) in card["field_roles"] as JsonObject ?? new()) if (roles.GetValueOrDefault(role, "").Length > 0) fields.AddRange((names as JsonArray ?? []).Select(n => n!.ToString()));
        foreach (var condition in rule?["all"] as JsonArray ?? [])
        {
            fields.AddRange((condition?["fields"] as JsonArray ?? []).Select(n => n!.ToString()));
            fields.AddRange((card["field_roles"]?[Text(condition, "role")] as JsonArray ?? []).Select(n => n!.ToString()));
            if (condition?["dc"]?.ToString() == "true") fields.Add("server");
            if (condition?["contains_any"] is JsonArray { Count: > 0 }) fields.Add("event_data");
        }
        if (row["watch_priority"] is JsonObject priority && Text(priority, "reason") == "watch")
        {
            string b = Text(priority, "base_severity"), f = Text(priority, "effective_severity");
            if (f == (b switch { "info" => "low", "low" => "medium", "medium" => "high", "high" => "critical", "critical" => "critical", _ => "" })) { baseRisk = b; risk = f; reasons.Add("watch"); }
        }
        string riskLabel = !known ? "Оценка ИБ не определена" : risk switch { "critical" or "high" => "Высокий риск", "medium" => "Требует проверки", "low" => "Низкий риск", _ => "Информация" };
        var output = new JsonObject();
        foreach (string key in new[] { "event_record_id", "time_created_utc", "server", "channel", "provider_name" }) output[key] = row[key]?.DeepClone();
        output["event_db_id"] = Number(row, "id") is > 0 and var id ? id : Number(row, "event_db_id"); output["event_id"] = Number(row, "event_id");
        output["label"] = known ? Text(card, "action", Text(entry, "title", Label((int)Number(row, "event_id")))) : Number(row,"event_id") == 0 ? "Событие журнала" : Storage.EventReports.EventListProjection.Label(row);
        output["category"] = known ? category : Declarations["accounts"]?[Number(row,"event_id").ToString()]?[1]?.ToString() ?? "event";
        output["severity"] = known ? risk : Declarations["accounts"]?[Number(row,"event_id").ToString()]?[2]?.ToString() ?? "info";
        output["tier"] = known ? tier : null; output["purpose_tier"] = known ? tier : "technical";
        output["base_risk"] = baseRisk; output["final_risk"] = risk; output["final_security_severity"] = risk;
        output["confidence"] = confidence; output["assessment_confidence"] = confidence;
        output["noise_class"] = Text(card, "noise_class", Text(entry, "noise_class", known ? risk is "high" or "medium" or "critical" ? "signal" : "context" : "unknown"));
        output["source_payload_state"] = row["source_payload_state"]?.DeepClone(); output["catalog_match"] = known;
        output["reasons"] = new JsonArray(reasons.Distinct().Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
        output["evidence_fields"] = new JsonArray(fields.Distinct().Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
        output["display_labels"] = new JsonObject { ["risk"] = riskLabel, ["confidence"] = confidenceLabel };
        output["time_created_utc_display"] = Display(row["time_created_utc"]); output["time_created_local_display"] = Display(row["time_created_local"], false);
        string assessment = rule is null ? Text(card,"assessment") : Text(rule,"assessment");
        output["summary"] = !known ? "Каталог не содержит проверенной интерпретации этого события." : assessment.Length>0 ? assessment : Text(card, "purpose", Text(entry, "why", "Событие расшифровано локальным каталогом."));
        return output;
    }
    internal static string Display(JsonNode? value, bool utc = true) =>
        Sli.Server.Reporting.ReportTime.Event(value?.ToString(), suffix: utc ? "UTC" : "");

    internal static (string Sql, bool Exact, JsonArray Limitations) MonitorRiskSql(LegacySql sql, JsonArray groups)
    {
        var ids = groups.OfType<JsonObject>().SelectMany(g => g["event_ids"]!.AsArray().Select(n => int.Parse(n!.ToString()))).ToHashSet();
        var cases = new List<string>(); var limitations = new JsonArray();
        // compile_catalog_risk_sql only compiles the canonical AD catalogue.
        var entries = Entries.Where(e => ids.Contains((int)Number(e, "event_id")))
            .OrderByDescending(e => (Text(e, "channel").Length > 0 ? 1 : 0) + (Text(e, "provider_name").Length > 0 ? 1 : 0)).ThenByDescending(e => Number(e, "event_id"));
        foreach (var entry in entries)
        {
            var conditions = new List<string> { "e.event_id=" + sql.Bind((int)Number(entry, "event_id")) };
            foreach (string key in new[] { "channel", "provider_name" }) if (Text(entry, key).Length > 0) conditions.Add($"lower(coalesce(e.{key},''))={sql.Bind(Text(entry, key).ToLowerInvariant())}");
            string baseRisk = Risk(Text(entry, "base_risk", Text(entry, "severity", "info")));
            string expression = sql.Bind(baseRisk);
            var rules = entry["card"]?["risk_rules"] as JsonArray ?? [];
            for (int i = rules.Count - 1; i >= 0; i--)
            {
                var rule = rules[i]!; string severity = Risk(Text(rule, "severity", baseRisk)); if (severity == baseRisk) continue;
                var checks = new List<string>(); bool supported = true;
                foreach (var condition in rule["all"] as JsonArray ?? [])
                {
                    if (condition?["microsoft_namespace"]?.ToString() == "true" || condition?["machine_or_system"]?.ToString() == "true") { supported = false; break; }
                    if (condition?["dc"]?.ToString() == "true") checks.Add("lower(coalesce(s.hostname,'')) like 'dc%'");
                    if (condition?["contains_any"] is JsonArray { Count: > 0 } tokens)
                        checks.Add("(" + string.Join(" or ", tokens.Select(t => "lower(coalesce(e.event_data_json,'')) like " + sql.Bind("%" + System.Text.Json.JsonSerializer.Serialize(t!.ToString().ToLowerInvariant())[1..^1] + "%"))) + ")");
                }
                if (!supported) { limitations.Add($"event_id={Number(entry, "event_id")}:risk_rule={i}"); continue; }
                expression = "case when " + (checks.Count == 0 ? "true" : string.Join(" and ", checks)) + " then " + sql.Bind(severity) + " else " + expression + " end";
            }
            cases.Add("when " + string.Join(" and ", conditions) + " then " + expression);
        }
        string fallback = "case " + string.Join(" ", groups.OfType<JsonObject>().Select(g => "when e.event_id in (" + string.Join(",", g["event_ids"]!.AsArray().Select(n => int.Parse(n!.ToString()))) + ") then " + sql.Bind(Text(g, "severity")))) + " else 'info' end";
        return ("case " + string.Join(" ", cases) + " else " + fallback + " end", limitations.Count == 0, limitations);
    }
}
