using System.Text.Json.Nodes;
using System.Globalization;

namespace Sli.Server.Investigations;

internal static class InvestigationTimeline
{
    static readonly Lazy<JsonObject[]> Entries = new(() => new[] { "Sli.Server.Semantic.Risk.event_catalog.json", "Sli.Server.Investigations.file_audit_event_catalog.json", "Sli.Server.Investigations.radius_event_catalog.json", "Sli.Server.Investigations.workstations_event_catalog.json" }.SelectMany(name =>
    {
        using var stream = typeof(InvestigationTimeline).Assembly.GetManifestResourceStream(name)!;
        return JsonNode.Parse(stream)!["entries"]!.AsArray().Select(e => e!.AsObject()).ToArray();
    }).ToArray());
    internal static string Text(JsonObject item, string key) => item[key]?.ToString() ?? "";
    internal static DateTimeOffset? Instant(JsonNode? raw)
    {
        if (raw is JsonValue value)
        {
            if (value.TryGetValue<DateTimeOffset>(out var offset)) return offset;
            if (value.TryGetValue<DateTime>(out var date))
                return new DateTimeOffset(date.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(date, DateTimeKind.Utc) : date);
        }
        return raw is not null && DateTimeOffset.TryParse(raw.ToString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var time) ? time : null;
    }
    static JsonNode? Utc(JsonNode? raw)
    {
        if (Instant(raw) is not { } parsed) return raw?.DeepClone();
        var time = parsed.ToUniversalTime();
        return JsonValue.Create(time.ToString(time.Ticks % TimeSpan.TicksPerSecond == 0 ? "yyyy-MM-dd'T'HH:mm:ss'Z'" : "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture));
    }
    static string Risk(string value, string fallback = "unknown") => value.Trim().ToLowerInvariant() switch
    { "critical" => "critical", "high" => "high", "important" or "warning" or "warn" or "medium" => "medium", "low" => "low", "info" => "info", _ => fallback };
    static string Category(string value, bool known) => value.Trim().ToLowerInvariant() switch
    {
        "auth" or "logon" or "authentication" => "authentication", "account" or "accounts" or "account_management" => "account_management",
        "privileges" or "privilege_management" => "privilege_management", "policy_change" => "policy_change", "services_tasks" or "service" or "service_task" => "service_task",
        "operations" => "operations", "infra" or "infrastructure" => "infrastructure", "event" or "other" => "other", "unknown" => "unknown", _ => known ? "other" : "unknown"
    };
    static string Tier(string risk) => risk is "critical" or "high" ? "critical" : risk == "medium" ? "important" : "technical";
    internal static JsonObject? Entry(JsonObject row) => Entries.Value.FirstOrDefault(e => Text(e, "event_id") == Text(row, "event_id") &&
        Text(e, "channel").Equals(Text(row, "channel").Trim(), StringComparison.OrdinalIgnoreCase) && Text(e, "provider_name").Equals(Text(row, "provider_name").Trim(), StringComparison.OrdinalIgnoreCase));
    static string First(JsonObject row, JsonArray? names)
    {
        foreach (var n in names ?? [])
        {
            string key = n!.ToString(), value = row.ContainsKey(key) ? row[key]?.ToString() ?? "" : row["event_data"]?[key]?.ToString() ?? "";
            if (value.Trim() is { Length: > 0 } text && text is not ("-" or "—")) return text;
        }
        return "";
    }
    static bool Matches(JsonObject rule, JsonObject row, Dictionary<string, string> roles)
    {
        foreach (var n in rule["all"] as JsonArray ?? [])
        {
            var c = n!.AsObject(); string value = roles.GetValueOrDefault(Text(c, "role"), "");
            if (value.Length == 0) value = First(row, c["fields"] as JsonArray);
            value = value.ToLowerInvariant();
            if (c["microsoft_namespace"]?.ToString() == "true" && !value.StartsWith("\\microsoft\\windows\\", StringComparison.Ordinal)) return false;
            if (c["machine_or_system"]?.ToString() == "true" && !value.EndsWith('$') && value is not ("system" or "nt authority\\system")) return false;
            if (c["dc"]?.ToString() == "true" && !Text(row, "server").StartsWith("dc", StringComparison.OrdinalIgnoreCase)) return false;
            var contains = c["contains_any"] as JsonArray;
            string data = string.Join(" ", (row["event_data"] as JsonObject ?? []).Select(p => p.Value?.ToString() ?? "")).ToLowerInvariant();
            if (contains is { Count: > 0 } && !contains.Any(t => data.Contains(t!.ToString().ToLowerInvariant(), StringComparison.Ordinal))) return false;
        }
        return true;
    }
    internal static (JsonObject Item, JsonObject Card) Build(JsonObject row, string reason, bool metadata = false)
    {
        var entry = Entry(row); bool known = entry is not null;
        var card = entry?["card"] as JsonObject ?? new JsonObject();
        var roles = (card["field_roles"] as JsonObject ?? []).ToDictionary(p => p.Key, p => First(row, p.Value as JsonArray));
        bool missing = (card["expected_roles"] as JsonArray ?? []).Any(n => roles.GetValueOrDefault(n!.ToString(), "").Length == 0);
        string severity = known ? Risk(Text(entry!, "severity"), "info") : "unknown", assessment = Text(card, "assessment"), tier = Text(card, "tier"), confidence = Text(card, "confidence");
        int? matched = null;
        if (card["risk_rules"] is JsonArray rules)
            for (int i = 0; i < rules.Count; i++) if (Matches(rules[i]!.AsObject(), row, roles))
            {
                var rule = rules[i]!.AsObject(); severity = Risk(Text(rule, "severity"), severity); assessment = Text(rule, "assessment");
                tier = Text(rule, "tier") is { Length: > 0 } rt ? rt : tier; confidence = Text(rule, "confidence"); matched = i; break;
            }
        string baseRisk = known ? Risk(Text(entry!, "base_risk") is { Length: > 0 } br ? br : Text(entry!, "severity")) : "unknown";
        string origin = known ? matched.HasValue ? "contextual_rule" : "catalog_base" : "unavailable";
        if (row["watch_priority"] is JsonObject watch && Text(watch, "reason") == "watch")
        {
            string b = Text(watch, "base_severity"), final = Text(watch, "effective_severity");
            string? expected = b switch { "info" => "low", "low" => "medium", "medium" => "high", "high" or "critical" => "critical", _ => null };
            if (expected == final) { baseRisk = b; severity = final; origin = "contextual_rule"; }
        }
        if (confidence.Length == 0) confidence = card.Count == 0 ? "unknown" : missing ? "medium" : "high";
        confidence = confidence switch { "высокая" => "high", "средняя" => "medium", "низкая" => "low", "high" or "medium" or "low" => confidence, _ => "unknown" };
        if (!known) confidence = "unknown";
        string code = known ? $"{Text(entry!, "channel")}:{Text(entry!, "provider_name")}:{Text(entry!, "event_id")}" : "";
        string fallbackTitle = Text(row, "label") is { Length: > 0 } label ? label : Storage.EventReports.EventListProjection.Label(row);
        string title = known ? metadata ? Text(row, "label") is { Length: > 0 } sourceLabel ? sourceLabel : Text(entry!, "title") : Text(card, "action") is { Length: > 0 } action ? action : Text(entry!, "title") : fallbackTitle;
        string summary = known ? assessment.Length > 0 ? assessment : Text(card, "purpose") is { Length: > 0 } purpose ? purpose : Text(entry!, "why") : "Каталог не содержит правила для этого Provider, Channel и Event ID. Ни действие, ни результат не интерпретируются автоматически.";
        string? summaryCode = known && !metadata ? code + (matched.HasValue && assessment.Length > 0 ? $".summary.rule.{matched}" : ".summary") : null;
        var checks = known ? card["checks"]?.DeepClone() as JsonArray ?? [] : new JsonArray("Проверить исходные поля опорного события.");
        if (known && checks.Count == 0) checks.Add(Text(entry!, "fix") is { Length: > 0 } fix ? fix : "Открыть технические данные и сообщение Windows.");
        var item = new JsonObject
        {
            ["event_db_id"] = row["event_db_id"]?.DeepClone() ?? row["id"]?.DeepClone(), ["time_utc"] = Utc(row["time_created_utc"]), ["server"] = row["server"]?.DeepClone(), ["channel"] = row["channel"]?.DeepClone(),
            ["event_id"] = row["event_id"]?.DeepClone() ?? JsonValue.Create(0), ["title"] = title, ["title_code"] = known ? code + ".title" : null, ["summary_code"] = summaryCode,
            ["category"] = Category(metadata ? entry is null ? "" : Text(entry, "category") : Text(card, "category") is { Length: > 0 } category ? category : entry is null ? "" : Text(entry, "category"), known),
            ["severity"] = metadata ? "unknown" : severity, ["purpose_tier"] = metadata ? "technical" : tier is "critical" or "important" or "technical" ? tier : Tier(severity),
            ["base_risk"] = metadata ? "unknown" : baseRisk, ["confidence"] = metadata ? "unknown" : confidence, ["assessment_confidence"] = metadata ? "unknown" : confidence,
            ["noise_class"] = metadata ? "unknown" : Text(card, "noise_class") is { Length: > 0 } noise ? noise : entry is not null && Text(entry, "noise_class") is { Length: > 0 } en ? en : !known ? "unknown" : severity is "critical" or "high" or "medium" ? "signal" : "context",
            ["classification_origin"] = metadata ? "unavailable" : origin, ["card_completeness"] = metadata || card.Count == 0 ? "not_applicable" : missing ? "partial" : "complete",
            ["inclusion_reason"] = reason, ["actor"] = row[metadata ? "subject_user_name" : "subject"]?.DeepClone(), ["target"] = row[metadata ? "target_user_name" : "target"]?.DeepClone(),
            ["source"] = metadata ? null : row["source"]?.DeepClone(), ["summary"] = metadata || !known ? null : summary, ["catalogued"] = known
        };
        return (item, new JsonObject { ["known"] = known, ["risk"] = severity, ["classification_origin"] = origin, ["card_completeness"] = item["card_completeness"]!.DeepClone(), ["story"] = summary, ["story_code"] = known ? summaryCode : "uncatalogued.summary", ["checks"] = checks, ["check_codes"] = known ? new JsonArray(Enumerable.Range(0, checks.Count).Select(i => (JsonNode?)JsonValue.Create(code + $".checks.{i}")).ToArray()) : new JsonArray() });
    }
}
