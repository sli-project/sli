using System.Globalization;
using System.Text.Json.Nodes;

namespace Sli.Server.Reporting;

// Direct-render parity with semantic.findings.render_findings_report.
// The retired /reports/findings.html route deliberately remains HTTP 410.
public static class FindingsReportRenderer
{
    private static string Text(JsonNode? value, string empty = "") => value?.ToString() is { Length: > 0 } text ? text : empty;
    private static string E(string value) => value.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&#x27;");
    private static string E(JsonNode? value, string empty = "") => E(Text(value, empty));
    private static IEnumerable<JsonObject> Rows(JsonNode? value) => (value as JsonArray)?.OfType<JsonObject>() ?? [];
    private static string Time(JsonNode? value) => DateTimeOffset.TryParse(Text(value), CultureInfo.InvariantCulture,
        DateTimeStyles.AssumeUniversal, out var stamp) ? stamp.UtcDateTime.ToString("dd.MM.yyyy HH:mm:ss 'UTC'", CultureInfo.InvariantCulture) : Text(value, "—");

    public static string StatusLabel(string? status) => status switch
    {
        "new" => "новый", "active" => "активный", "repeated" => "повторяется", "review" => "проверяется",
        "confirmed" => "подтвержден", "false_positive" => "ложное срабатывание", "closed" => "закрыт",
        null or "" or "unknown" => "неизвестно", _ => status
    };

    private static string Severity(JsonNode? severity) => Text(severity) switch
    {
        "critical" => "критично", "high" => "высокий", "medium" => "средний", "warn" => "внимание",
        "low" => "низкий", "info" => "информация", "ok" => "норма", "" or "unknown" => "неизвестно", var other => other
    };

    public static string Render(JsonObject data)
    {
        var items = Rows(data["items"]).ToArray();
        string cards = string.Concat(items.Select(Card));
        if (cards.Length == 0) cards = "<div class=\"empty\">Findings пока не обнаружены.</div>";
        string summary = string.Concat(Rows(data["summary"]).Select(row => $"<tr><td>{E(Severity(row["severity"]))}</td><td>{E(StatusLabel(Text(row["status"])))}</td><td>{E(row["count"])}</td></tr>"));
        if (summary.Length == 0) summary = "<tr><td colspan=\"3\">Нет данных</td></tr>";
        return $$"""
            <!doctype html>
            <html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Findings</title></head>
            <body><main class="wrap">
            <header class="hero"><div class="eyebrow">ИБ-слой</div><h1>Findings: объекты проверки</h1><p class="subtitle">Повторяемые выводы с evidence-событиями, статусом, важностью и рекомендацией. Это не автоматическое доказательство инцидента, а список направлений для проверки.</p><div class="pillrow"><span class="pill">Сформирован: {{E(Time(data["generated_at_utc"]))}}</span><span class="pill">Найдено: {{items.Length}}</span></div></header>
            <section><h2>Сводка</h2><table><thead><tr><th>Важность</th><th>Статус</th><th>Количество</th></tr></thead><tbody>{{summary}}</tbody></table></section>
            <section><h2>Активные findings</h2><div class="grid">{{cards}}</div></section>
            </main></body></html>
            """;
    }

    private static string Card(JsonObject item)
    {
        var evidence = Rows(item["evidence"]).ToArray();
        string EventLabel(JsonNode? value)
        {
            if (!int.TryParse(Text(value), CultureInfo.InvariantCulture, out int id)) return "Event ID —";
            string label = Entities.EntityEventLabels.Label(id);
            return label.StartsWith("Event ID ", StringComparison.Ordinal) ? label : $"Event ID {id}: {label}";
        }
        string links = string.Concat(evidence.Select(ev => $"<a class=\"button\" href=\"/reports/event-details.html?event_db_id={Uri.EscapeDataString(Text(ev["event_db_id"], "None"))}&amp;limit=1\">{E(EventLabel(ev["event_id"]))} · {E(ev["hostname"], "None")}</a>"));
        if (links.Length == 0) links = "<span class=\"muted\">Нет evidence</span>";
        string counters = $"<span class=\"pill\">evidence: {E(item["evidence_count"] is null || Text(item["evidence_count"]) == "0" ? evidence.Length.ToString(CultureInfo.InvariantCulture) : Text(item["evidence_count"]))}</span>";
        if (Text(item["repeat_count"], "0") != "0")
        {
            counters += $"<span class=\"pill\">повторов: {E(item["repeat_count"])}</span>";
            if (item["last_repeat_detected_at"] is not null) counters += $"<span class=\"pill\">последний повтор: {E(Time(item["last_repeat_detected_at"]))}</span>";
        }
        return $$"""
            <article class="card">
            <div class="pillrow"><span class="badge {{E(item["severity"], "None")}}">{{E(Severity(item["severity"]))}}</span><span class="pill">{{E(StatusLabel(Text(item["status"])))}}</span><span class="pill">confidence: {{E(item["confidence"], "None")}}</span>{{counters}}</div>
            <h3>{{E(item["title"], "None")}}</h3><p>{{E(item["summary"])}}</p>
            <div class="entity-grid"><div><span>Кто</span><strong>{{E(item["actor"], "—")}}</strong></div><div><span>Цель</span><strong>{{E(item["target"], "—")}}</strong></div><div><span>Источник</span><strong>{{E(item["source"], "—")}}</strong></div></div>
            <p><b>Почему важно:</b> {{E(item["why_it_matters"], "—")}}</p><p><b>Что сделать:</b> {{E(item["recommended_action"], "—")}}</p>
            <p><b>Назначено:</b> {{E(item["assigned_to"], "—")}} · <b>Причина статуса:</b> {{E(item["status_reason"], "—")}}</p>
            <p class="muted">Связанные сущности: {{RelatedEntities(item["entities"])}}</p>
            {{History(item["status_history"])}}<div class="evidence-actions">{{links}}</div></article>
            """;
    }

    private static string RelatedEntities(JsonNode? entities)
    {
        var seen = new HashSet<(string Role, string Type, string Display)>();
        var labels = new List<string>();
        foreach (var entity in Rows(entities))
        {
            string display = Text(entity["display_name"]).Trim(), role = Text(entity["entity_role"]);
            if (display.Length == 0 || !seen.Add((role, Text(entity["entity_type"]), display.ToUpperInvariant()))) continue;
            string prefix = role.Trim() switch { "actor" => "инициатор: ", "target" => "цель: ", "source" => "источник: ", _ => "" };
            labels.Add(prefix + E(display));
        }
        if (labels.Count == 0) return "—";
        return string.Join("; ", labels.Take(8)) + (labels.Count > 8 ? $"; еще {labels.Count - 8}" : "");
    }

    private static string History(JsonNode? history)
    {
        string rows = string.Concat(Rows(history).Take(8).Select(item => $"<li>{E(item["old_status"] is null || Text(item["old_status"]) == "" ? "создан" : StatusLabel(Text(item["old_status"])))} → {E(StatusLabel(Text(item["new_status"])))} · {E(item["changed_by"], "system")} · {E(Time(item["changed_at"]))}{(Text(item["note"]).Length > 0 ? ": " + E(item["note"]) : "")}</li>"));
        return rows.Length == 0 ? "<p class=\"muted\">История статуса отсутствует.</p>" : "<details><summary>История статуса</summary><ul>" + rows + "</ul></details>";
    }
}
