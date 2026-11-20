using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Server.Domains;

namespace Sli.Server.Compatibility;

internal static class LegacyRender
{
    static string Text(JsonNode? obj, string key) => LegacySemantics.Text(obj, key);
    static string Escape(string value) => WebUtility.HtmlEncode(value);
    internal static async Task CsvAsync(HttpContext context, JsonObject data, CancellationToken ct)
    {
        var output = new StringBuilder();
        void Row(params string[] fields)
        {
            output.AppendJoin(',', fields.Select(value =>
            {
                // Host strings are untrusted even when a spreadsheet opens the CSV.
                string safe = value.TrimStart().StartsWith('=') || value.TrimStart().StartsWith('+') || value.TrimStart().StartsWith('-') || value.TrimStart().StartsWith('@') || value.StartsWith('\t') || value.StartsWith('\r') ? "'" + value : value;
                return safe.IndexOfAny([',', '"', '\r', '\n']) >= 0 ? "\"" + safe.Replace("\"", "\"\"") + "\"" : safe;
            }));
            output.Append('\n');
        }
        Row("record_type", "time", "group", "event_id", "event_label", "account", "actor", "target", "source", "server", "risk", "event_record_id", "matched_total", "returned_count", "truncated", "filters_json");
        Row("metadata", Text(data, "generated_at_utc"), "", "", "", "", "", "", "", "", "", "", Text(data, "matched_total"), Text(data, "returned_count"), Text(data, "truncated").ToLowerInvariant(), data["filters"]?.ToJsonString() ?? "{}");
        foreach (var item in data["items"] as JsonArray ?? [])
            Row("event", LegacySemantics.Display(item?["time_created_utc"]), Text(item, "group_label"), Text(item, "event_id"), "Event ID "+Text(item,"event_id")+(LegacySemantics.Label((int)LegacySemantics.Number(item,"event_id")) is {} label && label!="Событие журнала" ? ": "+label : ""), Text(item, "account"), Text(item, "actor"), Text(item, "target_principal"), Text(item, "source"), Text(item, "server"), Text(item, "severity"), Text(item, "event_record_id"), "", "", "", "");
        byte[] bytes = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(output.ToString())).ToArray();
        context.Response.Headers.ContentDisposition = "attachment; filename=security-events-monitor.csv";
        context.Response.ContentType = "text/csv; charset=utf-8"; context.Response.ContentLength = bytes.Length;
        DomainHttp.ApplyHeaders(context); await context.Response.Body.WriteAsync(bytes, ct);
    }
    internal static async Task HtmlAsync(HttpContext context, string path, JsonObject data, CancellationToken ct)
    {
        if (path == "/reports/ui-navigation.html")
        {
            byte[] navigation = Encoding.UTF8.GetBytes(Workspace.LegacyWorkspaceModels.RenderNavigation(data));
            context.Response.ContentType = "text/html; charset=utf-8";
            context.Response.ContentLength = navigation.Length;
            DomainHttp.ApplyHeaders(context); await context.Response.Body.WriteAsync(navigation, ct); return;
        }
        var html = new StringBuilder("<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>")
            .Append(path == "/reports/investigation.html" ? "Рабочее место расследования" : "AI-отчеты").Append("</title></head><body><main>");
        const string notice = "<span data-ai-draft-label-ru=\"черновик ИИ, не решение\" data-ai-draft-label-en=\"AI draft, not a decision\">черновик ИИ, не решение</span>";
        if (path == "/reports/investigation.html")
        {
            html.Append("<h1>Рабочее место расследования</h1><section><h2>Кратко</h2>");
            foreach (var (key, label) in new[] { ("total_events", "Событий"), ("chain_events", "В истории"), ("findings", "Находок") })
                html.Append("<p>").Append(label).Append(": ").Append(Escape(Text(data["summary"], key))).Append("</p>");
            html.Append("</section><section><h2>Смысловая сводка</h2><p>").Append(Escape(Text(data["summary"], "story")))
                .Append("</p><p>").Append(Escape(Text(data["summary"], "why_it_matters"))).Append("</p><ul>");
            foreach (var check in data["next_checks"] as JsonArray ?? []) html.Append("<li>").Append(Escape(check?.ToString() ?? "")).Append("</li>");
            html.Append("</ul></section><section><h2>Цепочка событий</h2>");
            var chain = data["timeline"]?["chain"] as JsonArray ?? [];
            foreach (var item in chain)
            {
                string label = Text(item, "label");
                html.Append("<article><h3>").Append(Escape(label.Length > 0 ? label : "Event ID " + Text(item, "event_id"))).Append("</h3>");
                foreach (string key in new[] { "time", "category_label", "server", "channel", "subject", "target", "source", "logon_id", "summary" })
                    html.Append("<p>").Append(Escape(Text(item, key))).Append("</p>");
                string url = Text(item, "detail_url");
                if (url.StartsWith("/reports/event-details.html?", StringComparison.Ordinal))
                    html.Append("<a href=\"").Append(Escape(url)).Append("\">Открыть событие</a>");
                html.Append("</article>");
            }
            if (chain.Count == 0) html.Append("<p>История не построена.</p>");
            html.Append("</section><section><h2>Связанные findings</h2><table><thead><tr><th>Важность</th><th>Название</th><th>Цель</th><th>Почему важно</th><th>Действие</th></tr></thead><tbody>");
            var findings = data["findings"]?["items"] as JsonArray ?? [];
            foreach (var item in findings)
            {
                html.Append("<tr>");
                foreach (string key in new[] { "severity", "title", "target", "why_it_matters", "recommended_action" })
                    html.Append("<td>").Append(Escape(Text(item, key))).Append("</td>");
                html.Append("</tr>");
            }
            if (findings.Count == 0) html.Append("<tr><td colspan=\"5\">Связанных находок нет.</td></tr>");
            html.Append("</tbody></table></section>");
        }
        else if (path.Contains("preview", StringComparison.Ordinal))
        {
            bool prompt = path.Contains("prompt-preview", StringComparison.Ordinal);
            html.Append("<h1>").Append(prompt ? "Prompt preview для AI-анализа" : "Предпросмотр данных для AI-анализа").Append("</h1><p>Локальная подготовка. Данные наружу не отправляются; запрос к AI не выполняется.</p>");
            if (prompt) html.Append("<h2>Prompt для модели</h2><pre>").Append(Escape(Text(data, "prompt_text"))).Append("</pre><h2>Тело запроса</h2><pre>").Append(Escape(AiPreviewRedaction.Request(data).ToJsonString(AiPreviewRedaction.PrettyJson))).Append("</pre>");
            else html.Append("<h2>Подготовленные события</h2><pre>").Append(Escape(data["payload"]?.ToJsonString(AiPreviewRedaction.PrettyJson) ?? "{}")).Append("</pre>");
            html.Append("<h2>Параметры и безопасность</h2><pre>").Append(Escape((prompt ? data["preview"] : data)?.ToJsonString(AiPreviewRedaction.PrettyJson) ?? "{}")).Append("</pre>");
        }
        else if (path == "/reports/ai-reports.html")
        {
            html.Append("<h1>История AI-отчетов</h1><p>Локальный журнал подготовленных и выполненных AI-анализов.</p><table><thead><tr><th>ID</th><th>Статус</th><th>API</th><th>Модель</th><th>Маскирование</th><th>Создан</th><th>Завершен</th><th>Проверка</th><th>Отчет</th></tr></thead><tbody>");
            foreach (var item in data["items"] as JsonArray ?? [])
            {
                html.Append("<tr><td>").Append(Escape(Text(item, "id"))).Append("</td><td>").Append(notice).Append(' ').Append(Escape(Status(Text(item, "status")))).Append("</td>");
                foreach (string key in new[] { "ai_call_performed", "model", "redaction_level", "created_at_display", "completed_at_display" }) html.Append("<td>").Append(Escape(key == "ai_call_performed" ? Text(item, key) == "true" ? "да" : "нет" : Text(item, key))).Append("</td>");
                int errors = (item?["validation_errors"] as JsonArray)?.Count ?? 0;
                html.Append("<td>").Append(errors == 0 ? "ок" : "предупреждения: " + errors).Append("</td><td><a href=\"/reports/ai-analysis.html?run_id=").Append(LegacySemantics.Number(item, "id")).Append("\">Открыть</a></td></tr>");
            }
            if ((data["items"] as JsonArray)?.Count == 0) html.Append("<tr><td colspan=\"9\">AI-запуски пока не выполнялись.</td></tr>");
            html.Append("</tbody></table>");
        }
        else if (data["run"] is not JsonObject run) html.Append("<p>AI-отчет не найден.</p>");
        else
        {
            var result = Draft(LegacySemantics.Object(run["result"]));
            var analysis = result["analysis"] as JsonObject ?? new();
            html.Append("<h1>AI-отчет #").Append(LegacySemantics.Number(run, "id")).Append("</h1>").Append(notice).Append("<p>AI-отчет не является доказательством инцидента без ручной проверки evidence.</p>");
            foreach(var (key,label) in new[]{("status","Статус"),("ai_call_performed","API-вызов"),("model","Модель"),("redaction_level","Маскирование"),("created_at_display","Создан")})
                html.Append("<p>").Append(label).Append(": ").Append(Escape(key=="status" ? Status(Text(run,key)) : Text(run,key))).Append("</p>");
            if(run["validation_errors"] is JsonArray {Count:>0} validation) html.Append("<p>Предупреждения проверки JSON: ").Append(Escape(validation.ToJsonString())).Append("</p>");
            html.Append("<h2>Резюме</h2><p>").Append(Escape(Text(analysis, "summary") is { Length: > 0 } summary ? summary : "AI-вызов еще не выполнялся или результат не содержит резюме.")).Append("</p>");
            foreach (var (key, title) in new[] { ("facts", "Факты"), ("hypotheses", "Гипотезы"), ("alternative_explanations", "Альтернативные объяснения"), ("manual_checks", "Что проверить вручную"), ("evidence", "Evidence"), ("recommended_actions", "Рекомендации"), ("limitations", "Ограничения анализа") })
                html.Append("<section><h2>").Append(title).Append("</h2><pre>").Append(Escape(analysis[key]?.ToJsonString() ?? "[]")).Append("</pre></section>");
            html.Append("<details><summary>Технический JSON</summary><pre>").Append(Escape(result.ToJsonString())).Append("</pre></details>");
        }
        html.Append("</main></body></html>");
        byte[] bytes = Encoding.UTF8.GetBytes(html.ToString()); context.Response.ContentType = "text/html; charset=utf-8";
        context.Response.ContentLength = bytes.Length; DomainHttp.ApplyHeaders(context); await context.Response.Body.WriteAsync(bytes, ct);
    }
    static string Status(string value) => value switch { "prepared" => "подготовлен", "completed" => "завершен", "completed_with_validation_warnings" => "завершен с предупреждениями", "failed" => "ошибка", _ => value };
    internal static JsonObject Draft(JsonObject input)
    {
        JsonNode? Strip(JsonNode? node) => node switch
        {
            JsonObject obj => new JsonObject(obj.Where(p => !new[] { "provenance", "status", "severity", "risk", "risk_class", "overall_risk", "confidence" }.Contains(p.Key)).Select(p => KeyValuePair.Create(p.Key, Strip(p.Value)))) { ["provenance"] = LegacyHttpReader.Provenance() },
            JsonArray array => new JsonArray(array.Select(Strip).ToArray()),
            _ => node?.DeepClone()
        };
        var result = new JsonObject { ["provenance"] = LegacyHttpReader.Provenance() };
        foreach (string key in new[] { "job", "ai_call_performed", "validation_errors" }) if (input.ContainsKey(key)) result[key] = input[key]?.DeepClone();
        bool called = Text(input, "ai_call_performed") == "true";
        result["status"] = Text(input, "status") == "failed" ? "failed" : !called && Text(input, "status") == "prepared_blocked_by_leak_check" ? "prepared_blocked_by_leak_check" : called ? input["validation_errors"] is JsonArray { Count: > 0 } ? "completed_with_validation_warnings" : "completed" : "prepared";
        foreach (string key in new[] { "analysis", "raw_response" }) if (input.ContainsKey(key)) result[key] = Strip(input[key]);
        return result;
    }
}
