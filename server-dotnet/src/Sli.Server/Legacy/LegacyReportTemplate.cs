using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Semantic;
using static Sli.Server.Legacy.LegacyReportContext;

namespace Sli.Server.Legacy;

// Markup, inline CSS and JS are copied from reporting/report_template.py and report_ui.py.
// Replace template tokens in one pass: source strings can never inject another token.
internal static class LegacyReportTemplate
{
    private static readonly string Template = ReadTemplate();
    private static string ReadTemplate()
    {
        using var stream = typeof(LegacyReportTemplate).Assembly.GetManifestResourceStream("Sli.Server.Legacy.report-template.html")!;
        using var reader = new StreamReader(stream); return reader.ReadToEnd();
    }
    private static IEnumerable<JsonNode> Rows(JsonNode? rows) => rows?.AsArray().OfType<JsonNode>() ?? [];
    private static string List(JsonNode? rows) => !Rows(rows).Any() ? "<p class=\"muted\">Нет данных.</p>" : "<ul>" + string.Concat(Rows(rows).Select(x => "<li>" + E(x) + "</li>")) + "</ul>";
    private static string Badge(string risk) => $"<span class=\"risk-badge risk-{E(risk.ToLowerInvariant())}\">{E(risk)}</span>";
    private static string Pill(string label,JsonNode? value,string cls="") => $"<span class=\"pill {E(cls)}\"><strong>{E(label)}:</strong> {E(value)}</span>";
    internal static string Render(JsonObject context)
    {
        string Cards(string key,Func<JsonNode,string> render) => string.Concat(Rows(context[key]).Select(render));
        var values = context.ToDictionary(x => x.Key,x => E(x.Value));
        values["pill_scope_name"]=Pill("Объект",context["scope_name"]);
        values["pill_period_text"]=$"<span class=\"pill\" title=\"{E(context["period_tooltip"])}\"><strong>Окно наблюдения:</strong> {E(context["period_text"])}</span>";
        values["pill_total_events"]=Pill("Событий",context["total_events"]); values["pill_analysis_mode"]=Pill("Режим",context["analysis_mode"]);
        values["pill_main_noise"]=Pill("Главный шум",context["main_noise"],context.Text("main_noise_class") ?? "");
        values["pill_coverage_status"]=Pill("Покрытие",context["coverage_status"],context.Text("coverage_class") ?? "");
        values["score_text"]=context["risk_score"] is null ? "—" : E(context["risk_score"]) + "<span>/100</span>";
        values["score_width"]=Math.Clamp(context.Number("risk_score"),0,100).ToString(CultureInfo.InvariantCulture);
        values["kpis"]=Cards("kpis",x=>$"<div class=\"card kpi-card {E(x.Text("risk"))}\"><div class=\"value\">{E(x["value"])}</div><div class=\"name\">{E(x["name"])}</div><div class=\"hint\">{E(x["hint"])}</div></div>");
        values["actions"]=Cards("actions",x=>$"<div class=\"card action {E(x.Text("risk"))}\"><h3>{E(x["title"])}</h3><p class=\"muted\">{E(x["body"])}</p>{List(x["points"])}</div>");
        values["findings"]=Cards("findings",x=>$"<div class=\"card {E(x.Text("severity"))}\"><div class=\"finding-title\"><h3>{E(x["title"])}</h3>{Badge(x.Text("severity") ?? "info")}</div><p><strong>Факт:</strong> {E(x["facts"])}</p><p><strong>Почему важно:</strong> {E(x["why_it_matters"])}</p><p><strong>Действие:</strong> {E(x["recommended_action"])}</p>{Evidence(x["evidence_refs"])}<p class=\"confidence\">Уверенность: {E(x["confidence"])}. Недостающие данные: {E(x["missing_data"])}</p></div>");
        values["coverage_rows"]=Cards("coverage_rows",x=>$"<div>{E(x["name"])}{(x["event_id"]!.ToString() == "-" ? "" : " (" + E(x["event_id"]) + ")")}</div><div class=\"{(x.Text("status") == "Собирается" ? "status-ok" : "status-miss")}\">{E(x["status"])}</div><div>{E(x["source"])} {E(x["recommendation"])}</div>");
        values["correlation_rows"]="<table><thead><tr><th>Риск</th><th>Сценарий</th><th>Факты</th><th>Пояснение</th><th>Что проверить</th><th>Уверенность</th></tr></thead><tbody>" + Cards("correlation_rows",x=>$"<tr><td>{Badge(Display(x.Text("risk") ?? "info"))}</td><td>{E(x["scenario"])}</td><td>{E(x["facts"])}</td><td>{E(x["meaning"])}</td><td>{E(x["recommendation"])}</td><td>{E(x.Text("confidence") ?? "средняя")}</td></tr>") + "</tbody></table>";
        values["channel_rows"]=Timeline(context["channel_rows"]);
        values["event_rows"]=string.Concat(Rows(context["event_rows"]).Select(x => x.Text("channel")).Where(x => !string.IsNullOrEmpty(x)).Distinct().Order(StringComparer.Ordinal).Select(x=>"<option>"+E(x)+"</option>"));
        // The default System.Text.Json encoder escapes < > & and both line separators.
        // Keep JSON inside the script safe even for adversarial channel/provider names.
        values["event_rows_json"]=(context["event_rows"] ?? new JsonArray()).ToJsonString();
        values["source_facts"]=List(context["source_facts"]); values["assumptions"]=List(context["assumptions"]);
        values["server_links_section"]=!Rows(context["server_links"]).Any() ? "" : "<section id=\"servers\"><h2>7. Отчеты по контроллерам домена</h2><table><thead><tr><th>Сервер</th><th>Отчет</th></tr></thead><tbody>" + Cards("server_links",x=>$"<tr><td>{E(x["name"])}</td><td><a href=\"{E(x["url"])}\">{E(x["file"])}</a></td></tr>") + "</tbody></table></section>";
        return Regex.Replace(Template,@"@@([a-z_]+)@@",m=>values.TryGetValue(m.Groups[1].Value,out string? value) ? value : throw new InvalidDataException("legacy_report_template_token_invalid"));
    }
    private static string Evidence(JsonNode? refs)
    {
        if (!Rows(refs).Any()) return "<p class=\"muted evidence-empty\">Evidence-ссылки появятся после привязки finding к конкретным Event ID.</p>";
        return "<div class=\"evidence-box\"><div class=\"evidence-title\">Evidence</div>" + string.Concat(Rows(refs).Select(x=>$"<div class=\"evidence-ref\"><div class=\"evidence-meta\"><strong>{E(x["label"])}</strong> · servers: {E(string.Join(", ",Rows(x["servers"])))}</div><div class=\"evidence-fields\"><span>actor: {E(x["actor"])}</span><span>target: {E(x["target"])}</span><span>source: {E(x["source"])}</span></div><div class=\"evidence-actions\"><a class=\"detail-link\" href=\"{E(x["detail_url"])}\">Открыть события-доказательства</a><a class=\"detail-link secondary\" href=\"{E(x["neighbors_url"])}\">Соседние события ±15 минут</a></div></div>")) + "</div>";
    }
    private static string Timeline(JsonNode? rows)
    {
        long total = Rows(rows).Sum(x=>x.Number("count")); if (total <= 0) return "<div class=\"callout\">Нет событий для распределения по каналам.</div>";
        string Class(JsonNode row) { string c=row.Text("channel")!.ToLowerInvariant(); return c.Contains("security") ? "security" : c.Contains("dns") ? "dns" : c.Contains("system") ? "system" : "other"; }
        return "<div class=\"timeline\">" + string.Concat(Rows(rows).Select(x=>$"<div class=\"seg {Class(x)}\" style=\"width:{Math.Max(2,Math.Round(x.Number("count")*100.0/total,2,MidpointRounding.ToEven)).ToString(CultureInfo.InvariantCulture)}%\"></div>")) + "</div><div class=\"legend\">" + string.Concat(Rows(rows).Select(x=>$"<span><i class=\"dot {Class(x)}\"></i>{E(x["channel"])} - {E(x["count"])}</span>")) + "</div>";
    }
}
