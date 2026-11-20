using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Semantic;

namespace Sli.Server.Legacy;

internal sealed record LegacyEventCount(int EventId, string Channel, string Provider, long Total);
internal static class LegacyReportContext
{
    private static readonly JsonArray Catalog = LoadCatalog();
    private static JsonArray LoadCatalog()
    {
        using var stream = typeof(LegacyReportContext).Assembly.GetManifestResourceStream("Sli.Server.Semantic.Risk.event_catalog.json")!;
        return JsonNode.Parse(stream)!["entries"]!.AsArray();
    }
    internal static JsonObject Criticality(LegacyEventCount row)
    {
        string N(string? value) => (value ?? "").Trim().ToLowerInvariant();
        foreach (var (channel,provider) in new[] { (N(row.Channel),N(row.Provider)),(N(row.Channel),""),("",N(row.Provider)),("","") }) {
            var entry = Catalog.LastOrDefault(x => x.Number("event_id") == row.EventId && N(x.Text("channel")) == channel && N(x.Text("provider_name")) == provider);
            if (entry is not null) return new() { ["severity"] = entry.Text("severity") ?? "info", ["title"] = entry.Text("title") ?? $"{row.Channel} Event ID {row.EventId}",
                ["fix"] = entry.Text("fix") ?? "Проверить message/XML и соседние события.", ["why"] = entry.Text("why") ?? "Событие описано в локальном справочнике.",
                ["missing"] = entry.Text("missing") ?? "Provider, Level, Message, XML, EventData", ["catalog_status"]="catalog" };
        }
        return new() { ["severity"]="info",["title"]=$"{(row.Provider.Length > 0 ? row.Provider + ": " : "")}{row.Channel} Event ID {row.EventId}",
            ["fix"]="Добавить запись в config/event_catalog.json после проверки provider/message/XML.",
            ["why"]="Событие есть в журнале, но пока не классифицировано в локальном справочнике проекта.",
            ["missing"]="Provider, Level, Message, XML, EventData",["catalog_status"]="gap" };
    }
    internal static string DetailUrl(IEnumerable<int> ids, string[] servers, string? channel = null, int limit = 300)
    {
        var values = new List<(string,string)> { ("limit",limit.ToString(CultureInfo.InvariantCulture)),("order","desc"),("event_id",string.Join(",",ids)) };
        if (!string.IsNullOrEmpty(channel)) values.Add(("channel",channel));
        if (servers.Length > 0) values.Add(("server",string.Join(",",servers)));
        return "/reports/event-details.html?" + string.Join("&",values.Select(x => Uri.EscapeDataString(x.Item1) + "=" + Uri.EscapeDataString(x.Item2).Replace("%20","+")));
    }
    internal static int? ThreatScore(long totalEvents, IEnumerable<JsonNode?> correlations, IEnumerable<JsonNode?> criticality)
    {
        if (totalEvents == 0) return null;
        int Weight(string? risk) => risk switch { "critical"=>40,"high"=>25,"medium"=>10,"low"=>3,_=>0 };
        return Math.Clamp(correlations.Sum(x=>Weight(x.Text("risk"))) + criticality.Sum(x=>Weight(x.Text("severity"))),0,100);
    }
    internal static JsonObject DraftFinding(JsonObject hint)
    {
        var draft=(JsonObject)hint.DeepClone();
        draft["risk"]="unknown";
        draft["confidence"]="not_applicable";
        draft["provenance"]=new JsonObject { ["source"]="deterministic_hint",["authority"]="draft_only" };
        return draft;
    }
    internal static JsonArray FindingCards(IReadOnlyList<(string Risk,string Title,string Reason,string Action)> recommendations,
        JsonArray correlations, string[] servers)
    {
        var findings=new JsonArray();
        foreach (var item in correlations.OfType<JsonObject>()) {
            var correlation=DraftFinding(item);
            findings.Add(new JsonObject { ["title"]=correlation["scenario"].Copy(),["severity"]=correlation["risk"].Copy(),["provenance"]=correlation["provenance"].Copy(),
                ["facts"]=correlation["facts"].Copy(),["why_it_matters"]=correlation["meaning"].Copy(),["recommended_action"]=correlation["recommendation"].Copy(),
                ["confidence"]=correlation["confidence"].Copy(),["missing_data"]=correlation["missing_data"].Copy() ?? JsonValue.Create("инициатор, целевой объект, raw XML, соседние события"),["evidence_refs"]=new JsonArray() });
        }
        foreach (var rec in recommendations) {
            var evidence = new JsonArray();
            int[] ids = Regex.Matches(rec.Title + " " + rec.Reason,@"\b(\d{3,5})\b").Select(x => int.Parse(x.Value,CultureInfo.InvariantCulture)).Distinct().Take(5).ToArray();
            if (ids.Length > 0) evidence.Add(new JsonObject { ["label"]="Event ID " + string.Join(", ",ids),["servers"]=JsonSerializer.SerializeToNode(servers),
                ["actor"]="см. Subject/EventData",["target"]="см. Target/EventData",["source"]="см. Source/EventData",["detail_url"]=DetailUrl(ids,servers,limit:500),["neighbors_url"]=DetailUrl(ids,servers,limit:500) });
            findings.Add(new JsonObject { ["title"]=rec.Title,["severity"]="unknown",["provenance"]=new JsonObject { ["source"]="deterministic_hint",["authority"]="draft_only" },
                ["facts"]=rec.Reason,["why_it_matters"]="Рекомендация сформирована из агрегатов Event ID, каналов и покрытия логирования.",["recommended_action"]=rec.Action,
                ["confidence"]="not_applicable",["missing_data"]="raw XML, EventData, пользователь, источник, процесс или baseline - если применимо",["evidence_refs"]=evidence });
        }
        return new JsonArray(findings.Take(6).Select(x=>x.Copy()).ToArray());
    }
    internal static JsonObject Build(long job, string[] servers, IReadOnlyList<LegacyEventCount> rows, string? first, string? last,
        IReadOnlyList<(string Risk,string Title,string Reason,string Action)> recommendations, bool overview, string? timezoneName = null)
    {
        long total = rows.Sum(x => x.Total);
        var channels = rows.GroupBy(x => x.Channel).Select(g => new { Channel=g.Key, Count=g.Sum(x => x.Total) }).OrderByDescending(x => x.Count).ToArray();
        var top = rows.GroupBy(x => (x.EventId,x.Channel)).Select(g => new LegacyEventCount(g.Key.EventId,g.Key.Channel,"",g.Sum(x => x.Total))).OrderByDescending(x => x.Total).FirstOrDefault();
        var coverage = new JsonArray();
        string[] expected = ["Security","System","Directory Service","DNS Server","Microsoft-Windows-PowerShell/Operational","Microsoft-Windows-TaskScheduler/Operational"];
        string[] channelNames = ["Базовый канал безопасности","Системный журнал","Directory Service","DNS Server","PowerShell Operational","Task Scheduler Operational"];
        string[] channelHints = ["Должны быть видны входы, изменения учетных записей, групп и аудита.","Нужен для системных ошибок и состояния служб.","Нужен для контроля событий AD DS.","Нужен для контроля DNS на DC.","Нужен для расследований PowerShell-активности.","Нужен для контроля задач планировщика."];
        void AddCoverage(string channel, JsonNode id, string name, string source, bool present) => coverage.Add(new JsonObject {
            ["channel"]=channel,["event_id"]=id,["name"]=name,["source"]=source,["status"]=present ? "Собирается" : "Не видно",
            ["recommendation"]=present ? "Оставить контроль включенным." : "Проверить расширенное логирование и период сбора." });
        for (int i=0;i<expected.Length;i++) AddCoverage(expected[i],JsonValue.Create("-")!,channelNames[i],channelHints[i],channels.Any(x => x.Channel == expected[i]));
        int[] controls = [4624,4625,4634,4672,4719,4720,4722,4728,4732,4740,4768,4769,1102];
        string[] names = ["Logon success","Logon failure","Logoff","Special Logon","Audit Policy Change","User Account Created","User Account Enabled","Member added to privileged global group","Member added to local/domain local group","Account Lockout","Kerberos Authentication Service","Kerberos Service Ticket Operations","Security log cleared"];
        string[] hints = ["Logon Success","Logon Failure","Logoff Success","Special Logon","Audit Policy Change","User Account Management","User Account Management","Security Group Management","Security Group Management","Account Lockout","Kerberos Authentication Service","Kerberos Service Ticket Operations","Критичный контроль целостности журналов"];
        for (int i=0;i<controls.Length;i++) AddCoverage("Security",JsonValue.Create(controls[i])!,names[i],
            (i == 12 ? "" : i is 10 or 11 ? "DC additions: " : "Microsoft minimum audit policy: ") + hints[i] + ".",rows.Any(x => x.EventId == controls[i]));
        int missing = coverage.Count(x => x.Text("status") != "Собирается");
        var events = new JsonArray(); var criticality = new JsonArray(); int high = 0;
        foreach (var row in rows) {
            var c = Criticality(row); string risk = c.Text("severity")!;
            criticality.Add(c);
            if (risk is "critical" or "high") high++;
            events.Add(new JsonObject { ["risk"]=Display(risk),["event_id"]=row.EventId,["channel"]=row.Channel,["provider_name"]=row.Provider,["count"]=row.Total,
                ["description"]=c["title"].Copy(),["why"]=c["why"].Copy(),["action"]=c["fix"].Copy(),["missing"]=c["missing"].Copy(),["detail_url"]=DetailUrl([row.EventId],servers,row.Channel) });
        }
        var correlations = new JsonArray();
        if (total == 0) correlations.Add(new JsonObject { ["risk"]="high",["scenario"]="Нет данных для анализа",["facts"]="В базе нет событий по выбранному серверу или группе серверов.",
            ["meaning"]="Система не может подтвердить состояние безопасности этого DC по журналам. Это чаще эксплуатационная проблема сбора, но для ИБ это слепая зона.",
            ["recommendation"]="Проверить сетевую доступность, имя DC, права чтения журналов, состояние служб Event Log/Remote Event Log Management и ошибки последней задачи." });
        int? score = ThreatScore(total,correlations,criticality);
        string noise = top is null ? "нет событий" : $"{top.Channel} {top.EventId} / {top.Total}";
        string period = first is null || last is null ? "нет данных"
            : Sli.Server.Reporting.ReportTime.Report(first, timezoneName) + " -> " + Sli.Server.Reporting.ReportTime.Report(last, timezoneName);
        string duration = "-";
        if (DateTimeOffset.TryParse(first,CultureInfo.InvariantCulture,DateTimeStyles.AssumeUniversal,out var a) && DateTimeOffset.TryParse(last,CultureInfo.InvariantCulture,DateTimeStyles.AssumeUniversal,out var b)) {
            long minutes = Math.Max(0,(long)(b-a).TotalMinutes); duration = minutes >= 60 ? $"{minutes/60}ч {minutes%60}м" : $"{minutes}м";
        }
        string channelHint = channels.Length == 0 ? "нет каналов с событиями" : string.Join(", ",channels.Take(4).Select(x => $"{x.Channel} {x.Count}"));
        var kpis = new JsonArray();
        void Kpi(object value,string name,string hint,string risk) => kpis.Add(new JsonObject { ["value"]=JsonSerializer.SerializeToNode(value),["name"]=name,["hint"]=hint,["risk"]=risk });
        Kpi(total,"событий собрано",channelHint,"info");
        Kpi(top is null || total == 0 ? "0%" : Math.Round(top.Total*100.0/total,MidpointRounding.ToEven).ToString(CultureInfo.InvariantCulture)+"%","главный Event ID",top is null ? "нет событий" : $"{top.Channel} / {top.EventId} / {top.Total}",top is null ? "info" : "medium");
        Kpi(duration,"период наблюдения",period,"info"); Kpi(high,"High/Critical finding","по текущим правилам критичности",high > 0 ? "high" : "low");
        Kpi(missing,"контролей не видно","каналы и Event ID baseline",missing > 0 ? "medium" : "low"); Kpi(channels.Length,"каналов с данными","факт по PostgreSQL","info");
        var findings = FindingCards(recommendations,correlations,servers); var actions = new JsonArray();
        foreach (var correlation in correlations) {
            actions.Add(new JsonObject { ["risk"]=correlation!["risk"].Copy(),["title"]=correlation["scenario"].Copy(),["body"]=correlation["meaning"].Copy(),["points"]=new JsonArray(correlation["facts"].Copy(),correlation["recommendation"].Copy()) });
        }
        foreach (var rec in recommendations) {
            actions.Add(new JsonObject { ["risk"]=rec.Risk,["title"]=rec.Title,["body"]=rec.Reason,["points"]=new JsonArray(rec.Action) });
        }
        if (missing > 0) actions.Add(new JsonObject { ["risk"]="medium",["title"]="Улучшить покрытие логирования",["body"]="Часть каналов или Event ID не видна в текущей базе. Это ограничивает уверенность анализа.",
            ["points"]=new JsonArray("Проверить период сбора и ошибки последней задачи.","Сверить настройки с ручным скриптом расширения аудита.","Не трактовать 'не видно' как отсутствие угрозы.") });
        var facts = new JsonArray($"Всего событий в PostgreSQL: {total}.",$"Окно наблюдения: {period}.",$"Каналы: {channelHint}.");
        if (top is not null) facts.Add($"Топ Event ID: {top.EventId} в канале {top.Channel} ({top.Total} событий).");
        if (overview) facts.Add($"Job ID анализа: {job}.");
        return new() { ["title"]=overview ? "Локальный аналитический отчёт: обзор контроллеров домена" : "Локальный аналитический отчёт: контроллер домена " + servers.Single(),
            ["subtitle"]="Цель отчета - быстро ответить, что требует внимания, почему это важно, какие факты есть, каких данных не хватает и какие действия выполнить в первую очередь.",
            ["scope_name"]=string.Join(", ",servers),["period_text"]=period,
            ["period_tooltip"]=first is null || last is null ? "" : Sli.Server.Reporting.ReportTime.WithContext(first)["tooltip"] + " -> " + Sli.Server.Reporting.ReportTime.WithContext(last)["tooltip"],
            ["total_events"]=total,["main_noise"]=noise,["main_noise_class"]=top is null ? "" : "warn",
            ["coverage_status"]=missing == 0 ? "полное" : $"неполное: {missing} не видно",["coverage_class"]=missing == 0 ? "ok" : "danger",["analysis_mode"]="local_rules",
            ["risk_score"]=total == 0 ? null : JsonValue.Create(score),["risk_note"]=total == 0 ? "Оценка угрозы недоступна: событий нет; состояние видимости показано отдельно." : score >= 70 ? "Высокая оценка угрозы по наблюдаемым событиям и корреляциям." : score >= 40 ? "Средняя оценка угрозы: наблюдаемые признаки требуют проверки." : score > 0 ? "Низкая оценка угрозы по доступным наблюдаемым признакам." : "Наблюдаемые признаки угроз не найдены; это не доказывает отсутствие активности.",
            ["kpis"]=kpis,["main_conclusion"]=total == 0 ? "По выбранному контроллеру домена нет событий в базе. Главный вывод относится к качеству сбора: это слепая зона мониторинга." : recommendations.Count > 0 ? $"В текущей выборке нет доказательства инцидента, но нужно проверить: {recommendations[0].Title}. Главный шум: {noise}." : "Явных первичных признаков риска в текущей выборке нет. Нужны более длинный период и baseline.",
            ["main_limitation"]=total == 0 ? "Отчет не может оценить состояние DC без событий. Нужно сначала устранить проблему сбора или доступа к журналам." : missing > 0 ? $"Не видны {missing} контрольных канала или Event ID. Это риск слепой зоны, а не доказательство отсутствия угроз." : "Анализ строится на текущем окне событий и локальных правилах. Для уверенных выводов нужны baseline и внешний ИИ-слой.",
            ["channel_rows"]=new JsonArray(channels.Select(x => (JsonNode)new JsonObject { ["channel"]=x.Channel,["count"]=x.Count }).ToArray()),
            ["actions"]=new JsonArray(actions.Take(3).Select(x => x.Copy()).ToArray()),["findings"]=new JsonArray(findings.Take(6).Select(x => x.Copy()).ToArray()),["coverage_rows"]=coverage,["correlation_rows"]=correlations,["event_rows"]=events,["source_facts"]=facts,
            ["assumptions"]=new JsonArray("Текущий слой анализа локальный; внешний ИИ-провайдер пока не подключен.","Отсутствие события или канала означает 'не видно в текущей базе', а не доказанное отсутствие активности.","Уверенность ограничена коротким периодом сбора и полнотой EventData/XML.","Рекомендации являются read-only аналитикой и не выполняют действий в AD."),
            ["server_links"]=overview ? new JsonArray(servers.Select(s => (JsonNode)new JsonObject { ["name"]=LegacyAnalysis.SafeName(s),["file"]=$"server-{LegacyAnalysis.SafeName(s)}-security-profile.html",["url"]=$"/reports/server-{LegacyAnalysis.SafeName(s)}-security-profile.html" }).ToArray()) : new JsonArray() };
    }
    internal static string Display(string risk) => risk switch { "critical"=>"Critical","high"=>"High","medium"=>"Medium","low"=>"Low",_=>"Info" };
    internal static string E(object? value) => WebUtility.HtmlEncode(Convert.ToString(value,CultureInfo.InvariantCulture) ?? "");
}
