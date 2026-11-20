using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Semantic;

namespace Sli.Server.Reporting.V2;

public sealed class RuleQualityReader(ISemanticDatabase database) : IReportV2Reader
{
    public string OwnerId => "sli.core";
    public bool Handles(string key) => key == "security.rule-quality";
    internal const string CohortSql = """
        with cohort as (
            select f.id,f.rule_code,f.created_at,f.repeat_count,f.evidence_count from findings_active f
            where is_semantic_finding_published_v1(f.id) and f.created_at >= $1 and f.created_at < $2
              and ($3::bigint[] is null or (exists(select 1 from finding_event_details337 e where e.finding_id=f.id)
                and not exists(select 1 from finding_event_details337 e
                    where e.finding_id=f.id and (e.domain_id is null or not(e.domain_id=any($3))))))
            order by f.created_at,f.id limit 10001)
        select f.*,semantic_finding_suppressed_v160(f.id,f.rule_code) as suppressed,coalesce(h.history,'[]'::jsonb) as history,
            (ev.total>0 and ev.total=f.evidence_count and ev.resolved=ev.total) as complete_evidence
        from cohort f left join lateral (
            select jsonb_agg(jsonb_build_object('id',id,'old_status',old_status,'new_status',new_status,'changed_at',changed_at) order by changed_at,id) as history
            from finding_status_history where finding_id=f.id and changed_at<$2) h on true
        left join lateral (select count(*) as total,count(*) filter(where e.event_id is not null and e.time_created_utc is not null
            and e.event_record_id is not null and e.channel is not null) as resolved
            from finding_event_details337 e where e.finding_id=f.id) ev on true
        """;
    internal const string PoliciesSql = """
        select p.policy_id,p.policy_version,'semantic.'||(p.definition_json->>'scenario_kind') as rule_code,
            p.definition_json->>'result_class' as result_class,
            semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)='enabled' as enabled,a.policy_id is not null as managed
        from semantic_risk_policies p left join semantic_policy_admission a on a.policy_id=p.policy_id and a.policy_version=p.policy_version
        order by p.policy_id,p.policy_version
        """;
    internal static JsonObject[] Metrics(IEnumerable<JsonObject> findings, DateTimeOffset end, bool acceptedRisk = true)
    {
        static DateTimeOffset Time(JsonNode? value) => DateTimeOffset.Parse(value!.ToString(), CultureInfo.InvariantCulture).ToUniversalTime();
        static long N(JsonObject row, string key) => long.TryParse(row[key]?.ToString(), out long n) ? n : 0;
        var result = new List<JsonObject>();
        foreach (var group in findings.GroupBy(f => f.Text("rule_code")).OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            var counts = new Dictionary<string, long>(new[] { "confirmed", "false_positive", "closed", "accepted_risk", "suppressed", "repeated", "complete_evidence", "missing_history" }.Select(k => KeyValuePair.Create(k, 0L)));
            var durations = new List<double>();
            foreach (var f in group)
            {
                var created = Time(f["created_at"]);
                var history = f.Objects("history").Where(h => Time(h["changed_at"]) >= created && Time(h["changed_at"]) < end).OrderBy(h => Time(h["changed_at"])).ThenBy(h => N(h, "id")).ToArray();
                var transitions = history.Where(h => h.Text("new_status") != h.Text("old_status")).ToArray();
                var classification = transitions.LastOrDefault(h => h.Text("new_status") is "confirmed" or "false_positive" or "accepted_risk");
                if (classification is not null) counts[classification.Text("new_status")]++;
                if (history.LastOrDefault()?.Text("new_status") == "closed") counts["closed"]++;
                if (history.Length == 0) counts["missing_history"]++;
                if (transitions.FirstOrDefault(h => h.Text("new_status") is "confirmed" or "false_positive" or "closed" or "accepted_risk") is {} decision) durations.Add((Time(decision["changed_at"]) - created).TotalSeconds);
                if (f.Flag("suppressed")) counts["suppressed"]++;
                if (N(f, "repeat_count") > 0 || transitions.Any(h => h.Text("new_status") == "repeated")) counts["repeated"]++;
                if (f.Flag("complete_evidence")) counts["complete_evidence"]++;
            }
            long classified = counts["confirmed"] + counts["false_positive"]; int total = group.Count(); durations.Sort();
            var row = JsonSerializer.SerializeToNode(counts)!.AsObject(); row["rule_code"] = group.Key; row["findings_produced"] = total; row["classified"] = classified; row["decided"] = durations.Count;
            if (!acceptedRisk) row["accepted_risk"] = null;
            row["false_positive_rate"] = classified > 0 ? Math.Round(100.0 * counts["false_positive"] / classified, 2) : null;
            row["median_decision_seconds"] = durations.Count == 0 ? null : durations.Count % 2 == 1 ? durations[durations.Count / 2] : (durations[durations.Count / 2 - 1] + durations[durations.Count / 2]) / 2;
            row["repeat_rate"] = Math.Round(100.0 * counts["repeated"] / total, 2); row["complete_evidence_share"] = Math.Round(100.0 * counts["complete_evidence"] / total, 2); result.Add(row);
        }
        return result.ToArray();
    }
    public async Task<JsonObject> QueryAsync(ReportQueryContext c, CancellationToken ct)
    {
        var domains = c.Scope.DomainIds();
        var period = c.Params["period"]!.AsObject();
        var binding = new JsonObject { ["scope"] = c.Scope.Fingerprint, ["period"] = period["preset"]!.DeepClone(), ["sort"] = c.Paging.Sort, ["direction"] = c.Paging.Direction, ["principal"] = JsonSerializer.SerializeToNode(c.Principal), ["access"] = JsonSerializer.SerializeToNode(c.Access) };
        if (period.Text("preset") == "custom") { binding["start"] = period["from_utc"]!.DeepClone(); binding["end"] = period["to_utc"]!.DeepClone(); }
        JsonObject? after = c.Paging.Cursor is null ? null : JsonNode.Parse(ReportCursor.Decode(c.Paging.Cursor, binding)!)!.AsObject();
        var start = DateTimeOffset.Parse((after?["start"] ?? period["from_utc"])!.ToString(), CultureInfo.InvariantCulture).ToUniversalTime();
        var end = DateTimeOffset.Parse((after?["end"] ?? period["to_utc"])!.ToString(), CultureInfo.InvariantCulture).ToUniversalTime();
        if (start >= end || end - start > TimeSpan.FromDays(90) || after is not null && period.Text("preset") == "custom" && (start != DateTimeOffset.Parse(period.Text("from_utc"), CultureInfo.InvariantCulture) || end != DateTimeOffset.Parse(period.Text("to_utc"), CultureInfo.InvariantCulture))) throw new ReportRequestException("invalid_cursor");
        int offset = after?["offset"]?.GetValue<int>() ?? 0; if (offset < 0) throw new ReportRequestException("invalid_cursor");
        JsonArray findings, policies;
        try
        {
            await using var db = await database.OpenAsync(false, ct);
            findings = await db.QueryAsync(CohortSql, ct, start, end, domains); policies = await db.QueryAsync(PoliciesSql, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception)
        { var error = ReportResult.Create(c.Definition.Key, "error", limitations: new JsonArray(Note("unavailable", "Сохранённые данные качества правил недоступны. Оценка качества не выполнена."))); error["window"] = Window(start, end); return error; }
        bool truncated = findings.Count > 10000;
        var rows = Metrics(findings.OfType<JsonObject>().Take(10000), end, Sli.Server.Problems.FindingStatusInput.Statuses.Contains("accepted_risk"));
        foreach (var row in rows)
        {
            var matched = policies.OfType<JsonObject>().Where(p => p.Text("rule_code") == row.Text("rule_code")).ToArray();
            string[] classes = matched.Select(p => p.Text("result_class")).Distinct().ToArray(); row["rule_result_class"] = classes.Length == 1 && classes[0] is "security_incident" or "security_exposure" or "control_gap" ? classes[0] : null;
            foreach (string key in new[] { "policies", "admitted_policies", "managed_policies" }) row[key] = new JsonArray(matched.Where(p => key == "policies" || p.Flag(key == "admitted_policies" ? "enabled" : "managed")).Select(p => (JsonNode?)JsonValue.Create(p.Text("policy_id") + ":" + p["policy_version"])).ToArray());
        }
        string sort = c.Paging.Sort ?? "false_positive_rate"; bool descending = c.Paging.Sort is null || c.Paging.Direction == "desc";
        double Value(JsonObject r) => double.TryParse(r[sort]?.ToString(), NumberStyles.Float, CultureInfo.InvariantCulture, out double value) ? value : 0;
        var ordered = rows.OrderBy(r => r[sort] is null).ThenBy(r => descending ? -Value(r) : Value(r)).ThenBy(r => r.Text("rule_code"), StringComparer.Ordinal).ToArray();
        var page = ordered.Skip(offset).Take(c.Paging.Limit).Select(row => Present(row, start, end)).ToArray(); bool more = offset + c.Paging.Limit < rows.Length;
        var notes = new JsonArray(Note("basis", "Когорта — находки, созданные за период. Решения учитываются до конца периода; подавление, повторы, evidence и допуск policy — текущий снимок. Проценты рассчитаны по сохранённым данным, полнота сбора не доказана."), Note("classification", "Доля ложных срабатываний: FP / (FP + confirmed) по последней классификации каждой находки. Закрытие сохраняет классификацию; принятый риск исключён из знаменателя. Нет классификаций — нет оценки."), Note("policy_context", "Счётчики относятся к rule_code. Список policy и их допуск — текущий контекст, а не доказанная атрибуция находок конкретной версии policy."), Note("evidence", "Полные evidence здесь означают: все заявленные связи ведут к сохранённым фактам с кодом, временем, record ID и каналом. Полнота источника и наличие полного исходного текста этим не доказаны."));
        if (!Sli.Server.Problems.FindingStatusInput.Statuses.Contains("accepted_risk")) notes.Add(Note("accepted_risk_unavailable", "Статус принятого риска не поддерживается текущим lifecycle; метрика недоступна."));
        bool missing = rows.Any(r => r["missing_history"]!.GetValue<long>() > 0);
        if (truncated) notes.Add(Note("truncated", "Достигнут предел чтения 10 000 находок. Метрики и порядок частичные; сузьте период."));
        if (missing) notes.Add(Note("history_missing", "Для части находок нет сохранённой истории за выбранное окно. Решения и время до решения неполны."));
        var result = ReportResult.Create(c.Definition.Key, truncated || missing ? "partial" : rows.Length > 0 ? "ok" : "empty", new JsonArray(page.Select(r => (JsonNode?)r).ToArray()), new JsonObject { ["completeness"] = "not_proven", ["truncated"] = truncated, ["accepted_risk_supported"] = Sli.Server.Problems.FindingStatusInput.Statuses.Contains("accepted_risk") }, limitations: notes);
        result["filtered_count"] = rows.Length; result["has_more"] = more; result["next_cursor"] = more ? ReportCursor.Encode(binding, new JsonObject { ["start"] = start.ToString("O"), ["end"] = end.ToString("O"), ["offset"] = offset + c.Paging.Limit }.ToJsonString()) : null; result["window"] = Window(start, end); return result;
    }
    static JsonObject Window(DateTimeOffset start, DateTimeOffset end) => new() { ["from_utc"] = start.ToString("O"), ["to_utc_exclusive"] = end.ToString("O") };
    static JsonObject Note(string code, string text) => new() { ["code"] = code, ["text"] = text };
    static readonly Dictionary<string, string> Names = new() { ["semantic.qw.password-spray"] = "password_spray", ["semantic.qw.password-brute-force"] = "password_brute", ["semantic.qw.disabled-account-logon"] = "disabled_logon", ["semantic.qw.account-decoy"] = "account_decoy", ["semantic.qw.account-watch"] = "account_watch", ["semantic.qw.file-decoy"] = "file_decoy", ["semantic.qw.file-ransom"] = "file_ransom", ["semantic.qw.file-acl-broad-write"] = "file_acl", ["semantic.qw.nps-denials"] = "nps_denials", ["semantic.security.audit_controls_changed"] = "audit_controls_changed", ["semantic.security.privileged_group_member_added"] = "privileged_group_member_added", ["semantic.security.scheduled_task_created"] = "scheduled_task_created" };
    static JsonObject Present(JsonObject row, DateTimeOffset start, DateTimeOffset end)
    {
        row = row.Copy(); string suffix = Names.GetValueOrDefault(row.Text("rule_code"), row["rule_result_class"] is {} kind ? "metadata." + kind : "unknown"); var name = ReportResult.Message("reports.v2.security.rule-quality.names." + suffix);
        row["rule_name"] = name["text"]!.DeepClone(); row["presentation_messages"] = new JsonObject { ["rule_name"] = name };
        row["technical_details"] = new JsonArray(new JsonObject(new[] { "rule_code", "policies", "admitted_policies", "managed_policies", "closed", "accepted_risk", "suppressed", "classified", "median_decision_seconds", "decided", "repeat_rate" }.Select(k => KeyValuePair.Create(k, row[k]?.DeepClone()))));
        row["cohort_from"] = start.ToString("O"); row["cohort_to"] = end.ToString("O"); return row;
    }
}
