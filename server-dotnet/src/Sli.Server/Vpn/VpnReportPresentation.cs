using System.Text.Json.Nodes;

namespace Sli.Server.Vpn;

public static partial class VpnReports
{
    internal static string OutcomeText(JsonObject row)
    {
        string result=row["outcome"].Text("result");
        if(result is "success" or "failure") return result=="success"?"успех":"отказ";
        string fact=row.Text("authentication_fact"),code=row["source_native"].Text("result_code").Trim().ToLowerInvariant();
        return fact switch
        {
            "observed_successful_logon"=>"успех",
            "observed_failed_logon" or "observed_kerberos_preauth_failure" or "observed_kerberos_service_ticket_failure"=>"отказ",
            "observed_credential_validation" when code!=""=>code is "0" or "0x0"?"успех":"отказ",
            _=>"не зафиксирован"
        };
    }

    static string CombinedState(JsonObject branches)
    {
        var loaded=branches.Select(b=>b.Value!).Where(b=>b.Text("state")!="not_requested").ToArray();
        var states=loaded.Select(b=>b.Text("state")).ToHashSet();
        if(loaded.Any(b=>b.Text("reason")=="source_read_timeout")) return "partial";
        if(states.Contains("processing")) return "processing";
        if(states.Contains("stale")) return "stale";
        if(states.Contains("partial") || states.Overlaps(["ok","empty"]) && states.Overlaps(["error","denied","not_collected"])) return "partial";
        if(states.Contains("ok")) return "ok";
        if(states.Contains("empty")) return "empty";
        return states.SetEquals(["denied"])?"denied":states.SetEquals(["not_collected"])?"not_collected":"error";
    }

    internal static JsonObject SourceBranch(JsonObject raw,string source,bool empty=false)
    {
        var notes=new List<JsonObject>();
        void Note(string code,string text,object? parameters=null)
        {
            var note=VpnJson.Obj(new {code,text});if(parameters is not null) note["params"]=System.Text.Json.JsonSerializer.SerializeToNode(parameters);notes.Add(note);
        }
        string state=raw.Text("state"),reason=raw.Text("unavailable_reason");
        if(source=="accounting")
        {
            foreach(var text in raw["limitations"]?.AsArray()??[]) Note("vpn_note",text?.ToString()??"");
            string coverage=raw["coverage"] is JsonObject c?VpnSessions.CoverageState(c):"";
            string? coverageNote=coverage switch
            {
                "processing"=>"Часть событий RADIUS ещё обрабатывается.",
                "identity_incomplete"=>"Для части сессий не удалось определить учётную запись.",
                "partial"=>"Часть событий не сопоставлена с учётной записью или временем.",
                "not_collected"=>"События RADIUS для этого домена не собраны.",_=>null
            };
            if(coverageNote is not null) Note("coverage_"+coverage,coverageNote);
            if(state is "not_authorized" or "unavailable" or "not_collected") Note("vpn_source_unreadable","Источник VPN-сессий сейчас не читается (нет собранных данных RADIUS или прав на их чтение). Отсутствие строк не означает отсутствия подключений.");
        }
        if(source=="nps")
        {
            Note("authorizations_meaning","6272 — разрешено, 6273 — отказано; это самостоятельные факты NPS, а не начало или конец VPN-сессии.");
            if(state is not ("available" or "partial")) Note("authorizations_unavailable","Решения NPS для этого окна недоступны или не собраны; отсутствие строк не означает отсутствия попыток.");
        }
        if(source=="windows_heatmap") Note(state=="available"?"windows_heatmap_meaning":"windows_heatmap_unavailable",state=="available"?"Отказы посчитаны за всё окно (не шире 90 дней), а не по показанной странице событий; это наблюдаемые факты, а не вывод об атаке.":"Тепловая карта недоступна: проверьте доступ, источник и окно не шире 90 дней. Отсутствие данных не означает отсутствия отказов.");
        if(source=="windows")
        {
            Note("windows_meaning","Независимые наблюдаемые факты Windows Security; строки не образуют сессии и не связаны с NPS или RADIUS Accounting.");
            string? stateNote=state switch
            {
                "not_authorized"=>"Назначение не включает одновременно vpn.audit и просмотр событий Windows в этом домене.",
                "not_collected"=>"Сбор подходящих событий Windows Security для домена не подтверждён.",
                "empty_unverified"=>"В сохранённых данных окна факты не найдены, но полнота источника не подтверждена.",
                "coverage_unverified"=>"Полнота источника в выбранном окне не подтверждена.",
                "available" or "partial"=>null,_=>"Факты аутентификации Windows недоступны: проверьте источник и окно не шире 90 дней. Отсутствие строк не означает отсутствия событий."
            };
            if(stateNote is not null) Note(state is "not_authorized" or "not_collected" or "empty_unverified" or "coverage_unverified"?"windows_"+state:"windows_unavailable",stateNote);
            if(raw["result_window"].Flag("truncated")) Note("windows_truncated","В показанной выборке первые "+raw["result_window"].Text("returned_event_count")+" событий; список обрезан. Сигналы рассчитываются отдельно; отсутствие события в выборке не является отрицательным выводом.",new {count=raw["result_window"]?["returned_event_count"]?.DeepClone()});
            var policy=raw["manual_review_policy"];
            bool whole=policy.Text("coverage_scope")=="whole_period";
            if(policy is JsonObject {Count:>0})
            {
                if(policy.Text("coverage_scope")=="not_evaluated") Note("windows_review_unavailable","Проверка сигналов за весь период не завершена. Показанные события сохранены; отсутствие сигналов не означает отсутствия атак.");
                else
                {
                    Note(whole?"windows_review_whole_period":"windows_review_sample",whole?"Сигналы рассчитаны по всему периоду сохранённых данных.":"Сигналы рассчитаны только в показанной выборке.");
                    if(policy.Text("state")=="no_observed_signal_unverified") Note("windows_review_no_signal","Пороги правил не достигнуты; это не доказывает отсутствия подбора паролей.");
                    if(policy.Flag("signals_truncated")) Note("windows_review_truncated","Список сигналов обрезан; охват расчёта указан отдельно.");
                    if(whole) Note("windows_review_first_windows","Показано первое подходящее окно для каждого IP и первое распределённое окно. Правила не доказывают использование одного пароля.");
                }
            }
            foreach(var signal in policy?["signals"]?.AsArray().OfType<JsonObject>()??[])
            {
                var parameters=VpnJson.Obj(new {source=signal.Text("source_ip"),failures=signal["failure_fact_count"]?.DeepClone(),accounts=signal["distinct_target_sid_count"]?.DeepClone(),minutes=policy?["conditions"]?["rolling_window_minutes"]?.DeepClone(),sources=signal["distinct_source_count"]?.DeepClone(),hours=policy?["distributed_conditions"]?["rolling_window_hours"]?.DeepClone(),maximum=policy?["distributed_conditions"]?["maximum_failures_per_target"]?.DeepClone(),from=signal["window"]?["from_utc"]?.DeepClone(),to=signal["window"]?["to_utc_exclusive"]?.DeepClone(),@event=signal["evidence_event_db_id"]?.DeepClone()});
                bool distributed=signal.Text("rule")=="distributed";
                string text=distributed?$"Распределённый подбор паролей: сигнал для ручной проверки, не вердикт. {parameters.Text("accounts")} SID, {parameters.Text("failures")} отказов, {parameters.Text("sources")} источников за окно до {parameters.Text("hours")} ч, не более {parameters.Text("maximum")} отказов на SID.":$"Сигнал для ручной проверки: IP {parameters.Text("source")} — {parameters.Text("failures")} наблюдаемых отказов по {parameters.Text("accounts")} SID за {parameters.Text("minutes")} мин. Не вердикт; это не вывод об атаке.";
                Note(distributed?"windows_distributed_review":"windows_manual_review",text+$" Окно {parameters.Text("from")} — {parameters.Text("to")}. Событие {parameters.Text("event")}.",parameters);
            }
            foreach(var limitation in raw["limitations"]?.AsArray()??[])
            {
                string code=limitation?.ToString()??"";
                string? text=code switch
                {
                    "source_events_not_windows_sessions"=>"Строки — самостоятельные события источника; Windows-сессия и длительность из них не восстановлены.",
                    "manual_review_signal_not_attack_verdict"=>"Сигнал ручной проверки не является выводом об атаке.",
                    "empty_window_source_completeness_not_proven"=>"Пустое окно не доказывает полноту источника.",
                    "unknown_results_remain_unknown"=>"Если код результата не сохранён, результат неизвестен и не считается отказом.",
                    "source_completeness_not_proven"=>"Полнота источника за выбранный период не подтверждена.",
                    "earlier_failure_context_displayed_sample_only"=>"Связи с более ранними отказами относятся только к показанной выборке.",_=>null
                };
                if(text is not null) Note("windows_"+code,text);
            }
        }
        var branch=Branch(raw,empty);
        // Accounting coverage can be incomplete even when the engine returned rows.
        if(reason!="source_read_timeout" && (State(state) is "ok" or "empty" or "partial") && raw["coverage"] is JsonObject coverageRow && coverageRow.ContainsKey("total_delivery_count"))
        {
            string coverageState=State(VpnSessions.CoverageState(coverageRow));
            if(coverageState is "processing" or "not_collected" or "partial") branch["state"]=coverageState;
        }
        reason=branch.Text("reason");
        if(reason=="source_read_timeout") notes.Insert(0,VpnJson.Obj(new {code="source_read_timeout",text="Чтение заняло слишком много времени. Результат неполный; показаны только полученные данные. Повторите попытку или сократите период."}));
        if(reason=="result_truncated") notes.Insert(0,VpnJson.Obj(new {code="result_truncated",text="Событий больше, чем можно показать за один раз. Список неполный; сократите период, чтобы увидеть остальные события."}));
        if(reason=="review_input_limit") notes.Insert(0,VpnJson.Obj(new {code="review_input_limit",text="Событий слишком много для полной проверки сигналов. История показана частично; отсутствие сигналов не означает отсутствия атак."}));
        branch["limitations"]=VpnJson.Array(notes);
        branch["limits"]!["max_period_days"]=source is "windows" or "windows_heatmap"?90:366;
        return branch;
    }
}
