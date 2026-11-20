using System.Text.Json.Nodes;

namespace Sli.Server.Storage.EventReports;

// Port of event_card_semantics.build_event_card and event_semantic_contract.
// Meaning and field roles come from the admitted catalogue, never from Event ID alone.
internal static class EventCardSemantics
{
    internal static string Text(JsonNode? node) => node is JsonValue value && value.TryGetValue<bool>(out bool flag) ? flag ? "True" : "False" : node?.ToString() ?? "";
    static string Or(JsonNode? node,string fallback) => Text(node) is { Length:>0 } value ? value : fallback;
    static IEnumerable<string> Strings(JsonNode? node) => node is JsonArray a ? a.Select(Text) : [];
    static JsonArray Array(IEnumerable<string> values) => new(values.Select(v=>(JsonNode?)JsonValue.Create(v)).ToArray());
    static string Risk(string value,string unknown="unknown") => value.Trim().ToLowerInvariant() switch
    { "important" or "warning" or "warn"=>"medium", "critical"=>"critical", "high"=>"high", "medium"=>"medium", "low"=>"low", "info"=>"info", "unknown"=>"unknown", _=>unknown };
    static string Tier(string risk) => risk is "critical" or "high" ? "critical" : risk is "important" or "medium" ? "important" : "technical";
    static (string Label,string Class) RiskLabel(string risk) => risk switch
    { "critical" or "high"=>("Высокий риск","risk-high"), "medium"=>("Требует проверки","risk-medium"), "low"=>("Низкий риск","risk-low"), _=>("Информация","risk-info") };
    static string First(JsonObject item,IEnumerable<string> fields)
    {
        foreach(string field in fields)
        {
            var node=item.ContainsKey(field) ? item[field] : (item["event_data"] as JsonObject)?[field];
            if(node is JsonValue scalar && (scalar.TryGetValue<bool>(out bool flag) && !flag || scalar.TryGetValue<double>(out double number) && number==0)) continue;
            string value=Text(node).Trim(); if(value is not ("" or "-" or "—")) return value;
        }
        return "";
    }
    internal static string Category(string value,bool known)
    {
        value=value.Trim().ToLowerInvariant() switch { "auth" or "logon"=>"authentication", "account" or "accounts"=>"account_management", "privileges"=>"privilege_management", "services_tasks" or "service"=>"service_task", "event"=>"other", "infra"=>"infrastructure", var v=>v };
        return value is "authentication" or "account_management" or "privilege_management" or "policy_change" or "service_task" or "operations" or "infrastructure" or "other" or "unknown" ? value : known ? "other" : "unknown";
    }
    static bool Matches(JsonObject rule,JsonObject item,Dictionary<string,string> values)
    {
        foreach(var condition in rule["all"] as JsonArray ?? [])
        {
            string role=Text(condition?["role"]);
            string value=values.GetValueOrDefault(role,"");
            if(value.Length==0) value=First(item,Strings(condition?["fields"]));
            string normalized=value.ToLowerInvariant();
            if(condition?["microsoft_namespace"]?.GetValue<bool>()==true && !normalized.StartsWith("\\Microsoft\\Windows\\",StringComparison.OrdinalIgnoreCase)) return false;
            if(condition?["machine_or_system"]?.GetValue<bool>()==true && !(normalized.EndsWith('$') || normalized is "system" or "nt authority\\system")) return false;
            if(condition?["dc"]?.GetValue<bool>()==true && !Text(item["server"]).StartsWith("dc",StringComparison.OrdinalIgnoreCase)) return false;
            var contains=Strings(condition?["contains_any"]).Select(v=>v.ToLowerInvariant()).ToArray();
            string haystack=string.Join(' ',(item["event_data"] as JsonObject ?? []).Select(kv=>Text(kv.Value))).ToLowerInvariant();
            if(contains.Length>0 && !contains.Any(haystack.Contains)) return false;
        }
        return true;
    }
    internal static JsonObject Build(JsonObject item,JsonObject? entry,JsonObject? pack)
    {
        bool known=entry is not null;
        var card=entry?["card"] as JsonObject ?? [];
        var roles=card["field_roles"] as JsonObject ?? [];
        var values=roles.ToDictionary(kv=>kv.Key,kv=>First(item,Strings(kv.Value)));
        var missing=Strings(card["expected_roles"]).Where(role=>values.GetValueOrDefault(role,"").Length==0).ToArray();
        string technical=missing.Length==0 ? "" : "Не извлечены обязательные роли карточки: "+string.Join(", ",missing)+".";
        string severity=Or(entry?["severity"],"info"), assessment=Text(card["assessment"]), tier=Or(card["tier"],Tier(severity)), confidenceOverride=Text(card["confidence"]);
        JsonObject? matched=null; int? ruleIndex=null;
        var rules=card["risk_rules"] as JsonArray ?? [];
        for(int i=0;i<rules.Count;i++) if(rules[i] is JsonObject rule && Matches(rule,item,values))
        {
            matched=rule; ruleIndex=i; severity=Or(rule["severity"],severity); assessment=Text(rule["assessment"]);
            tier=Or(rule["tier"],Or(card["tier"],Tier(severity))); confidenceOverride=Text(rule["confidence"]); break;
        }
        bool hasCard=card.Count>0;
        string confidence=!hasCard ? "unknown" : technical.Length==0 ? "высокая" : "средняя";
        if(confidenceOverride.Length>0) confidence=confidenceOverride switch { "low"=>"низкая", "medium"=>"средняя", "high"=>"высокая", _=>confidenceOverride };
        severity=Risk(severity,"info");
        var (risk,riskClass)=RiskLabel(severity);
        var reasons=new List<string> { known ? "catalog_rule_matched" : "catalog_rule_missing" };
        if(ruleIndex.HasValue) reasons.Add("contextual_rule_matched:"+ruleIndex.Value);
        reasons.AddRange(missing.Select(role=>"expected_role_missing:"+role));
        var fields=new List<string>();
        foreach(var (role,names) in roles) if(values.GetValueOrDefault(role,"").Length>0) fields.AddRange(Strings(names));
        foreach(var condition in matched?["all"] as JsonArray ?? [])
        {
            fields.AddRange(Strings(condition?["fields"])); string role=Text(condition?["role"]);
            if(role.Length>0) fields.AddRange(Strings(roles[role]));
            if(condition?["dc"]?.GetValue<bool>()==true) fields.Add("server");
            if(condition?["contains_any"] is JsonArray {Count:>0}) fields.Add("event_data");
        }
        string Code(string field)=>Text(entry?["channel"])+":"+Text(entry?["provider_name"])+":"+Text(entry?["event_id"])+"."+field;
        var facts=new JsonArray(); void Fact(string label,string value)=>facts.Add(new JsonArray(label,value));
        var labels=new List<string>{"facts.event"};
        JsonObject result;
        if(!known)
        {
            if(Text(item["server"]).Trim() is {Length:>0} server) Fact("Сервер",server);
            if(Text(item["channel"]).Trim() is {Length:>0} channel) Fact("Журнал",channel);
            confidence="низкая"; risk="Оценка ИБ не определена";
            result=new JsonObject { ["known"]=false,["has_card"]=false,["title"]="Событие пока не расшифровано каталогом",["title_code"]="uncatalogued.title",["summary_code"]="uncatalogued.summary",["severity"]="unknown",["tier"]="technical",["risk_class"]="risk-info",["facts"]=facts,["summary"]="Каталог не содержит правила для этого Provider, Channel и Event ID. Ни действие, ни результат не интерпретируются автоматически.",["checks"]=new JsonArray("Открыть технические данные и сообщение Windows.","Добавить проверенное правило в каталог события, если оно повторяется."),["related_event_ids"]=new JsonArray(),["technical_reason"]="Не найдено правило по ключу Provider + Channel + Event ID." };
        }
        else
        {
            string action=Or(card["action"],Or(entry!["title"],"Event ID "+Text(item["event_id"])));
            Fact("Событие",action);
            var factLabels=new Dictionary<string,string> { ["object"]=Or(card["object_label"],"Объект изменения"),["initiator"]="Кто выполнил изменение",["account"]="Учётная запись",["result"]="Результат" };
            var order=Strings(card["fact_order"]).ToArray(); if(order.Length==0) order=["object","initiator","account"];
            foreach(string role in order)
            {
                string value=values.GetValueOrDefault(role,"");
                if(value.Length==0 && !Strings(card["expected_roles"]).Contains(role)) continue;
                Fact(factLabels.GetValueOrDefault(role,role),value.Length==0 ? "Не удалось определить" : value);
                labels.Add(role=="object" ? Code("object_label") : "facts."+role);
            }
            Fact("Сервер",Or(item["server"],Or(item["computer"],"Не удалось определить"))); labels.Add("facts.server");
            string outcome=values.GetValueOrDefault("result",""); if(outcome.Length==0) outcome=Text(card["result"]).Trim();
            if(outcome.Length>0) { Fact("Результат",outcome); labels.Add("facts.result"); }
            var checks=Strings(card["checks"]).Where(s=>s.Trim().Length>0).ToArray();
            if(checks.Length==0) checks=[Or(entry!["fix"],"Открыть технические данные и сообщение Windows.")];
            result=new JsonObject { ["known"]=true,["has_card"]=hasCard,["severity"]=severity,["tier"]=tier,["title"]=action,["title_code"]=Code("title"),["summary_code"]=Code(ruleIndex.HasValue && assessment.Length>0 ? "summary.rule."+ruleIndex.Value : "summary"),["risk_class"]=riskClass,["facts"]=facts,["fact_label_codes"]=Array(labels),["summary"]=assessment.Length>0 ? assessment : Or(card["purpose"],Or(entry!["why"],"Событие расшифровано локальным каталогом.")),["checks"]=Array(checks),["check_codes"]=Array(Enumerable.Range(0,checks.Length).Select(i=>Code("checks."+i))),["related_event_ids"]=card["related_event_ids"]?.DeepClone() ?? new JsonArray(),["technical_reason"]=technical };
        }
        string final=known ? severity : "unknown", baseRisk=known ? Risk(Or(entry!["base_risk"],Text(entry["severity"]))) : "unknown";
        string machineConfidence=confidence.Trim().ToLowerInvariant() switch { "высокая"=>"high", "средняя"=>"medium", "низкая"=>"low", "high"=>"high", "medium"=>"medium", "low"=>"low", _=>"unknown" };
        string purpose=Or(card["tier"],Or(entry?["purpose_tier"],Tier(final)));
        // Contextual rules own purpose_tier whenever a card is known.
        if(known) purpose=tier;
        if(purpose is not ("critical" or "important" or "technical")) purpose=Tier(final);
        string noise=Or(card["noise_class"],Text(entry?["noise_class"])).Trim().ToLowerInvariant();
        if(noise is not ("signal" or "context" or "noise" or "unknown")) noise=!known ? "unknown" : final is "critical" or "high" or "medium" ? "signal" : "context";
        result["source_pack"]=pack?.DeepClone(); result["risk"]=risk; result["assessment_confidence_label"]=confidence;
        result["category"]=Category(Or(card["category"],Text(entry?["category"])),known); result["purpose_tier"]=purpose;
        result["base_risk"]=baseRisk; result["final_security_severity"]=final; result["final_risk"]=final;
        result["assessment_confidence"]=machineConfidence; result["confidence"]=machineConfidence;
        result["classification_origin"]=!known ? "unavailable" : ruleIndex.HasValue ? "contextual_rule" : "catalog_base";
        result["card_completeness"]=!hasCard ? "not_applicable" : technical.Length>0 ? "partial" : "complete";
        result["catalog_match"]=known; result["reasons"]=Array(reasons.Distinct()); result["evidence_fields"]=Array(fields.Where(v=>v.Length>0).Distinct()); result["noise_class"]=noise;
        result["display_labels"]=new JsonObject { ["risk"]=risk,["confidence"]=confidence };
        if(item["watch_priority"] is JsonObject priority && Text(priority["reason"])=="watch")
        {
            string[] severities=["info","low","medium","high","critical"];
            int index=System.Array.IndexOf(severities,Text(priority["base_severity"]));
            string effective=Text(priority["effective_severity"]);
            if(index>=0 && effective==severities[Math.Min(index+1,severities.Length-1)])
            {
                var label=RiskLabel(effective); result["base_risk"]=severities[index];
                foreach(string key in new[]{"severity","final_risk","final_security_severity"}) result[key]=effective;
                result["risk"]=label.Label; result["risk_class"]=label.Class; result["classification_origin"]="contextual_rule";
                result["reasons"]=Array(reasons.Append("watch").Distinct()); result["watch_priority"]=priority.DeepClone(); result["display_labels"]!["risk"]=label.Label;
            }
        }
        return result;
    }
}
