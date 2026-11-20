using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Compatibility;

namespace Sli.Server.Storage.EventReports;

internal static class EventListProjection
{
    internal static readonly Dictionary<string,int[]> Families=new()
    {
        ["authentication"]=[4624,4625,4634,4648,4768,4769,4771,4776], ["account_management"]=[4720,4722,4723,4724,4725,4726,4728,4729,4732,4733,4738,4740,4767,4781,4756,4757],
        ["privilege_management"]=[4672], ["policy_change"]=[1102,4719]
    };
    internal static int[] AttentionIds=>Catalog.Value.Where(e=>Text(e["purpose_tier"])=="critical" || Risk(Or(e["base_risk"],e["severity"])) is "critical" or "high").Select(e=>int.Parse(Text(e["event_id"]),CultureInfo.InvariantCulture)).Where(id=>id>0).Distinct().Order().ToArray();
    static readonly Lazy<JsonObject[]> Catalog=new(()=>new[]{"event_catalog","file_audit_event_catalog","radius_event_catalog","workstations_event_catalog"}.SelectMany(name=>
    {
        using var stream=typeof(EventListProjection).Assembly.GetManifestResourceStream("Sli.Server.Semantic.Risk."+name+".json")??throw new InvalidOperationException("event_catalog_missing");
        return JsonNode.Parse(stream)!["entries"]!.AsArray().OfType<JsonObject>().ToArray();
    }).ToArray());
    static string Text(JsonNode? n)=>n?.ToString()??"";
    internal static bool Matches(JsonObject item,EventListInput input)
    {
        var risks=(input.Risk??"").Split(',',StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries).Select(s=>s.ToLowerInvariant()).ToArray();
        return (risks.Length==0 || risks.Contains(Text(item["final_security_severity"]??item["final_risk"]??item["severity"]).ToLowerInvariant()))
            && (input.Tier is null || Text(item["purpose_tier"]??item["tier"]).ToLowerInvariant()==input.Tier)
            && (input.Category is null || Text(item["category"]).ToLowerInvariant()==input.Category);
    }
    internal static string FallbackCategory(JsonObject row)
    {
        int id=int.TryParse(Text(row["event_id"]),out int value)?value:0;
        string channel=Text(row["channel"]),provider=Text(row["provider_name"]);
        return Families.FirstOrDefault(f=>f.Value.Contains(id)).Key
            ?? (channel.Contains("taskscheduler",StringComparison.OrdinalIgnoreCase) || provider.Contains("task scheduler",StringComparison.OrdinalIgnoreCase)
                || new[]{7036,7040,7045}.Contains(id) && (channel.Equals("System",StringComparison.OrdinalIgnoreCase) || provider.Contains("service control manager",StringComparison.OrdinalIgnoreCase))?"service_task":"operations");
    }
    static string Or(params JsonNode?[] nodes)=>nodes.Select(Text).FirstOrDefault(t=>t.Length>0)??"";
    static string Risk(string s,string fallback="unknown")=>s.ToLowerInvariant() switch { "important" or "warning" or "warn"=>"medium","critical"=>"critical","high"=>"high","medium"=>"medium","low"=>"low","info"=>"info","unknown"=>"unknown",_=>fallback };
    static string Tier(string risk)=>risk is "high" or "critical"?"critical":risk=="medium"?"important":"technical";
    static readonly Lazy<Dictionary<string,string>> Russian=new(()=>Messages("ru")),English=new(()=>Messages("en"));
    static Dictionary<string,string> Messages(string language)
    {
        using var stream=typeof(EventListProjection).Assembly.GetManifestResourceStream("Sli.Server.Access.Administration.server."+language+".json")!;
        return JsonSerializer.Deserialize<Dictionary<string,string>>(stream)!;
    }
    internal static string Label(JsonObject row,string language="ru")
    {
        var messages=language.Trim().Equals("en",StringComparison.OrdinalIgnoreCase)?English.Value:Russian.Value;
        var entry=Entry(row);
        // A numeric Event ID cannot supply semantics without an exact source identity.
        if(entry is not null && Text(row["channel"]).Trim().Length>0 && Text(row["provider_name"]).Trim().Length>0 &&
            Text(entry["channel"]).Equals(Text(row["channel"]).Trim(),StringComparison.OrdinalIgnoreCase) &&
            Text(entry["provider_name"]).Equals(Text(row["provider_name"]).Trim(),StringComparison.OrdinalIgnoreCase))
        {
            string code="events.semantic."+Text(entry["channel"])+":"+Text(entry["provider_name"])+":"+Text(entry["event_id"])+".title";
            if(messages.TryGetValue(code,out string? title)) return title;
            if(!ReferenceEquals(messages,English.Value)) return Text(entry["title"]);
        }
        return messages["events.unknown_type"];
    }
    internal static JsonObject Summary(JsonObject row)
    {
        // Port of event_summary_projection: allowlisted metadata, never evidence payload.
        string[] keys=["event_db_id","event_id","event_record_id","time_created_utc","time_created_utc_display","time_created_local_display","server","channel","provider_name","label","category","severity","tier","purpose_tier","base_risk","final_risk","final_security_severity","confidence","noise_class","source_payload_state","assessment_confidence","catalog_match","reasons","evidence_fields","display_labels","summary","relation_count","relation_count_status"];
        var result=new JsonObject();
        foreach(string key in keys) if(row.ContainsKey(key)) result[key]=row[key]?.DeepClone();
        result["event_db_id"]=row["event_db_id"]?.DeepClone() ?? row["id"]?.DeepClone() ?? JsonValue.Create(0);
        result["event_id"]=row["event_id"]?.DeepClone() ?? JsonValue.Create(0);
        result["label"]=Text(row["label"]) is {Length:>0} label?label:Label(row);
        result["summary"]=Text(row["summary"]) is {Length:>0} summary?summary:"Сводка события; точные данные доступны в карточке доказательства.";
        return result;
    }
    internal static string? Title(JsonObject row)
    {
        var entry=ExactTitleEntry(row);
        return entry is null?null:Or(entry["card"]?["action"],entry["title"]);
    }
    internal static JsonObject? ExactTitleEntry(JsonObject row)
    {
        var entry=Entry(row);
        return entry is not null && Text(entry["channel"]).Equals(Text(row["channel"]),StringComparison.OrdinalIgnoreCase) && Text(entry["provider_name"]).Equals(Or(row["provider_name"],row["provider"]),StringComparison.OrdinalIgnoreCase)?entry:null;
    }
    static JsonObject? Entry(JsonObject row)
    {
        string channel=Text(row["channel"]).Trim(),provider=Or(row["provider_name"],row["provider"]).Trim();
        return Catalog.Value.Where(e=>Text(e["event_id"])==Text(row["event_id"]) && (Text(e["channel"])=="" || Text(e["channel"]).Equals(channel,StringComparison.OrdinalIgnoreCase)) && (Text(e["provider_name"])=="" || Text(e["provider_name"]).Equals(provider,StringComparison.OrdinalIgnoreCase))).OrderByDescending(e=>(Text(e["channel"]).Length>0?1:0)+(Text(e["provider_name"]).Length>0?1:0)).FirstOrDefault();
    }
    internal static JsonObject Project(JsonObject row)
    {
        // Hot rows carry serialized event data; history rows already carry an object.
        // Use the same decoded values as the report/card projection.
        if(row["event_data"] is not JsonObject && row["event_data_json"] is JsonValue serialized)
        {
            row=(JsonObject)row.DeepClone();
            try { row["event_data"]=JsonNode.Parse(serialized.ToString()) as JsonObject; }
            catch(System.Text.Json.JsonException) { row["event_data"]=null; }
        }
        var entry=Entry(row); var card=entry?["card"] as JsonObject??[]; var data=row["event_data"] as JsonObject??new JsonObject();
        string First(JsonArray? names)
        {
            foreach(var name in names??[]) { string key=Text(name); string text=Text(row.ContainsKey(key)?row[key]:data[key]).Trim(); if(text.Length>0 && text is not ("-" or "—")) return text; } return "";
        }
        var roles=card["field_roles"] as JsonObject??[]; var values=roles.ToDictionary(p=>p.Key,p=>First(p.Value as JsonArray));
        int? matched=null; JsonObject? rule=null;
        foreach(var candidate in (card["risk_rules"] as JsonArray??[]).OfType<JsonObject>().Select((r,i)=>(r,i)))
        {
            bool pass=true;
            foreach(var c in (candidate.r["all"] as JsonArray??[]).OfType<JsonObject>())
            {
                string v=values.GetValueOrDefault(Text(c["role"]),""); if(v.Length==0) v=First(c["fields"] as JsonArray); v=v.ToLowerInvariant();
                if(c["microsoft_namespace"]?.ToString()=="true" && !v.StartsWith("\\microsoft\\windows\\",StringComparison.Ordinal) || c["machine_or_system"]?.ToString()=="true" && !(v.EndsWith('$') || v is "system" or "nt authority\\system") || c["dc"]?.ToString()=="true" && !Text(row["server"]).StartsWith("dc",StringComparison.OrdinalIgnoreCase)) pass=false;
                var contains=(c["contains_any"] as JsonArray??[]).Select(Text).ToArray(); string haystack=string.Join(" ",data.Select(p=>Text(p.Value)));
                if(contains.Length>0 && !contains.Any(t=>haystack.Contains(t,StringComparison.OrdinalIgnoreCase))) pass=false;
            }
            if(pass) { matched=candidate.i; rule=candidate.r; break; }
        }
        string baseRisk=Risk(Or(entry?["base_risk"],entry?["severity"])),risk=entry is null?"unknown":Risk(Or(rule?["severity"],entry["severity"]),"info");
        string tier=entry is null?"technical":Or(rule?["tier"],card["tier"]); if(tier.Length==0) tier=Tier(risk);
        string[] missing=(card["expected_roles"] as JsonArray??[]).Select(Text).Where(r=>values.GetValueOrDefault(r,"").Length==0).ToArray();
        string confidence=entry is null?"low":card.Count==0?"unknown":missing.Length>0?"medium":"high";
        string declaredConfidence=Or(rule?["confidence"],card["confidence"]);
        if(declaredConfidence.Length>0) confidence=declaredConfidence switch { "высокая"=>"high","средняя"=>"medium","низкая"=>"low",_=>declaredConfidence };
        var reasons=new List<string>(); var evidence=new List<string>();
        if(entry is null) reasons.Add("catalog_rule_missing");
        else
        {
            reasons.Add("catalog_rule_matched"); if(matched is {} m) reasons.Add("contextual_rule_matched:"+m);
            reasons.AddRange(missing.Select(r=>"expected_role_missing:"+r));
            foreach(var (name,names) in roles) if(values.GetValueOrDefault(name,"").Length>0) evidence.AddRange((names as JsonArray??[]).Select(Text));
            foreach(var c in (rule?["all"] as JsonArray??[]).OfType<JsonObject>())
            {
                evidence.AddRange((c["fields"] as JsonArray??[]).Select(Text));
                evidence.AddRange((roles[Text(c["role"])] as JsonArray??[]).Select(Text));
                if(c["dc"]?.ToString()=="true") evidence.Add("server"); if((c["contains_any"] as JsonArray)?.Count>0) evidence.Add("event_data");
            }
        }
        if(row["watch_priority"] is JsonObject watch && Text(watch["reason"])=="watch")
        {
            string b=Text(watch["base_severity"]),f=Text(watch["effective_severity"]);
            if(new[]{"info","low","medium","high","critical"}.Contains(b) && f==(b=="info"?"low":b=="low"?"medium":b=="medium"?"high":b=="high"?"critical":"critical")) { baseRisk=b; risk=f; reasons.Add("watch"); }
        }
        string category=Or(card["category"],entry?["category"]); if(category is "" or "other" or "unknown" && entry is not null)
        { category=FallbackCategory(row); }
        if(entry is null) category="event";
        string riskLabel=risk is "critical" or "high"?"Высокий риск":risk=="medium"?"Требует проверки":risk=="low"?"Низкий риск":risk=="info"?"Информация":"Оценка ИБ не определена";
        string confidenceLabel=confidence=="high"?"высокая":confidence=="medium"?"средняя":confidence=="low"?"низкая":"unknown";
        string label=entry is null?Text(row["event_id"])=="0"?"Событие журнала":"неизвестный тип события":Or(card["action"],entry["title"]);
        var result=new JsonObject { ["event_db_id"]=row["id"]?.DeepClone(),["event_id"]=row["event_id"]?.DeepClone(),["event_record_id"]=row["event_record_id"]?.DeepClone(),["time_created_utc"]=row["time_created_utc"]?.DeepClone(),["server"]=row["server"]?.DeepClone(),["channel"]=row["channel"]?.DeepClone(),["provider_name"]=row["provider_name"]?.DeepClone(),["label"]=label,["summary"]=entry is null?"Каталог не содержит проверенной интерпретации этого события.":Or(rule?["assessment"],card["assessment"],card["purpose"],entry["why"]),["category"]=category,["severity"]=risk,["tier"]=entry is null?null:tier,["purpose_tier"]=tier,["base_risk"]=baseRisk,["final_risk"]=risk,["final_security_severity"]=risk,["confidence"]=confidence,["assessment_confidence"]=confidence,["noise_class"]=Or(card["noise_class"],entry?["noise_class"]),["catalog_match"]=entry is not null,["reasons"]=new JsonArray(reasons.Distinct().Select(s=>JsonValue.Create(s) as JsonNode).ToArray()),["evidence_fields"]=new JsonArray(evidence.Distinct().Select(s=>JsonValue.Create(s) as JsonNode).ToArray()),["display_labels"]=new JsonObject { ["risk"]=riskLabel,["confidence"]=confidenceLabel },["time_created_utc_display"]=EventReadService.Stamp(row["time_created_utc"]).ToString("dd.MM.yyyy HH:mm:ss",CultureInfo.InvariantCulture)+" UTC",["time_created_local_display"]=row["time_created_local"] is null?"—":EventReadService.Stamp(row["time_created_local"]).ToString("dd.MM.yyyy HH:mm:ss",CultureInfo.InvariantCulture),["relation_count"]=null,["relation_count_status"]="unavailable",["source_payload_state"]=row["source_payload_state"]?.ToString()=="expired"?"expired":null };
        var utc = EventReadService.Stamp(row["time_created_utc"]);
        result["time_created_utc"] = utc.ToString(utc.Ticks % TimeSpan.TicksPerSecond == 0 ? "yyyy-MM-dd'T'HH:mm:ss'Z'" : "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
        if(Text(result["noise_class"]).Length==0) result["noise_class"]=entry is null?"unknown":risk is "critical" or "high" or "medium"?"signal":"context";
        if(entry is null)
        {
            // Python keeps legacy list fields while canonical final_risk stays unknown.
            int id=int.Parse(Text(row["event_id"]),CultureInfo.InvariantCulture);
            string legacyCategory=LegacySemantics.AccountCategory(id);
            result["category"]=legacyCategory.Length>0?legacyCategory:"event";
            result["severity"]=LegacySemantics.AccountSeverity(id);
        }
        return Summary(result);
    }
}
