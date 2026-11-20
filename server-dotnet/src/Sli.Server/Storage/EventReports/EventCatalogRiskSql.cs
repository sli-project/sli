using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sli.Server.Storage.EventReports;

internal sealed record CompiledCatalogRiskSql(string CaseSql,string MatchedSql,IReadOnlyDictionary<string,object> Parameters,bool Exact,string[] Limitations);

// Compiles against a projected event row (event_id/channel/provider_name/event_data_json)
// and server row (hostname). Identifiers are fixed; every catalogue value is bound.
internal static class EventCatalogRiskSql
{
    static string Text(JsonNode? n)=>EventCardSemantics.Text(n);
    static string Risk(JsonNode? n,string fallback="info")=>Text(n).Trim().ToLowerInvariant() switch
    { "important" or "warning" or "warn"=>"medium", "critical"=>"critical", "high"=>"high", "medium"=>"medium", "low"=>"low", "info"=>"info", _=>fallback };
    internal static CompiledCatalogRiskSql Compile(IEnumerable<int> eventIds)
    {
        var ids=eventIds.ToHashSet(); var parameters=new Dictionary<string,object>();
        string Bind(object value) { string name="catalog"+parameters.Count; parameters[name]=value; return "@"+name; }
        var cases=new List<string>(); var matches=new List<string>(); var limitations=new List<string>();
        var entries=EventCatalogQuality.ShippedCatalog()["entries"]!.AsArray().OfType<JsonObject>()
            .Where(e=>ids.Contains((int)e["event_id"]!)).OrderByDescending(e=>(Text(e["channel"]).Length>0?1:0)+(Text(e["provider_name"]).Length>0?1:0)).ThenByDescending(e=>(int)e["event_id"]!);
        foreach(var entry in entries)
        {
            var identity=new List<string> { "e.event_id = "+Bind((int)entry["event_id"]!) };
            foreach(string field in new[]{"channel","provider_name"}) if(Text(entry[field]).Trim().ToLowerInvariant() is {Length:>0} v) identity.Add("lower(coalesce(e."+field+", '')) = "+Bind(v));
            string match="("+string.Join(" and ",identity)+")",baseRisk=Risk(entry["base_risk"]??entry["severity"]),risk=Bind(baseRisk);
            var rules=entry["card"]?["risk_rules"] as JsonArray??[];
            for(int index=rules.Count-1;index>=0;index--)
            {
                var rule=rules[index]!.AsObject(); string severity=Risk(rule["severity"],baseRisk); if(severity==baseRisk) continue;
                // Check support before binding, so unsupported rules leave no unused parameters.
                var conditions=(rule["all"] as JsonArray??[]).OfType<JsonObject>().ToArray();
                if(conditions.Any(c=>c["microsoft_namespace"]?.ToString()=="true" || c["machine_or_system"]?.ToString()=="true" || c.Any(p=>!new[]{"dc","contains_any","role","fields","microsoft_namespace","machine_or_system"}.Contains(p.Key))))
                { limitations.Add("event_id="+entry["event_id"]+":risk_rule="+index); continue; }
                var checks=new List<string>();
                foreach(var c in conditions)
                {
                    if(c["dc"]?.ToString()=="true") checks.Add("lower(coalesce(s.hostname, '')) like "+Bind("dc%"));
                    var contains=(c["contains_any"] as JsonArray??[]).Select(v=>Text(v).ToLowerInvariant()).ToArray();
                    if(contains.Length>0)
                    {
                        var parts=contains.Select(token=>
                        {
                            string encoded=JsonSerializer.Serialize(token,new JsonSerializerOptions { Encoder=JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
                            return "lower(coalesce(e.event_data_json, '')) like "+Bind("%"+encoded[1..^1]+"%");
                        });
                        checks.Add("("+string.Join(" or ",parts)+")");
                    }
                }
                string condition=checks.Count==0?"(1 = 1)":"("+string.Join(" and ",checks)+")";
                risk="case when "+condition+" then "+Bind(severity)+" else "+risk+" end";
            }
            matches.Add(match); cases.Add("when "+match+" then "+risk);
        }
        string unknown=Bind("unknown");
        return new(cases.Count==0?unknown:"case "+string.Join(" ",cases)+" else "+unknown+" end",matches.Count==0?"(1 = 0)":"("+string.Join(" or ",matches)+")",parameters,limitations.Count==0,limitations.ToArray());
    }
}
