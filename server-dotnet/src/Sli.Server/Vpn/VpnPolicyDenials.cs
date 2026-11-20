using System.Text.Json.Nodes;

namespace Sli.Server.Vpn;

public static class VpnPolicyDenials
{
    static readonly string[] Dimensions=["network_policy","nas_identifier","reason_code","authentication_type","authentication_provider"];
    static string? Clean(string value)=>value.Trim() is "" or "-" or "N/A"?null:value.Trim();
    static string? Account(JsonObject row)=>row["quality_json"]?["identity_roles"]?["affected_entity"] is {} identity && identity.Text("state")=="resolved" && !identity.Flag("provisional")?Clean(row["roles_json"].Text("affected_entity")):null;
    public static async Task<JsonObject> Read(IVpnReadSession db,VpnAccess access,VpnQuery q,IQueryCollection query,CancellationToken ct)
    {
        if(!access.Windows(q.Domain)) return VpnReports.Result("vpn.connections","denied");
        var to=q.To!.Value;var from=q.From!.Value;bool clamped=to-from>TimeSpan.FromDays(31);if(clamped) from=to.AddDays(-31);
        int minDecisions=VpnReports.ParseInt(query["min_decisions"].FirstOrDefault()??"0","report_parameter_invalid:min_decisions"),minGrowth=VpnReports.ParseInt(query["min_growth"].FirstOrDefault()??"0","report_parameter_invalid:min_growth");
        if(minDecisions<0 || minGrowth<0) throw new VpnInputException("nps_policy_threshold_invalid");
        string[] filters=[query["policy"].ToString(),query["nas"].ToString(),query["reason"].ToString(),query["method"].ToString()];if(filters.Any(s=>s.Length>256)) throw new VpnInputException("nps_policy_filter_invalid");
        const string sql="module_disabled:NpsPolicyDenials";
        var raw=await VpnReports.Safe(async()=>
        {
            var current=await db.ReadAsync(sql,[from,to,q.Domain.ToString(System.Globalization.CultureInfo.InvariantCulture),..filters.Select(s=>Clean(s)??"")],ct);
            var previous=await db.ReadAsync(sql,[from-(to-from),from,q.Domain.ToString(System.Globalization.CultureInfo.InvariantCulture),..filters.Select(s=>Clean(s)??"")],ct);
            return Compose(current.Take(10000).ToList(),previous.Take(10000).ToList(),from,to,current.Count>10000,previous.Count>10000,minDecisions,minGrowth);
        });
        var result=VpnReports.Result("vpn.connections",VpnReports.State(raw.Text("state")));var rows=raw["items"]?.AsArray().OfType<JsonObject>().Select(r=>(JsonObject)r.DeepClone()).ToArray()??[];
        foreach(var row in rows) {row["current_coverage"]=raw["coverage"]?["current"]?["state"]?.DeepClone();row["previous_coverage"]=raw["coverage"]?["previous"]?["state"]?.DeepClone();}
        result["collections"]=VpnJson.Obj(new {policy_denials=rows,policy_denials_growth=rows.OrderByDescending(r=>r.Number("growth")),policy_denials_events=raw["events"]?.DeepClone()??new JsonArray()});
        var metrics=new List<JsonObject>();foreach(var (key,label) in new[]{("allowed","Разрешений NPS"),("denied","Отказов NPS"),("denial_share","Доля отказов, %"),("affected_accounts","Аккаунтов с отказами"),("unknown_identity_denials","Отказы с неизвестной идентичностью"),("growing_policies","Политик с ростом отказов"),("growing_nas","NAS с ростом отказов"),("missing_policy","Решений без политики"),("missing_reason","Решений без причины")}) metrics.Add(VpnJson.Obj(new {key="nps_"+key,label,value=raw["metrics"]?[key]?.DeepClone()}));result["metrics"]=raw["metrics"] is null?new JsonArray():VpnJson.Array(metrics);
        result["coverage"]=VpnJson.Obj(new {state="partial",current=raw["coverage"]?["current"]?.DeepClone(),previous=raw["coverage"]?["previous"]?.DeepClone()});
        result["window"]=VpnJson.Obj(new {from_utc=VpnJson.Iso(from),to_utc_exclusive=VpnJson.Iso(to),nps_period_clamped=clamped,timezone=q.Timezone,source_domain_id=q.Domain});
        var branches=new JsonObject();foreach(string branch in new[]{"policy_denials","policy_denials_growth","policy_denials_events","accounting","nps","windows","windows_heatmap"}) branches[branch]=branch.StartsWith("policy_denials",StringComparison.Ordinal)?VpnReports.Branch(raw):VpnJson.Obj(new {state="not_requested",reason="load_on_open",limitations=Array.Empty<object>(),limits=new {}});result["branches"]=branches;return result;
    }
    public static JsonObject Compose(List<JsonObject> current,List<JsonObject> previous,DateTimeOffset from,DateTimeOffset to,bool currentTruncated=false,bool previousTruncated=false,int minDecisions=0,int minGrowth=0)
    {
        if(from>=to || to-from>TimeSpan.FromDays(31)) throw new VpnInputException("nps_policy_window_or_threshold_invalid");
        var groups=new Dictionary<string,JsonObject>(StringComparer.Ordinal);var groupAccounts=new Dictionary<string,HashSet<string>>(StringComparer.Ordinal);var accounts=new HashSet<string>();var policies=new Dictionary<string,long[]>();var nas=new Dictionary<string,long[]>();
        long allowed=0,denied=0,unknown=0,missingPolicy=0,missingReason=0;
        for(int window=0;window<2;window++)
        {
            var seen=new HashSet<long>();foreach(var row in window==0?current:previous)
            {
                if(!seen.Add(row.Number("source_event_id"))) throw new VpnInputException("nps_policy_duplicate_source_event");
                var at=row.At("occurred_at_utc");if(at is null || at<(window==0?from:from-(to-from)) || at>=(window==0?to:from) || row.Text("semantic_type") is not ("remote_access.authentication.allowed" or "remote_access.authentication.denied")) throw new VpnInputException("nps_policy_fact_invalid");
                var dimensions=Dimensions.Select(key=>Clean(row["facts_json"].Text(key))).ToArray();string groupKey=System.Text.Json.JsonSerializer.Serialize(dimensions);bool failure=row.Text("semantic_type").EndsWith(".denied",StringComparison.Ordinal);
                if(!groups.TryGetValue(groupKey,out var group))
                {
                    group=VpnJson.Obj(new {allowed=0,denied=0,previous_denied=0,previous_decisions=0,unknown_identity_denials=0,first_denial_utc=(string?)null,last_denial_utc=(string?)null,first_event_id=(long?)null,last_event_id=(long?)null});for(int i=0;i<Dimensions.Length;i++) group[Dimensions[i]]=dimensions[i];groups[groupKey]=group;groupAccounts[groupKey]=[];
                }
                void Add(string key,long delta=1)=>group[key]=group.Number(key)+delta;
                if(window==1) {Add("previous_decisions");if(failure) Add("previous_denied");}
                else
                {
                    Add(failure?"denied":"allowed");if(failure) denied++;else allowed++;
                    if(dimensions[0] is null) missingPolicy++;if(dimensions[2] is null) missingReason++;
                    if(failure)
                    {
                        if(Account(row) is {} account) {accounts.Add(account);groupAccounts[groupKey].Add(account);}else {unknown++;Add("unknown_identity_denials");}
                        if(group.At("first_denial_utc") is not {} first || at<first) {group["first_denial_utc"]=VpnJson.Iso(at);group["first_event_id"]=row.Number("source_event_id");}
                        if(group.At("last_denial_utc") is not {} last || at>=last) {group["last_denial_utc"]=VpnJson.Iso(at);group["last_event_id"]=row.Number("source_event_id");}
                    }
                }
                if(failure) foreach(var (key,counts) in new[]{(dimensions[0],policies),(dimensions[1],nas)}) if(key is not null) {if(!counts.TryGetValue(key,out var values)) counts[key]=values=new long[2];values[window]++;}
            }
        }
        bool comparable=!currentTruncated && !previousTruncated;var items=new List<JsonObject>();
        foreach(var (key,group) in groups)
        {
            long count=group.Number("allowed")+group.Number("denied"),growth=group.Number("denied")-group.Number("previous_denied");if(count==0 || count<minDecisions || minGrowth>0 && (!comparable || growth<minGrowth)) continue;
            group["decisions"]=count;group["affected_accounts"]=groupAccounts[key].Count;group["denial_share"]=Math.Round(100.0*group.Number("denied")/count,2,MidpointRounding.ToEven);group["growth"]=comparable?JsonValue.Create(growth):null;group["coverage_state"]=comparable?"observed_unverified":"truncated";items.Add(group);
        }
        items=items.OrderByDescending(r=>r.Number("denied")).ThenBy(r=>string.Join("\0",Dimensions.Select(key=>r.Text(key))),StringComparer.Ordinal).ToList();
        JsonObject Coverage(List<JsonObject> rows,DateTimeOffset a,DateTimeOffset b,bool truncated)=>VpnJson.Obj(new {state=truncated?"truncated":rows.Count>0?"observed_unverified":"empty_unverified",from_utc=VpnJson.Iso(a),to_utc_exclusive=VpnJson.Iso(b),observed_decisions=rows.Count,source_completeness="not_proven",truncated});
        return VpnJson.Obj(new {report_key="vpn.policy-denials",state="partial",items=items.Take(500),metrics=new {allowed,denied,affected_accounts=accounts.Count,unknown_identity_denials=unknown,missing_policy=missingPolicy,missing_reason=missingReason,denial_share=allowed+denied>0?(double?)Math.Round(100.0*denied/(allowed+denied),2,MidpointRounding.ToEven):null,growing_policies=comparable?(int?)policies.Count(x=>x.Value[0]>x.Value[1]):null,growing_nas=comparable?(int?)nas.Count(x=>x.Value[0]>x.Value[1]):null},coverage=new {current=Coverage(current,from,to,currentTruncated),previous=Coverage(previous,from-(to-from),from,previousTruncated)},result_truncated=items.Count>500,evidence_truncated=current.Count>500,events=current.Take(500).Select(row=> {var item=VpnJson.Obj(new {event_db_id=row.Number("source_event_id"),normalized_event_id=row.Text("normalized_event_id"),event_id=row.Text("semantic_type").EndsWith(".allowed",StringComparison.Ordinal)?6272:6273,occurred_at_utc=VpnJson.Iso(row.At("occurred_at_utc")),decision=row.Text("semantic_type").EndsWith(".allowed",StringComparison.Ordinal)?"allowed":"denied",identity_state=Account(row) is null?"unknown":"resolved"});foreach(string key in Dimensions) item[key]=Clean(row["facts_json"].Text(key));return item;}),limits=new {max_period_days=31,input_limit_per_window=10000,group_limit=500,evidence_limit=500}});
    }
}
