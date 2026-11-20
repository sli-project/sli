using System.Text.Json.Nodes;

namespace Sli.Server.Vpn;

public static class VpnWindows
{
    public const string Contract="sli.vpn-audit-windows-authentication.v1";
    public static readonly int[] EventIds=[4624,4625,4634,4647,4648,4672,4768,4769,4770,4771,4773,4776];
    static readonly string[] Facts=["observed_successful_logon","observed_failed_logon","observed_logoff","observed_user_initiated_logoff","observed_explicit_credentials","observed_special_privileges","observed_kerberos_as_request","observed_kerberos_service_ticket","observed_kerberos_ticket_renewal","observed_kerberos_preauth_failure","observed_kerberos_service_ticket_failure","observed_credential_validation"];
    static readonly int[] FailureIds=[4625,4771,4773],MixedIds=[4768,4769,4776],SubjectIds=[4672];
    static readonly string[] ZeroCodes=["0","0x0","0x00000000","00000000"];
    public static async Task<JsonObject> Read(IVpnReadSession db,VpnAccess access,VpnQuery q,CancellationToken ct)
    {
        if(q.To-q.From>TimeSpan.FromDays(90)) throw new VpnInputException("windows_authentication_period_too_wide");
        var payload=VpnJson.Obj(new {contract_id=Contract,report_key="vpn.audit",source_domain_id=q.Domain,state="not_authorized",time_bounds=new {from_utc=VpnJson.Iso(q.From),to_utc_exclusive=VpnJson.Iso(q.To)},items=Array.Empty<object>(),result_window=new {display_limit=q.Limit,returned_event_count=0,truncated=false},limits=new {max_period_days=90,display_limit=q.Limit,max_display_limit=500,bounded=true}});
        if(!access.Windows(q.Domain)) return payload;
        List<JsonObject> rows=[];JsonObject coverage=new(),policy=new();bool truncated=false;
        try
        {
            rows=await db.ReadAsync(VpnSql.WindowsEvents,[q.Domain,EventIds,"Security","Microsoft-Windows-Security-Auditing",q.From,q.To,q.Limit+1],ct);
            truncated=rows.Count>q.Limit;rows=rows.Take(q.Limit).ToList();
            coverage=(await db.ReadAsync(VpnSql.WindowsCoverage,[q.Domain,EventIds,"Security","Microsoft-Windows-Security-Auditing"],ct)).FirstOrDefault()??new();
            var failures=await db.ReadAsync(VpnSql.WindowsReview,[q.Domain,"Security","Microsoft-Windows-Security-Auditing",q.From,q.To,FailureIds,MixedIds,ZeroCodes,100001],ct);
            // These four non-secret policy keys are the only settings this reader needs.
            var settings=await db.ReadAsync("select key,value from platform_settings where key=any($1)",[new[]{"windows_auth.distributed_window_hours","windows_auth.distributed_min_accounts","windows_auth.distributed_min_sources","windows_auth.distributed_max_failures_per_account"}],ct);
            int Setting(string key,int fallback)=>settings.FirstOrDefault(r=>r.Text("key")=="windows_auth."+key) is {} row && int.TryParse(row["value"]?.ToString(),out int value) && value is >=1 and <=744?value:fallback;
            policy=Review(failures,q,Setting("distributed_window_hours",24),Setting("distributed_min_accounts",10),Setting("distributed_min_sources",5),Setting("distributed_max_failures_per_account",3));
        }
        catch(Exception e) when(VpnAuthorizations.IsTimeout(e) && !ct.IsCancellationRequested)
        {
            coverage["history_event_present"]=rows.Count>0?(JsonNode?)JsonValue.Create(true):null;coverage["read_incomplete"]=true;coverage["unavailable_reason"]="source_read_timeout";
            policy=VpnJson.Obj(new {state="unavailable",coverage_scope="not_evaluated",signals=Array.Empty<object>(),not_a_verdict=true});
        }
        return Compose(q,rows,coverage,policy,truncated,payload);
    }
    static JsonObject Observed(JsonObject row,params (string Input,string Output)[] fields)
    {
        var result=new JsonObject();foreach(var (input,output) in fields) if(row.Text(input).Trim() is {Length:>0} text) result[output]=text;
        result["state"]=result.Count>0?"observed":"unknown";return result;
    }
    public static JsonObject Compose(VpnQuery q,List<JsonObject> events,JsonObject coverage,JsonObject policy,bool truncated,JsonObject? payload=null)
    {
        payload??=VpnJson.Obj(new {contract_id=Contract,report_key="vpn.audit",source_domain_id=q.Domain,time_bounds=new {from_utc=VpnJson.Iso(q.From),to_utc_exclusive=VpnJson.Iso(q.To)},limits=new {max_period_days=90,display_limit=q.Limit,max_display_limit=500,bounded=true}});
        if(events.Count>q.Limit) throw new VpnInputException("windows_authentication_input_bound_exceeded");
        var seen=new HashSet<long>();var items=new List<JsonObject>();var failures=new Dictionary<(string,string),List<JsonObject>>();
        foreach(var row in events.OrderBy(r=>r.At("time_created_utc")).ThenBy(r=>r.Number("event_db_id")))
        {
            int code=(int)row.Number("event_id"),index=Array.IndexOf(EventIds,code);
            if(index<0) throw new VpnInputException("windows_authentication_event_invalid");
            if(row.At("time_created_utc") is not {} at || at<q.From || at>=q.To) throw new VpnInputException("windows_authentication_event_outside_bounds");
            if(row.Number("event_db_id")<=0 || !seen.Add(row.Number("event_db_id"))) throw new VpnInputException("windows_authentication_event_identity_invalid");
            if(string.IsNullOrWhiteSpace(row.Text("domain_controller"))) throw new VpnInputException("windows_authentication_domain_controller_missing");
            var item=VpnJson.Pick(row,"event_db_id","event_record_id","event_id","time_created_utc","domain_controller");item["authentication_fact"]=Facts[index];
            item["target"]=Observed(row,("target_user_sid","target_user_sid"),("target_user_name","target_user_name"));
            string role=SubjectIds.Contains(code)?"subject":"target";
            var principal=Observed(row,(role+"_user_sid","principal_user_sid"),(role+"_user_name","principal_user_name"));principal["role"]=role+"_account";item["principal"]=principal;
            item["source"]=Observed(row,("source_ip","source_ip"),("workstation_name","workstation_name"));
            var native=new JsonObject();foreach(string key in new[]{"logon_type","result_code","process_name","target_server_name"}) if(row.Text(key).Trim() is {Length:>0} value) native[key]=value;item["source_native"]=native;
            item["evidence"]=VpnJson.Pick(row,"event_db_id","event_record_id","source_core_sha256","source_facts_sha256");
            bool mixed=MixedIds.Contains(code);string result=row.Text("result_code").Trim();bool failure=FailureIds.Contains(code) || mixed && result!="" && !ZeroCodes.Contains(result.ToLowerInvariant());
            if(mixed) item["outcome"]=result==""?VpnJson.Obj(new {state="unknown"}):VpnJson.Obj(new {state="observed",result=ZeroCodes.Contains(result.ToLowerInvariant())?"success":"failure",result_code=result});
            string sid=principal.Text("principal_user_sid"),ip=row.Text("source_ip").Trim();
            if(code==4624)
                item["earlier_observed_failures_in_window"]=sid=="" || ip==""?VpnJson.Obj(new {state="unknown",reason="target_sid_or_source_ip_not_observed"}):VpnJson.Obj(new {state="observed",event_references=failures.GetValueOrDefault((sid,ip),[]).Select(r=>VpnJson.Pick(r,"event_db_id","event_record_id","event_id","time_created_utc"))});
            if(failure && sid!="" && ip!="") { if(!failures.TryGetValue((sid,ip),out var prior)) failures[(sid,ip)]=prior=[];prior.Add(item); }
            items.Add(item);
        }
        bool incomplete=coverage.Flag("read_incomplete"),history=coverage.Flag("history_event_present");if(!incomplete && events.Count>0 && !history) throw new VpnInputException("windows_authentication_collection_coverage_invalid");
        string state=incomplete?"partial":events.Count>0?"available":history?"empty_unverified":"not_collected";
        JsonObject publicCoverage=incomplete?(JsonObject)coverage.DeepClone():VpnJson.Pick(coverage,"history_event_present");publicCoverage["state"]=state;publicCoverage["source_completeness"]="not_proven";
        payload["state"]=policy.Text("state")=="unavailable"?"partial":state;payload["items"]=VpnJson.Array(items);payload["collection_coverage"]=publicCoverage;payload["manual_review_policy"]=policy.DeepClone();
        payload["unavailable_reason"]=coverage["unavailable_reason"]?.DeepClone()??policy["reason"]?.DeepClone();
        payload["result_window"]=VpnJson.Obj(new {display_limit=q.Limit,returned_event_count=items.Count,truncated});
        payload["limitations"]=new JsonArray("source_events_not_windows_sessions","manual_review_signal_not_attack_verdict","empty_window_source_completeness_not_proven","unknown_results_remain_unknown","earlier_failure_context_displayed_sample_only","source_completeness_not_proven");return payload;
    }
    public static JsonObject Review(List<JsonObject> failures,VpnQuery q,int hours=24,int minimumAccounts=10,int minimumSources=5,int maximumPerAccount=3)
    {
        if(failures.Count>100000) return VpnJson.Obj(new {state="unavailable",reason="review_input_limit",coverage_scope="not_evaluated",signals=Array.Empty<object>(),not_a_verdict=true,input_limit=100000});
        var signals=new List<JsonObject>();
        JsonObject? First(List<JsonObject> ordered,string rule,string? ip,TimeSpan duration,int minFailures,int minAccounts,int minSources,int? cap)
        {
            int left=0,right=0;var accounts=new Dictionary<string,int>();var sourcesByAccount=new Dictionary<string,Dictionary<string,int>>();var targets=new Dictionary<string,int>();var sources=new Dictionary<string,int>();int count=0;
            void ChangeCount(Dictionary<string,int> values,string key,int delta) { int next=values.GetValueOrDefault(key)+delta;if(next==0) values.Remove(key);else values[key]=next; }
            void Contribute(string sid,string source,int delta) { ChangeCount(targets,sid,delta);ChangeCount(sources,source,delta);count+=delta; }
            void Change(JsonObject row,int delta)
            {
                string sid=row.Text("sid"),source=row.Text("source");bool eligible=cap is null || accounts.GetValueOrDefault(sid)<=cap;
                ChangeCount(accounts,sid,delta);bool nextEligible=cap is null || accounts.GetValueOrDefault(sid)<=cap;
                if(!sourcesByAccount.TryGetValue(sid,out var accountSources)) sourcesByAccount[sid]=accountSources=[];
                if(eligible && !nextEligible) foreach(var (key,n) in accountSources) Contribute(sid,key,-n);
                if(source!="") ChangeCount(accountSources,source,delta);
                if(nextEligible && !eligible) foreach(var (key,n) in accountSources) Contribute(sid,key,n);
                else if(nextEligible && eligible && source!="") Contribute(sid,source,delta);
                if(!accounts.ContainsKey(sid)) sourcesByAccount.Remove(sid);
            }
            while(left<ordered.Count)
            {
                var start=ordered[left].At("at")!.Value;var end=start+duration;int anchor=left+1;while(anchor<ordered.Count && ordered[anchor].At("at")==start) anchor++;
                while(right<ordered.Count && ordered[right].At("at")<end) Change(ordered[right++],1);
                if(ordered.Skip(left).Take(anchor-left).Any(r=>r.Text("source")!="") && count>=minFailures && targets.Count>=minAccounts && sources.Count>=minSources)
                {
                    long evidence=ordered.Skip(left).Take(right-left).Where(r=>r.Text("source")!="" && (cap is null || accounts.GetValueOrDefault(r.Text("sid"))<=cap)).Min(r=>r.Number("id"));
                    return VpnJson.Obj(new {state="manual_review_signal",rule,source_ip=ip,window=new {from_utc=VpnJson.Iso(start),to_utc_exclusive=VpnJson.Iso(end<q.To?end:q.To)},failure_fact_count=count,distinct_target_sid_count=targets.Count,distinct_source_count=sources.Count,event_references=Array.Empty<object>(),evidence_event_db_id=evidence,not_a_verdict=true});
                }
                while(left<anchor) Change(ordered[left++],-1);
            }
            return null;
        }
        var ordered=failures.OrderBy(r=>r.At("at")).ThenBy(r=>r.Number("id")).ToList();
        foreach(var group in ordered.Where(r=>r.Text("ip")!="").GroupBy(r=>r.Text("ip"))) if(First(group.ToList(),"single_ip",group.Key,TimeSpan.FromMinutes(15),5,3,1,null) is {} signal) signals.Add(signal);
        if(First(ordered,"distributed",null,TimeSpan.FromHours(hours),0,minimumAccounts,minimumSources,maximumPerAccount) is {} distributed) signals.Add(distributed);
        return VpnJson.Obj(new {id="windows-authentication-failure-manual-review",version="v2",conditions=new {minimum_failure_facts=5,minimum_distinct_target_sids=3,source_ip="nonempty_source_native",rolling_window_minutes=15},distributed_conditions=new {rolling_window_hours=hours,minimum_distinct_target_sids=minimumAccounts,minimum_distinct_sources=minimumSources,maximum_failures_per_target=maximumPerAccount},coverage_scope="whole_period",time_bounds=new {from_utc=VpnJson.Iso(q.From),to_utc_exclusive=VpnJson.Iso(q.To)},state=signals.Count>0?"manual_review_signal":"no_observed_signal_unverified",signals=signals.OrderBy(r=>r.Text("rule"),StringComparer.Ordinal).ThenBy(r=>r["window"].Text("from_utc"),StringComparer.Ordinal).ThenBy(r=>r.Text("source_ip"),StringComparer.Ordinal).Take(100),not_a_verdict=true,signals_truncated=signals.Count>100,signal_limit=100,signal_selection="first_matching_window_per_ip_and_first_distributed_window"});
    }
}
