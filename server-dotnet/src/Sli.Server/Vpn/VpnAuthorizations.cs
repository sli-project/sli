using System.Text.Json.Nodes;

namespace Sli.Server.Vpn;

public static class VpnAuthorizations
{
    public const string TimelineContract="sli.vpn-audit-authorization-timeline.v1",SeriesContract="sli.vpn-audit-failed-authorization-series.v1";
    public static JsonObject Identity(long entity,JsonObject? source)
    {
        string Text(string key,string fallback="Не определено")=>string.IsNullOrWhiteSpace(source.Text(key))?fallback:source.Text(key);
        string account=Text("netbios_name","")!="" && Text("sam_account_name","")!=""?Text("netbios_name")+"\\"+Text("sam_account_name"):"Не определено";
        return VpnJson.Obj(new {entity_id=entity,display_name=Text("display_name"),account_name=account,department=Text("department"),enabled=source?["enabled"]?.DeepClone(),last_logon_utc=source?["last_logon_utc"]?.DeepClone(),privileged=source.Flag("privileged")});
    }
    static (string? Key,string State,JsonObject Identity) Resolve(JsonObject row,Dictionary<long,JsonObject> identities)
    {
        long entity=row.Number("entity_id"),matches=row.Number("alias_match_count");
        if(matches==1 && entity>0) return ($"canonical_entity:{entity}","resolved",VpnJson.Pick(Identity(entity,identities.GetValueOrDefault(entity)),"entity_id","display_name","account_name","department"));
        string sid=row.Text("subject_user_sid").Trim();return(sid==""?null:"observed_subject_sid:"+sid,matches>1 && sid!=""?"ambiguous":"unresolved",VpnJson.Obj(new {entity_id=(long?)null,observed_subject_sid=sid==""?null:sid}));
    }
    public static async Task<JsonObject> Read(IVpnReadSession db,VpnAccess access,VpnQuery q,bool series,CancellationToken ct,bool failedOnly=false)
    {
        var bounds=VpnJson.Obj(new {from_utc=VpnJson.Iso(q.From),to_utc_exclusive=VpnJson.Iso(q.To)});
        var limits=series?VpnJson.Obj(new {input_event_limit=2000,series_limit=500,event_reference_limit=100,bounded=true}):VpnJson.Obj(new {input_event_limit=2000,bounded=true});
        var payload=VpnJson.Obj(new {contract_id=series?SeriesContract:TimelineContract,report_key="vpn.audit",source_domain_id=q.Domain,state="not_authorized",time_bounds=bounds,items=System.Array.Empty<object>(),limits});
        if(!access.Branch("sessions",q.Domain).Allowed) return payload;
        List<JsonObject> events=[];JsonObject coverage=new();Dictionary<long,JsonObject> identities=[];
        try
        {
            events=await db.ReadAsync(series?VpnSql.FailedEvents:VpnSql.NpsEvents,series?[q.Domain,q.From,q.To,2001]:[q.Domain,failedOnly?new[]{6273}:new[]{6272,6273},q.From,q.To,2001],ct);
            if(series && events.Count>2000) throw new VpnInputException("vpn_audit_failed_authorization_input_bound_exceeded");
            bool truncated=events.Count>2000;events=events.Take(2000).ToList();coverage["truncated"]=truncated;
            var loaded=await db.ReadAsync(series?VpnSql.FailedCoverage:VpnSql.NpsCoverage,series?[q.From,q.To,q.From,q.To,q.Domain]:[q.Domain,q.Domain,q.From,q.To],ct);
            foreach(var (key,value) in loaded.FirstOrDefault()??new JsonObject()) coverage[key]=value?.DeepClone();
            long[] ids=events.Where(r=>r.Number("alias_match_count")==1 && r.Number("entity_id")>0).Select(r=>r.Number("entity_id")).Distinct().Order().ToArray();
            if(ids.Length>0) identities=(await db.ReadAsync(VpnSql.Identities,[ids,q.Domain],ct)).ToDictionary(r=>r.Number("entity_id"));
        }
        catch(Exception e) when(!series && IsTimeout(e) && !ct.IsCancellationRequested)
        { coverage["read_incomplete"]=true;coverage["unavailable_reason"]="source_read_timeout";coverage["history_event_present"]=events.Count>0?(JsonNode?)JsonValue.Create(true):null; }
        return Compose(q,events,identities,coverage,series,payload);
    }
    internal static bool IsTimeout(Exception e)=>e is TimeoutException || e is Npgsql.PostgresException {SqlState:"57014"} || e is OperationCanceledException;
    public static JsonObject Compose(VpnQuery q,List<JsonObject> events,Dictionary<long,JsonObject> identities,JsonObject coverage,bool series,JsonObject? payload=null,int eventReferenceLimit=100)
    {
        if(series && eventReferenceLimit is <1 or >100) throw new VpnInputException("vpn_audit_failed_authorization_reference_limit_invalid");
        payload??=VpnJson.Obj(new {contract_id=series?SeriesContract:TimelineContract,report_key="vpn.audit",source_domain_id=q.Domain,time_bounds=new {from_utc=VpnJson.Iso(q.From),to_utc_exclusive=VpnJson.Iso(q.To)},limits=series?(object)new {input_event_limit=2000,series_limit=500,event_reference_limit=eventReferenceLimit,bounded=true}:new {input_event_limit=2000,bounded=true}});
        if(series) payload["limits"]!["event_reference_limit"]=eventReferenceLimit;
        if(events.Count>2000) throw new VpnInputException(series?"vpn_audit_failed_authorization_input_bound_exceeded":"vpn_audit_authorization_timeline_input_bound_exceeded");
        string prefix=series?"vpn_audit_failed_authorization":"vpn_audit_authorization_timeline";
        foreach(var row in events)
        {
            long code=row.Number("event_id");if(series?code!=6273:code is not (6272 or 6273)) throw new VpnInputException(prefix+"_event_invalid");
            var at=row.At("time_created_utc");if(at is null || at<q.From || at>=q.To) throw new VpnInputException(prefix+"_event_outside_bounds");
        }
        long failed=events.Count(r=>r.Number("event_id")==6273),successCount=coverage.Number("window_success_6272_count"),failedCount=coverage.Number("window_failed_6273_count");
        bool history=series?coverage.Number("history_event_count")>0:coverage.Flag("history_event_present"),incomplete=coverage.Flag("read_incomplete"),truncated=coverage.Flag("truncated");
        if(!incomplete)
        {
            if(successCount<0 || failedCount<0 || series && coverage.Number("history_event_count")<successCount+failedCount || events.Count>0 && !history) throw new VpnInputException(prefix+"_collection_coverage_invalid");
            if(series?failedCount!=failed:failedCount<failed || !truncated && failedCount!=failed) throw new VpnInputException(prefix+"_collection_coverage_mismatch");
        }
        string state=incomplete || truncated && events.Count>0?"partial":events.Count>0?"available":!history?"not_collected":successCount>0?"empty_unverified":"coverage_unverified";
        JsonObject publicCoverage=incomplete?(JsonObject)coverage.DeepClone():series?VpnJson.Pick(coverage,"history_event_count","window_success_6272_count","window_failed_6273_count"):VpnJson.Pick(coverage,"history_event_present","window_success_6272_count","window_failed_6273_count");
        publicCoverage["state"]=state;publicCoverage["empty_window_basis"]=events.Count==0 && history && successCount>0?"durable_6272_nps_event":null;publicCoverage["source_completeness"]="not_proven";publicCoverage["freshness"]="not_asserted";
        payload["state"]=state;payload["collection_coverage"]=publicCoverage;
        var items=new List<JsonObject>();
        if(!series)
        {
            foreach(var row in events.OrderBy(r=>r.At("time_created_utc")).ThenBy(r=>r.Number("event_db_id")))
            {
                var (_,identityState,identity)=Resolve(row,identities);var item=VpnJson.Pick(row,"event_db_id","event_record_id","event_id","time_created_utc","source_core_sha256");
                item["authorization_result"]=row.Number("event_id")==6272?"allowed":"denied";item["identity_state"]=identityState;item["identity"]=identity;
                foreach(string key in new[]{"source_ip","correlation_id","reason_code"})
                    if((key!="reason_code" || row.Number("event_id")==6273) && row.Text(key).Trim() is {Length:>0} value) item[key]=value;
                items.Add(item);
            }
            payload["unavailable_reason"]=coverage["unavailable_reason"]?.DeepClone();payload["result_window"]=VpnJson.Obj(new {truncated,returned_event_count=events.Count,display_limit=2000});
        }
        else
        {
            var groups=events.GroupBy(row=> { var (key,_,_)=Resolve(row,identities);string ip=row.Text("source_ip").Trim();return key is not null && ip!=""?"series\0"+key+"\0"+ip:"single_event\0"+row.Text("event_db_id"); },StringComparer.Ordinal).ToArray();
            if(groups.Length>500) throw new VpnInputException("vpn_audit_failed_authorization_series_bound_exceeded");
            foreach(var group in groups)
            {
                var ordered=group.OrderBy(r=>r.At("time_created_utc")).ThenBy(r=>r.Number("event_db_id")).ToArray();var first=ordered[0];var (key,identityState,identity)=Resolve(first,identities);string ip=first.Text("source_ip").Trim();
                string[] reasons=ordered.Select(r=>r.Text("reason_code").Trim()).Where(s=>s!="").Distinct().Order(StringComparer.Ordinal).ToArray();
                items.Add(VpnJson.Obj(new {series_state=key is not null && ip!=""?"grouped":"single_event_unattributed",event_id=6273,identity_state=identityState,identity,source_state=ip==""?"unavailable":"available",source_ip=ip==""?null:ip,count=ordered.Length,first_failed_at_utc=first.Text("time_created_utc"),last_failed_at_utc=ordered[^1].Text("time_created_utc"),time_bounds=payload["time_bounds"]!.DeepClone(),reason_codes=reasons.Take(100),reason_codes_truncated=reasons.Length>100,event_references=ordered.Take(eventReferenceLimit).Select(r=>VpnJson.Pick(r,"event_db_id","event_record_id","event_id","time_created_utc","source_core_sha256")),event_references_truncated=ordered.Length>eventReferenceLimit}));
            }
            items=items.OrderByDescending(r=>r.Text("last_failed_at_utc"),StringComparer.Ordinal).ThenByDescending(r=>r.Text("first_failed_at_utc"),StringComparer.Ordinal).ThenByDescending(r=>r.Text("source_ip"),StringComparer.Ordinal).ThenByDescending(r=>r["identity"]!.ToJsonString(),StringComparer.Ordinal).ToList();
        }
        payload["items"]=VpnJson.Array(items);return payload;
    }
}
