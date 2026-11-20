using System.Text.Json.Nodes;

namespace Sli.Server.Vpn;

public static class VpnConnections
{
    public static long UnionSeconds(IEnumerable<(DateTimeOffset Start,DateTimeOffset End)> intervals)
    {
        var values=intervals.OrderBy(x=>x.Start).ThenBy(x=>x.End).ToArray();if(values.Length==0) return 0;
        var start=values[0].Start;var end=values[0].End;long total=0;
        foreach(var next in values.Skip(1)) { if(next.Start<=end) { if(next.End>end) end=next.End; }else { total+=(long)(end-start).TotalSeconds;start=next.Start;end=next.End; } }
        return total+(long)(end-start).TotalSeconds;
    }
    static long Minutes(long seconds)=>(long)(seconds/60.0+0.5);
    static DateTimeOffset Max(DateTimeOffset x,DateTimeOffset y)=>x>y?x:y;
    static DateTimeOffset Min(DateTimeOffset x,DateTimeOffset y)=>x<y?x:y;
    static (DateTimeOffset Start,DateTimeOffset End)? Closed(JsonObject row,DateTimeOffset from,DateTimeOffset to)
    {
        var start=row.At("started_at_utc");var stop=row.At("stopped_at_utc");if(start is null || stop is null) return null;
        var a=Max(start.Value,from);var b=Min(stop.Value,to);return a<b?(a,b):null;
    }
    internal static (DateTimeOffset From,DateTimeOffset To) ReportPeriod(DateTimeOffset? from,DateTimeOffset? to,TimeZoneInfo zone,DateTimeOffset now)
    {
        if(from is null && to is null)
        {
            var local=TimeZoneInfo.ConvertTime(now,zone);var first=new DateTime(local.Year,local.Month,1);
            return(new DateTimeOffset(first,zone.GetUtcOffset(first)).ToUniversalTime(),new DateTimeOffset(first.AddMonths(1),zone.GetUtcOffset(first.AddMonths(1))).ToUniversalTime());
        }
        if(from is null || to is null) throw new VpnInputException("vpn_connections_period_requires_both_bounds");
        if(from>=to) throw new VpnInputException("empty_or_reversed_time_range");
        if(to-from>TimeSpan.FromDays(366)) throw new VpnInputException("vpn_connections_period_too_wide");
        return(from.Value,to.Value);
    }
    public static async Task<JsonObject> Read(IVpnReadSession db,VpnAccess access,VpnQuery q,IQueryCollection query,CancellationToken ct,bool includeFailedAuthorizations=true)
    {
        var payload=VpnJson.Obj(new {contract_id="sli.vpn-connections-report.v1",report_key="vpn.connections",source_domain_id=q.Domain,state="not_authorized",branches=access.Branches(q.Domain),employees=Array.Empty<object>()});
        if(!access.Branch("directory",q.Domain).Allowed || !access.Branch("sessions",q.Domain).Allowed) return payload;
        string office=Environment.GetEnvironmentVariable("ADLOG_DISPLAY_TIMEZONE")??"UTC";
        TimeZoneInfo zone;try {zone=TimeZoneInfo.FindSystemTimeZoneById(office);}catch(TimeZoneNotFoundException) {zone=TimeZoneInfo.Utc;}
        var (from,to)=ReportPeriod(q.From,q.To,zone,DateTimeOffset.UtcNow);q=q with {From=from,To=to};
        var coverage=(await db.ReadAsync(VpnSql.Coverage,[q.Domain],ct)).FirstOrDefault();
        if(coverage is null) { payload["state"]="not_collected";payload["unavailable_reason"]="no_accounting_data";return payload; }
        var rows=await db.ReadAsync(VpnSql.ConnectionSessions,[q.Domain,q.To,q.From,q.From,20001],ct);
        if(rows.Count>20000) throw new VpnInputException("vpn_connections_session_bound_exceeded");
        var entitlements=await db.ReadAsync(VpnSql.Entitlements,[q.Domain,5001],ct);if(entitlements.Count>5000) throw new VpnInputException("vpn_connections_entitlement_bound_exceeded");
        List<JsonObject> failed=[];string failedState="not_collected";
        if(includeFailedAuthorizations)
        {
            failed=await db.ReadAsync(VpnSql.ConnectionFailedEvents,[q.Domain,q.From,q.To,2001],ct);
            bool exceeded=failed.Count>2000;if(exceeded) failed=[];
            var collected=(await db.ReadAsync(VpnSql.ConnectionFailedCollected,[q.Domain],ct)).FirstOrDefault().Flag("collected");
            failedState=exceeded?"unavailable":collected?"available":"not_collected";
        }
        long[] ids=rows.Concat(entitlements).Concat(failed).Select(r=>r.Number("entity_id")).Where(id=>id>0).Distinct().Order().ToArray();
        var identities=ids.Length==0?new Dictionary<long,JsonObject>():(await db.ReadAsync(VpnSql.FullIdentities,[ids,q.Domain],ct)).ToDictionary(r=>r.Number("entity_id"));
        var composed=Compose(q,rows,identities,entitlements,coverage,zone,query["q"].FirstOrDefault(),query["department"].FirstOrDefault(),query["status"].FirstOrDefault()??"all",failed,failedState);
        composed["branches"]=access.Branches(q.Domain);return composed;
    }
    public static JsonObject Compose(VpnQuery q,List<JsonObject> rows,Dictionary<long,JsonObject> identities,List<JsonObject> entitlements,JsonObject coverage,TimeZoneInfo zone,string? search=null,string? department=null,string status="all",List<JsonObject>? failedEvents=null,string failedCollectionState="not_collected")
    {
        if(status is not ("all" or "closed" or "open")) throw new VpnInputException("vpn_connections_status_invalid");
        if(q.Limit is <1 or >200 || q.Offset is <0 or >20000) throw new VpnInputException("vpn_connections_page_invalid");
        var from=q.From!.Value;var to=q.To!.Value;var employees=new List<JsonObject>();
        bool Match(JsonObject row)=>(string.IsNullOrWhiteSpace(search) || (row.Text("display_name")+" "+row.Text("account_name")).Contains(search.Trim(),StringComparison.OrdinalIgnoreCase)) && (string.IsNullOrWhiteSpace(department) || row.Text("department").Equals(department.Trim(),StringComparison.OrdinalIgnoreCase));
        foreach(var group in rows.GroupBy(r=>r.Number("entity_id")))
        {
            var actual=group.Where(r=>r.At("started_at_utc") is {} start && start<to && (r.At("stopped_at_utc") is {} stop?Max(start,from)<Min(stop,to):r.At("last_observed_at_utc") is {} last && last>=start && last>=from)).ToArray();
            if(actual.Length==0) continue;
            var identity=VpnAuthorizations.Identity(group.Key,identities.GetValueOrDefault(group.Key));
            var closed=actual.Select(r=>(Row:r,Interval:Closed(r,from,to))).Where(x=>x.Interval is not null).Select(x=>(x.Row,x.Interval!.Value)).ToArray();
            var overlapping=new HashSet<string>();int pairs=0;
            for(int i=0;i<closed.Length;i++) for(int j=i+1;j<closed.Length;j++) if(Max(closed[i].Value.Start,closed[j].Value.Start)<Min(closed[i].Value.End,closed[j].Value.End)) {overlapping.Add(closed[i].Row.Text("session_row_id"));overlapping.Add(closed[j].Row.Text("session_row_id"));pairs++;}
            long seconds=UnionSeconds(closed.Select(x=>x.Value));
            var sessions=new List<JsonObject>();
            foreach(var row in actual.OrderByDescending(r=>r.At("started_at_utc")))
            {
                var interval=Closed(row,from,to);var item=VpnJson.Pick(row,"session_row_id","lifecycle_state","completeness","started_at_utc","last_observed_at_utc","stopped_at_utc","duration_seconds","observation_count","anomalies");
                item["confirmed_seconds_in_period"]=interval is {} range?(JsonNode?)JsonValue.Create((long)(range.End-range.Start).TotalSeconds):null;
                item["effective_start_utc"]=VpnJson.Iso(interval?.Start??(row.At("started_at_utc") is {} s?Max(s,from):null));
                item["effective_stop_utc"]=VpnJson.Iso(interval?.End??((row.At("stopped_at_utc")??row.At("last_observed_at_utc")) is {} e?Min(e,to):null));
                item["overlap_violation"]=overlapping.Contains(row.Text("session_row_id"));item["evidence_links"]=new JsonArray();item["evidence_state"]="not_available_in_current_safe_read_path";sessions.Add(item);
            }
            identity["closed_session_count"]=closed.Length;identity["open_session_count"]=actual.Count(r=>r.At("stopped_at_utc") is null);
            identity["confirmed_seconds"]=closed.Length>0?(JsonNode?)JsonValue.Create(seconds):null;identity["confirmed_minutes"]=closed.Length>0?(JsonNode?)JsonValue.Create(Minutes(seconds)):null;
            identity["overlap_violation"]=overlapping.Count>0;identity["overlap_count"]=pairs;identity["days_with_observed_start"]=actual.Select(r=>TimeZoneInfo.ConvertTime(r.At("started_at_utc")!.Value,zone).Date).Distinct().Count();
            identity["session_count"]=actual.Length;identity["session_details_has_more"]=sessions.Count>100;identity["sessions"]=VpnJson.Array(sessions.Take(100));identity["sessions_all"]=VpnJson.Array(sessions);
            if(Match(identity) && (status!="closed" || closed.Length>0) && (status!="open" || identity.Number("open_session_count")>0)) employees.Add(identity);
        }
        employees=employees.OrderBy(r=>r.Text("display_name"),StringComparer.OrdinalIgnoreCase).ThenBy(r=>r.Text("account_name"),StringComparer.OrdinalIgnoreCase).ThenBy(r=>r.Number("entity_id")).ToList();
        var daily=new List<JsonObject>();DateTime day=TimeZoneInfo.ConvertTime(from,zone).Date,lastDay=TimeZoneInfo.ConvertTime(to.AddTicks(-10),zone).Date;
        for(;day<=lastDay;day=day.AddDays(1))
        {
            var a=Max(new DateTimeOffset(day,zone.GetUtcOffset(day)).ToUniversalTime(),from);var b=Min(new DateTimeOffset(day.AddDays(1),zone.GetUtcOffset(day.AddDays(1))).ToUniversalTime(),to);
            int starts=0,closedCount=0;long seconds=0;
            foreach(var employee in employees)
            {
                var sessions=employee["sessions_all"]!.AsArray().OfType<JsonObject>().ToArray();
                if(sessions.Any(r=>r.At("started_at_utc")>=a && r.At("started_at_utc")<b)) starts++;
                closedCount+=sessions.Count(r=>r.At("stopped_at_utc") is not null && r.At("started_at_utc")>=a && r.At("started_at_utc")<b);
                seconds+=UnionSeconds(sessions.Select(r=>Closed(r,a,b)).Where(x=>x is not null).Select(x=>x!.Value));
            }
            daily.Add(VpnJson.Obj(new {date=day.ToString("yyyy-MM-dd"),employees_with_observed_start=starts,closed_session_count=closedCount,confirmed_seconds=seconds,confirmed_minutes=Minutes(seconds)}));
        }
        JsonObject Aggregate(IEnumerable<JsonObject> source)
        {
            var list=source.ToArray();bool confirmed=list.Any(r=>r["confirmed_seconds"] is not null);long seconds=list.Sum(r=>r.Number("confirmed_seconds"));
            return VpnJson.Obj(new {employee_count=list.Length,closed_session_count=list.Sum(r=>r.Number("closed_session_count")),confirmed_seconds=confirmed?(long?)seconds:null,confirmed_minutes=confirmed?(long?)Minutes(seconds):null,open_session_count=list.Sum(r=>r.Number("open_session_count")),employees_with_open_sessions=list.Count(r=>r.Number("open_session_count")>0),employees_with_overlap=list.Count(r=>r.Flag("overlap_violation"))});
        }
        var analytics=Aggregate(employees);analytics.Remove("employees_with_open_sessions");analytics["daily"]=VpnJson.Array(daily);
        analytics["employees"]=VpnJson.Array(employees.Take(200).Select(r=> {var clone=(JsonObject)r.DeepClone();clone.Remove("sessions");clone.Remove("sessions_all");return clone;}));analytics["employees_has_more"]=employees.Count>200;
        var departments=employees.GroupBy(r=>r.Text("department")).OrderBy(g=>g.Key,StringComparer.Ordinal).Select(g=> {var row=Aggregate(g);row["department"]=g.Key;row.Remove("open_session_count");return row;}).ToArray();
        analytics["departments"]=VpnJson.Array(departments.Take(200));analytics["departments_has_more"]=departments.Length>200;
        var entitlementItems=entitlements.Select(r=>VpnAuthorizations.Identity(r.Number("entity_id"),identities.GetValueOrDefault(r.Number("entity_id")))).Where(Match).ToArray();
        var failedItems=new List<JsonObject>();
        foreach(var row in failedEvents??[])
        {
            if(row.Number("event_id")!=6273) continue;
            long entity=row.Number("entity_id");var identity=VpnAuthorizations.Identity(entity,identities.GetValueOrDefault(entity));
            var item=VpnJson.Pick(row,"event_db_id","event_record_id","event_id","time_created_utc","source_core_sha256");
            item["entity_id"]=entity>0?JsonValue.Create(entity):null;item["display_name"]=entity>0?identity["display_name"]?.DeepClone():JsonValue.Create("Не определено");
            string observed=string.Join("\\",new[]{row.Text("subject_domain_name").Trim(),row.Text("subject_user_name").Trim()}.Where(s=>s!=""));
            item["account_name"]=entity>0?identity["account_name"]?.DeepClone():JsonValue.Create(observed==""?"Не определено":observed);
            item["department"]=entity>0?identity["department"]?.DeepClone():JsonValue.Create("Не определено");item["identity_state"]=entity>0?"resolved":"unresolved";item["reason_code"]=row.Text("reason_code","Не определён");item["reason_text"]=null;
            if(Match(item)) failedItems.Add(item);
        }
        bool unavailable=failedCollectionState=="unavailable";
        JsonObject failedAuthorizations=unavailable?VpnJson.Obj(new {state="unavailable",unavailable_reason="input_event_bound_exceeded",count=(int?)null,items=Array.Empty<object>()}):VpnJson.Obj(new {state=failedCollectionState,count=failedCollectionState=="not_collected"?(int?)null:failedItems.Count,items=failedItems.Take(200),has_more=failedItems.Count>200});
        var limitations=new List<string> {"Подтверждённое время VPN-подключения не является показателем рабочего времени.","NPS 6273 отражает отказ авторизации и не определяет длительность VPN-сессии.","Ссылки на raw Accounting evidence не публикуются текущей безопасной session view."};
        if(unavailable) limitations.Add("Список NPS 6273 превысил ограничение безопасного чтения; количество и список не показаны. Это не означает отсутствие отказов.");
        return VpnJson.Obj(new {contract_id="sli.vpn-connections-report.v1",report_key="vpn.connections",source_domain_id=q.Domain,state=unavailable?"partial":VpnSessions.CoverageState(coverage),office_timezone=zone.Id,generated_at_utc=VpnJson.Iso(DateTimeOffset.UtcNow),period=new {from_utc=VpnJson.Iso(from),to_utc_exclusive=VpnJson.Iso(to),local_from_date=TimeZoneInfo.ConvertTime(from,zone).ToString("yyyy-MM-dd"),local_to_date=TimeZoneInfo.ConvertTime(to.AddTicks(-10),zone).ToString("yyyy-MM-dd")},coverage=coverage.DeepClone(),employees=employees.Skip(q.Offset).Take(q.Limit).Select(r=> {var clone=(JsonObject)r.DeepClone();clone.Remove("sessions_all");return clone;}),employee_page=new {limit=q.Limit,offset=q.Offset,has_more=q.Offset+q.Limit<employees.Count,filtered_count=employees.Count},analytics,entitlements=new {state="available",items=entitlementItems.Take(200),has_more=entitlementItems.Length>200},failed_authorizations=failedAuthorizations,limitations,limits=new {session_calculation_limit=20000,employee_page_limit=200,session_details_per_employee=100,entitlement_limit=5000,failed_event_limit=2000,branch_output_limit=200}});
    }
}
