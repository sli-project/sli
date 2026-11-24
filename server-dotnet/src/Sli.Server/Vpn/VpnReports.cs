using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Sli.Server.Workspace;

namespace Sli.Server.Vpn;

public static partial class VpnReports
{
    public static string State(string state)=>state switch {"available"=>"ok","not_authorized"=>"denied","unavailable" or "failed"=>"error","empty_unverified" or "coverage_unverified" or "identity_incomplete"=>"partial","ok" or "empty" or "denied" or "error" or "partial" or "processing" or "stale" or "not_collected"=>state,_=>"error"};
    public static JsonObject Result(string report,string state,IEnumerable<JsonObject>? items=null)
    {
        string reason=state switch {"ok"=>"query_completed","empty"=>"query_completed_zero_rows","denied"=>"access_denied","not_collected"=>"collection_not_confirmed","partial"=>"coverage_incomplete","processing"=>"import_or_projection_pending","stale"=>"freshness_exceeded",_=>"source_or_storage_error"};
        return VpnJson.Obj(new {contract_id="sli.report-result.v2",report_key=report,state,state_message=new {code="reports.state."+state,@params=new {},text=StateText(state)},state_details=new {reason,source=(string?)null,stage="query",limitations=Array.Empty<object>(),missing_sources=Array.Empty<object>(),missing_domains=Array.Empty<object>(),observed_at_utc=(string?)null,stale_since_utc=(string?)null,source_issues=Array.Empty<object>()},items=items??[],has_more=false,next_cursor=(string?)null,filtered_count=(long?)null,metrics=Array.Empty<object>(),series=new {},coverage=new {},filter_options=new {},limitations=Array.Empty<object>(),window=new {},collections=new {},access=new {allowed=true,hidden_categories=Array.Empty<string>(),reason=(string?)null}});
    }
    static string StateText(string state)
    {
        using var stream=typeof(VpnReports).Assembly.GetManifestResourceStream("Sli.Server.Access.Administration.server.ru.json")!;
        using var document=JsonDocument.Parse(stream);return document.RootElement.GetProperty("reports.state."+state).GetString()!;
    }
    public static async Task<JsonObject> Read(IVpnReadSession db,VpnAccess access,string report,IQueryCollection query,string action,CancellationToken ct,bool accountingOnly=false)
    {
        if(!access.Assigned(action) || action=="export" && !access.Capabilities.Decide("reports.export").Allowed) return Result(report,"denied");
        Validate(query,report,accountingOnly);
        if(report=="vpn.accounts") return await VpnAccounts.Read(db,access,query,action,ct);
        string Get(string key,string fallback="")=>query[key].FirstOrDefault() is {Length:>0} value?value:fallback;
        string domain=Get("domain",Get("domain_id"));
        if(domain=="")
        {
            var available=await DomainOptions(db,access,ct,accountingOnly);if((await DefaultDomain(db,access,available,ct)).Id is {} chosen) domain=chosen.ToString(CultureInfo.InvariantCulture);
        }
        if(!long.TryParse(domain,out long id)||id<=0) throw new VpnInputException("report_parameter_required:domain");
        if(Get("scope")=="all") throw new VpnInputException("report_parameter_required:domain");
        if(Get("scope")!="") throw new VpnInputException("report_parameter_unknown:scope");
        if(Get("domain_id")!="" && Get("domain")!="" && Get("domain_id")!=Get("domain")) throw new VpnInputException("domain_scope_invalid");
        string timezone=Get("tz","UTC"),tab=Get("tab","employees");
        int limit=ParseInt(Get("limit","100"),"report_limit_invalid"),offset=ParseInt(Get("cursor","0"),"report_cursor_invalid");
        if(limit is <1 or >200) throw new VpnInputException("report_limit_invalid");if(offset<0) throw new VpnInputException("report_cursor_invalid");
        var (from,to)=Period(query,timezone);var q=new VpnQuery(id,action,timezone,from,to,limit,offset,"");
        if (accountingOnly && !access.AccountingReport(id))
            throw new VpnPermissionException("report_access_denied");
        JsonObject raw;
        if(tab=="session_overlap") return await VpnOverlap.Read(db,access,q,query,ct);
        if(tab.StartsWith("policy_denials",StringComparison.Ordinal)) return await VpnPolicyDenials.Read(db,access,q,query,ct);
        JsonObject? source=null;
        if(tab is "authorizations" or "failed" or "windows" or "windows_heatmap")
        {
            source=await Safe(async()=>tab switch
            {
                "windows"=>await Windows(db,access,q,ct),
                "windows_heatmap"=>await Grid(db,access,q,ct),
                _=>await VpnAuthorizations.Read(db,access,q,false,ct,tab=="failed")
            },ct);
        }
        raw = await Safe(() => VpnConnections.Read(db, access, q, query, ct, includeFailedAuthorizations: false,
            includeEntitlements: !accountingOnly), ct);
        var result = Compose(report, q, tab, raw, source, await DomainOptions(db, access, ct, accountingOnly));
        if (accountingOnly)
        {
            var branches = result["branches"]!.AsObject();
            foreach (var key in new[] { "nps", "windows", "windows_heatmap" }) branches.Remove(key);
            var collections = result["collections"]!.AsObject();
            collections.Remove("entitlements");
            collections.Remove("failed");
            result["coverage"]!["accounting_scope"] = "domain_history";
        }
        return result;
    }
    internal static JsonObject Compose(string report,VpnQuery q,string tab,JsonObject raw,JsonObject? source,List<JsonObject> domainOptions)
    {
        var collections=new JsonObject();var branches=new JsonObject();
        foreach(string name in new[]{"nps","windows","windows_heatmap"}) branches[name]=VpnJson.Obj(new {state="not_requested",reason="load_on_open",limitations=Array.Empty<object>(),limits=new {}});
        if(source is not null)
        {
            string branch=tab is "authorizations" or "failed"?"nps":tab;
            var rows=source["items"]?.AsArray().OfType<JsonObject>().Select(r=>(JsonObject)r.DeepClone()).ToList()??[];
            if(branch=="nps") foreach(var row in rows)
            {
                row["decision"]=row.Text("authorization_result")=="allowed"?"разрешено":"отказано";
                row["identity_text"]=row["identity"]?["display_name"]?.DeepClone()??row["identity"]?["account_name"]?.DeepClone()??row["identity"]?["observed_subject_sid"]?.DeepClone();
                row["identity_state_text"]=row.Text("identity_state") switch {"resolved"=>"определена","ambiguous"=>"неоднозначна",_=>"не определена"};
                row["reason"]=row.Number("event_id")==6273?row["reason_code"]?.DeepClone():null;
                if(tab=="failed") {row["display_name"]=row["identity"]?["display_name"]?.DeepClone();row["account_name"]=row["identity"]?["account_name"]?.DeepClone();}
            }
            if(tab=="windows") foreach(var row in rows)
            {
                row["account_text"]=row["principal"].Text("state")=="unknown"?null:row["principal"]?["principal_user_name"]?.DeepClone();row["account_sid"]=row["principal"]?["principal_user_sid"]?.DeepClone();
                row["source_text"]=string.Join(" · ",new[]{row["source"].Text("source_ip"),row["source"].Text("workstation_name")}.Where(x=>x!=""));
                row["outcome_text"]=OutcomeText(row);
                row["native_text"]=row["source_native"] is JsonObject native?string.Join("; ",native.Select(x=>x.Key+": "+x.Value)):null;
                row["evidence_id"]=row["evidence"]?["event_db_id"]?.DeepClone();row["earlier_failures"]=row["earlier_observed_failures_in_window"].Text("state")=="observed"?JsonValue.Create(row["earlier_observed_failures_in_window"]?["event_references"]?.AsArray().Count??0):null;
            }
            collections[tab]=VpnJson.Array(rows);branches[branch]=SourceBranch(source,branch,rows.Count==0);
        }
        var employees=raw["employees"]?.AsArray().OfType<JsonObject>().Select(r=>(JsonObject)r.DeepClone()).ToList()??[];
        foreach(var row in employees)
        {
            row["confirmed_hours"]=row.Number("closed_session_count")==0 && row.Number("open_session_count")>0?null:Hours(row["confirmed_minutes"]);
            foreach(var session in row["sessions"]?.AsArray().OfType<JsonObject>()??[]) session["duration_minutes"]=session["duration_seconds"] is null?null:JsonValue.Create(Math.Round(session.Number("duration_seconds")/60.0,MidpointRounding.ToEven));
        }
        var orderedBranches=new JsonObject { ["accounting"]=SourceBranch(raw,"accounting",employees.Count==0) };
        foreach(var (key,value) in branches) orderedBranches[key]=value?.DeepClone();branches=orderedBranches;
        string accountingState=branches["accounting"].Text("state"),state=CombinedState(branches);
        var payload=Result(report,state,employees);var page=raw["employee_page"];
        payload["has_more"]=page.Flag("has_more");payload["next_cursor"]=page.Flag("has_more")?(q.Offset+employees.Count).ToString(CultureInfo.InvariantCulture):null;payload["filtered_count"]=page?["filtered_count"]?.DeepClone();
        var analytics=raw["analytics"];var coverage=(JsonObject?)raw["coverage"]?.DeepClone()??new JsonObject();coverage["state"]=state;coverage["source"]="accounting";coverage["stage"]="session_projection";
        coverage["missing_sources"]=new JsonArray(branches.Where(x=>x.Value.Text("state") is "error" or "denied" or "not_collected").Select(x=>(JsonNode?)JsonValue.Create(x.Key)).ToArray());
        coverage["history_from_utc"]=coverage["history_available_from_utc"]?.DeepClone();coverage["history_to_utc"]=coverage["history_available_to_utc"]?.DeepClone();payload["coverage"]=coverage;
        foreach(string name in new[]{"daily","departments"})
        {
            var items=analytics?[name]?.AsArray().OfType<JsonObject>().Select(r=>(JsonObject)r.DeepClone()).ToArray()??[];foreach(var row in items) row["confirmed_hours"]=Hours(row["confirmed_minutes"]);collections[name]=VpnJson.Array(items);
        }
        collections["entitlements"]=raw["entitlements"]?["items"]?.DeepClone()??new JsonArray();if(!collections.ContainsKey("failed")) collections["failed"]=new JsonArray();payload["collections"]=collections;
        payload["filter_options"]=VpnJson.Obj(new {domain=domainOptions});
        payload["window"]=VpnJson.Obj(new {local_from_date=raw["period"]?["local_from_date"]?.DeepClone(),local_to_date=raw["period"]?["local_to_date"]?.DeepClone(),from_utc=VpnJson.Iso(q.From),to_utc_exclusive=VpnJson.Iso(q.To),timezone=raw.Text("office_timezone",q.Timezone),source_domain_id=q.Domain,generated_at_utc=raw["generated_at_utc"]?.DeepClone()});
        payload["branches"]=branches;
        payload["limitations"]=VpnJson.Array(branches.SelectMany(b=>b.Value?["limitations"]?.AsArray().OfType<JsonObject>()??[]));
        payload["state_details"]!["source"]="accounting";
        if(accountingState is "ok" or "empty" or "partial" or "processing" or "stale" && !(raw.Text("unavailable_reason")=="source_read_timeout" && employees.Count==0))
        {
            var metrics=new List<JsonObject>();
            foreach(var (key,label,field) in new[]{("employees","Сотрудников с VPN","employee_count"),("closed","Завершённых сессий","closed_session_count"),("hours","Подтверждено часов","confirmed_minutes"),("open","Незавершённых сессий","open_session_count"),("overlap","С пересечением сессий","employees_with_overlap")})
            {
                var value=key=="hours"?Hours(analytics?[field]):analytics?[field]?.DeepClone();bool complete=accountingState is "ok" or "empty" && coverage.Text("completeness") is "complete" or "proven";
                bool positive=double.TryParse(value?.ToString(),CultureInfo.InvariantCulture,out double number)&&number>0;
                var metric=VpnJson.Obj(new {key,label,value=complete||positive?value:null,quality=complete && value is not null?"complete":positive?"observed":"unknown",tone=key=="employees"?"accent":positive && key=="open"?"warning":positive && key=="overlap"?"danger":"neutral"});
                if(key=="open") metric["filter"]=VpnJson.Obj(new {status="open"});metrics.Add(metric);
            }
            payload["metrics"]=VpnJson.Array(metrics);
        }
        return payload;
    }
    static JsonNode? Hours(JsonNode? minutes)=>minutes is null?null:JsonValue.Create(Math.Round(double.Parse(minutes.ToString(),CultureInfo.InvariantCulture)/60,1,MidpointRounding.ToEven));
    internal static JsonObject Branch(JsonObject raw,bool empty=false)=>VpnJson.Obj(new {state=State(raw.Text("state")) is "ok" && raw["result_window"].Flag("truncated")?"partial":State(raw.Text("state"))=="ok" && empty?"empty":State(raw.Text("state")),reason=raw.Text("unavailable_reason",raw["result_window"].Flag("truncated")?"result_truncated":raw.Text("state")),limitations=Array.Empty<object>(),limits=raw["limits"]?.DeepClone()??new JsonObject()});
    internal static async Task<JsonObject> Safe(Func<Task<JsonObject>> read,CancellationToken ct=default)
    {
        try {return await read();}
        catch(VpnInputException) {return VpnJson.Obj(new {state="unavailable",unavailable_reason="window_or_input_limit"});}
        catch(Npgsql.PostgresException e) when(e.SqlState is "42501" or "42P01" or "42703") {return VpnJson.Obj(new {state="unavailable",unavailable_reason="source_unreadable"});}
        catch(Npgsql.NpgsqlException e) when(e is not Npgsql.PostgresException || e.SqlState?.StartsWith("08",StringComparison.Ordinal)==true) {return VpnJson.Obj(new {state="unavailable",unavailable_reason="source_unreadable"});}
        catch(Exception e) when(VpnAuthorizations.IsTimeout(e) && !ct.IsCancellationRequested) {return VpnJson.Obj(new {state="partial",unavailable_reason="source_read_timeout",coverage=new {state="partial",completeness="not_proven"}});}
    }
    static Task<JsonObject> Windows(IVpnReadSession db,VpnAccess access,VpnQuery q,CancellationToken ct)
    { if(q.To-q.From>TimeSpan.FromDays(90)) throw new VpnInputException("windows_authentication_period_too_wide");return VpnWindows.Read(db,access,q with {Limit=200},ct); }
    internal static async Task<JsonObject> Grid(IVpnReadSession db,VpnAccess access,VpnQuery q,CancellationToken ct)
    {
        if(q.To-q.From>TimeSpan.FromDays(90)) throw new VpnInputException("windows_authentication_period_too_wide");
        if(!access.Windows(q.Domain)) return VpnJson.Obj(new {state="not_authorized",items=Array.Empty<object>()});
        var cells=await db.ReadAsync(VpnSql.WindowsGrid,[q.Timezone,q.Timezone,q.Domain,"Security","Microsoft-Windows-Security-Auditing",q.From,q.To,new[]{4625,4771,4773},new[]{4768,4769,4776},new[]{"0","0x0","0x00000000","00000000"}],ct);
        string[] days=["Пн","Вт","Ср","Чт","Пт","Сб","Вс"];var rows=new List<JsonObject>();
        for(int d=1;d<=7;d++) for(int h=0;h<24;h++) rows.Add(VpnJson.Obj(new {hour=h.ToString("D2"),weekday=days[d-1],failures=cells.Where(r=>r.Number("isodow")==d && r.Number("hour")==h).Sum(r=>r.Number("failures"))}));
        return VpnJson.Obj(new {state="available",items=rows});
    }
    public static async Task<List<JsonObject>> DomainOptions(IVpnReadSession db,VpnAccess access,CancellationToken ct,bool accountingOnly=false)
    {
        if(!access.Assigned()) return [];
        try
        {
            var registered = accountingOnly ? new HashSet<long>() : (await VpnSessions.Sources(db,access,false,ct))["items"]!.AsArray().Select(r=>r!.Number("source_domain_id")).ToHashSet();
            var domains=await db.ReadAsync("select id,fqdn from domains order by id limit 10001",[],ct);
            if(domains.Count>10000) throw new VpnInputException("vpn_session_source_discovery_scan_limit");
            return domains.Where(r=>accountingOnly ? access.AccountingReport(r.Number("id")) : registered.Contains(r.Number("id"))||access.Windows(r.Number("id"))).Take(256).Select(r=>VpnJson.Obj(new {value=r.Text("id"),label=r.Text("fqdn")})).ToList();
        }
        catch(Npgsql.PostgresException e) when(e.SqlState is "42501" or "42P01" or "42703") {return [];}
        catch(Npgsql.NpgsqlException e) when(e is not Npgsql.PostgresException || e.SqlState?.StartsWith("08",StringComparison.Ordinal)==true) {return [];}
        catch(Exception e) when(VpnAuthorizations.IsTimeout(e) && !ct.IsCancellationRequested) {return [];}
    }
    public static async Task<(long? Id,string State)> DefaultDomain(IVpnReadSession db,VpnAccess access,List<JsonObject> options,CancellationToken ct)
    {
        try
        {
            long[] ids=options.Select(r=>long.Parse(r.Text("value"),CultureInfo.InvariantCulture)).Where(id=>access.Report(id).Allowed).ToArray();if(ids.Length==0) return (null,"unknown");
            string preferred=(await db.ReadAsync("select value from platform_settings where key='reports.domain_fqdn'",[],ct)).FirstOrDefault().Text("value");
            var domains=await db.ReadAsync("""
                select d.id,d.fqdn,d.is_archived,observed.observed_at_utc from domains d
                left join lateral(select max(run.observed_at_utc) as observed_at_utc from ad_context_runs run
                  where run.domain_id=d.id and run.status='completed') observed on true
                where d.id=any($1) order by d.id
                """,[ids],ct);
            var eligible=domains.Where(r=>!r.Flag("is_archived")).ToArray();
            if(preferred!="" && eligible.FirstOrDefault(r=>r.Text("fqdn").Equals(preferred,StringComparison.OrdinalIgnoreCase)) is {} saved) return (saved.Number("id"),"available");
            long? chosen=eligible.Where(r=>r.At("observed_at_utc") is {} at && at<=DateTimeOffset.UtcNow).OrderByDescending(r=>r.At("observed_at_utc")).ThenBy(r=>r.Number("id")).FirstOrDefault()?.Number("id");
            return (chosen,chosen is null?"unknown":"available");
        }
        catch(Exception e) when(e is not OperationCanceledException || !ct.IsCancellationRequested) {return (null,"unavailable");}
    }
    internal static int ParseInt(string text,string code)=>int.TryParse(text,NumberStyles.Integer,CultureInfo.InvariantCulture,out int n)?n:throw new VpnInputException(code);
    internal static (DateTimeOffset From,DateTimeOffset To) Period(IQueryCollection query,string zone,DateTimeOffset? now=null)
    {
        string Get(string key,string fallback="")=>query[key].FirstOrDefault()??fallback;
        string period=Get("period","7d");if(period=="custom")
        {var (a,b)=VpnQuery.Range(Get("time_from",Get("from")),Get("time_to",Get("to")),zone);if(a is null || b is null) throw new VpnInputException("report_parameter_required:period");if(b-a>TimeSpan.FromDays(366)) throw new VpnInputException("report_period_too_wide");return(a.Value,b.Value);}
        int days=period switch {"24h"=>1,"7d"=>7,"30d"=>30,"90d"=>90,"366d"=>366,_=>throw new VpnInputException("report_period_invalid")};
        var end=now??DateTimeOffset.UtcNow;return(end.AddDays(-days),end);
    }
    static void Validate(IQueryCollection query,string report,bool accountingOnly=false)
    {
        var allowed=new HashSet<string>(report=="vpn.accounts"?["cursor","limit","sort","direction","tz","tab","q","activity"]:["cursor","limit","sort","direction","tz","tab","q","domain","domain_id","scope","period","from","to","department","status","overlap_account","overlap_min_seconds","overlap_complete","policy","nas","reason","method","min_decisions","min_growth"],StringComparer.Ordinal);
        if (accountingOnly)
            allowed.ExceptWith(["overlap_account", "overlap_min_seconds", "overlap_complete", "policy", "nas", "reason", "method", "min_decisions", "min_growth"]);
        foreach(var (key,value) in query) {if(!allowed.Contains(key)) throw new VpnInputException("report_parameter_unknown:"+key);if(value.Count>1) throw new VpnInputException("report_parameter_duplicate:"+key);if(value.ToString().Length>4096) throw new VpnInputException("report_parameter_too_long:"+key);}
        string tab=query["tab"].ToString();string[] tabs=["employees","daily","departments","entitlements","failed","authorizations","windows","windows_heatmap","session_overlap","policy_denials","policy_denials_growth","policy_denials_events"];
        if(tab!="" && report=="vpn.connections" && !tabs.Contains(tab)) throw new VpnInputException("report_tab_invalid");
        if(tab!="" && report=="vpn.accounts") throw new VpnInputException("report_tab_invalid");
        string direction=query["direction"].FirstOrDefault()??"asc";if(direction is not ("asc" or "desc")) throw new VpnInputException("report_sort_invalid");
        string sort=query["sort"].ToString();
        var definition=WorkspaceJson.Declarations.GetProperty("reports").EnumerateArray().First(r=>r.GetProperty("key").GetString()==report);
        if(sort!="" && !definition.GetProperty("columns").EnumerateArray().Any(c=>c.GetProperty("key").GetString()==sort && (!c.TryGetProperty("sortable",out var sortable) || sortable.ValueKind!=JsonValueKind.False))) throw new VpnInputException("report_sort_invalid");
        _=VpnQuery.Range("","",query["tz"].FirstOrDefault()??"UTC");
        foreach(string key in new[]{"q","department","policy","nas","reason","method"}) if(query[key].ToString().Trim().Length>256) throw new VpnInputException("report_parameter_invalid:"+key);
    }
    public static string Csv(JsonObject result,string? tab)
    {
        var rows=result["items"]?.AsArray().OfType<JsonObject>().ToArray()??[];
        var fields=result["_export_fields"]?.AsArray().OfType<JsonObject>().ToArray()??[];
        string[] keys=fields.Select(f=>f.Text("key")).ToArray(),labels=fields.Select(f=>f.Text("label",f.Text("key"))).ToArray();
        string Cell(string value) {if(value.StartsWith('\t')||value.StartsWith('\r')||value.StartsWith('\n')||value.TrimStart().FirstOrDefault() is '=' or '+' or '-' or '@') value="'"+value;return "\""+value.Replace("\"","\"\"")+"\"";}
        return string.Join(",",labels.Select(Cell))+"\r\n"+string.Concat(rows.Select(row=>string.Join(",",keys.Select(key=>Cell(row.Text(key))))+"\r\n"));
    }
}
