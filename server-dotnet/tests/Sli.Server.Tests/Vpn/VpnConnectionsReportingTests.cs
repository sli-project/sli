using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Primitives;
using Npgsql;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Vpn;

// Behavioral vectors from tests/reporting/test_vpn_connections_reporting.py.
public sealed class VpnConnectionsReportingTests
{
    static JsonObject Json(object value)=>VpnRouteTests.Json(value);
    static DateTimeOffset At(string value)=>DateTimeOffset.Parse(value,System.Globalization.CultureInfo.InvariantCulture);
    static VpnQuery Query=>new(7,"view","UTC",At("2026-08-01T00:00:00Z"),At("2026-09-01T00:00:00Z"),200,0,"");
    static VpnAccess Owner=>new(VpnRouteTests.MakeFacts());
    static JsonObject Identity(long id=101)=>Json(new {entity_id=id,display_name="Иванов Иван Иванович",natural_key="ad:example.test:user:internal-canonical-key",sam_account_name="ivanov",netbios_name="EXAMPLE",department="ИТ",enabled=true,last_logon_utc="2026-07-31T00:00:00Z",privileged=false});
    static JsonObject Coverage=>Json(new {total_delivery_count=1,projected_session_count=1,queued_delivery_count=0,leased_delivery_count=0,failed_delivery_count=0,quarantined_delivery_count=0,identity_unresolved_count=0,timestamp_unresolved_count=0});
    static JsonObject Session(string id="s1",string start="2026-08-14T09:00:00Z",string? stop="2026-08-14T10:00:00Z",long entity=101,string? observed=null)=>Json(new {session_row_id=id,entity_id=entity,domain_id=7,generation=1,lifecycle_state=stop is null?"open_observed":"closed",completeness=stop is null?"partial":"complete",started_at_utc=start,last_observed_at_utc=observed??stop??start,stopped_at_utc=stop,duration_seconds=stop is null?(long?)null:(long)(At(stop)-At(start)).TotalSeconds,observation_count=stop is null?1:2,anomalies=Array.Empty<object>()});
    static JsonObject Compose(List<JsonObject> sessions,Dictionary<long,JsonObject>? identities=null,JsonObject? coverage=null,List<JsonObject>? failed=null,string failedState="not_collected")=>VpnConnections.Compose(Query,sessions,identities??new() {[101]=Identity()},[Json(new {entity_id=101})],coverage??Coverage,TimeZoneInfo.FindSystemTimeZoneById("Asia/Novosibirsk"),failedEvents:failed,failedCollectionState:failedState);
    static JsonObject Employee(JsonObject raw)=>raw["employees"]![0]!.AsObject();
    static JsonObject Report(JsonObject raw,string tab="employees",JsonObject? source=null)=>VpnReports.Compose("vpn.connections",Query,tab,raw,source,[]);
    static JsonObject Raw(string state="available",int count=1,string completeness="not_proven")=>Json(new {state,employees=count>0?new[]{new {entity_id=101,closed_session_count=1,open_session_count=0,confirmed_minutes=60,sessions=Array.Empty<object>()}}:[],employee_page=new {},analytics=new {employee_count=count,closed_session_count=0},coverage=new {completeness}});
    static QueryCollection Parameters(string tab="employees",string zone="UTC",string from="2026-08-01T00:00:00Z",string to="2026-09-01T00:00:00Z")=>new(new Dictionary<string,StringValues> { ["domain"]="7",["period"]="custom",["from"]=from,["to"]=to,["tab"]=tab,["tz"]=zone });
    static JsonObject Event(int code=6273,long? entity=101,int id=701)=>Json(new {event_db_id=id,event_record_id=id+8300,event_id=code,time_created_utc="2026-08-14T09:00:00Z",subject_user_sid="S-1-5-21-100000001-200000002-300000003-1001",subject_user_name=entity is null?"unknown-user":"observed-name-must-not-win",subject_domain_name="EXAMPLE",reason_code="16",entity_id=entity,alias_match_count=entity is null?0:1,source_core_sha256=new string('a',64)});
    static JsonObject WindowsEvent=>Json(new {event_db_id=10,event_id=4625,time_created_utc="2026-08-14T09:00:00Z",domain_controller="dc.example.test",target_user_name="synthetic",target_user_sid="S-1-5-21-100000001-200000002-300000003-1001",source_ip="192.0.2.7"});
    static PostgresException DatabaseError(string code)=>new("synthetic database error","ERROR","ERROR",code);

    sealed class Reader(Func<string,object?[],List<JsonObject>?>? intercept=null):IVpnReadSession,IVpnStore
    {
        public readonly List<(string Sql,object?[] Values)> Calls=[];
        public Task<IVpnReadSession> OpenAsync(CancellationToken ct)=>Task.FromResult<IVpnReadSession>(this);
        public ValueTask DisposeAsync()=>ValueTask.CompletedTask;
        public Task<List<JsonObject>> ReadAsync(string sql,object?[] parameters,CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();Calls.Add((sql,parameters));
            var result=intercept?.Invoke(sql,parameters);
            result??=sql switch
            {
                VpnSql.Coverage =>[Coverage],VpnSql.ConnectionSessions=>[Session()],
                VpnSql.Entitlements =>[Json(new {entity_id=101})],VpnSql.FullIdentities or VpnSql.Identities=>[Identity()],
                VpnSql.NpsEvents or VpnSql.ConnectionFailedEvents =>[Event()],
                VpnSql.NpsCoverage =>[Json(new {history_event_present=true,window_failed_6273_count=1,window_success_6272_count=0})],
                VpnSql.ConnectionFailedCollected =>[Json(new {collected=true})],
                VpnSql.WindowsEvents =>[WindowsEvent],VpnSql.WindowsCoverage=>[Json(new {history_event_present=true})],
                VpnSql.WindowsGrid =>[Json(new {isodow=4,hour=21,failures=1})],
                VpnSql.WindowsReview or VpnSql.SessionDomains =>[],
                "select id,fqdn from domains order by id limit 10001"=>[],
                _ when sql.Contains("read_plugin_states_v1",StringComparison.Ordinal)=>[Json(new {installed=true,enabled=true})],
                _ when sql.StartsWith("select key,value from platform_settings",StringComparison.Ordinal)=>[],
                _=>throw new InvalidOperationException("Unexpected synthetic SQL: "+sql)
            };
            if(sql==VpnSql.NpsEvents || sql==VpnSql.WindowsEvents)
                foreach(var row in result) row["time_created_utc"]=VpnJson.Iso(((DateTimeOffset)parameters[sql==VpnSql.NpsEvents?2:4]!).AddMinutes(1));
            return Task.FromResult(result);
        }
    }

    [Theory]
    [InlineData(0,3600,false)] [InlineData(1,2678400,false)] [InlineData(2,7200,true)]
    public void Closed_session_clipping_union_and_overlap(int vector,long seconds,bool overlap)
    {
        List<JsonObject> sessions=vector switch
        {
            1=>[Session(start:"2026-07-31T08:00:00Z",stop:"2026-09-02T12:00:00Z")],
            2=>[Session(),Session("s2","2026-08-14T09:30:00Z","2026-08-14T11:00:00Z")],_=>[Session()]
        };
        var employee=Employee(Compose(sessions));Assert.Equal(seconds,employee.Number("confirmed_seconds"));Assert.Equal(overlap,employee.Flag("overlap_violation"));Assert.Equal(overlap?1:0,employee.Number("overlap_count"));
    }

    [Theory] [InlineData(false,false)] [InlineData(true,false)] [InlineData(false,true)]
    public void Open_sessions_remain_visible_with_unknown_duration(bool includeClosed,bool point)
    {
        var open=Session("open","2026-08-15T09:00:00Z",null,observed:point?"2026-08-15T09:00:00Z":"2026-08-15T09:10:00Z");
        var employee=Employee(Compose(includeClosed?[Session(),open]:[open]));
        Assert.Equal(1,employee.Number("open_session_count"));
        if(includeClosed) Assert.Equal(3600,employee.Number("confirmed_seconds"));else {Assert.Null(employee["confirmed_seconds"]);Assert.Null(employee["confirmed_minutes"]);}
        var row=employee["sessions"]!.AsArray().Single(s=>s.Text("session_row_id")=="open")!;
        Assert.Null(row["duration_seconds"]);Assert.Null(row["confirmed_seconds_in_period"]);Assert.False(row.Flag("overlap_violation"));
    }

    [Fact] public void Rounding_follows_exact_union_and_membership_uses_intersection()
    {
        var employee=Employee(Compose([Session("a","2026-08-14T09:00:00Z","2026-08-14T09:00:31Z"),Session("b","2026-08-14T09:01:00Z","2026-08-14T09:01:31Z")]));
        Assert.Equal(62,employee.Number("confirmed_seconds"));Assert.Equal(1,employee.Number("confirmed_minutes"));
        employee=Employee(Compose([Session(start:"2026-07-31T23:30:00Z",stop:"2026-08-01T00:30:00Z")]));Assert.Equal(1800,employee.Number("confirmed_seconds"));
        Assert.Empty(Compose([Session(start:"2026-07-31T23:00:00Z",stop:"2026-08-01T00:00:00Z"),Session("end","2026-09-01T00:00:00Z",null)])["employees"]!.AsArray());
    }

    [Fact] public void Canonical_identity_is_human_readable_and_shared_with_entitlements_and_denials()
    {
        var raw=Compose([Session()],failed:[Event(),Event(entity:null,id:702),Event(6272,id:703)],failedState:"available");var employee=Employee(raw);
        Assert.Equal("Иванов Иван Иванович",employee.Text("display_name"));Assert.Equal("EXAMPLE\\ivanov",employee.Text("account_name"));Assert.Equal("ИТ",employee.Text("department"));
        Assert.Equal(employee.Text("account_name"),raw["entitlements"]!["items"]![0].Text("account_name"));
        var failures=raw["failed_authorizations"]!["items"]!.AsArray();Assert.Equal(2,failures.Count);
        Assert.Equal(employee.Text("account_name"),failures[0].Text("account_name"));Assert.Equal("resolved",failures[0].Text("identity_state"));Assert.Equal(employee.Text("display_name"),failures[0].Text("display_name"));
        Assert.Equal("EXAMPLE\\unknown-user",failures[1].Text("account_name"));Assert.Equal("Не определено",failures[1].Text("display_name"));Assert.Equal("unresolved",failures[1].Text("identity_state"));Assert.All(failures,r=>Assert.Equal(6273,r.Number("event_id")));
        Assert.DoesNotContain("Объект AD #",raw.ToJsonString());Assert.DoesNotContain("internal-canonical-key",raw.ToJsonString());Assert.DoesNotContain("observed-name-must-not-win",raw.ToJsonString());
        var identity=Identity();identity["sam_account_name"]=null;raw=Compose([Session()],new() {[101]=identity});Assert.Equal("Не определено",Employee(raw).Text("account_name"));Assert.DoesNotContain(identity.Text("natural_key"),raw.ToJsonString());
    }

    [Fact] public void Canonical_account_and_215_second_rounding_match_reference()
    {
        var identity=Identity(42369557);identity["display_name"]="Степанова Светлана Олеговна";identity["sam_account_name"]="coordfrs";
        var raw=VpnConnections.Compose(Query,[Session("s1","2026-08-14T08:20:27Z","2026-08-14T08:24:02Z",42369557)],new() {[42369557]=identity},[Json(new {entity_id=42369557})],Coverage,TimeZoneInfo.Utc,failedEvents:[Event(entity:42369557)],failedCollectionState:"available");
        Assert.Equal(215,Employee(raw).Number("confirmed_seconds"));Assert.Equal(4,Employee(raw).Number("confirmed_minutes"));Assert.Equal("EXAMPLE\\coordfrs",Employee(raw).Text("account_name"));Assert.Equal("EXAMPLE\\coordfrs",raw["entitlements"]!["items"]![0].Text("account_name"));Assert.Equal("EXAMPLE\\coordfrs",raw["failed_authorizations"]!["items"]![0].Text("account_name"));
    }

    [Fact] public void Partial_coverage_preserves_projected_rows_and_unresolved_count()
    {
        var coverage=Coverage;coverage["total_delivery_count"]=602;coverage["projected_session_count"]=510;coverage["identity_unresolved_count"]=92;
        var raw=Compose([Session()],coverage:coverage);Assert.Equal("partial",raw.Text("state"));Assert.Single(raw["employees"]!.AsArray());Assert.Equal(510,raw["coverage"].Number("projected_session_count"));Assert.Equal(92,raw["coverage"].Number("identity_unresolved_count"));
    }

    [Theory] [InlineData("not_collected")] [InlineData("unavailable")]
    public void Uncollected_or_unavailable_denials_never_become_zero_and_preserve_accounting(string state)
    {
        var raw=Compose([Session()],failedState:state);var failed=raw["failed_authorizations"]!;
        Assert.Equal(state,failed.Text("state"));Assert.Null(failed["count"]);Assert.Empty(failed["items"]!.AsArray());Assert.Single(raw["employees"]!.AsArray());Assert.Equal("available",raw["entitlements"].Text("state"));
        if(state=="unavailable") {Assert.Equal("partial",raw.Text("state"));Assert.Equal("input_event_bound_exceeded",failed.Text("unavailable_reason"));Assert.Contains(raw["limitations"]!.AsArray(),n=>n!.ToString().Contains("не показаны",StringComparison.Ordinal));}
    }

    [Fact] public async Task Denial_precedes_all_database_reads()
    {
        var reader=new Reader((_,_)=>throw new InvalidOperationException("database must not be read"));
        var raw=await VpnConnections.Read(reader,new(VpnRouteTests.MakeFacts(false,false)),Query,Parameters(),TestContext.Current.CancellationToken);
        Assert.Equal("not_authorized",raw.Text("state"));Assert.Empty(raw["employees"]!.AsArray());Assert.Empty(reader.Calls);
        raw=await VpnReports.Read(reader,new(VpnRouteTests.MakeFacts(false,false)),"vpn.connections",Parameters(),"view",TestContext.Current.CancellationToken);Assert.Equal("denied",raw.Text("state"));Assert.Empty(reader.Calls);
    }

    [Fact] public async Task Source_scoped_reader_uses_interval_intersection_and_canonical_AD_projection()
    {
        var reader=new Reader();var raw=await VpnConnections.Read(reader,Owner,Query,Parameters(),TestContext.Current.CancellationToken);
        var sessions=reader.Calls.Single(c=>c.Sql==VpnSql.ConnectionSessions);Assert.Equal(new object?[]{7L,Query.To,Query.From,Query.From,20001},sessions.Values);
        Assert.Contains("started_at_utc<$2",sessions.Sql);Assert.Contains("stopped_at_utc is not null and stopped_at_utc>$3",sessions.Sql);Assert.Contains("stopped_at_utc is null and last_observed_at_utc>=$4",sessions.Sql);
        var failures=reader.Calls.Single(c=>c.Sql==VpnSql.ConnectionFailedEvents);Assert.Equal(new object?[]{7L,Query.From,Query.To,2001},failures.Values);
        var identity=reader.Calls.Single(c=>c.Sql==VpnSql.FullIdentities);Assert.DoesNotContain("entity.natural_key",identity.Sql);Assert.Contains("domain_row.netbios_name",identity.Sql);Assert.Contains("sam_account_name",identity.Sql);Assert.Equal(7L,identity.Values[1]);Assert.Equal("EXAMPLE\\ivanov",Employee(raw).Text("account_name"));
    }

    [Fact] public async Task Oversized_denials_are_isolated_and_accounting_can_skip_NPS_entirely()
    {
        var reader=new Reader((sql,_)=>sql==VpnSql.ConnectionFailedEvents?Enumerable.Range(0,2001).Select(i=>Event(id:i+1)).ToList():null);
        var raw=await VpnConnections.Read(reader,Owner,Query,Parameters(),TestContext.Current.CancellationToken);
        Assert.Equal("partial",raw.Text("state"));Assert.Equal("unavailable",raw["failed_authorizations"].Text("state"));Assert.Null(raw["failed_authorizations"]!["count"]);Assert.Single(raw["employees"]!.AsArray());Assert.Single(raw["entitlements"]!["items"]!.AsArray());Assert.Equal("available",raw["branches"]!["directory"].Text("state"));Assert.Equal("available",raw["branches"]!["sessions"].Text("state"));
        reader=new Reader((sql,_)=>sql.Contains("events_v2_core",StringComparison.Ordinal)?throw new InvalidOperationException("NPS must not be read"):null);
        raw=await VpnConnections.Read(reader,Owner,Query,Parameters(),TestContext.Current.CancellationToken,includeFailedAuthorizations:false);Assert.Single(raw["employees"]!.AsArray());Assert.DoesNotContain(reader.Calls,c=>c.Sql.Contains("events_v2_core",StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("employees",0)] [InlineData("daily",0)] [InlineData("departments",0)] [InlineData("entitlements",0)] [InlineData("failed",0)] [InlineData("authorizations",0)]
    [InlineData("failed",6273)] [InlineData("authorizations",6272)] [InlineData("authorizations",6273)]
    public void Missing_accounting_coverage_is_not_collected_without_hiding_NPS(string tab,int code)
    {
        var raw=Json(new {state="not_collected",unavailable_reason="no_accounting_data",employees=Array.Empty<object>()});
        JsonObject? source=tab is "failed" or "authorizations"?Json(new {state=code==0?"not_collected":"available",items=code==0?Array.Empty<JsonObject>():new[]{Event(code)}}):null;
        var report=Report(raw,tab,source);Assert.Equal(code==0?"not_collected":"partial",report.Text("state"));Assert.Empty(report["items"]!.AsArray());Assert.Empty(report["metrics"]!.AsArray());Assert.False(report.Flag("has_more"));Assert.Null(report["next_cursor"]);
        Assert.Equal("no_accounting_data",report["branches"]!["accounting"].Text("reason"));Assert.Equal("not_collected",report["branches"]!["accounting"].Text("state"));
        Assert.Equal(tab is "failed" or "authorizations" && code==0?new[]{"accounting","nps"}:new[]{"accounting"},report["coverage"]!["missing_sources"]!.AsArray().Select(n=>n!.ToString()));
        Assert.Contains(report["limitations"]!.AsArray(),n=>n.Text("code")=="vpn_source_unreadable");if(tab!="employees") Assert.Equal(code==0?0:1,report["collections"]![tab]!.AsArray().Count);
    }

    [Fact] public async Task V2_passes_filters_paging_and_server_access_to_accounting()
    {
        var parameters=new Dictionary<string,StringValues>(Parameters(zone:"Asia/Novosibirsk",from:"2026-08-01",to:"2026-08-31")) {["q"]="ivanov",["department"]="ИТ",["status"]="open",["limit"]="50",["cursor"]="10"};
        var reader=new Reader((sql,_)=>sql==VpnSql.ConnectionSessions?[Session(stop:null)]:null);
        var report=await VpnReports.Read(reader,Owner,"vpn.connections",new QueryCollection(parameters),"view",TestContext.Current.CancellationToken);
        var call=reader.Calls.Single(c=>c.Sql==VpnSql.ConnectionSessions);Assert.Equal(At("2026-07-31T17:00:00Z"),call.Values[2]);Assert.Equal(At("2026-08-31T17:00:00Z"),call.Values[1]);Assert.Equal(1,report.Number("filtered_count"));Assert.Empty(report["items"]!.AsArray());
        Assert.DoesNotContain(reader.Calls,c=>c.Sql==VpnSql.NpsEvents || c.Sql==VpnSql.ConnectionFailedEvents || c.Sql==VpnSql.WindowsEvents);
        parameters["cursor"]="0";report=await VpnReports.Read(new Reader((sql,_)=>sql==VpnSql.ConnectionSessions?[Session(stop:null)]:null),Owner,"vpn.connections",new QueryCollection(parameters),"view",TestContext.Current.CancellationToken);Assert.Single(report["items"]!.AsArray());Assert.Null(report["items"]![0]!["confirmed_hours"]);
        parameters["department"]="other";report=await VpnReports.Read(new Reader(),Owner,"vpn.connections",new QueryCollection(parameters),"view",TestContext.Current.CancellationToken);Assert.Empty(report["items"]!.AsArray());
    }

    [Fact] public void Partial_report_keeps_unknown_open_only_hours_and_session_minutes()
    {
        var raw=Raw("partial");raw["employees"]=new JsonArray(Json(new {entity_id=101,closed_session_count=0,open_session_count=1,confirmed_minutes=0,sessions=Array.Empty<object>()}),Json(new {entity_id=102,closed_session_count=2,open_session_count=0,confirmed_minutes=90,sessions=new[]{new {duration_seconds=5400}}}));
        var report=Report(raw);Assert.Equal("partial",report.Text("state"));Assert.Null(report["items"]![0]!["confirmed_hours"]);Assert.Equal(1.5,report["items"]![1]!["confirmed_hours"]!.GetValue<double>());Assert.Equal(90,report["items"]![1]!["sessions"]![0]!.Number("duration_minutes"));Assert.Empty(report["collections"]!["failed"]!.AsArray());
    }

    [Theory] [InlineData("employees")] [InlineData("daily")] [InlineData("departments")] [InlineData("entitlements")] [InlineData("failed")] [InlineData("authorizations")] [InlineData("windows")] [InlineData("windows_heatmap")]
    public async Task Only_open_tabs_read_NPS_or_Windows_and_all_sources_share_exact_window(string tab)
    {
        var reader=new Reader();var report=await VpnReports.Read(reader,Owner,"vpn.connections",Parameters(tab,"Asia/Novosibirsk","2026-09-14","2026-09-14"),"view",TestContext.Current.CancellationToken);
        Assert.Equal(tab is "failed" or "authorizations",reader.Calls.Any(c=>c.Sql==VpnSql.NpsEvents));Assert.Equal(tab=="windows",reader.Calls.Any(c=>c.Sql==VpnSql.WindowsEvents));Assert.Equal(tab=="windows_heatmap",reader.Calls.Any(c=>c.Sql==VpnSql.WindowsGrid));
        var start=At("2026-09-13T17:00:00Z");var stop=At("2026-09-14T17:00:00Z");
        var accounting=reader.Calls.Single(c=>c.Sql==VpnSql.ConnectionSessions);Assert.Equal(start,accounting.Values[2]);Assert.Equal(stop,accounting.Values[1]);
        foreach(var call in reader.Calls.Where(c=>c.Sql==VpnSql.NpsEvents || c.Sql==VpnSql.WindowsEvents || c.Sql==VpnSql.WindowsGrid)) {Assert.Contains(start,call.Values);Assert.Contains(stop,call.Values);Assert.Equal(7L,call.Values[call.Sql==VpnSql.WindowsGrid?2:0]);}
        Assert.Equal("2026-09-13T17:00:00Z",report["window"].Text("from_utc"));Assert.Equal("2026-09-14T17:00:00Z",report["window"].Text("to_utc_exclusive"));
        if(tab is "failed" or "authorizations" or "windows" or "windows_heatmap") Assert.Equal("ok",report["branches"]![tab is "failed" or "authorizations"?"nps":tab].Text("state"));
        reader=new Reader();report=await VpnReports.Read(reader,Owner,"vpn.connections",Parameters(tab,"Asia/Novosibirsk","2026-09-14T11:23:45Z","2026-09-14T13:45:56Z"),"view",TestContext.Current.CancellationToken);
        accounting=reader.Calls.Single(c=>c.Sql==VpnSql.ConnectionSessions);Assert.Equal(At("2026-09-14T11:23:45Z"),accounting.Values[2]);Assert.Equal(At("2026-09-14T13:45:56Z"),accounting.Values[1]);
        foreach(var call in reader.Calls.Where(c=>c.Sql==VpnSql.NpsEvents || c.Sql==VpnSql.WindowsEvents || c.Sql==VpnSql.WindowsGrid)) {Assert.Contains(At("2026-09-14T11:23:45Z"),call.Values);Assert.Contains(At("2026-09-14T13:45:56Z"),call.Values);}
    }

    [Theory]
    [InlineData("7d","Asia/Novosibirsk","2026-10-05T12:34:56Z","2026-09-28T12:34:56Z")]
    [InlineData("7d","America/New_York","2026-03-09T12:00:00Z","2026-03-02T12:00:00Z")]
    [InlineData("24h","Asia/Novosibirsk","2026-10-05T12:34:56Z","2026-10-04T12:34:56Z")]
    public void Rolling_period_is_exact_elapsed_time_across_timezones_and_DST(string period,string zone,string now,string expected)
    {
        var range=VpnReports.Period(new QueryCollection(new Dictionary<string,StringValues> {["period"]=period}),zone,At(now));Assert.Equal(At(expected),range.From);Assert.Equal(At(now),range.To);
        range=VpnReports.Period(Parameters(from:"2026-09-14T11:23:45Z",to:"2026-09-14T13:45:56Z"),zone);Assert.Equal(At("2026-09-14T11:23:45Z"),range.From);Assert.Equal(At("2026-09-14T13:45:56Z"),range.To);
    }

    [Fact] public void Default_raw_period_is_calendar_month_and_explicit_period_is_validated()
    {
        var zone=TimeZoneInfo.FindSystemTimeZoneById("Asia/Novosibirsk");var (from,to)=VpnConnections.ReportPeriod(null,null,zone,At("2026-08-14T12:00:00Z"));Assert.Equal(At("2026-07-31T17:00:00Z"),from);Assert.Equal(At("2026-08-31T17:00:00Z"),to);
        Assert.Equal("vpn_connections_period_too_wide",Assert.Throws<VpnInputException>(()=>VpnConnections.ReportPeriod(At("2025-01-01T00:00:00Z"),At("2026-01-03T00:00:00Z"),TimeZoneInfo.Utc,from)).Message);
        Assert.Equal("vpn_connections_period_requires_both_bounds",Assert.Throws<VpnInputException>(()=>VpnConnections.ReportPeriod(from,null,zone,from)).Message);
    }

    [Theory] [InlineData("employees")] [InlineData("daily")] [InlineData("departments")] [InlineData("entitlements")] [InlineData("failed")] [InlineData("authorizations")] [InlineData("windows")] [InlineData("windows_heatmap")]
    public async Task Accounting_timeout_keeps_report_open_without_false_metrics(string tab)
    {
        var reader=new Reader((sql,_)=>sql==VpnSql.Coverage?throw DatabaseError("57014"):null);
        var parameters=new Dictionary<string,StringValues>(Parameters(tab)) {["period"]="30d"};
        var report=await VpnReports.Read(reader,Owner,"vpn.connections",new QueryCollection(parameters),"view",TestContext.Current.CancellationToken);Assert.Equal("partial",report.Text("state"));Assert.Empty(report["items"]!.AsArray());Assert.Empty(report["metrics"]!.AsArray());Assert.Equal(7,report["window"].Number("source_domain_id"));Assert.Equal("source_read_timeout",report["branches"]!["accounting"].Text("reason"));
    }

    [Theory] [InlineData("42501")] [InlineData("57014")]
    public async Task Optional_domain_lookup_failure_preserves_rows_and_clean_install_has_honest_error(string code)
    {
        var reader=new Reader((sql,_)=>sql==VpnSql.SessionDomains?throw DatabaseError(code):null);
        var report=await VpnReports.Read(reader,Owner,"vpn.connections",Parameters(),"view",TestContext.Current.CancellationToken);Assert.Single(report["items"]!.AsArray());Assert.Empty(report["filter_options"]!["domain"]!.AsArray());
        reader=new Reader((sql,_)=>sql==VpnSql.Coverage || sql==VpnSql.SessionDomains?throw DatabaseError("42501"):null);
        report=await VpnReports.Read(reader,Owner,"vpn.connections",Parameters(),"view",TestContext.Current.CancellationToken);Assert.Equal("error",report.Text("state"));Assert.Empty(report["metrics"]!.AsArray());Assert.Contains(report["limitations"]!.AsArray(),n=>n.Text("code")=="vpn_source_unreadable");
    }



    public static TheoryData<string,string,string> AccountingFailures
    {
        get {var cases=new TheoryData<string,string,string>();foreach(string tab in new[]{"authorizations","failed","windows","windows_heatmap"}) foreach(var (failure,state) in new[]{("unreadable","error"),("not_authorized","denied"),("not_collected","not_collected"),("unregistered","error"),("connection_lost","error")}) cases.Add(tab,failure,state);return cases;}
    }
    static Task<JsonObject> SourceFailure(string failure)=>failure switch
    {
        "unreadable"=>throw DatabaseError("42501"),"unregistered" or "too_wide"=>throw new VpnInputException("synthetic_input_error"),"connection_lost"=>throw new NpgsqlException("synthetic connection loss"),_=>Task.FromResult(Json(new {state=failure,items=Array.Empty<object>()}))
    };
    [Theory,MemberData(nameof(AccountingFailures))]
    public async Task Accounting_failure_preserves_independent_sources(string tab,string failure,string expected)
    {
        var raw=await VpnReports.Safe(()=>SourceFailure(failure),TestContext.Current.CancellationToken);var source=Json(new {state="available",items=new[]{Event()}});var report=Report(raw,tab,source);string branch=tab is "authorizations" or "failed"?"nps":tab;
        Assert.Equal("partial",report.Text("state"));Assert.Empty(report["items"]!.AsArray());Assert.Empty(report["metrics"]!.AsArray());Assert.NotEmpty(report["collections"]![tab]!.AsArray());Assert.Equal("ok",report["branches"]![branch].Text("state"));Assert.Equal(expected,report["branches"]!["accounting"].Text("state"));Assert.Equal(new[]{"accounting"},report["coverage"]!["missing_sources"]!.AsArray().Select(n=>n!.ToString()));Assert.NotEmpty(report["branches"]!["accounting"]!["limitations"]!.AsArray());Assert.True(report["branches"]![branch]!["limits"].Number("max_period_days")>0);
    }
    public static TheoryData<string,string,string> SourceFailures
    {
        get {var cases=new TheoryData<string,string,string>();foreach(string tab in new[]{"authorizations","windows","windows_heatmap"}) foreach(var (failure,state) in new[]{("unreadable","error"),("not_authorized","denied"),("not_collected","not_collected"),("coverage_unverified","partial"),("too_wide","error"),("connection_lost","error"),("unavailable","error")}) cases.Add(tab,failure,state);return cases;}
    }
    [Theory,MemberData(nameof(SourceFailures))]
    public async Task Independent_source_failure_preserves_accounting(string tab,string failure,string expected)
    {
        var source=await VpnReports.Safe(()=>SourceFailure(failure),TestContext.Current.CancellationToken);var report=Report(Raw(),tab,source);string branch=tab=="authorizations"?"nps":tab;
        Assert.Equal("partial",report.Text("state"));Assert.Equal(101,report["items"]![0].Number("entity_id"));Assert.Equal("ok",report["branches"]!["accounting"].Text("state"));Assert.Equal(expected,report["branches"]![branch].Text("state"));Assert.Empty(report["collections"]![tab]!.AsArray());Assert.NotEmpty(report["branches"]![branch]!["limitations"]!.AsArray());Assert.Equal(expected=="partial"?Array.Empty<string>():[branch],report["coverage"]!["missing_sources"]!.AsArray().Select(n=>n!.ToString()));
    }

    [Fact] public async Task Unexpected_database_errors_propagate()
    {
        var error=DatabaseError("40P01");Assert.Same(error,await Assert.ThrowsAsync<PostgresException>(()=>VpnReports.Safe(()=>throw error,TestContext.Current.CancellationToken)));
        Assert.Same(error,await Assert.ThrowsAsync<PostgresException>(()=>VpnReports.DomainOptions(new Reader((_,_)=>throw error),Owner,TestContext.Current.CancellationToken)));
    }

    [Fact] public async Task Caller_cancellation_is_not_presented_as_a_partial_report()
    {
        using var cancellation=new CancellationTokenSource();cancellation.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(()=>VpnReports.Safe(()=>throw new OperationCanceledException(cancellation.Token),cancellation.Token));
        var options=await VpnReports.DomainOptions(new Reader((_,_)=>throw new NpgsqlException("synthetic connection loss")),Owner,TestContext.Current.CancellationToken);Assert.Empty(options);
    }

    [Theory] [InlineData("authorizations")] [InlineData("failed")] [InlineData("windows")] [InlineData("windows_heatmap")]
    public async Task Live_read_pipeline_preserves_independent_source_on_either_side_of_failure(string tab)
    {
        string sourceSql=tab is "authorizations" or "failed"?VpnSql.NpsEvents:tab=="windows"?VpnSql.WindowsEvents:VpnSql.WindowsGrid;
        string branch=tab is "authorizations" or "failed"?"nps":tab;
        var reader=new Reader((sql,_)=>sql==VpnSql.Coverage?throw DatabaseError("42501"):null);
        var report=await VpnReports.Read(reader,Owner,"vpn.connections",Parameters(tab),"view",TestContext.Current.CancellationToken);Assert.Equal("partial",report.Text("state"));Assert.NotEmpty(report["collections"]![tab]!.AsArray());Assert.Empty(report["metrics"]!.AsArray());Assert.Equal("ok",report["branches"]![branch].Text("state"));Assert.True(reader.Calls.FindIndex(c=>c.Sql==sourceSql)<reader.Calls.FindIndex(c=>c.Sql==VpnSql.Coverage));
        reader=new Reader((sql,_)=>sql==sourceSql?throw DatabaseError("42501"):null);
        report=await VpnReports.Read(reader,Owner,"vpn.connections",Parameters(tab),"view",TestContext.Current.CancellationToken);Assert.Equal("partial",report.Text("state"));Assert.Single(report["items"]!.AsArray());Assert.Equal(101,report["items"]![0].Number("entity_id"));Assert.Equal("error",report["branches"]![branch].Text("state"));Assert.Equal("ok",report["branches"]!["accounting"].Text("state"));
    }

    [Theory] [InlineData("partial",0,"unknown",null)] [InlineData("partial",2,"observed",2)] [InlineData("processing",0,"unknown",null)] [InlineData("stale",3,"observed",3)] [InlineData("available",0,"unknown",null)] [InlineData("available",0,"complete",0)]
    public void Metrics_qualify_incomplete_period_and_only_proven_coverage_confirms_zero(string state,int count,string quality,int? expected)
    {
        var report=Report(Raw(state,count,quality=="complete"?"proven":"not_proven"));var metric=report["metrics"]![0]!;Assert.Equal(quality,metric.Text("quality"));if(expected is null) Assert.Null(metric["value"]);else Assert.Equal(expected.Value,metric.Number("value"));Assert.Equal("accounting",report["state_details"].Text("source"));if(quality!="complete") Assert.Null(report["metrics"]![1]!["value"]);
    }

    [Fact] public async Task Heatmap_is_full_weekday_hour_grid_using_whole_window_and_user_timezone()
    {
        var reader=new Reader((sql,_)=>sql==VpnSql.WindowsGrid?[Json(new {isodow=2,hour=6,failures=2}),Json(new {isodow=7,hour=23,failures=1}),Json(new {isodow=9,hour=1,failures=5})]:null);
        var report=await VpnReports.Read(reader,Owner,"vpn.connections",Parameters("windows_heatmap","Asia/Novosibirsk"),"view",TestContext.Current.CancellationToken);
        var grid=report["collections"]!["windows_heatmap"]!.AsArray();Assert.Equal(168,grid.Count);Assert.Equal(new[]{"Пн","Вт","Ср","Чт","Пт","Сб","Вс"},grid.Where((_,i)=>i%24==0).Select(n=>n.Text("weekday")));Assert.Equal(Enumerable.Range(0,24).Select(h=>h.ToString("D2")),grid.Take(24).Select(n=>n.Text("hour")));Assert.Equal(new long[]{2,1},grid.Where(n=>n.Number("failures")>0).Select(n=>n.Number("failures")));Assert.Equal("06",grid[30].Text("hour"));Assert.Equal("Вт",grid[30].Text("weekday"));
        var call=reader.Calls.Single(c=>c.Sql==VpnSql.WindowsGrid);Assert.Equal("Asia/Novosibirsk",call.Values[0]);Assert.Equal("Asia/Novosibirsk",call.Values[1]);Assert.DoesNotContain(reader.Calls,c=>c.Sql==VpnSql.WindowsEvents);Assert.Contains(report["branches"]!["windows_heatmap"]!["limitations"]!.AsArray(),n=>n.Text("code")=="windows_heatmap_meaning");
    }

    [Fact] public void Heatmap_declaration_exposes_axes_and_failure_series()
    {
        var declaration=new Sli.Server.Reporting.V2.ReportDefinitionRegistry().Get("vpn.connections")!.Declaration;
        var view=declaration["views"]!.AsArray().Single(v=>v.Text("key")=="windows_heatmap")!;Assert.Equal("heatmap",view.Text("chart"));Assert.Equal("hour",view.Text("x"));Assert.Equal("weekday",view.Text("y"));Assert.True(JsonNode.DeepEquals(JsonNode.Parse("[{\"label\":\"Отказов\",\"path\":\"failures\"}]"),view["series"]));
    }

    [Fact] public void NPS_tab_presents_ambiguous_identity_without_turning_denials_into_sessions()
    {
        var source=Json(new {state="available",items=new[]{new {event_db_id=9,event_id=6273,authorization_result="denied",reason_code=16,identity_state="ambiguous",identity=new {observed_subject_sid="S-1-5-21-100000001-200000002-300000003-1001"}}}});
        var report=Report(Raw(),"authorizations",source);var row=report["collections"]!["authorizations"]![0]!;Assert.Equal("отказано",row.Text("decision"));Assert.Equal(16,row.Number("reason"));Assert.Equal("неоднозначна",row.Text("identity_state_text"));Assert.Equal("S-1-5-21-100000001-200000002-300000003-1001",row.Text("identity_text"));Assert.False(row.AsObject().ContainsKey("session_row_id"));
    }

    [Theory]
    [InlineData("observed_failed_logon",null,"отказ")] [InlineData("observed_kerberos_preauth_failure",null,"отказ")] [InlineData("observed_successful_logon",null,"успех")]
    [InlineData("observed_credential_validation","0x0","успех")] [InlineData("observed_credential_validation","0xC000006A","отказ")] [InlineData("observed_credential_validation",null,"не зафиксирован")] [InlineData("observed_logoff",null,"не зафиксирован")]
    public void Windows_outcome_uses_observed_fact_or_result_code(string fact,string? code,string expected)
    {
        var row=Json(new {authentication_fact=fact,source_native=new {result_code=code}});Assert.Equal(expected,VpnReports.OutcomeText(row));row["outcome"]=Json(new {result="failure"});Assert.Equal("отказ",VpnReports.OutcomeText(row));
    }

    [Theory] [InlineData("whole_period")] [InlineData("displayed_sample")]
    public void Windows_review_explains_scope_truncation_and_distributed_rule(string scope)
    {
        var source=Json(new {state="available",items=new[]{new {event_db_id=10}},result_window=new {truncated=true,returned_event_count=200},limits=new {display_limit=1},manual_review_policy=new {coverage_scope=scope,signals_truncated=true,distributed_conditions=new {rolling_window_hours=24,maximum_failures_per_target=3},signals=new[]{new {rule="distributed",failure_fact_count=10,distinct_target_sid_count=10,distinct_source_count=5,evidence_event_db_id=201,window=new {from_utc="2026-08-21T00:00:00Z",to_utc_exclusive="2026-08-22T00:00:00Z"}}}},limitations=new[]{"unknown_results_remain_unknown","source_completeness_not_proven","earlier_failure_context_displayed_sample_only"}});
        var report=Report(Raw(),"windows",source);Assert.Equal("partial",report.Text("state"));Assert.Equal(10,report["collections"]!["windows"]![0].Number("event_db_id"));var branch=report["branches"]!["windows"]!;Assert.Equal("partial",branch.Text("state"));Assert.Equal("result_truncated",branch.Text("reason"));Assert.Equal(90,branch["limits"].Number("max_period_days"));Assert.Equal(1,branch["limits"].Number("display_limit"));
        var notes=branch["limitations"]!.AsArray().ToDictionary(n=>n.Text("code"));Assert.Contains(scope=="whole_period"?"windows_review_whole_period":"windows_review_sample",notes.Keys);Assert.Equal(200,notes["windows_truncated"]!["params"].Number("count"));Assert.Contains("не вердикт",notes["windows_distributed_review"].Text("text"));Assert.Equal(10,notes["windows_distributed_review"]!["params"].Number("accounts"));Assert.Equal(5,notes["windows_distributed_review"]!["params"].Number("sources"));
        foreach(string code in new[]{"windows_review_truncated","windows_unknown_results_remain_unknown","windows_source_completeness_not_proven","windows_earlier_failure_context_displayed_sample_only"}) Assert.Contains(code,notes.Keys);
        Assert.Equal(scope=="whole_period",notes.ContainsKey("windows_review_first_windows"));Assert.Equal("not_requested",report["branches"]!["nps"].Text("state"));Assert.Equal("not_requested",report["branches"]!["windows_heatmap"].Text("state"));
    }

    [Fact] public void Windows_without_signal_keeps_unverified_coverage_and_single_IP_note_is_not_verdict()
    {
        var source=Json(new {state="coverage_unverified",items=Array.Empty<object>(),manual_review_policy=new {coverage_scope="whole_period",state="no_observed_signal_unverified",signals=Array.Empty<object>()},limitations=new[]{"source_completeness_not_proven"}});
        var branch=VpnReports.SourceBranch(source,"windows",true);Assert.Equal("partial",branch.Text("state"));var codes=branch["limitations"]!.AsArray().Select(n=>n.Text("code")).ToArray();foreach(string code in new[]{"windows_coverage_unverified","windows_review_whole_period","windows_review_no_signal","windows_source_completeness_not_proven"}) Assert.Contains(code,codes);
        source["manual_review_policy"]=Json(new {coverage_scope="displayed_sample",conditions=new {rolling_window_minutes=10},signals=new[]{new {source_ip="192.0.2.5",failure_fact_count=7,distinct_target_sid_count=3}}});branch=VpnReports.SourceBranch(source,"windows");var note=branch["limitations"]!.AsArray().Single(n=>n.Text("code")=="windows_manual_review");Assert.Contains("192.0.2.5",note.Text("text"));Assert.Contains("не вывод об атаке",note.Text("text"));
    }

    [Fact] public async Task Too_wide_Windows_window_explains_90_days_without_discarding_accounting()
    {
        var report=await VpnReports.Read(new Reader(),Owner,"vpn.connections",Parameters("windows",from:"2026-06-01T00:00:00Z",to:"2026-09-01T00:00:00Z"),"view",TestContext.Current.CancellationToken);Assert.Equal("partial",report.Text("state"));Assert.Single(report["items"]!.AsArray());Assert.Contains(report["limitations"]!.AsArray(),n=>n.Text("text").Contains("90 дней",StringComparison.Ordinal));
    }
}
