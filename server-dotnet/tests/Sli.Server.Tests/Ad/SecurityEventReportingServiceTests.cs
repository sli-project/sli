using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sli.Server.Access;
using Sli.Server.Ad;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
using Sli.Server.Reporting.V2;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Ad;

public sealed partial class SecurityEventReportingTests
{
    static AccessDecision Access(long[]? domains = null, bool events = true, bool report = true, bool export = true, string[]? fields = null)
    {
        var grant = new AtomicReportGrant(JsonSerializer.SerializeToElement(new { kind = "domain", ids = domains ?? [7,8] }),
            (fields ?? ["security","technical","raw_evidence"]).ToHashSet(), (export ? new[] {"view","export"} : ["view"]).ToHashSet(),1,1);
        return new("viewer",new(false,(events ? new[] {"events.view"} : []).ToHashSet(),new HashSet<string>(),[],new Dictionary<string,JsonElement>()),
            report ? [new("security.events.chains",true,[grant])] : []);
    }
    static ReportQueryContext Context(AccessDecision? access = null, string? tab = "events", string? cursor = null, long? domain = null)
    {
        var parameters = O("""{"period":{"from_utc":"2026-09-01T10:00:00Z","to_utc":"2026-09-01T11:00:00Z"}}""");
        if (domain is not null) parameters["domain"] = domain.Value;
        return new(new ReportDefinitionRegistry().Get("security.events.chains")!,access ?? Access(),new("session",1,"operator"),parameters,
            new(cursor,2,"UTC",null,"desc",tab),ReportScope.None,null,"view",_ => true,[]);
    }
    sealed class Store : IAdReportStore
    {
        public List<AdReportRequest> Reads = []; public List<long> Presence = []; public List<JsonObject> Rows = []; public JsonObject? Payload;
        public Func<AdReportRequest,CancellationToken,Task<JsonObject>>? OnRead;
        public Task<IReadOnlyList<long>> DomainsAsync(long after,CancellationToken ct) => Task.FromResult<IReadOnlyList<long>>(after == 0 ? [1,7,8] : []);
        public Task<bool> HasSourceAsync(string kind,long domain,CancellationToken ct) { Presence.Add(domain); return Task.FromResult(true); }
        public Task<JsonObject> ReadAsync(AdReportRequest request,bool sensitive,CancellationToken ct)
        {
            Reads.Add(request); Assert.False(sensitive);
            if (OnRead is not null) return OnRead(request,ct);
            if (Payload is not null) return Task.FromResult(Payload.DeepClone().AsObject());
            IEnumerable<JsonObject> rows = Rows.Where(r => r["domain_id"]!.GetValue<long>() == request.Domain);
            if (request.Cursor is not null) {
                var before = AdSecurity.DecodeCursor(request.Cursor,request.Domain,request.Period!,request.Filters);
                rows = rows.Where(r => AdJson.Time(r,"time_created_utc") < before.Time || AdJson.Time(r,"time_created_utc") == before.Time && r["event_db_id"]!.GetValue<long>() < before.Id);
            }
            var ordered = rows.OrderByDescending(r => AdJson.Time(r,"time_created_utc")).ThenByDescending(r => r["event_db_id"]!.GetValue<long>()).ToArray();
            return Task.FromResult(AdSecurity.Compose(request,ordered.Take(request.Limit).ToArray(),true,ordered.Length > request.Limit,new()));
        }
    }
    sealed class Domains : IReportDomains
    {
        public Task<IReadOnlyList<DomainItem>> ReadAsync(long[]? ids,CancellationToken ct) => Task.FromResult<IReadOnlyList<DomainItem>>([]);
    }
    sealed class DailyDatabase : ISemanticDatabase, ISemanticSession
    {
        public List<(string Sql,object?[] Args)> Queries = [];
        public Task<ISemanticSession> OpenAsync(bool write,CancellationToken ct) { Assert.False(write); return Task.FromResult<ISemanticSession>(this); }
        public Task<JsonArray> QueryAsync(string sql,CancellationToken ct,params object?[] values)
        {
            if (sql.StartsWith("select id, fqdn from domains", StringComparison.Ordinal))
                return Task.FromResult(new JsonArray(((long[])values[0]!).Select(id => (JsonNode)new JsonObject { ["id"] = id, ["fqdn"] = $"domain-{id}.example.test" }).ToArray()));
            Queries.Add((sql,values)); Assert.DoesNotContain("limit",sql,StringComparison.OrdinalIgnoreCase);
            return Task.FromResult(JsonNode.Parse("""[{"date":"2026-09-02","event_id":4624,"count":3},{"date":"2026-09-02","event_id":4776,"count":2},{"date":"2026-09-02","event_id":4720,"count":1}]""")!.AsArray());
        }
        public Task CommitAsync(CancellationToken ct) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    static SecurityEventsReader Reader(Store store,DailyDatabase? db = null) => new(store,db ?? new(),new BuiltinReportExports(null!,null!,store,null!));

    [Theory]
    [InlineData(3)] [InlineData(21)]
    public async Task Chains_and_daily_use_configured_boundary_with_invalid_retired_history_settings(int days)
    {
        var store=new Store();var db=new DailyDatabase();
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["Sli:Storage:HotRetentionDays"]=days.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["Sli:Storage:ShortEventReads"]="false",["Sli:Storage:HistoryReadMode"]="primary",
            ["Sli:Storage:HistoryClickHousePort"]="invalid"
        }).Build();
        var result=await new SecurityEventsReader(store,db,new BuiltinReportExports(null!,null!,store,null!),config).QueryAsync(Context(tab:"daily",domain:7),Ct);
        Assert.NotEqual("error",result["state"]!.ToString());
        Assert.Equal(new DateTimeOffset(DateTime.UtcNow.Date,TimeSpan.Zero).AddDays(-days),Assert.Single(store.Reads).AuthenticationCutoff);
        Assert.NotEmpty(result["collections"]!["daily"]!.AsArray());
    }

    [Fact]
    public async Task All_domain_page_is_globally_ordered_and_cursor_binds_authorized_domains_and_filters()
    {
        var store = new Store { Rows = [Event(30,4624,30,8),Event(20,4625,20),Event(10,4776,10,8)] }; var reader = Reader(store);
        var context = Context(); var page = await reader.QueryAsync(context,Ct);
        Assert.Equal(new long[]{30,20},page["items"]!.AsArray().Select(r => r!["event_db_id"]!.GetValue<long>()));
        Assert.Equal(new long[]{7,8},store.Reads.Select(r => r.Domain)); Assert.True(page["has_more"]!.GetValue<bool>());
        string cursor = page["next_cursor"]!.ToString(); store.Reads.Clear();
        var next = await reader.QueryAsync(context with { Paging = context.Paging with { Cursor = cursor } },Ct);
        Assert.Equal(10,Assert.Single(next["items"]!.AsArray())!["event_db_id"]!.GetValue<long>());
        Assert.All(store.Reads,r => Assert.Equal((Period.Start.AddMinutes(20),20L),AdSecurity.DecodeCursor(r.Cursor!,r.Domain,Period,r.Filters)));
        int calls = store.Reads.Count;
        var changed = context with { Access = Access([7]), Paging = context.Paging with { Cursor = cursor } };
        Assert.Equal("invalid_cursor",(await Assert.ThrowsAsync<ReportRequestException>(() => reader.QueryAsync(changed,Ct))).Message);
        var parameters = context.Params.DeepClone().AsObject(); parameters["event_db_id"] = 91; parameters["entity_id"] = 55;
        Assert.Equal("invalid_cursor",(await Assert.ThrowsAsync<ReportRequestException>(() => reader.QueryAsync(context with { Params = parameters, Paging = changed.Paging },Ct))).Message);
        Assert.Equal(calls,store.Reads.Count);
    }

    [Fact]
    public async Task Grants_require_events_view_report_domain_and_atomic_fields_but_not_identity_basic()
    {
        var store = new Store(); var reader = Reader(store);
        foreach(var access in new[] { Access(events:false),Access(report:false),Access([8]),Access(fields:["security","identity_basic"]) })
        {
            var page = await reader.QueryAsync(Context(access,domain:7),Ct); Assert.Equal("denied",page["state"]!.ToString());
        }
        Assert.Empty(store.Reads);
        var allowed = await reader.QueryAsync(Context(Access(),domain:7),Ct); Assert.Equal("partial",allowed["state"]!.ToString()); Assert.Single(store.Reads);
        store.Reads.Clear(); var export = new BuiltinReportExports(null!,null!,store,null!);
        foreach(var access in new[] {Access(export:false),Access(report:false),Access(events:false)}) {
            var error = await Assert.ThrowsAsync<ReportRequestException>(() => export.ExportAsync(Context(access) with { Action = "export" },Ct)); Assert.Equal(403,error.Status);
        }
        Assert.Empty(store.Reads);
        await export.ExportAsync(Context(Access([7])) with { Action = "export" },Ct);
        Assert.Equal(7,Assert.Single(store.Reads).Domain); Assert.True(store.Reads[0].Export);
    }

    [Fact]
    public async Task Daily_tab_uses_same_authorized_scope_and_fills_every_local_day_only_on_request()
    {
        var store = new Store(); var database = new DailyDatabase(); var reader = Reader(store,database); var context = Context();
        await reader.QueryAsync(context,Ct); Assert.Empty(database.Queries);
        context.Params["period"] = O("""{"from_utc":"2026-09-01T00:00:00Z","to_utc":"2026-09-04T00:00:00Z"}"""); context.Params["event_db_id"] = 77;
        var page = await reader.QueryAsync(context with { Paging = context.Paging with { Tab = "daily" } },Ct);
        Assert.Equal(new long[]{7,8},database.Queries.Select(q => (long)q.Args[0]!));
        Assert.All(database.Queries,q => { Assert.Equal("UTC",q.Args[^1]); Assert.Contains("at time zone",q.Sql); Assert.Contains("group by 1,event.event_id",q.Sql); Assert.DoesNotContain(77L,q.Args); Assert.Contains(4624,(int[])q.Args[1]!); });
        var days = page["collections"]!["daily"]!.AsArray(); Assert.Equal(new[]{"2026-09-01","2026-09-02","2026-09-03"},days.Select(r => r!["date"]!.ToString()));
        Assert.Equal(12,days[1]!["total"]!.GetValue<long>()); Assert.Equal(10,days[1]!["authentication"]!.GetValue<long>()); Assert.Equal(2,days[1]!["account_lifecycle"]!.GetValue<long>());
        Assert.Equal(0,days[0]!["authentication"]!.GetValue<long>()); Assert.Equal(0,days[1]!["group_membership"]!.GetValue<long>());
        database.Queries.Clear(); await reader.QueryAsync(Context(Access(report:false),tab:"daily"),Ct); Assert.Empty(database.Queries);
    }

    sealed class Authentication : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context,CancellationToken ct) => ValueTask.FromResult(AuthenticationResult.Success(new("session",1,"operator")));
    }
    sealed class Facts : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal principal,CancellationToken ct)
        {
            JsonElement J(object value) => JsonSerializer.SerializeToElement(value);
            string[] fields = ["security","technical","raw_evidence"];
            return Task.FromResult(new AccessFacts(false,"viewer",[],[],new[]{"events.view","field.security","field.technical","field.raw_evidence","evidence.exact","reports.export"}.Select(c => J(new {capability_key=c,effect="allow",scope_json=new{kind="all"}})).ToArray(),[],[],
                [J(new{report_key="security.events.chains",effect="allow",allowed_actions=new[]{"view","export"},field_categories=fields,scope_json=new{kind="domain",ids=new[]{7}}})],
                [J(new{report_key="security.events.chains",version=1,dataset_version=1,actions_json=new[]{"view","export"},fields_json=fields.Select(f=>new{category=f}),definition_json=new{actions=new[]{"view","export"}}})]));
        }
    }
    static async Task<IHost> Host(Store store)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:AuthRequired"] = "true" }).Build();
        return await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s => {
            s.AddRouting(); s.AddLogging(); s.AddSingleton<IConfiguration>(config); s.AddSingleton(new AuthRequestPolicy(config)); s.AddSingleton(new TransportGate(config));
            s.AddSingleton<IPrincipalAuthenticator>(new Authentication()); s.AddSingleton<IAccessFactsRepository>(new Facts()); s.AddSingleton<IAdReportStore>(store);
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(routes => routes.MapAdReports()); })).StartAsync(Ct);
    }

    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Http_forwards_precise_window_all_selectors_cursor_and_export_metadata(bool export)
    {
        var store = new Store(); var row = Event(77,4728); row["source_facts_sha256"] = null; store.Rows.Add(row);
        using var host = await Host(store); using var client = host.GetTestClient();
        string[] pairs = ["category=group_membership","event_id=4728","event_db_id=77","entity_id=55","outcome=unknown","actor=operator","target=evidence-reader","group=fixture","source=dc01.example.test","q=VPN"];
        var filters = Filters(pairs.Select(p => { var parts = p.Split('='); return(parts[0],parts[1]); }).ToArray());
        var period = AdPeriod.Parse("2026-09-01T10:00:00.123456Z","2026-09-01T11:00:00.987654Z","Asia/Bangkok","security_events");
        string cursor = AdSecurity.EncodeCursor(7,period,filters,period.End,100);
        string url = "/api/v1/reports/ad.state/security-events" + (export ? ".csv" : "") + "?domain_id=7&time_from=2026-09-01T10:00:00.123456Z&time_to=2026-09-01T11:00:00.987654Z&timezone=Asia%2FBangkok&"+string.Join('&',pairs)+(export ? "" : "&limit=200&cursor="+cursor);
        using var response = await client.GetAsync(url,Ct); Assert.Equal(HttpStatusCode.OK,response.StatusCode);
        var request = Assert.Single(store.Reads); Assert.Equal(period,request.Period); Assert.Equal(export ? 500 : 200,request.Limit); Assert.Equal(export,request.Export); Assert.Equal(export ? null : cursor,request.Cursor);
        Assert.True(JsonNode.DeepEquals(filters,request.Filters));
        if(export) { Assert.Equal("text/csv",response.Content.Headers.ContentType!.MediaType); Assert.Equal("false",response.Headers.GetValues("X-Sli-Export-Truncated").Single()); Assert.Equal("1",response.Headers.GetValues("X-Sli-Export-Rows").Single()); Assert.Equal("attachment; filename=\"sli-security-events-complete-1-rows.csv\"",response.Content.Headers.ContentDisposition!.ToString()); Assert.Contains("incomplete=true",await response.Content.ReadAsStringAsync(Ct)); }
    }

    [Fact]
    public async Task Source_discovery_checks_server_built_access_before_presence()
    {
        var store = new Store(); using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v1/reports/ad.state/security-event-sources",Ct);
        Assert.Equal(HttpStatusCode.OK,response.StatusCode); Assert.Equal(new long[]{7},store.Presence);
        Equal("""[{"source_domain_id":7}]""",JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!["items"]);
    }

    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Http_csv_marks_hidden_evidence_incomplete_and_reports_truncation(bool more)
    {
        var payload = Compose(Event(77,4728)); payload["has_more"] = more; payload["items"]![0]!["evidence"]!["state"] = "hidden";
        var store = new Store { Payload = payload }; using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v1/reports/ad.state/security-events.csv?domain_id=7&time_from=2026-09-01T10:00:00Z&time_to=2026-09-01T11:00:00Z",Ct);
        Assert.Equal(HttpStatusCode.OK,response.StatusCode); Assert.Equal(more ? "true" : "false",response.Headers.GetValues("X-Sli-Export-Truncated").Single());
        Assert.Equal("1",response.Headers.GetValues("X-Sli-Export-Rows").Single());
        Assert.Contains(more ? "INCOMPLETE-first-1-rows.csv" : "complete-1-rows.csv",response.Content.Headers.ContentDisposition!.ToString());
        string body = await response.Content.ReadAsStringAsync(Ct); Assert.Contains("evidence_state",body); Assert.Contains("hidden",body); Assert.Contains("incomplete=true",body);
        Assert.Single(store.Reads);
    }

    [Theory]
    [InlineData("limit=501","security_events_limit_invalid")]
    [InlineData("time_to=2027-09-03T11:00:00Z","security_events_period_too_wide")]
    [InlineData("timezone=Mars/Olympus","invalid_timezone")]
    [InlineData("event_db_id=0","security_events_filter_invalid")]
    [InlineData("event_db_id=-1","security_events_filter_invalid")]
    [InlineData("event_db_id=not-an-id","security_events_filter_invalid")]
    public async Task Invalid_bounds_zone_limit_and_exact_ids_do_not_read(string query,string code)
    {
        var store = new Store(); using var host = await Host(store); using var client = host.GetTestClient();
        var values = new Dictionary<string,string> { ["domain_id"]="7",["time_from"]="2026-09-01T10:00:00Z",["time_to"]="2026-09-01T11:00:00Z" }; var parts = query.Split('='); values[parts[0]] = parts[1];
        using var response = await client.GetAsync("/api/v1/reports/ad.state/security-events?"+string.Join('&',values.Select(p => p.Key+"="+Uri.EscapeDataString(p.Value))),Ct);
        Assert.Equal(HttpStatusCode.BadRequest,response.StatusCode); Assert.Contains(code,await response.Content.ReadAsStringAsync(Ct)); Assert.Empty(store.Reads);
    }
}
