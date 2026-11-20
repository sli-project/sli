using System.Net;
using System.Text;
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
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Storage.EventReports;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed partial class EventQueryEndpointTests
{
    static readonly DateTimeOffset Now=DateTimeOffset.Parse("2026-11-05T12:00:00Z");
    sealed class Clock : TimeProvider { public DateTimeOffset Now=EventQueryEndpointTests.Now; public override DateTimeOffset GetUtcNow()=>Now; }
    sealed class Authentication : IPrincipalAuthenticator
    {
        public Principal Principal=new("session",1,"operator"); public bool Allowed=true;
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c,CancellationToken ct)=>ValueTask.FromResult(Allowed?AuthenticationResult.Success(Principal):AuthenticationResult.Denied(401,"authentication_required"));
    }
    internal static JsonElement Json(object o)=>JsonSerializer.SerializeToElement(o);
    internal static AccessFacts MakeFacts(bool allowed=true,int domain=1,bool owner=false)
    {
        var fields=EventSearchPolicy.BaseFields.Concat(EventSearchPolicy.OptionalFields).Distinct().Select(f=>new {key=f,category=f is "id" or "time_created_utc" or "channel" or "provider" or "server_id" or "domain_id" or "group_identity_complete" or "source_payload_state"?"technical":"security"}).ToArray();
        return new(owner,"operator",[],[],allowed?new[]{"events.view","evidence.exact","field.technical","field.security"}.Select(cap=>Json(new {capability_key=cap,effect="allow",scope_json=new {kind="all"}})).ToArray():[],[],[],
            allowed?[Json(new {report_key="events.explorer",effect="allow",scope_json=new {kind="domain",ids=new[]{domain}},field_categories=new[]{"technical","security"},allowed_actions=new[]{"view"}})]:[],
            [Json(new {report_key="events.explorer",version=1,dataset_version=1,dataset_key="events.v2",dataset_status="published",fields_json=fields,actions_json=new[]{"view"},definition_json=new {columns=EventSearchPolicy.BaseFields,evsearch_columns=EventSearchPolicy.OptionalFields.Distinct().ToArray(),actions=new[]{"view"},evsearch_questions=new {failed_logons=new[]{"provider","channel","event_id","outcome"}}}})]);
    }
    sealed class Facts : IAccessFactsRepository
    {
        public AccessFacts Value=MakeFacts();
        public Task<AccessFacts> LoadAsync(Principal p,CancellationToken ct)=>Task.FromResult(Value);
    }
    sealed class Reader : IEventReadService
    {
        public int Resources;
        public Task<IReadOnlyList<AccessResource>> ResourcesAsync(long id,CancellationToken ct) { Resources++; return Task.FromResult<IReadOnlyList<AccessResource>>(id==99?[]:[new("domain",id==8?2:1)]); }
        public Task<Dictionary<long,JsonObject>> DetailsAsync(long[] ids,bool exact,Func<long,CancellationToken,Task<bool>> admitted,CancellationToken ct)=>throw new NotSupportedException();
        public Task<JsonObject> RelationsAsync(long id,Func<long,CancellationToken,Task<bool>> admitted,CancellationToken ct)=>throw new NotSupportedException();
    }
    sealed class Store : IEventQueryStore
    {
        public int Captures,Lists,Entities; public Exception? Error,AdmissionError; public bool Available=true;
        public Func<CancellationToken,Task<IReadOnlyList<SearchEvent>>>? Capture;
        public JsonObject? ListRow;
        public DateTimeOffset RetentionBoundary { get; set; }=Now.AddDays(-7);
        public IReadOnlyList<SearchEvent>? Rows;
        public TaskCompletionSource? CaptureEntered,CaptureRelease;
        public void AdmitSearch() { if(AdmissionError is {} e) throw e; if(!Available) throw new EventSearchException("history_unavailable"); }
        public async Task<IReadOnlyList<SearchEvent>> CaptureAsync(EventSearchInput input,EventSearchPolicy policy,CancellationToken ct)
        {
            Captures++; if(Error is {} e) throw e;
            if(Capture is {} capture) return await capture(ct);
            CaptureEntered?.TrySetResult();
            if(CaptureRelease is {} release) await release.Task.WaitAsync(ct);
            // The adapter receives the server-issued scoped policy before any
            // projections, aggregates or paging can be produced.
            Assert.NotEmpty(policy.Scopes);
            _=new EventSearchSql().Predicate(input,policy);
            return Rows??Enumerable.Range(1,3).Select(i=>new SearchEvent(i,Now.AddMinutes(-i),new string('A',64),"postgres",new JsonObject { ["id"]=i,["event_id"]=4625,["channel"]="Security",["time_created_utc"]=Now.AddMinutes(-i) })).ToArray();
        }
        public Task<JsonObject> EntitiesAsync(long id,CancellationToken ct)
        { Entities++; if(Error is {} e) throw e; return Task.FromResult(new JsonObject { ["api_version"]="v1",["event_db_id"]=id,["event_found"]=id!=99,["items"]=new JsonArray(),["evidence_status"]=id==99?"event_not_found":"zero_extracted",["limit"]=30,["warning"]=null }); }
        public Task<JsonObject> ListAsync(EventListInput input,CapabilityDecisionSet caps,CancellationToken ct)
        { Lists++; if(Error is {} e) throw e; return Task.FromResult(new JsonObject { ["api_version"]="v1",["items"]=new JsonArray(ListRow is null ? new JsonObject { ["event_db_id"]=1,["event_id"]=4625 } : EventListProjection.Project(ListRow)),["has_more"]=false,["next_cursor"]=null,["query_status"]="ok",["warning"]=null,["category_counts"]=null }); }
    }
    sealed class Fixture : IAsyncDisposable
    {
        internal readonly Authentication Auth=new(); internal readonly Facts Facts=new(); internal readonly Store Store=new(); internal readonly Reader Reader=new(); internal readonly Clock Clock=new();
        IHost? host; internal HttpClient Client=null!;
        internal IServiceProvider Services=>host!.Services;
        internal async Task<Fixture> Start()
        {
            var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:AuthRequired"]="true" }).Build();
            host=await new HostBuilder().ConfigureWebHost(web=>web.UseTestServer().ConfigureServices(s=>
            {
                s.AddRouting(); s.AddLogging(); s.AddSingleton<IConfiguration>(config); s.AddSingleton(new AuthRequestPolicy(config)); s.AddSingleton(new TransportGate(config));
                s.AddSingleton<IPrincipalAuthenticator>(Auth); s.AddSingleton<IAccessFactsRepository>(Facts); s.AddSingleton<IEventQueryStore>(Store); s.AddSingleton<IEventReadService>(Reader); s.AddSingleton<TimeProvider>(Clock); s.AddEventReads();
            }).Configure(app=> { app.UseRouting(); app.UseEndpoints(r=>r.MapEventReads()); })).StartAsync(TestContext.Current.CancellationToken);
            Client=host.GetTestClient(); return this;
        }
        public ValueTask DisposeAsync() { Client.Dispose(); host?.Dispose(); return ValueTask.CompletedTask; }
        internal Task<HttpContext> Raw(string body,Action<HttpContext> configure)=>host!.GetTestServer().SendAsync(c=>
        {
            c.Request.Method="POST"; c.Request.Path="/api/v1/event-search/query"; c.Request.Scheme="http"; c.Request.Host=new HostString("example.test");
            byte[] data=Encoding.UTF8.GetBytes(body); c.Request.Body=new MemoryStream(data); c.Request.ContentLength=data.Length; c.Request.ContentType="application/json";
            configure(c);
        },TestContext.Current.CancellationToken);
    }
    static string Query(int size=1)=>new JsonObject { ["contract_version"]="evsearch.v1",["page_size"]=size }.ToJsonString();
    static Task<HttpResponseMessage> Post(Fixture f,string op,string body)=>f.Client.PostAsync("/api/v1/event-search/"+op,new StringContent(body,Encoding.UTF8,"application/json"),TestContext.Current.CancellationToken);
    static async Task<JsonObject> Body(HttpResponseMessage r)=>(JsonNode.Parse(await r.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)) as JsonObject)!;
    static async Task<JsonObject> Start(Fixture f,int size=1)
    { using var r=await Post(f,"query",Query(size)); Assert.Equal(HttpStatusCode.OK,r.StatusCode); return await Body(r); }

    [Theory] [InlineData("query")] [InlineData("page")] [InlineData("members")] [InlineData("summary")]
    public async Task Every_search_route_denies_before_read_without_capability(string operation)
    {
        await using var f=await new Fixture().Start(); f.Facts.Value=MakeFacts(false);
        using var r=await Post(f,operation,"{}"); Assert.Equal(HttpStatusCode.Forbidden,r.StatusCode); Assert.Equal(0,f.Store.Captures);
    }
    [Theory] [InlineData("/api/v1/events")] [InlineData("/api/v1/events/7/entities")]
    public async Task Every_get_route_denies_before_read_without_capability(string path)
    {
        await using var f=await new Fixture().Start(); f.Facts.Value=MakeFacts(false);
        using var r=await f.Client.GetAsync(path,TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.Forbidden,r.StatusCode); Assert.Equal(0,f.Store.Lists+f.Store.Entities+f.Reader.Resources);
    }
    [Theory] [InlineData("query")] [InlineData("page")] [InlineData("members")] [InlineData("summary")]
    public async Task Every_search_route_rejects_invalid_input(string operation)
    {
        await using var f=await new Fixture().Start(); using var r=await Post(f,operation,"{}");
        Assert.Equal(HttpStatusCode.UnprocessableEntity,r.StatusCode); Assert.Equal(operation=="query"?"evsearch.unsupported_version":"evsearch.invalid_request",(await Body(r))["error"]!.ToString()); Assert.Equal(0,f.Store.Captures);
    }
    [Theory] [InlineData("/api/v1/events?time_from=garbage","invalid_datetime")] [InlineData("/api/v1/events?timezone=invalid-zone","invalid_timezone")] [InlineData("/api/v1/events/0/entities","invalid_event_db_id")] [InlineData("/api/v1/events/no/entities","invalid_event_db_id")]
    public async Task Get_routes_reject_invalid_input(string path,string error)
    {
        await using var f=await new Fixture().Start(); using var r=await f.Client.GetAsync(path,TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest,r.StatusCode); Assert.Equal(error,(await Body(r))["error"]!.ToString()); Assert.Equal(0,f.Store.Lists+f.Store.Entities);
    }
    [Theory] [InlineData("/api/v1/events")] [InlineData("/api/v1/events/7/entities")] [InlineData("/api/v1/events/99/entities")]
    [InlineData("/api/v1/events?route=v1&authorization=invalid")]
    [InlineData("/api/v1/events/7/entities?route=v1&authorization=invalid")]
    public async Task Get_routes_succeed_with_typed_payload(string path)
    {
        await using var f=await new Fixture().Start(); using var r=await f.Client.GetAsync(path,TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK,r.StatusCode); var b=await Body(r); Assert.Equal("v1",b["api_version"]!.ToString()); Assert.NotNull(b["items"]); Assert.Equal(1,f.Store.Lists+f.Store.Entities);
    }
    [Fact] public async Task Entities_scope_denial_does_not_hydrate()
    {
        await using var f=await new Fixture().Start(); var facts=MakeFacts(); f.Facts.Value=facts with { DirectCapabilities=[Json(new {capability_key="evidence.exact",effect="allow",scope_json=new {kind="domain",ids=new[]{1}}})] };
        using var r=await f.Client.GetAsync("/api/v1/events/8/entities",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound,r.StatusCode); Assert.Equal(0,f.Store.Entities);
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task Round2V1ListIsSummaryOnlyEvenWithExactCapability(bool exact)
    {
        await using var f=await new Fixture().Start();
        if(!exact) f.Facts.Value=f.Facts.Value with { DirectCapabilities=f.Facts.Value.DirectCapabilities.Where(p=>p.GetProperty("capability_key").GetString()!="evidence.exact").ToArray() };
        f.Store.ListRow=Compatibility.LegacyProjectionTests.Round2RawEvent();
        using var response=await f.Client.GetAsync("/api/v1/events",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK,response.StatusCode); var body=await Body(response);
        Compatibility.LegacyProjectionTests.AssertRound2SummaryOnly(body);
        Assert.Equal("v1",body["api_version"]!.ToString()); Assert.Single(body["items"]!.AsArray()); Assert.Equal(1,f.Store.Lists);
        Assert.Equal(0,f.Reader.Resources);
    }
    [Fact] public async Task Query_page_members_summary_use_one_frozen_capture()
    {
        await using var f=await new Fixture().Start(); var first=await Start(f); string id=first["execution_id"]!.ToString();
        Assert.True(first["has_more"]!.GetValue<bool>()); string cursor=first["next_cursor"]!.ToString();
        var seen=new HashSet<string> { first["items"]![0]!["group_key"]!.ToString() };
        while(cursor.Length>0)
        {
            using var r=await Post(f,"page",new JsonObject { ["execution_id"]=id,["cursor"]=cursor,["page_size"]=1 }.ToJsonString()); Assert.Equal(HttpStatusCode.OK,r.StatusCode); var page=await Body(r);
            foreach(var group in page["items"]!.AsArray()) Assert.True(seen.Add(group!["group_key"]!.ToString())); cursor=page["next_cursor"]?.ToString()??"";
        }
        Assert.Equal(3,seen.Count);
        using var members=await Post(f,"members",new JsonObject { ["execution_id"]=id,["group_key"]=seen.First() }.ToJsonString()); Assert.Equal(HttpStatusCode.OK,members.StatusCode); var m=await Body(members); Assert.Single(m["items"]!.AsArray()); Assert.Equal("unknown",m["items"]![0]!["source_payload_state"]!.ToString());
        using var summary=await Post(f,"summary",new JsonObject { ["execution_id"]=id }.ToJsonString()); Assert.Equal(HttpStatusCode.OK,summary.StatusCode); var s=await Body(summary); Assert.Equal(3,s["totals"]!["events"]!["value"]!.GetValue<int>()); Assert.Equal(3,s["facets"]!["event_id"]!["items"]![0]!["count"]!.GetValue<int>()); Assert.Equal("unknown",s["coverage"]!.ToString()); Assert.Equal(1,f.Store.Captures);
    }
    [Theory] [InlineData("page")] [InlineData("members")] [InlineData("summary")]
    public async Task Snapshot_is_owner_bound_and_wrong_owner_cannot_destroy_it(string op)
    {
        await using var f=await new Fixture().Start(); var first=await Start(f); var body=new JsonObject { ["execution_id"]=first["execution_id"]!.DeepClone() }; if(op=="members") body["group_key"]=first["items"]![0]!["group_key"]!.DeepClone();
        f.Auth.Principal=new("session",2,"operator"); using var denied=await Post(f,op,body.ToJsonString()); Assert.Equal(HttpStatusCode.Gone,denied.StatusCode);
        f.Auth.Principal=new("session",1,"operator"); using var allowed=await Post(f,op,body.ToJsonString()); Assert.Equal(HttpStatusCode.OK,allowed.StatusCode);
    }
    [Theory] [InlineData("page")] [InlineData("members")] [InlineData("summary")]
    public async Task Changed_scope_invalidates_existing_execution(string op)
    {
        await using var f=await new Fixture().Start(); var first=await Start(f); var body=new JsonObject { ["execution_id"]=first["execution_id"]!.DeepClone() }; if(op=="members") body["group_key"]=first["items"]![0]!["group_key"]!.DeepClone();
        f.Facts.Value=MakeFacts(domain:2); using var r=await Post(f,op,body.ToJsonString()); Assert.Equal(HttpStatusCode.Conflict,r.StatusCode); Assert.Equal("evsearch.snapshot_invalidated",(await Body(r))["error"]!.ToString());
        f.Facts.Value=MakeFacts(); using var later=await Post(f,op,body.ToJsonString()); Assert.Equal(HttpStatusCode.Gone,later.StatusCode);
    }
    [Fact] public async Task Cursor_is_bound_to_execution_and_page_kind()
    {
        await using var f=await new Fixture().Start(); var first=await Start(f); var second=await Start(f);
        using var r=await Post(f,"page",new JsonObject { ["execution_id"]=second["execution_id"]!.DeepClone(),["cursor"]=first["next_cursor"]!.DeepClone() }.ToJsonString()); Assert.Equal(HttpStatusCode.UnprocessableEntity,r.StatusCode); Assert.Equal("evsearch.invalid_cursor",(await Body(r))["error"]!.ToString());
    }
    [Fact] public async Task Expired_snapshot_requires_a_new_query()
    {
        await using var f=await new Fixture().Start(); var first=await Start(f); f.Clock.Now=Now.AddMinutes(6);
        using var r=await Post(f,"page",new JsonObject { ["execution_id"]=first["execution_id"]!.DeepClone() }.ToJsonString()); Assert.Equal(HttpStatusCode.Gone,r.StatusCode); Assert.Equal(1,f.Store.Captures);
    }
    [Fact] public async Task History_switch_is_rechecked_on_pages_and_disabled_execution_cannot_revive()
    {
        await using var f=await new Fixture().Start(); var first=await Start(f); string body=new JsonObject { ["execution_id"]=first["execution_id"]!.DeepClone() }.ToJsonString();
        f.Store.Available=false; using var unavailable=await Post(f,"page",body); Assert.Equal(HttpStatusCode.ServiceUnavailable,unavailable.StatusCode); Assert.Equal("evsearch.history_unavailable",(await Body(unavailable))["error"]!.ToString());
        f.Store.Available=true; using var gone=await Post(f,"page",body); Assert.Equal(HttpStatusCode.Gone,gone.StatusCode);
    }
    [Theory] [InlineData("/api/v1/events")] [InlineData("/api/v1/events/7/entities")] [InlineData("/api/v1/event-search/query")]
    public async Task Unauthenticated_requests_do_not_read_data(string path)
    {
        await using var f=await new Fixture().Start(); f.Auth.Allowed=false;
        using var r=path.Contains("event-search",StringComparison.Ordinal)?await Post(f,"query",Query()):await f.Client.GetAsync(path,TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized,r.StatusCode); Assert.Equal(0,f.Store.Captures+f.Store.Lists+f.Store.Entities);
    }
    [Fact] public async Task Search_rejects_api_keys_cross_origin_and_large_bodies()
    {
        await using var f=await new Fixture().Start(); f.Auth.Principal=new("api_key",1,"operator"); using var key=await Post(f,"query",Query()); Assert.Equal(HttpStatusCode.Forbidden,key.StatusCode);
        f.Auth.Principal=new("session",1,"operator"); f.Client.DefaultRequestHeaders.Add("Origin","https://untrusted.example"); using var origin=await Post(f,"query",Query()); Assert.Equal(HttpStatusCode.Forbidden,origin.StatusCode);
        f.Client.DefaultRequestHeaders.Remove("Origin"); using var large=await Post(f,"query",new string('x',16385)); Assert.Equal(HttpStatusCode.RequestEntityTooLarge,large.StatusCode); Assert.Equal(0,f.Store.Captures);
    }
    [Theory] [InlineData("/api/v1/events","timeout")] [InlineData("/api/v1/events/7/entities","timeout")] [InlineData("/api/v1/event-search/query","evsearch.snapshot_timeout")]
    public async Task Timeout_is_not_empty_success_evidence(string path,string code)
    {
        await using var f=await new Fixture().Start(); f.Store.Error=new TimeoutException(); using var r=path.Contains("event-search",StringComparison.Ordinal)?await Post(f,"query",Query()):await f.Client.GetAsync(path,TestContext.Current.CancellationToken);
        var b=await Body(r); Assert.Equal(path.Contains("event-search",StringComparison.Ordinal)?HttpStatusCode.ServiceUnavailable:HttpStatusCode.OK,r.StatusCode); Assert.Equal(code,(b["error"]??b["evidence_status"]??b["query_status"])!.ToString());
    }

    // Missing HTTP/runtime vectors from tests/events/test_evsearch_runtime_routes.py.
    [Theory]
    [InlineData("content_type",415,"json_content_type_required")]
    [InlineData("content_length",400,"invalid_content_length")]
    [InlineData("large_length",413,"request_body_too_large")]
    [InlineData("array",400,"json_object_required")]
    [InlineData("malformed",400,"invalid_json")]
    [InlineData("duplicate_origin",403,"cross_origin_request_rejected")]
    public async Task Invalid_transport_or_json_never_captures(string kind,int status,string error)
    {
        await using var f=await new Fixture().Start();
        var result=await f.Raw(kind=="array"?"[1,2]":kind=="malformed"?"{bad":Query(),c=>
        {
            if(kind=="content_type") c.Request.ContentType="text/plain";
            if(kind=="content_length") c.Request.Headers["Content-Length"]="no";
            if(kind=="large_length") c.Request.ContentLength=20000;
            if(kind=="duplicate_origin") c.Request.Headers.Origin=new Microsoft.Extensions.Primitives.StringValues(["http://example.test","http://example.test"]);
        });
        Assert.Equal(status,result.Response.StatusCode);
        var body=await JsonNode.ParseAsync(result.Response.Body,cancellationToken:TestContext.Current.CancellationToken);
        Assert.Equal(error,body!["error"]!.ToString()); Assert.Null(body["execution_id"]); Assert.Equal(0,f.Store.Captures);
    }

    [Fact] public async Task Client_supplied_access_cannot_authorize_a_query()
    {
        await using var f=await new Fixture().Start();
        using var response=await Post(f,"query","""{"contract_version":"evsearch.v1","access":{"all":true}}""");
        Assert.Equal(HttpStatusCode.UnprocessableEntity,response.StatusCode); Assert.Equal("evsearch.invalid_request",(await Body(response))["error"]!.ToString()); Assert.Equal(0,f.Store.Captures);
    }

    [Fact] public async Task Missing_published_field_denies_before_capture()
    {
        await using var f=await new Fixture().Start(); var publication=JsonNode.Parse(f.Facts.Value.Definitions[0].GetRawText())!.AsObject();
        publication["fields_json"]!.AsArray().RemoveAt(0); f.Facts.Value=f.Facts.Value with {Definitions=[JsonSerializer.SerializeToElement(publication)]};
        using var response=await Post(f,"query",Query());
        Assert.Equal(HttpStatusCode.Forbidden,response.StatusCode); Assert.Equal("evsearch.policy_denied",(await Body(response))["error"]!.ToString()); Assert.Equal(0,f.Store.Captures);
    }

    [Theory]
    [InlineData("page","revoke",403)] [InlineData("members","revoke",403)]
    [InlineData("page","publication",409)] [InlineData("members","publication",409)]
    [InlineData("members","history",503)]
    public async Task Every_read_rechecks_access_publication_and_history(string operation,string change,int status)
    {
        await using var f=await new Fixture().Start(); var first=await Start(f); var facts=f.Facts.Value;
        var request=new JsonObject { ["execution_id"]=first["execution_id"]!.DeepClone() };
        if(operation=="members") request["group_key"]=first["items"]![0]!["group_key"]!.DeepClone();
        if(change=="revoke") f.Facts.Value=facts with {ReportAssignments=[]};
        if(change=="publication")
        {
            var publication=JsonNode.Parse(facts.Definitions[0].GetRawText())!.AsObject(); publication["definition_json"]!["revision"]=2;
            f.Facts.Value=facts with {Definitions=[JsonSerializer.SerializeToElement(publication)]};
        }
        if(change=="history") f.Store.Available=false;
        using var denied=await Post(f,operation,request.ToJsonString()); Assert.Equal(status,(int)denied.StatusCode); Assert.Null((await Body(denied))["items"]);
        f.Facts.Value=facts; f.Store.Available=true;
        using var later=await Post(f,operation,request.ToJsonString()); Assert.Equal(HttpStatusCode.Gone,later.StatusCode); Assert.Equal(1,f.Store.Captures);
    }

    [Fact] public async Task Retention_and_published_member_fields_are_frozen_without_recapture()
    {
        await using var f=await new Fixture().Start();
        var publication=JsonNode.Parse(f.Facts.Value.Definitions[0].GetRawText())!.AsObject(); publication["definition_json"]!.AsObject().Remove("evsearch_columns");
        f.Facts.Value=f.Facts.Value with {Definitions=[JsonSerializer.SerializeToElement(publication)]};
        var first=await Start(f); var request=new JsonObject { ["execution_id"]=first["execution_id"]!.DeepClone(),["group_key"]=first["items"]![0]!["group_key"]!.DeepClone() };
        using var before=await Post(f,"members",request.ToJsonString()); var expected=await Body(before); Assert.Equal(HttpStatusCode.OK,before.StatusCode);
        f.Store.RetentionBoundary=Now.AddDays(-90); f.Store.Error=new InvalidOperationException("page/members must not read changing source events");
        using var after=await Post(f,"members",request.ToJsonString()); Assert.Equal(HttpStatusCode.OK,after.StatusCode); var actual=await Body(after);
        Assert.True(JsonNode.DeepEquals(expected,actual)); Assert.Equal(first["retention_boundary"]!.ToString(),actual["retention_boundary"]!.ToString());
        var member=Assert.Single(actual["items"]!.AsArray())!; Assert.Equal("unknown",member["source_payload_state"]!.ToString());
        Assert.Equal(new[]{"channel","event_id","id","time_created_utc"},member["fields"]!.AsObject().Select(p=>p.Key).Order(StringComparer.Ordinal)); Assert.Equal(1,f.Store.Captures);
    }

    [Fact] public async Task Storage_admission_failure_invalidates_execution()
    {
        await using var f=await new Fixture().Start(); var first=await Start(f); string request=new JsonObject { ["execution_id"]=first["execution_id"]!.DeepClone() }.ToJsonString();
        f.Store.AdmissionError=new EventSearchException("history_unavailable");
        using var denied=await Post(f,"page",request); Assert.Equal(HttpStatusCode.ServiceUnavailable,denied.StatusCode); Assert.Null((await Body(denied))["items"]);
        f.Store.AdmissionError=null; using var later=await Post(f,"page",request); Assert.Equal(HttpStatusCode.Gone,later.StatusCode);
    }

    [Fact] public async Task Disabled_history_rejects_new_query_without_hot_only_fallback()
    {
        await using var f=await new Fixture().Start(); f.Store.Available=false; using var response=await Post(f,"query",Query());
        Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode); var body=await Body(response); Assert.Equal("evsearch.history_unavailable",body["error"]!.ToString()); Assert.Null(body["execution_id"]); Assert.Equal(0,f.Store.Captures);
    }

    [Theory] [InlineData("rows")] [InlineData("bytes")] [InlineData("integrity")]
    public async Task Capture_failure_never_publishes_partial_execution(string kind)
    {
        await using var f=await new Fixture().Start();
        var row=new SearchEvent(1,Now.AddMinutes(-1),new string('A',64),"postgres",new JsonObject { ["id"]=1,["channel"]="Security" });
        if(kind=="rows") f.Store.Rows=Enumerable.Repeat(row,250001).ToArray();
        if(kind=="bytes") { row.Fields["channel"]=new string('x',16*1024*1024); f.Store.Rows=[row]; }
        if(kind=="integrity") f.Store.Error=new EventSearchException("storage_integrity_error");
        using var response=await Post(f,"query",Query()); Assert.Contains(response.StatusCode,new[]{HttpStatusCode.UnprocessableEntity,HttpStatusCode.ServiceUnavailable});
        var body=await Body(response); Assert.Null(body["execution_id"]); Assert.Null(body["items"]);
        // A subsequent complete query must still be usable.
        f.Store.Rows=null; f.Store.Error=null; var complete=await Start(f); Assert.NotNull(complete["execution_id"]);
    }

    [Fact] public async Task Unsupported_source_predicate_never_publishes_a_partial_capture()
    {
        await using var f=await new Fixture().Start();
        // Domain grants are already exercised by every successful query above.
        // A failed scoped capture must never publish an unfiltered result.
        f.Store.Error=new EventSearchException("history_predicate_unavailable");
        f.Facts.Value=f.Facts.Value with {ReportAssignments=[Json(new {report_key="events.explorer",effect="allow",scope_json=new {mode="restricted",clauses=new[]{new {entity_ids=new[]{7}}}},field_categories=new[]{"technical","security"},allowed_actions=new[]{"view"}})]};
        using var response=await Post(f,"query",Query()); Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);
        var body=await Body(response); Assert.Equal("evsearch.history_predicate_unavailable",body["error"]!.ToString()); Assert.Null(body["execution_id"]); Assert.Null(body["items"]);
    }

    [Fact] public async Task Concurrent_capture_is_rejected_without_publishing_partial_result()
    {
        await using var f=await new Fixture().Start();
        f.Store.CaptureEntered=new(TaskCreationOptions.RunContinuationsAsynchronously); f.Store.CaptureRelease=new(TaskCreationOptions.RunContinuationsAsynchronously);
        var first=Post(f,"query",Query()); await f.Store.CaptureEntered.Task.WaitAsync(TestContext.Current.CancellationToken);
        try
        {
            using var busy=await Post(f,"query",Query()); Assert.Equal(HttpStatusCode.UnprocessableEntity,busy.StatusCode); var body=await Body(busy);
            Assert.Equal("evsearch.snapshot_limit_exceeded",body["error"]!.ToString()); Assert.Null(body["execution_id"]); Assert.Equal(1,f.Store.Captures);
        }
        finally { f.Store.CaptureRelease.TrySetResult(); }
        using var completed=await first; Assert.Equal(HttpStatusCode.OK,completed.StatusCode); Assert.NotNull((await Body(completed))["execution_id"]);
    }
}
