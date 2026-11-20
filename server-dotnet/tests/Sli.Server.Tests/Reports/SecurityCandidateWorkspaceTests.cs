using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Investigations;
using Sli.Server.Infrastructure;
using Sli.Server.Storage.EventReports;
using Sli.Server.Reports.SecurityCandidates;
using Xunit;

namespace Sli.Server.Tests.Reports;

public sealed partial class SecurityCandidateWorkspaceTests
{
    const string Query = "?entity_id=55&time_from=2026-01-01T00:00:00Z&time_to=2026-01-02T00:00:00Z";
    static JsonElement J(string text) => JsonDocument.Parse(text).RootElement.Clone();
    static AccessFacts Facts(string? missing = null, int reportDomain = 1, bool securityField = true, int exactDomain = 1) => new(false,"viewer",[],[],
        new[]{"objects.view","investigations.view","events.view","evidence.exact","field.security","field.technical","field.raw_evidence"}
            .Where(c => c != missing).Select(c => JsonSerializer.SerializeToElement(new {capability_key=c,effect="allow",scope_json=new {kind="domain",ids=new[]{c == "evidence.exact" ? exactDomain : 1}}})).ToArray(),[],[],
        new[]{"investigations.workspace","security.events.chains"}.Where(r => r != missing).Select(r => JsonSerializer.SerializeToElement(new {report_key=r,effect="allow",allowed_actions=new[]{"view"},field_categories=r == "security.events.chains" ? new[]{"security","technical","raw_evidence"} : securityField ? new[]{"security"} : Array.Empty<string>(),scope_json=new {kind="domain",ids=new[]{reportDomain}}})).ToArray(),
        new[]{"investigations.workspace","security.events.chains"}.Select(r => J($$"""{"report_key":"{{r}}","version":1,"dataset_version":1,"definition_json":{"actions":["view"]},"actions_json":["view"],"fields_json":[{"category":"security"},{"category":"technical"},{"category":"raw_evidence"}]}""")).ToArray());
    sealed class Authentication : IPrincipalAuthenticator
    { public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c,CancellationToken ct) => ValueTask.FromResult(AuthenticationResult.Success(new("session",1,"viewer"))); }
    sealed class FactsReader(AccessFacts facts) : IAccessFactsRepository
    { public Task<AccessFacts> LoadAsync(Principal p,CancellationToken ct) => Task.FromResult(facts); }
    sealed class Candidates : ISecurityCandidateStore
    {
        public EntityResource Entity = new(22,1,3);
        public long[] Ids = [8,7,6];
        public int Reads;
        public (long Id, long Domain, DateTimeOffset Start, DateTimeOffset End, int Count)? LastQuery;
        public Task<EntityResource?> EntityAsync(long id,CancellationToken ct) => Task.FromResult<EntityResource?>(Entity);
        public Task<IReadOnlyList<long>> CandidatesAsync(long id,long domain,DateTimeOffset start,DateTimeOffset end,int count,CancellationToken ct)
        { Reads++; LastQuery = (id, domain, start, end, count); return Task.FromResult<IReadOnlyList<long>>(Ids.Take(count).ToArray()); }
    }
    sealed class NeverConnect : IPostgresConnectionFactory
    { public Task<Npgsql.NpgsqlConnection> OpenAsync(CancellationToken ct) => throw new InvalidOperationException("unexpected_database_read"); }
    sealed class History(Candidates candidates) : IInvestigationEntityHistory, IEventReadService
    {
        public List<long> Preflights = [];
        public long[] Hydrated = [];
        public bool Incomplete, Fail, DuplicateMetadata;
        public long[] LegacyIds = [8];
        public Exception? MetadataFailure;
        public Func<long, JsonObject>? MetadataRow;
        public HashSet<long>? Permitted;
        public InvestigationWorkspaceInput? CandidateInput, MetadataInput;
        public List<string> Calls = [];
        public Task<long[]> CandidatesAsync(InvestigationWorkspaceInput input,AccessDecision access,string report,CancellationToken ct) =>
            (CandidateInput = input).From is not null && input.To is not null
                ? new InvestigationEntityHistory(new NeverConnect(),new SecurityCandidateOwner(candidates)).CandidatesAsync(input,access,report,ct)
                : Task.FromResult(LegacyIds);
        public Task<Dictionary<long,JsonObject>> DetailsAsync(long[] ids,bool exact,Func<long,CancellationToken,Task<bool>> admitted,CancellationToken ct) => throw new InvalidOperationException("unexpected_payload_hydration");
        public Task<JsonObject> RelationsAsync(long id,Func<long,CancellationToken,Task<bool>> admitted,CancellationToken ct) => throw new InvalidOperationException("unexpected_relation_read");
        public Task<IReadOnlyList<AccessResource>> ResourcesAsync(long id,CancellationToken ct)
        { Preflights.Add(id); Calls.Add("resource:" + id); return Task.FromResult<IReadOnlyList<AccessResource>>([new("domain",(Permitted is null ? id == 7 : !Permitted.Contains(id)) ? 2 : 1),new("server",3),new("channel",Value:"Security")]); }
        public Task<IReadOnlyList<JsonObject>> MetadataAsync(InvestigationWorkspaceInput input,long[] ids,CancellationToken ct)
        {
            Hydrated=ids;
            MetadataInput = input; Calls.Add("metadata");
            if(MetadataFailure is not null) throw MetadataFailure;
            if(Fail) throw new IOException("private-db-value");
            return Task.FromResult<IReadOnlyList<JsonObject>>((Incomplete ? ids.Take(1) : DuplicateMetadata ? ids.Append(ids[0]) : ids).Select(id => MetadataRow?.Invoke(id) ?? new JsonObject {
                ["event_db_id"]=id,["event_id"]=4724,["time_created_utc"]=id == 6 ? "2026-01-01T12:00:00Z" : "2026-01-01T13:00:00Z",
                ["server"]="dc.example.test",["channel"]="Security",["provider_name"]="Microsoft-Windows-Security-Auditing",
                ["subject_user_name"]="synthetic-actor",["target_user_name"]="synthetic-target"
            }).Reverse().ToArray());
        }
    }
    static (DefaultHttpContext Context,Candidates Candidates,History History,ServiceProvider Provider) Setup(AccessFacts? facts=null,string query=Query)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"Sli:AuthRequired","true"}}).Build();
        var candidates=new Candidates(); var history=new History(candidates);
        var provider=new ServiceCollection().AddLogging().AddSingleton<IConfiguration>(config)
            .AddSingleton(new AuthRequestPolicy(config)).AddSingleton(new TransportGate(config))
            .AddSingleton<IPrincipalAuthenticator>(new Authentication()).AddSingleton<IAccessFactsRepository>(new FactsReader(facts??Facts()))
            .AddSingleton<ISecurityCandidateStore>(candidates).AddSingleton<IInvestigationEntityHistory>(history).AddSingleton<IEventReadService>(history)
            .AddInvestigationWorkspace().AddInvestigationList().BuildServiceProvider();
        var context=new DefaultHttpContext{RequestServices=provider}; context.Request.Method="GET"; context.Request.Scheme="https";
        context.Request.Path="/api/v1/investigations"; context.Request.QueryString=new(query); context.Response.Body=new MemoryStream();
        return(context,candidates,history,provider);
    }
    static JsonElement Body(DefaultHttpContext context) => J(Encoding.UTF8.GetString(((MemoryStream)context.Response.Body).ToArray()));
    [Fact] public async Task ChecksEveryIdBeforeMetadataAndReturnsOnlyAuthorizedSortedHistory()
    {
        var (ctx,_,history,provider)=Setup(); using(provider) {
            await InvestigationWorkspaceEndpoints.HandleAsync(ctx);
            Assert.Equal(200,ctx.Response.StatusCode); var body=Body(ctx);
            Assert.Equal(new long[]{8,7,6},history.Preflights); Assert.Equal(new long[]{8,6},history.Hydrated);
            Assert.Equal(new[] { "resource:8", "resource:7", "resource:6", "metadata" }, history.Calls);
            var timeline=body.GetProperty("timeline"); Assert.Equal(2,timeline.GetArrayLength());
            Assert.Equal(8,timeline[0].GetProperty("event_db_id").GetInt64()); Assert.Equal(6,timeline[1].GetProperty("event_db_id").GetInt64());
            Assert.Equal("Security:Microsoft-Windows-Security-Auditing:4724.title",timeline[0].GetProperty("title_code").GetString());
            Assert.False(body.GetProperty("summary").GetProperty("has_more").GetBoolean());
        }
    }
    // Parity: exact SID/link candidates retain the selected microsecond window.
    [Fact] public async Task EntityAliasHistoryPreservesExactWindowAndIgnoresNameQuery()
    {
        var (ctx, candidates, history, provider) = Setup(query: "?entity_id=55&scope=all&q=name-must-not-be-used&time_from=2026-09-10T00:00:00.123001Z&time_to=2026-09-11T00:00:00.123999Z&timezone=Asia/Bangkok");
        using (provider)
        {
            await InvestigationWorkspaceEndpoints.HandleAsync(ctx); Assert.Equal(200, ctx.Response.StatusCode);
            var query = candidates.LastQuery!.Value;
            Assert.Equal(55, query.Id); Assert.Equal(1, query.Domain); Assert.Equal(102, query.Count);
            Assert.Equal(DateTimeOffset.Parse("2026-09-10T00:00:00.123001Z"), query.Start);
            Assert.Equal(DateTimeOffset.Parse("2026-09-11T00:00:00.123999Z"), query.End);
            foreach (var input in new[] { history.CandidateInput!, history.MetadataInput! })
            {
                Assert.Equal(55, input.Entity); Assert.Equal("2026-09-10T00:00:00.123001Z", input.From);
                Assert.Equal("2026-09-11T00:00:00.123999Z", input.To); Assert.Equal("Asia/Bangkok", input.Zone);
            }
            var body = Body(ctx); Assert.Equal("", body.GetProperty("query").GetString());
            Assert.Equal(JsonValueKind.Null, body.GetProperty("anchor_event_db_id").ValueKind);
            Assert.Equal(55, body.GetProperty("context").GetProperty("entity_id").GetInt64());
            Assert.Equal("all", body.GetProperty("scope").GetString());
            Assert.False(body.GetProperty("limits").GetProperty("full_history").GetBoolean());
            Assert.Equal("bounded_exact_entity_evidence", body.GetProperty("limits").GetProperty("coverage").GetString());
            Assert.All(body.GetProperty("timeline").EnumerateArray(), row => Assert.Contains("SID", row.GetProperty("inclusion_reason").GetString()));
        }
    }
    [Fact] public async Task HiddenCandidateCountCannotInflateEntityHistoryOrHasMore()
    {
        var (ctx, candidates, history, provider) = Setup(query: Query + "&scope=all"); using (provider)
        {
            candidates.Ids = Enumerable.Range(1, 101).Select(id => (long)id).ToArray(); history.Permitted = [1];
            await InvestigationWorkspaceEndpoints.HandleAsync(ctx); Assert.Equal(200, ctx.Response.StatusCode);
            Assert.Equal(new long[] { 1 }, history.Hydrated); var body = Body(ctx);
            Assert.Equal("all", body.GetProperty("scope").GetString()); Assert.Single(body.GetProperty("timeline").EnumerateArray());
            Assert.Equal(1, body.GetProperty("summary").GetProperty("events_returned").GetInt32());
            Assert.False(body.GetProperty("summary").GetProperty("has_more").GetBoolean());
        }
    }
    [Theory] [InlineData("evidence.exact")] [InlineData("field.security")]
    public async Task MissingExactEventPermissionCannotHydrateMetadata(string missing)
    {
        var (ctx,_,history,provider)=Setup(Facts(missing),query:"?entity_id=55"); using(provider) {
            await InvestigationWorkspaceEndpoints.HandleAsync(ctx);
            Assert.Equal(200,ctx.Response.StatusCode); Assert.Equal(new long[]{8},history.Preflights); Assert.Empty(history.Hydrated); Assert.Equal(0,Body(ctx).GetProperty("timeline").GetArrayLength());
        }
    }
    [Fact] public async Task WorkspaceGrantMustIncludeSecurityOnTheSameGrant()
    {
        var (ctx,_,history,provider)=Setup(Facts(securityField:false)); using(provider) {
            await InvestigationWorkspaceEndpoints.HandleAsync(ctx); Assert.Equal(200,ctx.Response.StatusCode); Assert.Empty(history.Hydrated);
        }
    }
    [Fact] public async Task ScopedExactPermissionIsCheckedForEveryCandidateNotJustTheEntity()
    {
        var (ctx,candidates,history,provider)=Setup(Facts(exactDomain:2)); using(provider) {
            await InvestigationWorkspaceEndpoints.HandleAsync(ctx); Assert.Equal(200,ctx.Response.StatusCode);
            Assert.Equal(1,candidates.Reads); Assert.Equal(new long[]{8,7,6},history.Preflights); Assert.Empty(history.Hydrated);
        }
    }
    [Theory] [InlineData("objects.view")] [InlineData("investigations.view")] [InlineData("investigations.workspace")]
    public async Task MissingModulePermissionDeniesBeforeCandidateRead(string missing)
    {
        var (ctx,candidates,history,provider)=Setup(Facts(missing)); using(provider) {
            await InvestigationWorkspaceEndpoints.HandleAsync(ctx); Assert.Equal(403,ctx.Response.StatusCode); Assert.Equal(0,candidates.Reads); Assert.Empty(history.Preflights);
        }
    }
    [Fact] public async Task ForeignEntityDomainReturnsIndistinguishableEmptyHistory()
    {
        var (ctx,candidates,history,provider)=Setup(); using(provider) {
            candidates.Entity=new(22,2,3); await InvestigationWorkspaceEndpoints.HandleAsync(ctx);
            Assert.Equal(200,ctx.Response.StatusCode); Assert.Equal(0,candidates.Reads); Assert.Empty(history.Hydrated); Assert.Equal(0,Body(ctx).GetProperty("timeline").GetArrayLength());
        }
    }
    [Theory] [InlineData("broken")] [InlineData("")]
    public async Task EntityCursorIsRejectedBeforeAnyCandidateOrMetadataRead(string cursor)
    {
        var (ctx,candidates,history,provider)=Setup(query:Query+"&cursor="+cursor); using(provider) {
            await InvestigationWorkspaceEndpoints.HandleAsync(ctx); Assert.Equal(400,ctx.Response.StatusCode);
            Assert.Equal("invalid_cursor",Body(ctx).GetProperty("error").GetString()); Assert.Equal(0,candidates.Reads); Assert.Empty(history.Preflights);
        }
    }
    [Theory] [InlineData(true)] [InlineData(false)]
    public async Task MissingOrFailedMetadataCannotMasqueradeAsEmptySuccess(bool incomplete)
    {
        var (ctx,_,history,provider)=Setup(); using(provider) {
            history.Incomplete=incomplete; history.Fail=!incomplete; await InvestigationWorkspaceEndpoints.HandleAsync(ctx);
            Assert.Equal(503,ctx.Response.StatusCode); Assert.Equal("unavailable",Body(ctx).GetProperty("error").GetString()); Assert.DoesNotContain("private-db-value",Body(ctx).GetRawText());
        }
    }
    [Fact] public async Task MoreThanOneHundredAuthorizedEventsAreBoundedAndMarkedHasMore()
    {
        var (ctx,candidates,history,provider)=Setup(); using(provider) {
            candidates.Ids=Enumerable.Range(1,101).Select(i=>(long)i+100).ToArray(); await InvestigationWorkspaceEndpoints.HandleAsync(ctx);
            Assert.Equal(200,ctx.Response.StatusCode); Assert.Equal(101,history.Hydrated.Length);
            Assert.Equal(100,Body(ctx).GetProperty("timeline").GetArrayLength()); Assert.True(Body(ctx).GetProperty("summary").GetProperty("has_more").GetBoolean());
        }
    }
    [Fact] public async Task HiddenExtraCandidateDoesNotLeakHasMore()
    {
        var (ctx,candidates,_,provider)=Setup(); using(provider) {
            candidates.Ids=Enumerable.Range(100,100).Select(i=>(long)i).Append(7).ToArray();
            await InvestigationWorkspaceEndpoints.HandleAsync(ctx); Assert.Equal(200,ctx.Response.StatusCode);
            Assert.Equal(100,Body(ctx).GetProperty("timeline").GetArrayLength()); Assert.False(Body(ctx).GetProperty("summary").GetProperty("has_more").GetBoolean());
        }
    }
    [Fact] public async Task DuplicateCandidatesAreHydratedOnlyOnce()
    {
        var (ctx,candidates,history,provider)=Setup(); using(provider) {
            candidates.Ids=[8,8,6]; await InvestigationWorkspaceEndpoints.HandleAsync(ctx);
            Assert.Equal(200,ctx.Response.StatusCode); Assert.Equal(new long[]{8,6},history.Hydrated); Assert.Equal(2,Body(ctx).GetProperty("timeline").GetArrayLength());
        }
    }
    [Fact] public async Task DuplicateMetadataIsUnavailable()
    {
        var (ctx,_,history,provider)=Setup(); using(provider) {
            history.DuplicateMetadata=true; await InvestigationWorkspaceEndpoints.HandleAsync(ctx);
            Assert.Equal(503,ctx.Response.StatusCode); Assert.Equal("unavailable",Body(ctx).GetProperty("error").GetString());
        }
    }
    [Theory] [InlineData(0L)] [InlineData(-1L)]
    public async Task InvalidCandidateIsRejectedBeforeResourceOrMetadataRead(long id)
    {
        var (ctx,candidates,history,provider)=Setup(); using(provider) {
            candidates.Ids=[8,id]; await InvestigationWorkspaceEndpoints.HandleAsync(ctx);
            Assert.Equal(503,ctx.Response.StatusCode); Assert.Equal("unavailable",Body(ctx).GetProperty("error").GetString());
            Assert.Empty(history.Preflights); Assert.Empty(history.Hydrated);
        }
    }
    [Theory]
    [InlineData("?entity_id=", "invalid_entity_id")]
    [InlineData("?event_db_id=", "invalid_event_db_id")]
    [InlineData("?entity_id=55&time_from=2026-01-01&time_to=2026-02-02", "security_events_period_too_wide")]
    public async Task UnifiedWorkspaceRetainsCandidateValidation(string query,string error)
    {
        var (ctx,candidates,history,provider)=Setup(query:query); using(provider) {
            await InvestigationWorkspaceEndpoints.HandleAsync(ctx);
            Assert.Equal(400,ctx.Response.StatusCode); Assert.Equal(error,Body(ctx).GetProperty("error").GetString());
            Assert.Equal(0,candidates.Reads); Assert.Empty(history.Preflights); Assert.Empty(history.Hydrated);
        }
    }
    [Fact] public async Task MissingTimeBoundsUsesExactLinksInsteadOfGlobalSecurityFeed()
    {
        var (ctx,candidates,history,provider)=Setup(query:"?entity_id=55"); using(provider) {
            await InvestigationWorkspaceEndpoints.HandleAsync(ctx); Assert.Equal(200,ctx.Response.StatusCode); Assert.Equal(0,candidates.Reads); Assert.Equal(new long[]{8},history.Hydrated);
        }
    }
    [Fact] public async Task RegisteredWorkspaceGetRouteIsDisabledBeforeCandidateReads()
    {
        var (_,candidates,history,provider)=Setup(); using(provider)
        using(var host=await new HostBuilder().ConfigureWebHost(web=>web.UseTestServer().ConfigureServices(services=> {
            services.AddRouting(); services.AddLogging();
            services.AddSingleton(provider.GetRequiredService<IConfiguration>());
            services.AddSingleton(provider.GetRequiredService<AuthRequestPolicy>());
            services.AddSingleton(provider.GetRequiredService<TransportGate>());
            services.AddSingleton(provider.GetRequiredService<IPrincipalAuthenticator>());
            services.AddSingleton(provider.GetRequiredService<IAccessFactsRepository>());
            services.AddSingleton<ISecurityCandidateStore>(candidates); services.AddSingleton<IInvestigationEntityHistory>(history).AddSingleton<IEventReadService>(history);
            services.AddInvestigationWorkspace(); services.AddInvestigationList();
        }).Configure(app=> {app.UseRouting();app.UseEndpoints(endpoints=>{endpoints.MapInvestigationWorkspace();endpoints.MapInvestigationList();});})).StartAsync(TestContext.Current.CancellationToken))
        using(var client=host.GetTestClient()) {
            using var response=await client.GetAsync("/api/v1/investigations"+Query,TestContext.Current.CancellationToken);
            Assert.Equal(System.Net.HttpStatusCode.ServiceUnavailable,response.StatusCode);
            using var body=JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            Assert.Equal("module_disabled",body.RootElement.GetProperty("error").GetString());
            Assert.Equal(0,candidates.Reads); Assert.Empty(history.Preflights); Assert.Empty(history.Hydrated);
        }
    }
    [Theory]
    [InlineData("2026-01-01","2026-01-01","Asia/Bangkok","2025-12-31T17:00:00Z","2026-01-01T17:00:00Z")]
    [InlineData("2026-01-01T03:00:00+03:00","2026-01-02T03:00:00+03:00","UTC","2026-01-01T00:00:00Z","2026-01-02T00:00:00Z")]
    public void NormalizesPeriodLikeTheFrozenTimeContract(string from,string to,string zone,string expectedStart,string expectedEnd)
    {
        var input=new InvestigationWorkspaceInput(null,55,"",null,from,to,zone,null).Normalize();
        var start=DateTimeOffset.Parse(input.From!); var end=DateTimeOffset.Parse(input.To!);
        Assert.Equal(DateTimeOffset.Parse(expectedStart),start); Assert.Equal(DateTimeOffset.Parse(expectedEnd),end);
    }
    [Theory]
    [InlineData("2026-11-01T01:30:00","2026-11-01T04:00:00","America/New_York","ambiguous_local_datetime_requires_offset")]
    [InlineData("2026-03-08T02:30:00","2026-03-08T04:00:00","America/New_York","nonexistent_local_datetime")]
    [InlineData("2026-01-02","2026-01-01","UTC","empty_or_reversed_time_range")]
    [InlineData("bad","2026-01-01","UTC","invalid_datetime")]
    [InlineData("2026-01-01","2026-01-02","Invalid/Zone","invalid_timezone")]
    public void RejectsInvalidPeriods(string from,string to,string zone,string error)
    {Assert.Equal(error,Assert.Throws<InvestigationException>(()=>new InvestigationWorkspaceInput(null,55,"",null,from,to,zone,null).Normalize()).Code);}
}
