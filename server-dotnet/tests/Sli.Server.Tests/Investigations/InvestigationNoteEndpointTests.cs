using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Investigations;
using Xunit;

namespace Sli.Server.Tests.Investigations;

public sealed class InvestigationNoteEndpointTests
{
    static JsonElement J(string value) => JsonDocument.Parse(value).RootElement.Clone();
    static AccessFacts Facts(string scope = "{\"kind\":\"all\"}", bool assigned = true, string[]? policies = null) => new(false,"viewer", [],[],
        (policies ?? ["{\"capability_key\":\"investigations.manage\",\"effect\":\"allow\",\"scope_json\":{\"kind\":\"all\"}}"] ).Select(J).ToArray(),[],[],
        assigned ? [J("{\"report_key\":\"investigations.workspace\",\"effect\":\"allow\",\"allowed_actions\":[\"view\",\"start_case\"],\"field_categories\":[],\"scope_json\":"+scope+"}")] : [],
        [J("""{"report_key":"investigations.workspace","version":1,"dataset_version":1,"definition_json":{"actions":["view","start_case"]},"actions_json":["view","start_case"],"fields_json":[]}""")]);

    sealed class Authentication(AuthenticationResult result) : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct) => ValueTask.FromResult(result);
    }
    sealed class FactsReader(AccessFacts facts) : IAccessFactsRepository
    {
        public int Reads;
        public Task<AccessFacts> LoadAsync(Principal principal,CancellationToken ct) { Reads++; return Task.FromResult(facts); }
    }
    sealed class Repository : IInvestigationRepository, IInvestigationCaseMutationRepository, IInvestigationVpnEvidence
    {
        public IReadOnlyList<IReadOnlyList<AccessResource>> Groups = [[new("server",2),new("domain",1),new("channel",Value:"Security")]];
        public int Reads, Writes;
        public string? Body, Actor;
        public Exception? ReadError, WriteError;
        public CancellationToken MutationToken;
        public Task<IReadOnlyList<IReadOnlyList<AccessResource>>> ResourceGroupsAsync(InvestigationIdentity identity,CancellationToken ct)
        { Reads++; if(ReadError is not null) throw ReadError; return Task.FromResult(Groups); }
        public Task<InvestigationCaseMutationResult> ApplyAsync(InvestigationIdentity identity,InvestigationCaseMutationInput input,string actor,CancellationToken ct)
        {
            Writes++; if(WriteError is not null) throw WriteError;
            var row=System.Text.Json.Nodes.JsonNode.Parse("""{"id":12,"public_id":null,"title":"T","status":"active","owner":"alice","created_by":"analyst","created_at":"2026-01-01T00:00:00+00:00","updated_at":"2026-01-01T00:00:00+00:00","closed_at":null,"events":[],"notes":[],"evidence_refs":[]}""")!.AsObject();
            row[input.Operation]=input.Value;return Task.FromResult(new InvestigationCaseMutationResult(row,true));
        }
        public bool Allowed(AccessDecision access,long domainId)=>true;
        public Task<InvestigationNote> AddNoteAsync(InvestigationIdentity identity,string body,string actor,CancellationToken ct)
        { Writes++; Body=body; Actor=actor; MutationToken=ct; if(WriteError is not null) throw WriteError; return Task.FromResult(new InvestigationNote(41,body,actor,"2026-11-05 01:02:03.123456+00:00")); }
    }
    sealed class ObservedBody(byte[] bytes) : MemoryStream(bytes)
    {
        public int Reads;
        public override ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken ct=default) { Reads++; return base.ReadAsync(buffer,ct); }
    }
    static (DefaultHttpContext Context, FactsReader Facts, Repository Repository, ObservedBody Body, ServiceProvider Provider) Setup(
        string body="{\"body\":\" note \"}",AccessFacts? facts=null,AuthenticationResult? auth=null,string path="/api/v1/investigations/12/notes")
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"Sli:AuthRequired","true"}}).Build();
        var reader=new FactsReader(facts??Facts()); var repository=new Repository();
        var services=new ServiceCollection().AddLogging().AddSingleton<IConfiguration>(config).AddSingleton(new AuthRequestPolicy(config))
            .AddSingleton(new TransportGate(config)).AddSingleton<IPrincipalAuthenticator>(new Authentication(auth??AuthenticationResult.Success(new("session",7,"viewer",Username:"analyst"))))
            .AddSingleton<IAccessFactsRepository>(reader).AddSingleton<IInvestigationRepository>(repository).AddSingleton<IInvestigationCaseMutationRepository>(repository).AddSingleton<IInvestigationVpnEvidence>(repository).BuildServiceProvider();
        var context=new DefaultHttpContext{RequestServices=services};
        context.Request.Method="POST"; context.Request.Path=path; context.Request.Scheme="https"; context.Request.Host=new("sli.invalid");
        var observed=new ObservedBody(Encoding.UTF8.GetBytes(body)); context.Request.Body=observed; context.Request.ContentLength=observed.Length; context.Request.ContentType="application/json";
        context.Response.Body=new MemoryStream();
        return(context,reader,repository,observed,services);
    }
    static JsonElement Response(DefaultHttpContext context)=>J(Encoding.UTF8.GetString(((MemoryStream)context.Response.Body).ToArray()));

    [Theory]
    [InlineData("{\"body\":[\"\\ud800\"]}", "['\\ud800']")]
    [InlineData("{\"body\":{\"a\":1,\"b\":2,\"a\":3}}", "{'a': 3, 'b': 2}")]
    public async Task ReviewedCoercionCasesReachNoteWriteAndReturnCreated(string body,string expected)
    {
        var state=Setup(body); using var provider=state.Provider;
        await InvestigationEndpoints.HandleNoteAsync(state.Context);
        Assert.Equal(201,state.Context.Response.StatusCode); Assert.Equal(1,state.Repository.Writes);
        Assert.Equal(expected,state.Repository.Body);
        Assert.Equal(expected,Response(state.Context).GetProperty("note").GetProperty("body").GetString());
    }

    [Fact]
    public async Task RegisteredPostRouteExecutesThroughInProcessHttpPipeline()
    {
        var state=Setup(); using var provider=state.Provider;
        using var host=await new HostBuilder().ConfigureWebHost(web=>web.UseTestServer().ConfigureServices(services=>
        {
            services.AddRouting(); services.AddLogging();
            services.AddSingleton(provider.GetRequiredService<IConfiguration>());
            services.AddSingleton(provider.GetRequiredService<AuthRequestPolicy>());
            services.AddSingleton(provider.GetRequiredService<TransportGate>());
            services.AddSingleton(provider.GetRequiredService<IPrincipalAuthenticator>());
            services.AddSingleton<IAccessFactsRepository>(state.Facts);
            services.AddSingleton<IInvestigationRepository>(state.Repository);
        }).Configure(app=>
        {
            app.UseRouting(); app.UseEndpoints(endpoints=>endpoints.MapInvestigationNoteEndpoints());
        })).StartAsync(TestContext.Current.CancellationToken);
        using var client=host.GetTestClient();
        using var response=await client.PostAsync("/api/v1/investigations/12/notes",new StringContent("{\"body\":\" note \"}",Encoding.UTF8,"application/json"),TestContext.Current.CancellationToken);
        Assert.Equal(System.Net.HttpStatusCode.ServiceUnavailable,response.StatusCode);
        Assert.Null(state.Repository.Body); Assert.Equal(0,state.Repository.Reads); Assert.Equal(0,state.Repository.Writes);
    }

    [Fact]
    public async Task AuthenticationAndRoleRejectBeforeModuleRepositoryOrBody()
    {
        foreach(var result in new[]{AuthenticationResult.Denied(401,"authentication_required"),AuthenticationResult.Success(new("session",7,"report_reader"))})
        {
            var state=Setup("{",auth:result); using var provider=state.Provider;
            await InvestigationEndpoints.HandleNoteAsync(state.Context);
            Assert.Equal(result.Succeeded?403:401,state.Context.Response.StatusCode);
            Assert.Equal(0,state.Facts.Reads); Assert.Equal(0,state.Repository.Reads); Assert.Equal(0,state.Body.Reads);
        }
    }
    [Fact]
    public async Task OriginRejectsBeforeAuthenticationModuleOrBody()
    {
        var state=Setup("{"); using var provider=state.Provider; state.Context.Request.Headers.Origin="https://other.invalid";
        await InvestigationEndpoints.HandleNoteAsync(state.Context);
        Assert.Equal(403,state.Context.Response.StatusCode); Assert.Equal("cross_origin_request_rejected",Response(state.Context).GetProperty("error").GetString());
        Assert.Equal(0,state.Facts.Reads); Assert.Equal(0,state.Body.Reads);
    }
    [Fact]
    public async Task ModuleBeforeInvalidIdentityAndBody()
    {
        var state=Setup("{",Facts(assigned:false),path:"/api/v1/investigations/nope/notes"); using var provider=state.Provider;
        await InvestigationEndpoints.HandleNoteAsync(state.Context);
        Assert.Equal(403,state.Context.Response.StatusCode); Assert.Equal("report_not_assigned",Response(state.Context).GetProperty("error").GetString());
        Assert.Equal(0,state.Repository.Reads); Assert.Equal(0,state.Body.Reads);
    }
    [Fact]
    public async Task MissingCaseScopeDenyAndUnresolvedLinkedEvidencePrecedeMalformedBody()
    {
        for(int vector=0;vector<4;vector++)
        {
            var state=Setup("{",Facts("{\"kind\":\"domain\",\"ids\":[1]}")); using var provider=state.Provider;
            if(vector==0) state.Repository.ReadError=new InvestigationException("not_found","Investigation 12 was not found",404);
            if(vector==1) state.Repository.Groups=[[new("domain",1)],[new("domain",9)]];
            if(vector==2) state.Repository.Groups=[[]];
            if(vector==3) state.Repository.Groups=[]; // Scoped report cannot cover an evidence-free case.
            await InvestigationEndpoints.HandleNoteAsync(state.Context);
            Assert.Equal(404,state.Context.Response.StatusCode); Assert.Equal("not_found",Response(state.Context).GetProperty("error").GetString());
            Assert.Equal(vector==0?"Investigation 12 was not found":"Investigation resource was not found",Response(state.Context).GetProperty("message").GetString());
            Assert.Equal(0,state.Body.Reads); Assert.Equal(0,state.Repository.Writes);
        }
    }
    [Fact]
    public async Task AllGroupsIncludeTypedEvidenceAndScopedDenyOverridesPackageLikeGlobalAllow()
    {
        var policies=new[]{"""{"capability_key":"investigations.manage","effect":"allow","scope_json":{"kind":"all"}}""",
            """{"capability_key":"investigations.manage","effect":"deny","scope_json":{"kind":"server","ids":[2]}}"""};
        var state=Setup("{",Facts(policies:policies)); using var provider=state.Provider;
        await InvestigationEndpoints.HandleNoteAsync(state.Context);
        Assert.Equal(404,state.Context.Response.StatusCode); Assert.Equal(0,state.Body.Reads);
    }
    [Theory]
    [InlineData("{",400,"invalid_json")]
    [InlineData("{\"body\":false}",400,"invalid_note")]
    [InlineData("{\"body\":\"  \"}",400,"invalid_note")]
    public async Task BodyValidationOnlyAfterSuccessfulPreflight(string body,int status,string error)
    {
        var state=Setup(body); using var provider=state.Provider;
        await InvestigationEndpoints.HandleNoteAsync(state.Context);
        Assert.Equal(status,state.Context.Response.StatusCode); Assert.Equal(error,Response(state.Context).GetProperty("error").GetString());
        Assert.Equal(1,state.Repository.Reads); Assert.True(state.Body.Reads>0); Assert.Equal(0,state.Repository.Writes);
    }
    [Fact]
    public async Task SuccessCarriesActorNoteAndSourceTimestampAndMutationFailureNeverSucceeds()
    {
        foreach(bool fail in new[]{false,true})
        {
            var state=Setup(); using var provider=state.Provider;
            if(fail) state.Repository.WriteError=new InvalidOperationException("private-db-value");
            await InvestigationEndpoints.HandleNoteAsync(state.Context);
            Assert.Equal(fail?500:201,state.Context.Response.StatusCode); Assert.Equal("note",state.Repository.Body); Assert.Equal("analyst",state.Repository.Actor);
            Assert.False(state.Repository.MutationToken.CanBeCanceled);
            if(!fail) { var row=Response(state.Context); Assert.Equal("ok",row.GetProperty("status").GetString()); Assert.Equal("2026-11-05 01:02:03.123456+00:00",row.GetProperty("note").GetProperty("created_at").GetString()); }
            else Assert.DoesNotContain("private-db-value",Response(state.Context).GetRawText());
        }
    }
    [Fact]
    public async Task StatusRouteIsRegisteredAndAppliesCaseAuthorizationBeforeBody()
    {
        var state=Setup("{", facts:Facts(assigned:false), path:"/api/v1/investigations/12/status"); using var provider=state.Provider;
        using var host=await new HostBuilder().ConfigureWebHost(web=>web.UseTestServer().ConfigureServices(services=>
        {
            services.AddRouting(); services.AddLogging();
            services.AddSingleton(provider.GetRequiredService<IConfiguration>());
            services.AddSingleton(provider.GetRequiredService<AuthRequestPolicy>());
            services.AddSingleton(provider.GetRequiredService<TransportGate>());
            services.AddSingleton(provider.GetRequiredService<IPrincipalAuthenticator>());
            services.AddSingleton<IAccessFactsRepository>(state.Facts);
            services.AddSingleton<IInvestigationRepository>(state.Repository);
        }).Configure(app=> { app.UseRouting(); app.UseEndpoints(endpoints=>endpoints.MapInvestigationNoteEndpoints()); })).StartAsync(TestContext.Current.CancellationToken);
        using var client=host.GetTestClient();
        using var response=await client.PostAsync("/api/v1/investigations/12/status",new StringContent("{",Encoding.UTF8,"application/json"),TestContext.Current.CancellationToken);
        Assert.Equal(System.Net.HttpStatusCode.Forbidden,response.StatusCode);
        Assert.Equal(0,state.Repository.Reads);
    }
    [Theory]
    [InlineData("status", "{\"status\":\"active\"}")]
    [InlineData("owner", "{\"owner\":\"alice\"}")]
    public async Task ReplayReturnsNormalCaseResponseByRootRuling(string operation,string body)
    {
        var state=Setup(body,path:"/api/v1/investigations/12/"+operation);using var provider=state.Provider;
        await InvestigationEndpoints.HandleCaseMutationAsync(state.Context);
        Assert.Equal(200,state.Context.Response.StatusCode);Assert.Equal(1,state.Repository.Writes);
        var result=Response(state.Context);Assert.Equal("INV-0000012",result.GetProperty("case_number").GetString());
        Assert.False(result.TryGetProperty("idempotent_replay",out _));Assert.Equal("v1",result.GetProperty("api_version").GetString());
    }
    [Fact]
    public async Task ScopeDenialHappensBeforeStatusBodyRead()
    {
        var state=Setup("{",facts:Facts("{\"kind\":\"domain\",\"ids\":[99]}"),path:"/api/v1/investigations/12/status");using var provider=state.Provider;
        await InvestigationEndpoints.HandleCaseMutationAsync(state.Context);
        Assert.Equal(404,state.Context.Response.StatusCode);Assert.Equal(0,state.Body.Reads);Assert.Equal(0,state.Repository.Writes);
    }
    [Fact]
    public async Task StatusMutationFailureCannotReturnSuccess()
    {
        var state=Setup("{\"status\":\"active\"}",path:"/api/v1/investigations/12/status");using var provider=state.Provider;
        state.Repository.WriteError=new InvalidOperationException("private database detail");
        await InvestigationEndpoints.HandleCaseMutationAsync(state.Context);
        Assert.Equal(500,state.Context.Response.StatusCode);
        Assert.DoesNotContain("private database detail",Encoding.UTF8.GetString(((MemoryStream)state.Context.Response.Body).ToArray()));
    }
}
