using System.Numerics;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Investigations;
using Xunit;
namespace Sli.Server.Tests.Investigations;
public sealed class InvestigationEventEndpointTests
{
    static JsonElement J(string s)=>JsonDocument.Parse(s).RootElement.Clone();
    static AccessFacts Facts(bool report=true,bool capability=true)=>new(false,"viewer",[],[],capability?[J("""{"capability_key":"investigations.manage","effect":"allow","scope_json":{"kind":"all"}}""")]:[],[],[],report?[J("""{"report_key":"investigations.workspace","effect":"allow","allowed_actions":["view","start_case"],"field_categories":[],"scope_json":{"kind":"domain","ids":[1]}}""")]:[],[J("""{"report_key":"investigations.workspace","version":1,"dataset_version":1,"definition_json":{"actions":["view","start_case"]},"actions_json":["view","start_case"],"fields_json":[]}""")]);
    sealed class Authentication:IPrincipalAuthenticator {public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c,CancellationToken t)=>ValueTask.FromResult(AuthenticationResult.Success(new("session",1,"viewer")));}
    sealed class FactsReader(AccessFacts facts):IAccessFactsRepository {public Task<AccessFacts> LoadAsync(Principal p,CancellationToken ct)=>Task.FromResult(facts);}
    sealed class Cases:IInvestigationRepository
    {
        public long Domain=1;public int Reads;
        public Task<IReadOnlyList<IReadOnlyList<AccessResource>>> ResourceGroupsAsync(InvestigationIdentity id,CancellationToken ct){Reads++;return Task.FromResult<IReadOnlyList<IReadOnlyList<AccessResource>>>([[new("domain",Domain)]]);}
        public Task<InvestigationNote> AddNoteAsync(InvestigationIdentity id,string body,string actor,CancellationToken ct)=>throw new NotSupportedException();
    }
    sealed class Events:IInvestigationEventRepository
    {
        public long Domain=1;public int Reads,Adds,Removes;public BigInteger EventId;public bool Replay;
        public Task<IReadOnlyList<AccessResource>> EventResourcesAsync(BigInteger id,CancellationToken ct){Reads++;return Task.FromResult<IReadOnlyList<AccessResource>>([new("domain",Domain),new("server",2),new("channel",Value:"Security")]);}
        public Task<InvestigationEventResult> AddAsync(InvestigationIdentity id,InvestigationEventInput input,string actor,CancellationToken ct){Adds++;EventId=input.EventId;return Task.FromResult(new InvestigationEventResult(new((long)input.EventId,input.Relation,actor,"2026-01-01 00:00:00+00:00"),Replay));}
        public Task RemoveAsync(InvestigationIdentity id,BigInteger eventId,string actor,CancellationToken ct){Removes++;EventId=eventId;return Task.CompletedTask;}
    }
    static (DefaultHttpContext,Cases,Events,ServiceProvider) Setup(string path,string body,bool report=true,bool capability=true)
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"Sli:AuthRequired","true"}}).Build();var cases=new Cases();var events=new Events();
        var provider=new ServiceCollection().AddLogging().AddSingleton<IConfiguration>(config).AddSingleton(new AuthRequestPolicy(config)).AddSingleton(new TransportGate(config)).AddSingleton<IPrincipalAuthenticator>(new Authentication()).AddSingleton<IAccessFactsRepository>(new FactsReader(Facts(report,capability))).AddSingleton<IInvestigationRepository>(cases).AddSingleton<IInvestigationEventRepository>(events).BuildServiceProvider();
        var ctx=new DefaultHttpContext{RequestServices=provider};ctx.Request.Method="POST";ctx.Request.Scheme="https";ctx.Request.Path=path;ctx.Request.ContentType="application/json";ctx.Request.Body=new MemoryStream(Encoding.UTF8.GetBytes(body));ctx.Request.ContentLength=ctx.Request.Body.Length;ctx.Response.Body=new MemoryStream();return(ctx,cases,events,provider);
    }
    static JsonElement Response(DefaultHttpContext c)=>J(Encoding.UTF8.GetString(((MemoryStream)c.Response.Body).ToArray()));
    [Fact] public async Task AddAuthorizedExactEventReturnsSourceShape()
    {var(c,_,events,p)=Setup("/api/v1/investigations/4/events","{\"event_db_id\":7}");using(p){await InvestigationEventEndpoints.AddAsync(c);Assert.Equal(201,c.Response.StatusCode);Assert.Equal(1,events.Adds);Assert.Equal(7,Response(c).GetProperty("event").GetProperty("event_db_id").GetInt64());Assert.False(Response(c).GetProperty("event").TryGetProperty("idempotent_replay",out _));}}
    [Fact] public async Task BothRoutesResolveAlongsideExistingInvestigationRoutes()
    {
        var(_,cases,events,provider)=Setup("/api/v1/investigations/4/events","{}");using(provider)
        using(var host=await new HostBuilder().ConfigureWebHost(web=>web.UseTestServer().ConfigureServices(services=>{
            services.AddRouting();services.AddLogging();services.AddSingleton(provider.GetRequiredService<IConfiguration>());services.AddSingleton(provider.GetRequiredService<AuthRequestPolicy>());services.AddSingleton(provider.GetRequiredService<TransportGate>());services.AddSingleton(provider.GetRequiredService<IPrincipalAuthenticator>());services.AddSingleton(provider.GetRequiredService<IAccessFactsRepository>());services.AddSingleton<IInvestigationRepository>(cases);services.AddSingleton<IInvestigationEventRepository>(events);
        }).Configure(app=>{app.UseRouting();app.UseEndpoints(routes=>{routes.MapInvestigationEvents();routes.MapInvestigationNoteEndpoints();routes.MapInvestigationDetail();});})).StartAsync(TestContext.Current.CancellationToken))
        using(var client=host.GetTestClient()) {
            client.BaseAddress=new Uri("https://localhost");
            using var add=await client.PostAsync("/api/v1/investigations/4/events",new StringContent("{\"event_db_id\":7}",Encoding.UTF8,"application/json"),TestContext.Current.CancellationToken);
            using var remove=await client.PostAsync("/api/v1/investigations/4/events/remove",new StringContent("{\"event_db_id\":7}",Encoding.UTF8,"application/json"),TestContext.Current.CancellationToken);
            Assert.Equal(System.Net.HttpStatusCode.ServiceUnavailable,add.StatusCode);Assert.Equal(System.Net.HttpStatusCode.ServiceUnavailable,remove.StatusCode);Assert.Equal(0,events.Adds);Assert.Equal(0,events.Removes);
        }
    }
    [Fact] public async Task AddReplayReturnsSourceReplayFlag()
    {var(c,_,events,p)=Setup("/api/v1/investigations/4/events","{\"event_db_id\":7}");using(p){events.Replay=true;await InvestigationEventEndpoints.AddAsync(c);Assert.Equal(201,c.Response.StatusCode);Assert.True(Response(c).GetProperty("event").GetProperty("idempotent_replay").GetBoolean());}}
    [Fact] public async Task AddDeniesOutOfScopeEventBeforeMutation()
    {var(c,_,events,p)=Setup("/api/v1/investigations/4/events","{\"event_db_id\":7}");using(p){events.Domain=2;await InvestigationEventEndpoints.AddAsync(c);Assert.Equal(404,c.Response.StatusCode);Assert.Equal(0,events.Adds);}}
    [Fact] public async Task RemoveChecksCaseBeforeBodyAndDoesNotLookupOtherEvent()
    {var(c,cases,events,p)=Setup("/api/v1/investigations/4/events/remove","not json");using(p){cases.Domain=2;await InvestigationEventEndpoints.RemoveAsync(c);Assert.Equal(404,c.Response.StatusCode);Assert.Equal(0,events.Reads);Assert.Equal(0,events.Removes);Assert.Equal(0,c.Request.Body.Position);}}
    [Fact] public async Task RemoveAuthorizedReturnsExactEventShape()
    {var(c,_,events,p)=Setup("/api/v1/investigations/4/events/remove","{\"event_db_id\":7}");using(p){await InvestigationEventEndpoints.RemoveAsync(c);Assert.Equal(200,c.Response.StatusCode);Assert.Equal(1,events.Removes);Assert.Equal(0,events.Reads);Assert.Equal(7,Response(c).GetProperty("event").GetProperty("event_db_id").GetInt64());}}
    [Fact] public async Task AddParsesEventIdBeforeResolvingCaseIdentity()
    {var(c,cases,events,p)=Setup("/api/v1/investigations/not-uuid/events","{\"event_db_id\":null}");using(p){await InvestigationEventEndpoints.AddAsync(c);Assert.Equal(400,c.Response.StatusCode);Assert.Equal("invalid_event_db_id",Response(c).GetProperty("error").GetString());Assert.Equal(0,cases.Reads);Assert.Equal(0,events.Reads);}}
    [Theory] [InlineData(false,true,"report_not_assigned")] [InlineData(true,false,"report_not_assigned")]
    public async Task ModuleDenialPrecedesBodyAndDatabase(bool report,bool capability,string error)
    {var(c,cases,events,p)=Setup("/api/v1/investigations/4/events","not json",report,capability);using(p){await InvestigationEventEndpoints.AddAsync(c);Assert.Equal(403,c.Response.StatusCode);Assert.Equal(error,Response(c).GetProperty("error").GetString());Assert.Equal(0,cases.Reads);Assert.Equal(0,events.Reads);Assert.Equal(0,c.Request.Body.Position);}}
}
