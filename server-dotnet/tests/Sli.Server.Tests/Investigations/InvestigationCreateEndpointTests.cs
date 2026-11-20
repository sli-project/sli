using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
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
public sealed class InvestigationCreateEndpointTests
{
    static JsonElement J(string s)=>JsonDocument.Parse(s).RootElement.Clone();
    static AccessFacts Facts(string scope,bool report=true)=>new(false,"viewer",[],[],[J("""{"capability_key":"investigations.manage","effect":"allow","scope_json":{"kind":"all"}}""")],[],[],report?[J("{\"report_key\":\"investigations.workspace\",\"effect\":\"allow\",\"allowed_actions\":[\"view\",\"start_case\"],\"field_categories\":[],\"scope_json\":"+scope+"}")]:[],[J("""{"report_key":"investigations.workspace","version":1,"dataset_version":1,"definition_json":{"actions":["view","start_case"]},"actions_json":["view","start_case"],"fields_json":[]}""")]);
    sealed class Authentication:IPrincipalAuthenticator {public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c,CancellationToken t)=>ValueTask.FromResult(AuthenticationResult.Success(new("session",1,"viewer","alice")));}
    sealed class FactsReader(AccessFacts facts):IAccessFactsRepository {public Task<AccessFacts> LoadAsync(Principal p,CancellationToken ct)=>Task.FromResult(facts);}
    sealed class Vpn:IInvestigationVpnEvidence {public bool Allowed(AccessDecision a,long id)=>false;}
    sealed class Events:IInvestigationEventRepository
    {
        public int Reads;public long Domain=1;
        public Task<IReadOnlyList<AccessResource>> EventResourcesAsync(BigInteger id,CancellationToken ct){Reads++;return Task.FromResult<IReadOnlyList<AccessResource>>([new("domain",Domain),new("server",2),new("channel",Value:"Security")]);}
        public Task<InvestigationEventResult> AddAsync(InvestigationIdentity id,InvestigationEventInput input,string actor,CancellationToken ct)=>throw new NotSupportedException();
        public Task RemoveAsync(InvestigationIdentity id,BigInteger ev,string actor,CancellationToken ct)=>throw new NotSupportedException();
    }
    sealed class Create:IInvestigationCreateRepository
    {
        public int Calls;public InvestigationCreateInput? Input;
        public Task<JsonObject> CreateAsync(InvestigationCreateInput input,string actor,CancellationToken ct){Calls++;input.Validate();Input=input;return Task.FromResult(JsonNode.Parse("{\"id\":4,\"public_id\":\"00000000-0000-4000-8000-000000000001\",\"title\":\"Case\",\"status\":\"new\",\"owner\":null,\"created_by\":\"alice\",\"created_at\":\"2026-01-01T00:00:00Z\",\"updated_at\":\"2026-01-01T00:00:00Z\",\"closed_at\":null,\"events\":[],\"notes\":[],\"evidence_refs\":[]}")!.AsObject());}
    }
    static (DefaultHttpContext,Events,Create,ServiceProvider) Setup(string body,string scope="{\"kind\":\"all\"}",bool report=true)
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"Sli:AuthRequired","true"}}).Build();var events=new Events();var repo=new Create();
        var provider=new ServiceCollection().AddLogging().AddSingleton<IConfiguration>(config).AddSingleton(new AuthRequestPolicy(config)).AddSingleton(new TransportGate(config)).AddSingleton<IPrincipalAuthenticator>(new Authentication()).AddSingleton<IAccessFactsRepository>(new FactsReader(Facts(scope,report))).AddSingleton<IInvestigationEventRepository>(events).AddSingleton<IInvestigationCreateRepository>(repo).AddSingleton<IInvestigationVpnEvidence>(new Vpn()).BuildServiceProvider();
        var c=new DefaultHttpContext{RequestServices=provider};c.Request.Method="POST";c.Request.Scheme="https";c.Request.Path="/api/v1/investigations";c.Request.ContentType="application/json";c.Request.Body=new MemoryStream(Encoding.UTF8.GetBytes(body));c.Request.ContentLength=c.Request.Body.Length;c.Request.Headers.AcceptLanguage="en";c.Response.Body=new MemoryStream();return(c,events,repo,provider);
    }
    static JsonElement Response(DefaultHttpContext c)=>J(Encoding.UTF8.GetString(((MemoryStream)c.Response.Body).ToArray()));
    [Fact] public async Task GlobalNoAnchorReturnsFullLocalizedCase()
    {var(c,events,repo,p)=Setup("{\"title\":\"Case\"}");using(p){await InvestigationCreateEndpoints.HandleAsync(c);Assert.Equal(201,c.Response.StatusCode);Assert.Equal(0,events.Reads);Assert.Equal(1,repo.Calls);var result=Response(c);Assert.Equal("INV-0000004",result.GetProperty("case_number").GetString());Assert.Equal("New",result.GetProperty("status_message").GetProperty("text").GetString());Assert.Equal(JsonValueKind.Array,result.GetProperty("events").ValueKind);Assert.Equal(JsonValueKind.Null,result.GetProperty("anchor_event").ValueKind);}}
    [Fact] public async Task ExactCreateRouteCoexistsWithOtherInvestigationRoutes()
    {
        var(_,events,repo,provider)=Setup("{}");using(provider)
        using(var host=await new HostBuilder().ConfigureWebHost(web=>web.UseTestServer().ConfigureServices(services=>{
            services.AddRouting();services.AddLogging();services.AddSingleton(provider.GetRequiredService<IConfiguration>());services.AddSingleton(provider.GetRequiredService<AuthRequestPolicy>());services.AddSingleton(provider.GetRequiredService<TransportGate>());services.AddSingleton(provider.GetRequiredService<IPrincipalAuthenticator>());services.AddSingleton(provider.GetRequiredService<IAccessFactsRepository>());services.AddSingleton<IInvestigationEventRepository>(events);services.AddSingleton<IInvestigationCreateRepository>(repo);services.AddSingleton(provider.GetRequiredService<IInvestigationVpnEvidence>());
        }).Configure(app=>{app.UseRouting();app.UseEndpoints(routes=>{routes.MapInvestigationCreate();routes.MapInvestigationEvents();routes.MapInvestigationNoteEndpoints();routes.MapInvestigationDetail();});})).StartAsync(TestContext.Current.CancellationToken))
        using(var client=host.GetTestClient()) {
            client.BaseAddress=new Uri("https://localhost");
            using var response=await client.PostAsync("/api/v1/investigations",new StringContent("{\"title\":\"Case\"}",Encoding.UTF8,"application/json"),TestContext.Current.CancellationToken);
            Assert.Equal(System.Net.HttpStatusCode.ServiceUnavailable,response.StatusCode);Assert.Equal(0,repo.Calls);
        }
    }
    [Fact] public async Task DomainOnlyCannotCreateUnscopedCase()
    {var(c,events,repo,p)=Setup("{\"title\":\"Case\"}","{\"kind\":\"domain\",\"ids\":[1]}");using(p){await InvestigationCreateEndpoints.HandleAsync(c);Assert.Equal(404,c.Response.StatusCode);Assert.Equal(0,events.Reads);Assert.Equal(0,repo.Calls);}}
    [Fact] public async Task ExactEventNeedsOwnScope()
    {var(c,events,repo,p)=Setup("{\"title\":\"Case\",\"event_db_id\":7}","{\"kind\":\"domain\",\"ids\":[1]}");using(p){events.Domain=2;await InvestigationCreateEndpoints.HandleAsync(c);Assert.Equal(404,c.Response.StatusCode);Assert.Equal(1,events.Reads);Assert.Equal(0,repo.Calls);}}
    [Fact] public async Task ExactEventInScopeAndBodyDefaults()
    {var(c,events,repo,p)=Setup("{\"title\":\"  Case  \",\"event_db_id\":7,\"owner\":\" bob \"}","{\"kind\":\"domain\",\"ids\":[1]}");using(p){await InvestigationCreateEndpoints.HandleAsync(c);Assert.Equal(201,c.Response.StatusCode);Assert.Equal(1,events.Reads);Assert.Equal("Case",repo.Input!.Title);Assert.Equal("bob",repo.Input.Owner);Assert.Equal(new BigInteger(7),repo.Input.EventId);}}
    [Fact] public async Task ModuleDenialBeforeReadingBody()
    {var(c,events,repo,p)=Setup("not json",report:false);using(p){await InvestigationCreateEndpoints.HandleAsync(c);Assert.Equal(403,c.Response.StatusCode);Assert.Equal(0,c.Request.Body.Position);Assert.Equal(0,events.Reads);Assert.Equal(0,repo.Calls);}}
    [Fact] public async Task InvalidTitleReturnsBeforeDatabaseRepository()
    {var(c,events,repo,p)=Setup("{\"title\":\"  \"}");using(p){await InvestigationCreateEndpoints.HandleAsync(c);Assert.Equal(400,c.Response.StatusCode);Assert.Equal("invalid_title",Response(c).GetProperty("error").GetString());Assert.Equal(0,events.Reads);Assert.Equal(0,repo.Calls);}}
    [Fact] public async Task InvalidAnchorProducesSourceBadRequest()
    {var(c,events,repo,p)=Setup("{\"title\":\"Case\",\"event_db_id\":\"1e2\"}");using(p){await InvestigationCreateEndpoints.HandleAsync(c);Assert.Equal(400,c.Response.StatusCode);Assert.Equal("invalid_event_db_id",Response(c).GetProperty("error").GetString());Assert.Equal(0,events.Reads);Assert.Equal(0,repo.Calls);}}
}
