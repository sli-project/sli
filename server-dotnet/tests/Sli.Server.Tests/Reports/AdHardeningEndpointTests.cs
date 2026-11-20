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
using Sli.Server.Reports;
using Xunit;

namespace Sli.Server.Tests.Reports;

public class AdHardeningEndpointTests
{
    static JsonElement J(string json)=>JsonDocument.Parse(json).RootElement.Clone();
    static AccessFacts Facts(bool assigned=true,bool identity=true)=>new(false,"viewer",[],[],(identity?new[]{J("""{"capability_key":"field.identity_basic","effect":"allow","scope_json":{"kind":"all"}}""")}:[]).Append(J("""{"capability_key":"field.security","effect":"allow","scope_json":{"kind":"all"}}""")).ToArray(),[],[],
        assigned?[J("""{"report_key":"security.queue","effect":"allow","allowed_actions":["view"],"field_categories":["security","identity_basic","technical"],"scope_json":{"kind":"domain","ids":[7]}}""")]:[],
        [J("""{"report_key":"security.queue","version":1,"dataset_version":1,"definition_json":{"actions":["view"]},"actions_json":["view"],"fields_json":[{"category":"security"},{"category":"identity_basic"},{"category":"technical"}]}""")]);
    sealed class Authentication(bool success=true):IPrincipalAuthenticator{public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c,CancellationToken ct)=>ValueTask.FromResult(success?AuthenticationResult.Success(new("session",1,"viewer")):AuthenticationResult.Denied(401,"authentication_required"));}
    sealed class FactsReader(AccessFacts facts):IAccessFactsRepository{public Task<AccessFacts> LoadAsync(Principal p,CancellationToken ct)=>Task.FromResult(facts);}
    sealed class Source:IAdHardeningSource
    {
        internal int Calls;internal long[]? Domains;internal bool Fail;
        public Task<AdHardeningSnapshots> LoadAsync(long[]? domains,CancellationToken ct){Calls++;Domains=domains;if(Fail)throw new InvalidOperationException("private-fixture");return Task.FromResult(new AdHardeningSnapshots(domains is {Length:0}?[]:[AdHardeningSourceTests.Snapshot()],false));}
    }
    static (DefaultHttpContext Context,Source Source,ServiceProvider Provider) Setup(AccessFacts? facts=null,string query="?tab=ad-hardening",bool authenticated=true)
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"Sli:AuthRequired","true"}}).Build();var source=new Source();var provider=new ServiceCollection().AddLogging().AddSingleton<IConfiguration>(config).AddSingleton(new AuthRequestPolicy(config)).AddSingleton(new TransportGate(config)).AddSingleton<IPrincipalAuthenticator>(new Authentication(authenticated)).AddSingleton<IAccessFactsRepository>(new FactsReader(facts??Facts())).AddSingleton<IAdHardeningSource>(source).BuildServiceProvider();var context=new DefaultHttpContext{RequestServices=provider};context.Request.Method="GET";context.Request.Scheme="https";context.Request.Path="/api/v2/reports/security.problems/data";context.Request.QueryString=new(query);context.Response.Body=new MemoryStream();return(context,source,provider);
    }
    static JsonObject Body(DefaultHttpContext c)=>JsonNode.Parse(((MemoryStream)c.Response.Body).ToArray())!.AsObject();
    [Fact]public async Task Registered_route_returns_real_report_contract_over_http()
    {
        var(_,source,provider)=Setup();using(provider)
        using(var host=await new HostBuilder().ConfigureWebHost(web=>web.UseTestServer().ConfigureServices(s=>{s.AddRouting();s.AddLogging();s.AddSingleton(provider.GetRequiredService<IConfiguration>());s.AddSingleton(provider.GetRequiredService<TransportGate>());s.AddSingleton(provider.GetRequiredService<IPrincipalAuthenticator>());s.AddSingleton(provider.GetRequiredService<IAccessFactsRepository>());s.AddSingleton<IAdHardeningSource>(source);}).Configure(app=>{app.UseRouting();app.UseEndpoints(e=>e.MapAdHardening());})).StartAsync(TestContext.Current.CancellationToken))
        using(var client=host.GetTestClient()){
            client.DefaultRequestHeaders.AcceptLanguage.ParseAdd("en");using var response=await client.GetAsync("/api/v2/reports/security.problems/data?tab=ad-hardening&domain=7",TestContext.Current.CancellationToken);Assert.Equal(System.Net.HttpStatusCode.OK,response.StatusCode);var data=JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;Assert.Equal("sli.report-result.v2",(string?)data["contract_id"]);Assert.Equal("security.problems",(string?)data["report_key"]);Assert.Single(data["collections"]!["ad_hardening"]!.AsArray());Assert.Equal(new long[]{7},source.Domains);Assert.Contains("long password",(string?)data["collections"]!["ad_hardening"]![0]!["what"]);
        }
    }
    [Theory][InlineData(false,true,403)][InlineData(true,false,401)]
    public async Task Authorization_denial_stops_before_snapshot_read(bool assigned,bool authenticated,int status)
    {
        var(c,s,p)=Setup(Facts(assigned),authenticated:authenticated);using(p){await AdHardeningEndpoints.HandleAsync(c);Assert.Equal(status,c.Response.StatusCode);Assert.Equal(0,s.Calls);}
    }
    [Theory][InlineData("?tab=ad-hardening&status=new")][InlineData("?tab=ad-hardening&cursor=next")][InlineData("?tab=ad-hardening&domain=0")][InlineData("?tab=ad-hardening&severity=critical")]
    public async Task Queue_filters_are_rejected_before_source_read(string query)
    {
        var(c,s,p)=Setup(query:query);using(p){await AdHardeningEndpoints.HandleAsync(c);Assert.Equal(400,c.Response.StatusCode);Assert.Equal(0,s.Calls);}
    }
    [Fact]public async Task Search_requires_identity_fields_and_outside_domain_does_not_read_any_snapshot()
    {
        var(c,s,p)=Setup(Facts(identity:false),"?tab=ad-hardening&q=private");using(p){await AdHardeningEndpoints.HandleAsync(c);Assert.Equal(403,c.Response.StatusCode);Assert.Equal(0,s.Calls);}
        var(d,t,q)=Setup(query:"?tab=ad-hardening&domain=8");using(q){await AdHardeningEndpoints.HandleAsync(d);Assert.Equal(200,d.Response.StatusCode);Assert.Empty(t.Domains!);Assert.Empty(Body(d)["collections"]!["ad_hardening"]!.AsArray());}
    }
    [Fact]public async Task Source_failure_is_an_error_without_private_data()
    {
        var(c,s,p)=Setup();using(p){s.Fail=true;await AdHardeningEndpoints.HandleAsync(c);Assert.Equal(500,c.Response.StatusCode);Assert.DoesNotContain("private-fixture",Body(c).ToJsonString());}
    }
}
