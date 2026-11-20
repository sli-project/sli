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

public sealed class InvestigationListEndpointTests
{
    static JsonElement J(string json)=>JsonDocument.Parse(json).RootElement.Clone();
    static AccessFacts Facts(bool report=true,bool capability=true)=>new(false,"viewer",[],[],
      capability?[J("""{"capability_key":"investigations.view","effect":"allow","scope_json":{"kind":"all"}}"""),J("""{"capability_key":"investigations.manage","effect":"allow","scope_json":{"kind":"all"}}""")]:[],[],[],
      report?[J("""{"report_key":"investigations.workspace","effect":"allow","allowed_actions":["view","start_case"],"field_categories":[],"scope_json":{"kind":"domain","ids":[1]}}""")]:[],
      [J("""{"report_key":"investigations.workspace","version":1,"dataset_version":1,"definition_json":{"actions":["view","start_case"]},"actions_json":["view","start_case"],"fields_json":[]}""")]);
    sealed class Authentication : IPrincipalAuthenticator
    { public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context,CancellationToken ct)=>ValueTask.FromResult(AuthenticationResult.Success(new("session",1,"viewer"))); }
    sealed class FactsReader(AccessFacts facts) : IAccessFactsRepository
    { public Task<AccessFacts> LoadAsync(Principal p,CancellationToken ct)=>Task.FromResult(facts); }
    sealed class Repo : IInvestigationListRepository
    {
        public int Limit, Reads, GroupsReads; public bool Fail; public InvestigationListRow? Override;
        public Task<IReadOnlyList<InvestigationListRow>> ReadAsync(int limit,CancellationToken ct)
        { Reads++; Limit=limit; if(Fail) throw new InvalidOperationException("private-db-value"); if(Override is not null) return Task.FromResult<IReadOnlyList<InvestigationListRow>>([Override]); return Task.FromResult<IReadOnlyList<InvestigationListRow>>([new(1,Guid.Empty,"visible","open",null,"analyst","2026-01-01 00:00:00+00:00","2026-01-01 00:00:00+00:00",null),new(2,null,"hidden","open",null,"analyst","2026-01-01 00:00:00+00:00","2026-01-01 00:00:00+00:00",null)]); }
        public Task<IReadOnlyDictionary<long,IReadOnlyList<IReadOnlyList<AccessResource>>>> GroupsAsync(long[] ids,CancellationToken ct)
        { GroupsReads++; return Task.FromResult<IReadOnlyDictionary<long,IReadOnlyList<IReadOnlyList<AccessResource>>>>(new Dictionary<long,IReadOnlyList<IReadOnlyList<AccessResource>>>{{1,[[new("domain",1)]]},{2,[[new("domain",1)],[new("domain",2)]]}}); }
    }
    static (DefaultHttpContext,Repo,ServiceProvider) Setup(AccessFacts facts,string query="?limit=2")
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"Sli:AuthRequired","true"}}).Build(); var repo=new Repo();
        var provider=new ServiceCollection().AddLogging().AddSingleton<IConfiguration>(config).AddSingleton(new AuthRequestPolicy(config)).AddSingleton(new TransportGate(config)).AddSingleton<IPrincipalAuthenticator>(new Authentication()).AddSingleton<IAccessFactsRepository>(new FactsReader(facts)).AddSingleton<IInvestigationListRepository>(repo).BuildServiceProvider();
        var ctx=new DefaultHttpContext{RequestServices=provider};ctx.Request.Method="GET";ctx.Request.Scheme="https";ctx.Request.Path="/api/v1/investigation-cases";ctx.Request.QueryString=new(query);ctx.Response.Body=new MemoryStream();return(ctx,repo,provider);
    }
    static JsonElement Response(DefaultHttpContext ctx)=>J(Encoding.UTF8.GetString(((MemoryStream)ctx.Response.Body).ToArray()));
    [Fact]
    public async Task ReturnsOnlyAuthorizedRowsAfterBoundedReadWithoutExposingHiddenMetadata()
    {
        var (ctx,repo,provider)=Setup(Facts()); using(provider)
        {
            await InvestigationListEndpoints.HandleAsync(ctx); var body=Response(ctx);
            Assert.Equal(200,ctx.Response.StatusCode);Assert.Equal(2,repo.Limit);Assert.Equal(1,repo.GroupsReads);Assert.Equal(2,body.GetProperty("limit").GetInt32());Assert.True(body.GetProperty("scope_filtered").GetBoolean());
            var rows=body.GetProperty("items");Assert.Equal(1,rows.GetArrayLength());Assert.Equal("INV-0000001",rows[0].GetProperty("case_number").GetString());Assert.Equal("Открыто",rows[0].GetProperty("status_message").GetProperty("text").GetString());Assert.DoesNotContain("hidden",body.GetRawText());
        }
    }
    [Fact]
    public async Task Registered_route_disables_hidden_module_before_reading_cases()
    {
        var (ctx,repo,provider)=Setup(Facts()); using(provider)
        using(var host=await new HostBuilder().ConfigureWebHost(web=>web.UseTestServer().ConfigureServices(services=>
        {
            services.AddRouting(); services.AddLogging();
            services.AddSingleton(provider.GetRequiredService<IConfiguration>());
            services.AddSingleton(provider.GetRequiredService<AuthRequestPolicy>());
            services.AddSingleton(provider.GetRequiredService<TransportGate>());
            services.AddSingleton(provider.GetRequiredService<IPrincipalAuthenticator>());
            services.AddSingleton(provider.GetRequiredService<IAccessFactsRepository>());
            services.AddSingleton<IInvestigationListRepository>(repo);
        }).Configure(app=>{app.UseRouting();app.UseEndpoints(endpoints=>{
            endpoints.MapInvestigationList(); endpoints.MapInvestigationWorkspace();
            endpoints.MapInvestigationDetail(); endpoints.MapInvestigationCreate();
            endpoints.MapInvestigationNoteEndpoints(); endpoints.MapInvestigationEvents();
            endpoints.MapInvestigationLinks();
        });})).StartAsync(TestContext.Current.CancellationToken))
        using(var client=host.GetTestClient())
        {
            foreach (string path in new[] { "/api/v1/investigation-cases?limit=&limit=2", "/api/v1/investigations",
                "/api/v1/investigations/1", "/api/v1/investigations/1/events" })
            {
                using var response=await client.GetAsync(path,TestContext.Current.CancellationToken);
                Assert.Equal(System.Net.HttpStatusCode.ServiceUnavailable,response.StatusCode);
                using var json=JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
                Assert.Equal("module_disabled",json.RootElement.GetProperty("error").GetString());
            }
            foreach (string suffix in new[] { "", "/from-finding", "/1/notes", "/1/status", "/1/owner",
                "/1/events", "/1/events/remove", "/1/findings", "/1/evidence-refs" })
            {
                using var response=await client.PostAsync("/api/v1/investigations"+suffix,new StringContent("invalid body"),TestContext.Current.CancellationToken);
                Assert.Equal(System.Net.HttpStatusCode.ServiceUnavailable,response.StatusCode);
                using var json=JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
                Assert.Equal("module_disabled",json.RootElement.GetProperty("error").GetString());
            }
            Assert.Equal(0,repo.Reads); Assert.Equal(0,repo.GroupsReads);
        }
    }
    [Fact]
    public async Task SessionTimestampProjectionSurvivesResponseSerialization()
    {
        var (ctx,repo,provider)=Setup(Facts()); using(provider)
        {
            repo.Override=new(1,Guid.Empty,"visible","open",null,"analyst",
                InvestigationList.FormatSessionTimestamp("2026-01-01 03:00:00.000000",10800),
                InvestigationList.FormatSessionTimestamp("2026-01-01 03:00:00.123400",10800),
                InvestigationList.FormatSessionTimestamp("2026-01-01 01:02:03.000001",-12600));
            await InvestigationListEndpoints.HandleAsync(ctx); var row=Response(ctx).GetProperty("items")[0];
            Assert.Equal("2026-01-01 03:00:00+03:00",row.GetProperty("created_at").GetString());
            Assert.Equal("2026-01-01 03:00:00.123400+03:00",row.GetProperty("updated_at").GetString());
            Assert.Equal("2026-01-01 01:02:03.000001-03:30",row.GetProperty("closed_at").GetString());
        }
    }
    [Fact]
    public async Task FailedDatabaseReadCannotReturnAnEmptySuccess()
    {
        var (ctx,repo,provider)=Setup(Facts()); using(provider)
        { repo.Fail=true; await InvestigationListEndpoints.HandleAsync(ctx); Assert.Equal(500,ctx.Response.StatusCode); Assert.DoesNotContain("private-db-value",Response(ctx).GetRawText()); Assert.Equal(0,repo.GroupsReads); }
    }
    [Theory] [InlineData(false,true,"report_not_assigned")] [InlineData(true,false,"insufficient_capability")]
    public async Task MissingModuleAccessStopsBeforeReadingCases(bool report,bool capability,string error)
    {
        var (ctx,repo,provider)=Setup(Facts(report,capability)); using(provider)
        { await InvestigationListEndpoints.HandleAsync(ctx);Assert.Equal(403,ctx.Response.StatusCode);Assert.Equal(error,Response(ctx).GetProperty("error").GetString());Assert.Equal(0,repo.Reads); }
    }

    [Theory] [InlineData(false,true,"report_not_assigned")] [InlineData(true,false,"insufficient_capability")]
    public async Task Disabled_route_preserves_module_permissions(bool report,bool capability,string error)
    {
        var (ctx,repo,provider)=Setup(Facts(report,capability)); using(provider)
        {
            await InvestigationEndpoints.HandleDisabledAsync(ctx);
            Assert.Equal(403,ctx.Response.StatusCode);
            Assert.Equal(error,Response(ctx).GetProperty("error").GetString());
            Assert.Equal(0,repo.Reads);
        }
    }

    [Fact]
    public async Task Disabled_mutation_preserves_origin_check_without_reading_body()
    {
        var (ctx,repo,provider)=Setup(Facts()); using(provider)
        {
            ctx.Request.Method="POST"; ctx.Request.Headers.Origin="https://foreign.example.test";
            ctx.Request.Body=new MemoryStream(Encoding.UTF8.GetBytes("invalid body"));
            await InvestigationEndpoints.HandleDisabledAsync(ctx);
            Assert.Equal(403,ctx.Response.StatusCode);
            Assert.Equal("cross_origin_request_rejected",Response(ctx).GetProperty("error").GetString());
            Assert.Equal(0,ctx.Request.Body.Position); Assert.Equal(0,repo.Reads);
        }
    }
}
