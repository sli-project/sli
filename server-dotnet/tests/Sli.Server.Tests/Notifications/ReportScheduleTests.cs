using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Notifications;
using Xunit;
namespace Sli.Server.Tests.Notifications;

public class ReportScheduleTests
{
    public const string Body="""
        {"report_key":"security.problems","filters":{"population":"attention"},"timezone":"UTC","local_time":"09:00","weekday":null,"period_days":1,"language":"en","enabled":true,"subscription_ids":["00000000-0000-4000-8000-000000000001"]}
        """;
    static JsonElement J(string value)=>JsonDocument.Parse(value).RootElement.Clone();
    sealed class Authentication(string role,string type):IPrincipalAuthenticator
    {public ValueTask<AuthenticationResult> AuthenticateAsync(Microsoft.AspNetCore.Http.HttpContext c,CancellationToken ct)=>ValueTask.FromResult(AuthenticationResult.Success(new(type,7,role)));}
    sealed class Facts(bool allowed):IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal p,CancellationToken ct)=>Task.FromResult(new AccessFacts(allowed,p.Role,[],[],[],allowed?[J("""{"capability_key":"access.manage"}""")]:[],[],[],allowed?[J("""{"report_key":"notifications.channels","version":1,"dataset_version":1,"definition_json":{"actions":["view","configure_channel"]},"fields_json":[{"category":"technical"}],"actions_json":["view","configure_channel"]}""")]:[]));
    }
    sealed class Repository:IReportScheduleRepository
    {
        public string? Error;public int Calls;
        public Task<IReadOnlyList<JsonObject>> ListAsync(bool runs,CancellationToken ct)
        {Calls++;Fail();return Task.FromResult<IReadOnlyList<JsonObject>>([new JsonObject{[runs?"quality":"report_key"]=runs?"partial":"security.problems"}]);}
        public Task<JsonObject> SaveAsync(Principal actor,Guid? id,ReportScheduleInput input,CancellationToken ct)
        {Calls++;Fail();return Task.FromResult(new JsonObject{["id"]=(id??Guid.NewGuid()).ToString(),["revision"]=input.Revision+1});}
        void Fail(){if(Error is {} code)throw new ReportScheduleException(code);}
    }
    static async Task<IHost> Host(Repository repo,bool allowed=true,string role="admin",string type="session")=>await new HostBuilder().ConfigureWebHost(web=>web.UseTestServer().ConfigureServices(s=>{
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"Sli:AuthRequired","true"}}).Build();
        s.AddRouting();s.AddLogging();s.AddSingleton<IConfiguration>(config);s.AddSingleton(new AuthRequestPolicy(config));s.AddSingleton(new TransportGate(config));s.AddSingleton<IPrincipalAuthenticator>(new Authentication(role,type));s.AddSingleton<IAccessFactsRepository>(new Facts(allowed));s.AddSingleton<IReportScheduleRepository>(repo);
    }).Configure(app=>{app.UseRouting();app.UseEndpoints(e=>e.MapReportSchedules());})).StartAsync(TestContext.Current.CancellationToken);
    public static TheoryData<string,string> Routes=>new(){ {"GET","schedules"},{"GET","runs"},{"POST","schedules"},{"POST","schedules/00000000-0000-4000-8000-000000000002"} };
    static HttpRequestMessage Request(string method,string suffix,string? body=null)=>new(new HttpMethod(method),"/api/v1/notification-subscriptions/"+suffix){Content=method=="POST"?new StringContent(body??(suffix.Contains('/')?Body[..^1]+",\"revision\":1}":Body),Encoding.UTF8,"application/json"):null};
    [Theory,MemberData(nameof(Routes))] public async Task EveryRouteSucceeds(string method,string route)
    {var repo=new Repository();using var host=await Host(repo);using var client=host.GetTestClient();client.BaseAddress=new("https://localhost");using var response=await client.SendAsync(Request(method,route),TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.OK,response.StatusCode);Assert.Equal(1,repo.Calls);var data=J(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));Assert.True(data.TryGetProperty(method=="GET"?"items":"item",out _));}
    [Theory,MemberData(nameof(Routes))] public async Task EveryRouteDeniesBeforeBodyOrRepository(string method,string route)
    {var repo=new Repository();using var host=await Host(repo,false);using var client=host.GetTestClient();using var response=await client.SendAsync(Request(method,route,"not json"),TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.Forbidden,response.StatusCode);Assert.Contains("notifications_access_denied",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));Assert.Equal(0,repo.Calls);}
    [Theory,InlineData("schedules"),InlineData("schedules/00000000-0000-4000-8000-000000000002"),InlineData("schedules/invalid")]
    public async Task MutationRejectsInput(string route)
    {var repo=new Repository();using var host=await Host(repo);using var client=host.GetTestClient();using var response=await client.SendAsync(Request("POST",route,"{}"),TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.BadRequest,response.StatusCode);Assert.Contains("invalid_notification_request",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));Assert.Equal(0,repo.Calls);}
    [Theory,InlineData("schedules"),InlineData("runs")] public async Task ReadsIgnoreQueryAsReferenceDoes(string route)
    {var repo=new Repository();using var host=await Host(repo);using var client=host.GetTestClient();using var response=await client.GetAsync("/api/v1/notification-subscriptions/"+route+"?limit=invalid",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.OK,response.StatusCode);}
    [Theory,InlineData("notification_schedule_conflict",409),InlineData("notifications_access_denied",403),InlineData("notifications_unavailable",503)]
    public async Task MapsRepositoryFailures(string error,int status)
    {var repo=new Repository{Error=error};using var host=await Host(repo);using var client=host.GetTestClient();using var response=await client.SendAsync(Request("POST","schedules"),TestContext.Current.CancellationToken);Assert.Equal(status,(int)response.StatusCode);Assert.Contains(error,await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));}
    [Theory,InlineData("viewer","session"),InlineData("admin","api_key")]
    public async Task WritesRequireAdminSession(string role,string type)
    {var repo=new Repository();using var host=await Host(repo,true,role,type);using var client=host.GetTestClient();using var response=await client.SendAsync(Request("POST","schedules"),TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.Forbidden,response.StatusCode);Assert.Equal(0,repo.Calls);}
    [Theory,InlineData("timezone","Mars/Olympus"),InlineData("local_time","9:00"),InlineData("language","de"),InlineData("period_days",2),InlineData("weekday",7),InlineData("enabled",1)]
    public void ValidatesExactInput(string key,object value)
    {var body=JsonNode.Parse(Body)!.AsObject();body[key]=JsonSerializer.SerializeToNode(value);Assert.Throws<ReportScheduleException>(()=>ReportScheduleInput.Parse(J(body.ToJsonString()),false));}
    [Fact] public void RejectsDuplicateIdsAndUnknownFilters()
    {var body=JsonNode.Parse(Body)!.AsObject();body["subscription_ids"]!.AsArray().Add(body["subscription_ids"]![0]!.DeepClone());Assert.Throws<ReportScheduleException>(()=>ReportScheduleInput.Parse(J(body.ToJsonString()),false));body=JsonNode.Parse(Body)!.AsObject();body["filters"]!["q"]="private";Assert.Throws<ReportScheduleException>(()=>ReportScheduleInput.Parse(J(body.ToJsonString()),false));}
    [Fact] public void CalendarAdvancesGapAndUsesFirstFold()
    {var zone=TimeZoneInfo.FindSystemTimeZoneById("America/New_York");Assert.Equal(DateTimeOffset.Parse("2026-03-08T07:00:00Z"),ReportScheduleCalendar.Instant(new DateTime(2026,3,8,2,30,0),zone));Assert.Equal(DateTimeOffset.Parse("2026-11-01T05:30:00Z"),ReportScheduleCalendar.Instant(new DateTime(2026,11,1,1,30,0),zone));}
}
