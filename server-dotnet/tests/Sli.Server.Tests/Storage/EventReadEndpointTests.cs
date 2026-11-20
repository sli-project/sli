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
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Storage.EventReports;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class EventReadEndpointTests
{
    sealed class Authentication(bool allowed) : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c,CancellationToken ct) =>
            ValueTask.FromResult(allowed ? AuthenticationResult.Success(new("session",1,"operator")) : AuthenticationResult.Denied(401,"authentication_required"));
    }
    sealed class Facts(bool allowed) : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal p,CancellationToken ct) => Task.FromResult(new AccessFacts(false,"operator",[],[],
            allowed ? [JsonSerializer.SerializeToElement(new {capability_key="evidence.exact",effect="allow",scope_json=new {kind="domain",ids=new[]{1}}})] : [],[],[],[],[]));
    }
    sealed class Reader : IEventReadService
    {
        public int Resources,Details,Relations;
        public Exception? Error;
        public bool ProjectCards;
        public int EventId = 4625;
        public TaskCompletionSource? ResourceEntered,ResourceRelease;
        public async Task<IReadOnlyList<AccessResource>> ResourcesAsync(long id,CancellationToken ct)
        { Resources++; ResourceEntered?.TrySetResult(); if(ResourceRelease is not null) await ResourceRelease.Task.WaitAsync(ct); return [new("domain",id==8?2:1)]; }
        public async Task<Dictionary<long,JsonObject>> DetailsAsync(long[] ids,bool exact,Func<long,CancellationToken,Task<bool>> admitted,CancellationToken ct)
        {
            Details++; if(Error is {} error) throw error;
            var result=new Dictionary<long,JsonObject>();
            foreach(long id in ids) if(await admitted(id,ct))
            {
                var row=new JsonObject { ["id"]=id,["event_id"]=EventId,["source_payload_state"]="expired",["channel"]="Security",["provider_name"]="Microsoft-Windows-Security-Auditing",["message_text"]="ROUND2-EXACT-MARKER" };
                result[id]=ProjectCards ? await new KnownBundleNormalizer(EventCardSemanticsTests.Repository(),null,null).ProjectAsync(row,ct) : row;
            }
            return result;
        }
        public async Task<JsonObject> RelationsAsync(long id,Func<long,CancellationToken,Task<bool>> admitted,CancellationToken ct)
        { Relations++; Assert.True(await admitted(id,ct)); return new JsonObject { ["api_version"]="v1",["event_db_id"]=id,["items"]=new JsonArray() }; }
    }
    static async Task<IHost> Host(Reader reader,bool capability=true,bool authenticated=true)
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:AuthRequired"]="true" }).Build();
        return await new HostBuilder().ConfigureWebHost(web=>web.UseTestServer().ConfigureServices(services=>
        {
            services.AddRouting(); services.AddLogging(); services.AddSingleton<IConfiguration>(config);
            services.AddSingleton(new AuthRequestPolicy(config)); services.AddSingleton(new TransportGate(config));
            services.AddSingleton<IPrincipalAuthenticator>(new Authentication(authenticated));
            services.AddSingleton<IAccessFactsRepository>(new Facts(capability)); services.AddSingleton<IEventReadService>(reader);
        }).Configure(app=>{ app.UseRouting(); app.UseEndpoints(routes=>routes.MapEventReads()); })).StartAsync(TestContext.Current.CancellationToken);
    }
    [Theory]
    [InlineData("/api/v1/events/7")] [InlineData("/api/v1/events/batch?event_db_id=7")]
    [InlineData("/api/v1/events/7/relations")]
    public async Task Capability_denial_precedes_all_event_data(string path)
    {
        var reader=new Reader(); using var host=await Host(reader,capability:false); using var client=host.GetTestClient();
        using var response=await client.GetAsync(path,TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden,response.StatusCode); Assert.Equal(0,reader.Resources+reader.Details+reader.Relations);
    }
    [Fact] public async Task Unauthenticated_request_never_reads_event_data()
    {
        var reader=new Reader(); using var host=await Host(reader,authenticated:false); using var client=host.GetTestClient();
        using var response=await client.GetAsync("/api/v1/events/7",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized,response.StatusCode); Assert.Equal(0,reader.Resources+reader.Details+reader.Relations);
    }
    [Fact] public async Task Round2ExactDetailReturnsAuthorizedEvidence()
    {
        var reader=new Reader(); using var host=await Host(reader); using var client=host.GetTestClient();
        using var response=await client.GetAsync("/api/v1/events/17",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK,response.StatusCode);
        var body=JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal("ROUND2-EXACT-MARKER",body["item"]!["message_text"]!.ToString()); Assert.Equal(1,reader.Details);
    }
    [Theory] [InlineData("/api/v1/events/8")] [InlineData("/api/v1/events/8/relations")]
    public async Task Scoped_denial_precedes_payload_and_correlation_read(string path)
    {
        var reader=new Reader(); using var host=await Host(reader); using var client=host.GetTestClient();
        using var response=await client.GetAsync(path,TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound,response.StatusCode); Assert.Equal(1,reader.Resources); Assert.Equal(0,reader.Details+reader.Relations);
    }
    [Fact] public async Task Batch_preserves_order_deduplicates_and_filters_scope_before_read()
    {
        var reader=new Reader(); using var host=await Host(reader); using var client=host.GetTestClient();
        using var response=await client.GetAsync("/api/v1/events/batch?event_db_id=9,8;7,bad,9&event_db_id=0",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK,response.StatusCode);
        var json=JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(new long[]{9,7},json["items"]!.AsArray().Select(x=>x!["event_db_id"]!.GetValue<long>()));
        Assert.Equal(new long[]{8},json["missing_event_db_ids"]!.AsArray().Select(x=>x!.GetValue<long>()));
        Assert.Equal(new long[]{9,8,7},json["requested_event_db_ids"]!.AsArray().Select(x=>x!.GetValue<long>()));
        Assert.Equal(100,json["limit"]!.GetValue<int>());
        Assert.Equal(3,reader.Resources); Assert.Equal(1,reader.Details);
    }
    [Fact] public async Task Batch_exact_ids_are_positive_deduplicated_and_capped_at_100()
    {
        var values=new[]{"3,2,3,0,-1,not-an-id"}.Concat(Enumerable.Range(4,146).Select(id=>id.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        long[] expected=[3,2,..Enumerable.Range(4,98).Select(id=>(long)id)];
        var reader=new Reader(); using var host=await Host(reader); using var client=host.GetTestClient();
        using var response=await client.GetAsync("/api/v1/events/batch?"+string.Join('&',values.Select(value=>"event_db_id="+Uri.EscapeDataString(value))),TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK,response.StatusCode);
        var json=JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(expected,json["requested_event_db_ids"]!.AsArray().Select(x=>x!.GetValue<long>()));
        Assert.Equal(expected.Where(id=>id!=8),json["items"]!.AsArray().Select(x=>x!["event_db_id"]!.GetValue<long>()));
        Assert.Equal(new long[]{8},json["missing_event_db_ids"]!.AsArray().Select(x=>x!.GetValue<long>()));
        Assert.Equal(100,json["limit"]!.GetValue<int>());
        Assert.Equal(100,reader.Resources); Assert.Equal(1,reader.Details);
    }
    [Theory] [InlineData("/api/v1/events/7")] [InlineData("/api/v1/events/7/relations")]
    [InlineData("/api/v1/events/7?route=v1&authorization=invalid")]
    [InlineData("/api/v1/events/7/relations?route=v1&authorization=invalid")]
    public async Task Registered_routes_dispatch(string path)
    {
        var reader=new Reader(); using var host=await Host(reader); using var client=host.GetTestClient();
        using var response=await client.GetAsync(path,TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK,response.StatusCode); Assert.Equal(1,reader.Details+reader.Relations);
    }
    [Fact]
    public async Task Product2ExactEventPreservesIdentifierAndUncataloguedSemantics()
    {
        var reader = new Reader { ProjectCards = true, EventId = 140 };
        using var host = await Host(reader); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v1/events/42", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal("v1", (string?)json["api_version"]);
        Assert.Equal(42, (long)json["item"]!["event_db_id"]!); Assert.Equal(140, (int)json["item"]!["event_id"]!);
        Assert.Equal("Событие пока не расшифровано каталогом", (string?)json["item"]!["semantics"]!["title"]);
        using var related = await client.GetAsync("/api/v1/events/42/relations", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, related.StatusCode);
        var relations = JsonNode.Parse(await related.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(42, (long)relations["event_db_id"]!); Assert.Empty(relations["items"]!.AsArray());
    }
    [Theory] [InlineData("/api/v1/events/bad","invalid_event_db_id")] [InlineData("/api/v1/events/batch?event_db_id=bad","event_db_id_required")]
    [InlineData("/api/v1/events/batch?event_db_id=bad,0","event_db_id_required")]
    public async Task Invalid_input_does_not_read_data(string path,string code)
    {
        var reader=new Reader(); using var host=await Host(reader); using var client=host.GetTestClient();
        using var response=await client.GetAsync(path,TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest,response.StatusCode); Assert.Contains(code,await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        if(path.StartsWith("/api/v1/events/batch",StringComparison.Ordinal))
            Assert.Equal(new JsonObject { ["error"]=code }.ToJsonString(),JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.ToJsonString());
        Assert.Equal(0,reader.Resources+reader.Details+reader.Relations);
    }
    [Fact] public async Task Internal_timeout_is_503_instead_of_missing_event()
    {
        var reader=new Reader { Error=new TimeoutException() }; using var host=await Host(reader); using var client=host.GetTestClient();
        using var response=await client.GetAsync("/api/v1/events/7",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);
        Assert.Contains("report_read_timeout",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
    [Fact] public async Task Caller_cancellation_stops_batch_admission_before_hydration()
    {
        var reader=new Reader { ResourceEntered=new(TaskCreationOptions.RunContinuationsAsynchronously),ResourceRelease=new(TaskCreationOptions.RunContinuationsAsynchronously) };
        using var host=await Host(reader); using var client=host.GetTestClient();
        using var cancellation=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var pending=client.GetAsync("/api/v1/events/batch?event_db_id="+string.Join(',',Enumerable.Range(1,100)),cancellation.Token);
        await reader.ResourceEntered.Task.WaitAsync(TestContext.Current.CancellationToken);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => { using var response=await pending; });
        Assert.Equal(1,reader.Resources); Assert.Equal(0,reader.Details);
    }
    [Theory] [InlineData("/api/v1/events/7",false)] [InlineData("/api/v1/events/batch?event_db_id=7",true)]
    public async Task Hydrated_single_and_batch_responses_include_card_semantics(string path,bool batch)
    {
        var reader=new Reader { ProjectCards=true }; using var host=await Host(reader); using var client=host.GetTestClient();
        using var response=await client.GetAsync(path,TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK,response.StatusCode);
        var json=JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        var item=batch ? json["items"]![0]! : json["item"]!;
        Assert.Equal("Security:Microsoft-Windows-Security-Auditing:4625.title",item["semantics"]!["title_code"]!.GetValue<string>());
        Assert.NotEmpty(item["semantics"]!["title"]!.GetValue<string>());
        Assert.NotNull(item["semantics"]!["card_completeness"]);
    }
    [Fact] public async Task Unavailable_normalizer_is_503_instead_of_501()
    {
        var reader=new Reader { Error=new InvalidOperationException("source_normalizer_bundle_unsupported") }; using var host=await Host(reader); using var client=host.GetTestClient();
        using var response=await client.GetAsync("/api/v1/events/7",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);
    }
}
