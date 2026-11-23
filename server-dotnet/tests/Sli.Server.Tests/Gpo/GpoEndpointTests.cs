using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Timeouts;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Gpo;
using Xunit;
using static Sli.Server.Gpo.GpoJson;

namespace Sli.Server.Tests.Gpo;

public sealed class GpoEndpointTests
{
    const string Prefix="/api/v2/reports/ad.gpo.v2";
    const string PolicySnapshots = Prefix + "/data?tab=gpos&policy_id=synthetic-policy&domain=1";
    const string SnapshotIds = "&before_snapshot=10000000-0000-0000-0000-000000000001&after_snapshot=10000000-0000-0000-0000-000000000003";
    sealed class Authentication(bool valid,string role) : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c,CancellationToken ct)=>ValueTask.FromResult(valid?AuthenticationResult.Success(new("session",1,role)):AuthenticationResult.Denied(401,"authentication_required"));
    }
    sealed class Facts(bool allowed,bool owner,bool export,string scope,string[]? fields) : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal p,CancellationToken ct)
        {
            var cats=fields??new[]{"identity_basic","technical","security","privilege"};
            var caps=cats.Select(f=>JsonSerializer.SerializeToElement(new {capability_key="field."+f,effect="allow",scope_json=new {kind="all"}})).ToList();if(export) caps.Add(JsonSerializer.SerializeToElement(new {capability_key="reports.export",effect="allow",scope_json=new {kind="all"}}));
            var definition=JsonSerializer.SerializeToElement(new { report_key="ad.gpo.v2",version=1,dataset_version=1,fields_json=new[]{"identity_basic","technical","security","privilege"}.Select(c=>new {category=c}),actions_json=new[]{"view","export"},definition_json=new {field_categories=new[]{"identity_basic","technical","security","privilege"},actions=new[]{"view","export"}} });
            var assignment=JsonSerializer.SerializeToElement(new {report_key="ad.gpo.v2",effect="allow",field_categories=cats,allowed_actions=export?new[]{"view","export"}:new[]{"view"},scope_json=JsonNode.Parse(scope)});
            return Task.FromResult(new AccessFacts(owner,p.Role,[],[],caps,[],[],allowed?[assignment]:[],[definition]));
        }
    }
    internal static async Task<IHost> Host(IGpoReadStore store,bool allowed=true,bool authenticated=true,string role="viewer",bool owner=false,bool export=true,string scope="{\"kind\":\"domain\",\"ids\":[1]}",string[]? fields=null,IHttpRequestTimeoutFeature? deadline=null)
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:AuthRequired"]="true" }).Build();
        return await new HostBuilder().ConfigureWebHost(web=>web.UseTestServer().ConfigureServices(s=>
        {
            s.AddRouting();s.AddLogging();s.AddSingleton<IConfiguration>(config);s.AddSingleton(new AuthRequestPolicy(config));s.AddSingleton(new TransportGate(config));
            s.AddSingleton<IPrincipalAuthenticator>(new Authentication(authenticated,role));s.AddSingleton<IAccessFactsRepository>(new Facts(allowed,owner,export,scope,fields));s.AddSingleton<IReportCatalogProvider>(new ReportRuleCatalog(new PluginGenerationReader(null)));s.AddSingleton<IGpoReadStore>(store);
            if (store is IGpoSnapshotReadStore snapshots) s.AddSingleton(snapshots);
        }).Configure(app=>{if(deadline is not null)app.Use((c,next)=>{c.Features.Set(deadline);return next(c);});app.UseRouting();app.UseEndpoints(r=>r.MapGpoReports());})).StartAsync(TestContext.Current.CancellationToken);
    }
    [Theory] [InlineData("")] [InlineData("/data?view=all")] [InlineData("/export.csv?view=all")]
    public async Task Routes_succeed_with_authorized_domain_and_fields(string suffix)
    {
        var store=new GpoReportTests.Store();using var host=await Host(store);using var client=host.GetTestClient();using var response=await client.GetAsync(Prefix+suffix,TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.OK,response.StatusCode);
        if(suffix.Length==0) { Assert.Equal(0,store.Reads);var body=JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;Assert.Equal(10,body["views"]!.AsArray().Count);Assert.True(body["export"]!.GetValue<bool>()); }
        else { Assert.Equal(new long[]{1},store.Domains);Assert.Equal(1,store.Reads);if(suffix.StartsWith("/export",StringComparison.Ordinal)) {Assert.Equal("text/csv",response.Content.Headers.ContentType!.MediaType);Assert.True(response.Headers.Contains("X-Sli-Export-Rows"));Assert.StartsWith("sli-ad.gpo.v2-complete-",response.Content.Headers.ContentDisposition!.FileName!.Trim('"'));} }
    }
    [Theory] [InlineData("")] [InlineData("/data")] [InlineData("/export.csv")] [InlineData("/rows/gpo-a/detail")]
    public async Task Every_route_rejects_missing_rights_before_data(string suffix)
    {
        var store=new GpoReportTests.Store();using var host=await Host(store,allowed:false);using var client=host.GetTestClient();using var response=await client.GetAsync(Prefix+suffix,TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.Forbidden,response.StatusCode);Assert.Equal(0,store.Reads);
    }
    [Theory] [InlineData("")] [InlineData("/data")] [InlineData("/export.csv")] [InlineData("/rows/gpo-a/detail")]
    public async Task Every_route_requires_authentication(string suffix)
    {
        var store=new GpoReportTests.Store();using var host=await Host(store,authenticated:false);using var client=host.GetTestClient();using var response=await client.GetAsync(Prefix+suffix,TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.Unauthorized,response.StatusCode);Assert.Equal(0,store.Reads);
    }
    [Theory] [InlineData("viewer")] [InlineData("operator")] [InlineData("admin")]
    public async Task Coarse_roles_still_require_report_scope(string role)
    {
        var store=new GpoReportTests.Store();using var host=await Host(store,role:role);using var client=host.GetTestClient();using var response=await client.GetAsync(Prefix+"/data?view=all",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.OK,response.StatusCode);Assert.Equal(new long[]{1},store.Domains);
    }
    [Theory] [InlineData("/data?tab=unknown","report_tab_invalid")] [InlineData("/export.csv?view=wrong","report_parameter_invalid:view")]
    public async Task Invalid_request_does_not_read_snapshots(string suffix,string error)
    {
        var store=new GpoReportTests.Store();using var host=await Host(store);using var client=host.GetTestClient();using var response=await client.GetAsync(Prefix+suffix,TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.BadRequest,response.StatusCode);Assert.Contains(error,await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));Assert.Equal(0,store.Reads);
    }
    [Fact] public async Task Declaration_ignores_query_and_detail_returns_source_404_even_with_invalid_query()
    {
        var store=new GpoReportTests.Store();using var host=await Host(store);using var client=host.GetTestClient();using var declaration=await client.GetAsync(Prefix+"?unknown=x",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.OK,declaration.StatusCode);
        using var detail=await client.GetAsync(Prefix+"/rows/gpo-a/detail?limit=bad",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.NotFound,detail.StatusCode);Assert.Contains("report_detail_not_available",await detail.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));Assert.Equal(0,store.Reads);
    }
    [Theory] [InlineData("/data")] [InlineData("/export.csv")]
    public async Task All_four_categories_must_be_granted_atomically(string suffix)
    {
        var store=new GpoReportTests.Store();using var host=await Host(store,fields:["identity_basic","technical","security"]);using var client=host.GetTestClient();using var response=await client.GetAsync(Prefix+suffix,TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.Forbidden,response.StatusCode);Assert.Contains("report_field_categories_not_allowed",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));Assert.Equal(0,store.Reads);
    }
    [Fact] public async Task Export_has_its_own_grant()
    {
        var store=new GpoReportTests.Store();using var host=await Host(store,export:false);using var client=host.GetTestClient();using var response=await client.GetAsync(Prefix+"/export.csv",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.Forbidden,response.StatusCode);Assert.Equal(0,store.Reads);
    }
    [Fact] public async Task Csv_separates_unverified_information_and_assignment_questions_for_one_policy()
    {
        var snapshot=GpoReportTests.ReviewSnapshot();snapshot["gpos"]![0]!["source_states"]!["sysvol_gpt"]!["status"]="failed";
        var store=new GpoReportTests.Store { Pair=new JsonObject { ["state"]="available",["current"]=snapshot } };
        using var host=await Host(store);using var client=host.GetTestClient();
        using var response=await client.GetAsync(Prefix+"/export.csv?view=all&tab=gpos",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK,response.StatusCode);Assert.Equal("1",Assert.Single(response.Headers.GetValues("X-Sli-Export-Rows")));
        string csv=await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("Непроверенные сведения",csv);Assert.Contains("Вопросы назначения",csv);
        Assert.Contains("Ошибка обязательного источника",csv);Assert.Contains("Связи не наблюдались",csv);Assert.Contains("Включённая часть без настроек",csv);
        Assert.Equal(2,csv.TrimStart('\uFEFF').Split("\r\n",StringSplitOptions.RemoveEmptyEntries).Length);
    }
    [Fact] public async Task Unsupported_scope_never_becomes_all_domains()
    {
        var store=new GpoReportTests.Store();using var host=await Host(store,scope:"{\"kind\":\"server\",\"ids\":[1]}");using var client=host.GetTestClient();using var response=await client.GetAsync(Prefix+"/data",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.Forbidden,response.StatusCode);Assert.Contains("report_scope_not_executable",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));Assert.Equal(0,store.Reads);
    }
    [Fact]
    public async Task Policy_card_and_history_use_the_selected_granted_domain()
    {
        var snapshot=GpoReportTests.ReviewSnapshot();
        var policy=Assert.Single(snapshot.Rows("gpos"));
        policy["computer"]!["sysvol_version"]=2;
        snapshot["settings"]=JsonNode.Parse("""
            [{"id":"setting-a","gpo_id":"synthetic-policy","side":"computer","setting_name":"Timeout","path":"Security/Timeout","value_display":"600"},
             {"id":"setting-b","gpo_id":"another-policy","side":"computer","setting_name":"Other","value_display":"500"}]
            """);
        var store=new GpoReportTests.Store {
            Pair=new JsonObject { ["state"]="available",["domain_id"]=1,["current"]=snapshot },
            PolicyHistory=JsonNode.Parse("""
                {"state":"ok","items":[{"id":"change-a","object_type":"gpo_setting","object_id":"setting-a","kind":"attribute_changed",
                 "field":"value_display","observed_at":"2026-10-07T00:00:00Z","before_value":"900","after_value":"600"}]}
                """)!.AsObject()
        };
        using var host=await Host(store);using var client=host.GetTestClient();
        var ct=TestContext.Current.CancellationToken;
        using var denied=await client.GetAsync(Prefix+"/data?tab=gpos&policy_id=synthetic-policy&domain=2",ct);
        Assert.Equal(HttpStatusCode.Forbidden,denied.StatusCode);
        Assert.Equal(0,store.Reads);
        using var response=await client.GetAsync(Prefix+"/data?tab=gpos&policy_id=synthetic-policy&domain=1",ct);
        response.EnsureSuccessStatusCode();
        Assert.Equal(new long[]{1},store.Domains);
        var details=JsonNode.Parse(await response.Content.ReadAsStringAsync(ct))!["collections"]!;
        Assert.Equal("Timeout",Assert.Single(details["settings"]!.AsArray())!["setting_name"]!.GetValue<string>());
        Assert.Equal(2,Assert.Single(details["versions"]!.AsArray())!["computer_sysvol_version"]!.GetValue<int>());
        using var history=await client.GetAsync(Prefix+"/data?tab=changes&policy_id=synthetic-policy&domain=1",ct);
        history.EnsureSuccessStatusCode();
        var change=Assert.Single(JsonNode.Parse(await history.Content.ReadAsStringAsync(ct))!["collections"]!["changes"]!.AsArray())!;
        Assert.Equal("Timeout",change["name"]!.GetValue<string>());
        Assert.Equal("900",change["before_value"]!.GetValue<string>());
        Assert.Equal("600",change["after_value"]!.GetValue<string>());
        using var export=await client.GetAsync(Prefix+"/export.csv?tab=gpos&view=unlinked_version_mismatch&domain=1",ct);
        export.EnsureSuccessStatusCode();
        Assert.Contains("Synthetic policy",await export.Content.ReadAsStringAsync(ct));
    }
    [Fact] public async Task Corrupt_source_is_503_and_never_exposes_source_fields()
    {
        var store=new GpoReportTests.Store {Error=new GpoSourceException()};using var host=await Host(store);using var client=host.GetTestClient();using var response=await client.GetAsync(Prefix+"/data",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);Assert.Contains("source_contract_error",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(false, true, false)]
    [InlineData(true, false, false)]
    [InlineData(true, true, true)]
    public async Task Snapshot_comparison_requires_report_fields_and_domain(bool allowed, bool fullFields, bool crossDomain)
    {
        var store = new GpoReportTests.Store();
        using var host = await Host(store, allowed: allowed, fields: fullFields ? null : ["identity_basic", "technical"]);
        using var client = host.GetTestClient();
        var url = crossDomain ? PolicySnapshots.Replace("domain=1", "domain=2") : PolicySnapshots;
        using var response = await client.GetAsync(url + SnapshotIds, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, store.Reads);
    }

    [Theory]
    [InlineData("&before_snapshot=10000000-0000-0000-0000-000000000001")]
    [InlineData("&before_snapshot=invalid&after_snapshot=10000000-0000-0000-0000-000000000003")]
    [InlineData("&before_snapshot=10000000-0000-0000-0000-000000000003&after_snapshot=10000000-0000-0000-0000-000000000003")]
    public async Task Invalid_snapshot_pair_is_rejected_before_reading(string parameters)
    {
        var store = new GpoReportTests.Store();
        using var host = await Host(store);
        using var client = host.GetTestClient();
        using var response = await client.GetAsync(PolicySnapshots + parameters, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, store.Reads);
    }

    [Fact]
    public async Task A_missing_snapshot_is_distinct_from_a_successful_empty_comparison()
    {
        var store = new GpoReportTests.Store();
        using var host = await Host(store);
        using var client = host.GetTestClient();
        var ct = TestContext.Current.CancellationToken;
        using var list = await client.GetAsync(PolicySnapshots + "&snapshots=1", ct);
        list.EnsureSuccessStatusCode();
        var collection = JsonNode.Parse(await list.Content.ReadAsStringAsync(ct))!["collections"]!;
        Assert.Empty(collection.Rows("snapshots"));
        using var pair = await client.GetAsync(PolicySnapshots + SnapshotIds, ct);
        pair.EnsureSuccessStatusCode();
        var body = JsonNode.Parse(await pair.Content.ReadAsStringAsync(ct))!;
        Assert.Equal("unavailable", body["coverage"].Text("snapshot_comparison_state"));
        Assert.Null(body["collections"]!["snapshot_comparison"]);
    }

    [Fact]
    public async Task Comparison_matches_changed_collector_ids_and_only_returns_visible_settings_of_the_selected_policy()
    {
        var store = new GpoReportTests.Store();
        var old = SyntheticSnapshot(1, """
            [{"id":"timeout-value-900","gpo_id":"synthetic-policy","side":"computer","extension":"security","path":"Policy/Timeout","setting_name":"Timeout","value_display":"900","fingerprint":"synthetic-hidden-fingerprint"},
             {"id":"timeout-user","gpo_id":"synthetic-policy","side":"user","extension":"security","path":"Policy/Timeout","setting_name":"Timeout","value_display":"450"},
             {"id":"desktop","gpo_id":"synthetic-policy","side":"user","extension":"personalization","path":"Desktop/Theme","setting_name":"Theme","value_display":"Blue"},
             {"id":"hidden-before","gpo_id":"synthetic-policy","side":"computer","extension":"security","path":"Policy/Password","setting_name":"Password","value_display":"synthetic-value-before"},
             {"id":"other-policy","gpo_id":"another-policy","side":"computer","path":"Other/Timeout","setting_name":"Other policy","value_display":"synthetic-unrelated-value"}]
            """);
        var current = SyntheticSnapshot(3, """
            [{"id":"timeout-value-600","gpo_id":"synthetic-policy","side":"computer","extension":"security","path":"Policy/Timeout","setting_name":"Timeout","value_display":"600"},
             {"id":"timeout-user","gpo_id":"synthetic-policy","side":"user","extension":"security","path":"Policy/Timeout","setting_name":"Timeout","value_display":"450"},
             {"id":"audit","gpo_id":"synthetic-policy","side":"computer","extension":"security","path":"Logging/Audit","setting_name":"Audit","value_display":"Enabled"},
             {"id":"hidden-after","gpo_id":"synthetic-policy","side":"computer","extension":"security","path":"Policy/Password","setting_name":"Password","value_display":"synthetic-value-after"}]
            """);
        var same = old with { Id = SnapshotId(2), ObservedAt = old.ObservedAt.AddDays(1) };
        store.Snapshots.AddRange([(1, "synthetic-policy", old), (1, "synthetic-policy", same), (1, "synthetic-policy", current),
            (1, "synthetic-policy", current with { Id = SnapshotId(4), ObservedAt = current.ObservedAt.AddDays(1) }),
            (2, "synthetic-policy", current with { Id = SnapshotId(5) }), (1, "another-policy", current with { Id = SnapshotId(6) })]);
        using var host = await Host(store);
        using var client = host.GetTestClient();
        var ct = TestContext.Current.CancellationToken;

        var list = JsonNode.Parse(await client.GetStringAsync(PolicySnapshots + "&snapshots=1", ct))!;
        var choices = list["collections"].Rows("snapshots").ToArray();
        Assert.Equal(new[] { SnapshotId(4), SnapshotId(3), SnapshotId(2), SnapshotId(1) }, choices.Select(row => Guid.Parse(row.Text("id"))));
        Assert.All(choices, row => Assert.Equal(2, row.Count));

        string response = await client.GetStringAsync(PolicySnapshots + SnapshotIds, ct);
        var changes = JsonNode.Parse(response)!["collections"].Rows("snapshot_comparison");
        Assert.Collection(changes,
            row => Assert.Equal(("Audit", "added", "", "Enabled"), Change(row)),
            row => { Assert.Equal(("Timeout", "changed", "900", "600"), Change(row)); Assert.Equal("computer", row.Text("side")); },
            row => Assert.Equal(("Theme", "removed", "Blue", ""), Change(row)));
        Assert.DoesNotContain("fingerprint", response);
        Assert.DoesNotContain("synthetic-value-", response);
        Assert.DoesNotContain("unrelated-value", response);
        Assert.Equal(new long[] { 1 }, store.Domains);

        var unchanged = JsonNode.Parse(await client.GetStringAsync(PolicySnapshots + SnapshotIds.Replace(SnapshotId(3).ToString(), SnapshotId(2).ToString()), ct))!;
        Assert.Empty(Assert.IsType<JsonArray>(unchanged["collections"]!["snapshot_comparison"]));

        foreach (int forbiddenSnapshot in new[] { 5, 6 })
        {
            var denied = JsonNode.Parse(await client.GetStringAsync(PolicySnapshots + SnapshotIds.Replace(SnapshotId(3).ToString(), SnapshotId(forbiddenSnapshot).ToString()), ct))!;
            Assert.Equal("unavailable", denied["coverage"].Text("snapshot_comparison_state"));
            Assert.Null(denied["collections"]!["snapshot_comparison"]);
        }

        static (string, string, string, string) Change(JsonObject row) =>
            (row.Text("setting_name"), row.Text("kind"), row.Text("before_value"), row.Text("after_value"));
    }

    private static Guid SnapshotId(int number) => Guid.Parse($"10000000-0000-0000-0000-{number:D12}");

    private static GpoPolicySnapshot SyntheticSnapshot(int number, string settings) => new(SnapshotId(number),
        Stamp("2026-11-19T12:00:00Z").AddDays(number - 1), new JsonObject { ["settings"] = JsonNode.Parse(settings) });
    [Fact] public async Task History_export_fails_when_confirmed_storage_is_unavailable()
    {
        var store=new GpoReportTests.Store();using var host=await Host(store);using var client=host.GetTestClient();using var response=await client.GetAsync(Prefix+"/export.csv?tab=changes",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.BadRequest,response.StatusCode);Assert.Contains("gpo_history_not_exportable",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
    [Fact] public async Task State_message_uses_the_same_localized_envelope_as_the_reference()
    {
        var store=new GpoReportTests.Store();using var host=await Host(store);using var client=host.GetTestClient();client.DefaultRequestHeaders.AcceptLanguage.ParseAdd("en");
        using var response=await client.GetAsync(Prefix+"/data?view=all",TestContext.Current.CancellationToken);var body=JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal("reports.state."+body.Text("state"),body["state_message"].Text("code"));Assert.Equal(Metadata["messages"]!["en"]![body["state_message"].Text("code")]!.ToJsonString(),body["state_message"]!.ToJsonString());
    }}
