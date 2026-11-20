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
using Sli.Server.Ad;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Xunit;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;

namespace Sli.Server.Tests.Ad;

public sealed partial class AdV2Tests
{
    [Theory]
    [InlineData(false, "domain_controllers_missing")]
    [InlineData(true, "users_context_missing")]
    public async Task NewLogonPairsExplainMissingContextFromRealPostgres(bool withController, string expected)
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct);
        // No snapshots or history: missing context must be explained before history reads.
        await PostCollectionPostgres.Sql(db, """
            create table domains(id bigint primary key,fqdn text,is_archived boolean not null default false);
            insert into domains(id,fqdn) values(1,'t002.example.test');
            create table platform_settings(key text,value text);
            insert into platform_settings values('reports.domain_fqdn','t002.example.test');
            create table ad_context_runs(domain_id bigint,status text,observed_at_utc timestamptz);
            create table servers(id bigint primary key,domain_id bigint,hostname text,role text);
            create table computers_v6_source_snapshots(source_snapshot_id bigint,domain_id bigint,snapshot_uuid uuid,source_completed_at_utc timestamptz,
                collection_status text,base_inventory_status text,object_count int,payload_json jsonb,payload_sha256 bytea);
            create table users_report_v2_snapshots(snapshot_id bigint,domain_id bigint,captured_at_utc timestamptz,source_state text,payload_json jsonb,payload_sha256 bytea);
            """, Ct);
        if (withController)
            await PostCollectionPostgres.Sql(db, "insert into servers values(1,1,'dc-t002','domain_controller')", Ct);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["ConnectionStrings:Sli"] = pg.ConnectionString,
            ["Sli:Storage:HistoryReadMode"] = "disabled"
        }).Build();
        var store = new AdV2Store(new PostgresConnectionFactory(config), config);
        using var host = await Host(store, facts: new ScopedFacts()); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v2/reports/ad.new-logon-pairs/data", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!;
        Assert.Equal("error", result["state"]?.ToString());
        Assert.Empty(result["items"]!.AsArray());
        Assert.Equal(expected, result["limitations"]![0]!["code"]?.ToString());
    }

    [Theory]
    [InlineData(false, "history_read_failed")]
    [InlineData(true, "context_verification_failed")]
    public async Task NewLogonPairsUseVerifiedLatestRetainedSourcesWithoutAJobManifest(bool corrupt, string expected)
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db, """
            create table domains(id bigint primary key,fqdn text);
            insert into domains values(1,'example.test');
            create table servers(id bigint primary key,domain_id bigint,role text);
            insert into servers values(1,1,'domain_controller');
            create table computers_v6_source_snapshots(source_snapshot_id bigint,domain_id bigint,snapshot_uuid uuid,source_completed_at_utc timestamptz,
                collection_status text,base_inventory_status text,object_count int,payload_json jsonb,payload_sha256 bytea);
            create table users_report_v2_snapshots(snapshot_id bigint,domain_id bigint,captured_at_utc timestamptz,source_state text,payload_json jsonb,payload_sha256 bytea);
            create table ad_context_entity_aliases(domain_id bigint,alias_type text,normalized_value text,entity_id bigint);

            """, Ct);
        using var stream = typeof(AdV2Tests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Domains.home-computer-source.json")!;
        var payload = (await JsonNode.ParseAsync(stream, cancellationToken: Ct))!.AsObject();
        payload["objects"]![0]!["classification"]!["result"] = "workstation";
        string guid = payload["objects"]![0]!["objectGuid"]!.ToString();
        var users = JsonNode.Parse("""{"users":[{"samAccountName":"synthetic-user"}]}""")!.AsObject();
        await using (var seed = new Npgsql.NpgsqlCommand("""
            insert into computers_v6_source_snapshots values(1,1,@uuid,now(),'complete','observed',1,@payload,decode(@hash,'hex'));
            insert into users_report_v2_snapshots values(1,1,now(),'complete',@users,decode(@userHash,'hex'));
            insert into ad_context_entity_aliases values(1,'object_guid',@guid,1);
            """, db))
        {
            seed.Parameters.AddWithValue("uuid", Guid.Parse(payload["metadata"]!["snapshot_id"]!.ToString()));
            seed.Parameters.AddWithValue("payload", NpgsqlTypes.NpgsqlDbType.Jsonb, payload.ToJsonString()); seed.Parameters.AddWithValue("users", NpgsqlTypes.NpgsqlDbType.Jsonb, users.ToJsonString());
            seed.Parameters.AddWithValue("hash", corrupt ? new string('0', 64) : AdJobPlugin.Digest(payload)); seed.Parameters.AddWithValue("userHash", AdJobPlugin.Digest(users)); seed.Parameters.AddWithValue("guid", guid.ToLowerInvariant()); await seed.ExecuteNonQueryAsync(Ct);
        }
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["ConnectionStrings:Sli"] = pg.ConnectionString, ["Sli:Storage:HistoryReadMode"] = "disabled", ["Sli:Storage:ShortEventReads"] = "false" }).Build();
        var parameters = JsonNode.Parse("""{"period":{"preset":"custom","from_utc":"2026-01-01T00:00:00Z","to_utc":"2026-01-02T00:00:00Z"},"baseline_days":30}""")!.AsObject();
        var result = await new AdV2Store(new PostgresConnectionFactory(config), config).ReadAsync(new("ad.new-logon-pairs", "view", null, [1], parameters, "table", null, false, 50, null, "UTC"), _ => true, Ct);
        Assert.Equal("error", result["state"]?.ToString()); Assert.Equal(expected, result["limitations"]![0]!["code"]?.ToString());
    }
    static CancellationToken Ct=>TestContext.Current.CancellationToken;
    public static IEnumerable<object[]> Routes()
    {
        foreach(string key in AdV2Endpoints.Definitions.Select(p=>p.Key))
        {
            yield return [key,""];
            yield return [key,"/data"];
            if(AdV2Endpoints.Definitions[key]!["declaration"]!["export"]!.GetValue<bool>())yield return [key,"/export.csv"];
            if(key=="ad.computer-logons")yield return [key,"/rows/7/detail"];
        }
    }
    sealed class Auth:IPrincipalAuthenticator
    {public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c,CancellationToken ct)=>ValueTask.FromResult(AuthenticationResult.Success(new("session",1,"operator")));}
    sealed class Facts(bool allowed):IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal p,CancellationToken ct)
        {
            var fields=new[]{"identity_basic","technical","security","privilege","contact","hr","raw_evidence","computer_logon_observation"};
            var definitions=AdV2Endpoints.Definitions.Select(p=>p.Value!["access_key"]!.ToString()).Distinct().Select(key=>JsonSerializer.SerializeToElement(new{report_key=key,version=1,dataset_version=1,definition_json=new{field_categories=fields,actions=new[]{"view","export"}},fields_json=fields.Select(category=>new{category}),actions_json=new[]{"view","export"}})).ToArray();
            return Task.FromResult(new AccessFacts(allowed,"operator",[],[],[],[],[],[],definitions));
        }
    }
    sealed class Store:IAdV2Store
    {
        public int Reads;
        public bool MissingReportDomain;
        public AdV2Request? LastRequest;
        public Exception? DomainFailure;
        public Task<IReadOnlyList<JsonObject>> DomainsAsync(DomainGrant g,CancellationToken ct)=>DomainFailure is {} error ? throw error : Task.FromResult<IReadOnlyList<JsonObject>>([new JsonObject { ["id"] = 1L, ["display_name"] = "example.test", ["is_report_domain"] = !MissingReportDomain, ["report_domain_id"] = MissingReportDomain ? null : JsonValue.Create(1L), ["is_preferred"] = !MissingReportDomain }]);
        public Task<JsonObject> ReadAsync(AdV2Request r,Func<IEnumerable<string>,bool> fields,CancellationToken ct)
        {
            Reads++; LastRequest=r;
            return Task.FromResult(JsonNode.Parse("{\"contract_id\":\"sli.report-result.v2\",\"state\":\"ok\",\"items\":[{\"entity_id\":7,\"display_name\":\"synthetic\"}],\"has_more\":false,\"metrics\":[],\"collections\":{}}")!.AsObject());
        }
    }
    sealed class Catalog(bool available=true):IReportCatalogProvider
    {
        public ReportCatalogSnapshot Capture()=>new(available?AdV2Endpoints.Definitions.Select(p=>new ReportRule(p.Key,p.Value!["access_key"]!.ToString(),"domain",new HashSet<string>(),new HashSet<string>(),null,false){OwnerId="sli.ad"}):[],new Dictionary<string,PluginGeneration>(),new Dictionary<string,string>());
        public ReportCatalogSnapshot Recheck(ReportCatalogSnapshot captured)=>captured;
    }
    sealed class ScopedFacts(bool export=true,bool fields=true,string kind="domain",long[]? ids=null,bool view=true):IAccessFactsRepository
    {
        public async Task<AccessFacts> LoadAsync(Principal principal,CancellationToken ct)
        {
            var owner=await new Facts(true).LoadAsync(principal,ct);string[] categories=fields?["identity_basic","technical","security","privilege","contact","hr","raw_evidence","computer_logon_observation"]:["identity_basic"];
            var policies=categories.Select(f=>"field."+f).Concat(new[]{"workspace.view","events.view","evidence.exact"}).Concat(export?new[]{"reports.export"}:[]).Select(key=>JsonSerializer.SerializeToElement(new{capability_key=key,effect="allow",scope_json=new{kind="all"}})).ToArray();
            var scope=kind=="all"?JsonSerializer.SerializeToElement(new{kind}):JsonSerializer.SerializeToElement(new{kind,ids=ids??[1]});
            var assignments=owner.Definitions.Select(d=>JsonSerializer.SerializeToElement(new{report_key=d.GetProperty("report_key").GetString(),effect="allow",scope_json=scope,field_categories=categories,allowed_actions=view?new[]{"view","export"}:new[]{"export"}})).ToArray();
            return new(false,"operator",[],[],policies,[],[],assignments,owner.Definitions);
        }
    }
    internal static async Task<IHost> Host(IAdV2Store store,bool allowed=true,IAccessFactsRepository? facts=null,bool pluginAvailable=true,IHttpRequestTimeoutFeature? deadline=null)
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{["Sli:AuthRequired"]="true"}).Build();
        return await new HostBuilder().ConfigureWebHost(web=>web.UseTestServer().ConfigureServices(s=>
        {
            s.AddRouting();s.AddLogging();s.AddSingleton<IConfiguration>(config);s.AddSingleton(new AuthRequestPolicy(config));s.AddSingleton(new TransportGate(config));s.AddSingleton<IPrincipalAuthenticator>(new Auth());s.AddSingleton<IAccessFactsRepository>(facts??new Facts(allowed));s.AddSingleton<IAdV2Store>(store);s.AddSingleton<IReportCatalogProvider>(new Catalog(pluginAvailable));
        }).Configure(app=>{if(deadline is not null)app.Use((c,next)=>{c.Features.Set(deadline);return next(c);});app.UseRouting();app.UseEndpoints(e=>e.MapAdV2());})).StartAsync(Ct);
    }
    [Theory][MemberData(nameof(Routes))]public async Task Every_AD_report_operation_dispatches(string key,string suffix)
    {
        var store=new Store();using var host=await Host(store);using var client=host.GetTestClient();
        using var response=await client.GetAsync("/api/v2/reports/"+key+suffix,Ct);
        Assert.Equal(HttpStatusCode.OK,response.StatusCode);Assert.Equal(suffix.Length==0?0:1,store.Reads);
    }
    [Theory][MemberData(nameof(Routes))]public async Task Missing_report_grant_denies_before_data(string key,string suffix)
    {
        var store=new Store();using var host=await Host(store,false);using var client=host.GetTestClient();
        using var response=await client.GetAsync("/api/v2/reports/"+key+suffix+"?untrusted=bad",Ct);
        Assert.Equal(HttpStatusCode.Forbidden,response.StatusCode);Assert.Equal(0,store.Reads);
    }
    [Theory][MemberData(nameof(Routes))]public async Task Input_errors_do_not_read_data(string key,string suffix)
    {
        if(suffix.Length==0)return; // Python declaration reads ignore query parameters.
        var store=new Store();using var host=await Host(store);using var client=host.GetTestClient();
        using var response=await client.GetAsync("/api/v2/reports/"+key+suffix+"?untrusted=bad",Ct);
        Assert.Equal(HttpStatusCode.BadRequest,response.StatusCode);Assert.Contains("report_parameter_unknown:untrusted",await response.Content.ReadAsStringAsync(Ct));Assert.Equal(0,store.Reads);
    }
    [Fact]public void Domain_selection_cannot_cross_issued_scope()
    {
        var context=new DefaultHttpContext();context.Request.QueryString=new("?domain_id=2");
        Assert.Throws<AdAccessException>(()=>AdV2Endpoints.Parse(context.Request,"ad.users.v2","view",[1]));
    }
    [Fact]
    public async Task ComputerLogonsWithoutReportDomainReturnsSpecificLimitationBeforeData()
    {
        var store = new Store { MissingReportDomain = true };
        using var host = await Host(store, facts: new ScopedFacts()); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v2/reports/ad.computer-logons/data?period=custom&from=2026-08-01T00:00:00Z&to=2026-09-01T00:00:00Z", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var payload = JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!.AsObject();
        Assert.Equal("error", payload["state"]!.ToString()); Assert.Empty(payload["items"]!.AsArray());
        var limitation = Assert.Single(payload["limitations"]!.AsArray())!;
        Assert.Equal("report_domain_not_configured", limitation["code"]!.ToString());
        Assert.Contains("Настройки платформы", limitation["text"]!.ToString()); Assert.Equal(0, store.Reads);
    }
    [Theory][InlineData("ad.users.v2")][InlineData("ad.computers.v6")][InlineData("ad.infrastructure")][InlineData("ad.computer-logons")][InlineData("ad.new-logon-pairs")]
    public async Task Scoped_nonowner_can_read_only_the_granted_domain_and_field_set(string key)
    {
        var store=new Store();using var host=await Host(store,facts:new ScopedFacts());using var client=host.GetTestClient();
        using var ok=await client.GetAsync("/api/v2/reports/"+key+"/data",Ct);Assert.Equal(HttpStatusCode.OK,ok.StatusCode);Assert.Equal(1,store.Reads);
        using var limitedHost=await Host(new Store(),facts:new ScopedFacts(fields:false));using var limited=limitedHost.GetTestClient();
        using var denied=await limited.GetAsync("/api/v2/reports/"+key+"/data",Ct);Assert.Equal(HttpStatusCode.Forbidden,denied.StatusCode);
    }
    [Theory][InlineData("ad.users.v2")][InlineData("ad.computers.v6")][InlineData("ad.infrastructure")]
    public async Task View_grant_does_not_imply_export(string key)
    {
        var store=new Store();using var host=await Host(store,facts:new ScopedFacts(export:false));using var client=host.GetTestClient();
        using var response=await client.GetAsync("/api/v2/reports/"+key+"/export.csv",Ct);Assert.Equal(HttpStatusCode.Forbidden,response.StatusCode);Assert.Equal(0,store.Reads);
    }
    [Fact]public async Task Draining_or_unreviewed_plugin_generation_cannot_execute_a_reader()
    {
        var store=new Store();using var host=await Host(store,pluginAvailable:false);using var client=host.GetTestClient();
        using var response=await client.GetAsync("/api/v2/reports/ad.users.v2/data",Ct);Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);Assert.Equal(0,store.Reads);
    }
}
