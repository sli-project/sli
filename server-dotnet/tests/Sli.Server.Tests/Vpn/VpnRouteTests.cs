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
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Vpn;

public sealed class VpnRouteTests
{
    static readonly string[] Categories=["identity_basic","technical","security","privilege","hr","contact"];
    internal static JsonObject Json(object value)=>JsonSerializer.SerializeToNode(value)!.AsObject();
    internal static List<JsonObject> Observations()
    {
        return new[]{"start","interim_update","stop"}.Select((kind,i)=>Json(new {observation_id="observation-"+i,lifecycle_event=kind,identity_state="exact",timestamp_state="ready",session_identity_key="radius-session:"+new string('a',64),exact_principal_key="synthetic-principal",observed_at_utc=$"2026-01-01T00:0{i+1}:00Z",canonical_record_sha256=new string('b',64),evidence_uid=$"00000000-0000-4000-8000-{i+1:D12}",source_instance_id="synthetic-radius",stream_id="accounting",transport_binding="synthetic-binding",object_reference="evidence:synthetic",object_sha256=new string('b',64),object_size_bytes=100,verified_at_utc="2026-01-01T01:00:00Z"})).ToList();
    }
    internal static string RowId=>RadiusSessionFold.Fold(Observations())[0]["session_row_id"]!.ToString();
    internal static AccessFacts MakeFacts(bool owner=true,bool catalog=true)
    {
        var capabilities=catalog?new[]{JsonSerializer.SerializeToElement(new {capability_key="reports.catalog",effect="allow",scope_json=new {kind="all"}})}:Array.Empty<JsonElement>();
        return new(owner,"operator",[],[],capabilities,[],[],[],[JsonSerializer.SerializeToElement(new {report_key="vpn.audit",version=1,dataset_version=1,definition_json=new {field_categories=Categories,actions=new[]{"view","export"},required_capabilities=Array.Empty<string>()},fields_json=Categories.Select(c=>new {key=c,category=c}),actions_json=new[]{"view","export"}})]);
    }
    sealed class Facts(AccessFacts facts) : IAccessFactsRepository {public Task<AccessFacts> LoadAsync(Principal p,CancellationToken ct)=>Task.FromResult(facts);}
    sealed class Authentication(bool allowed=true,string role="operator") : IPrincipalAuthenticator
    {public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context,CancellationToken ct)=>ValueTask.FromResult(allowed?AuthenticationResult.Success(new("session",1,role)):AuthenticationResult.Denied(401,"authentication_required"));}
    internal sealed class Store : IVpnStore,IVpnReadSession
    {
        public int Opens;public bool AccountingReady;public bool Installed=true,Enabled=true,MissingSession;public readonly List<(string Sql,object?[] Values)> Calls=[];
        public Task<IVpnReadSession> OpenAsync(CancellationToken ct) {Opens++;return Task.FromResult<IVpnReadSession>(this);}
        public ValueTask DisposeAsync()=>ValueTask.CompletedTask;
        public bool AccountingConfigured => AccountingReady;
        public async Task<IVpnReadSession?> OpenAccountingAsync(CancellationToken ct) => AccountingReady ? await OpenAsync(ct) : null;
        public Task<List<JsonObject>> ReadAsync(string sql,object?[] values,CancellationToken ct)
        {
            Calls.Add((sql,values));List<JsonObject> result;
            if(sql.Contains("read_plugin_states_v1",StringComparison.Ordinal)) result=[Json(new {installed=Installed,enabled=Enabled})];
            else if(sql==VpnSql.SessionDomains || sql==VpnSql.WindowsDomains) result=(long)values[0]!<1?[Json(new {domain_id=1})]:[];
            else if(sql==VpnSql.WindowsPresent) result=[Json(new {source_present=true})];
            else if(sql==VpnSql.Coverage) result=MissingSession?[]:[Json(new {domain_id=1,total_delivery_count=3,projected_session_count=1,delivered_delivery_count=3})];
            else if(sql==VpnSql.Evidence) result=MissingSession?[]:Observations();
            else if(sql.Contains("from radius_vpn_session_rows_v1",StringComparison.Ordinal))
            {var row=(JsonObject)RadiusSessionFold.Fold(Observations())[0].DeepClone();foreach(string key in new[]{"session_identity_key","exact_principal_key","observation_ids","evidence_sha256s"}) row.Remove(key);row["domain_id"]=1;row["entity_id"]=7;result=[row];}
            else if(sql==VpnSql.FailedEvents || sql==VpnSql.NpsEvents) result=[Json(new {event_db_id=19,event_record_id=20,event_id=6273,time_created_utc="2026-01-01T00:02:00Z",source_ip="192.0.2.7",subject_user_sid="S-1-5-21-100000001-200000002-300000003-7",alias_match_count=1,entity_id=7,reason_code="16",source_core_sha256=new string('c',64)})];
            else if(sql==VpnSql.FailedCoverage) result=[Json(new {history_event_count=1,window_success_6272_count=0,window_failed_6273_count=1})];
            else if(sql==VpnSql.NpsCoverage) {Assert.Equal(4,values.Length);Assert.Equal(1L,values[0]);Assert.Equal(1L,values[1]);result=[Json(new {history_event_present=true,window_success_6272_count=0,window_failed_6273_count=1})];}
            else if(sql==VpnSql.Identities || sql==VpnSql.FullIdentities) result=[Json(new {entity_id=7,display_name="Synthetic User",netbios_name="EXAMPLE",sam_account_name="synthetic",department="Synthetic"})];
            else if(sql==VpnSql.WindowsEvents) result=[Json(new {event_db_id=21,event_record_id=22,event_id=4625,time_created_utc="2026-01-01T00:02:00Z",domain_controller="dc.example.test",target_user_sid="S-1-5-21-100000001-200000002-300000003-7",target_user_name="synthetic",source_ip="192.0.2.7",source_core_sha256=new string('c',64)})];
            else if(sql==VpnSql.WindowsCoverage) result=[Json(new {history_event_present=true})];
            else if(sql==VpnSql.WindowsReview || sql==VpnSql.WindowsGrid || sql.Contains("from normalized_events n",StringComparison.Ordinal)) result=[];
            else if(sql==VpnSql.Entitlements) result=[Json(new {entity_id=7})];
            else if(sql.StartsWith("select key,value from platform_settings",StringComparison.Ordinal) || sql.StartsWith("select value from platform_settings",StringComparison.Ordinal)) result=[];
            else if(sql=="select id,fqdn from domains order by id limit 10001") result=[Json(new {id=1,fqdn="example.test"})];
            else if(sql=="select id from domains order by id limit 10001") result=[Json(new {id=1})];
            else if(sql.Contains("select d.id,d.fqdn,d.is_archived",StringComparison.Ordinal)) result=[Json(new {id=1,fqdn="example.test",is_archived=false,observed_at_utc="2026-01-01T00:00:00Z"})];
            else if(sql.Contains("select d.fields_json,r.definition_json",StringComparison.Ordinal)) result=[Json(new {fields_json=new[]{new {key="object_id",category="identity_basic",label="ID"},new {key="display_name",category="identity_basic",label="Пользователь"},new {key="department",category="hr",label="Подразделение"}},definition_json=new {export_policy="controlled",columns=new[]{new {key="object_id"},new {key="display_name"},new {key="department"}}}})];
            else if(sql.Contains("as filtered_count from vpn_accounts",StringComparison.Ordinal)) result=[Json(new {filtered_count=1})];
            else if(sql.Contains("select * from vpn_accounts",StringComparison.Ordinal)) {Assert.IsType<JsonObject>(values[0]);result=[Json(new {id=7,object_id="7",domain_id=1,display_name="Synthetic User",department="Synthetic"})];}
            else if(sql.Contains("as total_users",StringComparison.Ordinal)) result=[Json(new {total_users=1})];
            else if(sql.Contains("from ad_context_runs run",StringComparison.Ordinal)) result=new[]{"vpn_membership","directory_accounts","privileged_membership"}.Select(s=>Json(new {section_name=s,domain_count=1,complete_domain_count=1})).ToList();
            else throw new InvalidOperationException("Unexpected SQL in synthetic reader: "+sql);
            return Task.FromResult(result);
        }
    }
    internal static async Task<IHost> Host(IVpnStore store,AccessFacts? facts=null,bool authenticated=true,string role="operator")
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:AuthRequired"]="true" }).Build();
        return await new HostBuilder().ConfigureWebHost(web=>web.UseTestServer().ConfigureServices(services=>
        {
            services.AddRouting();services.AddLogging();services.AddSingleton<IConfiguration>(config);services.AddSingleton(new AuthRequestPolicy(config));services.AddSingleton(new TransportGate(config));
            services.AddSingleton<IPrincipalAuthenticator>(new Authentication(authenticated,role));services.AddSingleton<IAccessFactsRepository>(new Facts(facts??MakeFacts()));services.AddSingleton<IVpnStore>(store);
        }).Configure(app=> {app.UseRouting();app.UseEndpoints(routes=>routes.MapVpn());})).StartAsync(TestContext.Current.CancellationToken);
    }
    static string Path(string operation,string domain="1")=>"/api/v1/reports/vpn.audit/"+operation+(operation.EndsWith("sources",StringComparison.Ordinal)?"":$"?domain_id={domain}&time_from=2026-01-01T00:00:00Z&time_to=2026-01-02T00:00:00Z"+(operation=="sessions/evidence"?"&session_row_id="+RowId:""));
    public static TheoryData<string> Operations=>new(VpnEndpoints.Operations);
    [Theory,MemberData(nameof(Operations))]
    public async Task Every_v1_route_is_disabled_without_storage(string operation)
    {
        var store=new Store {Installed=true,Enabled=true}; using var host=await Host(store);
        using var response=await host.GetTestClient().GetAsync(Path(operation),TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);
        Assert.Contains("module_disabled",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)); Assert.Equal(0,store.Opens); Assert.Empty(store.Calls);
    }
    [Theory,MemberData(nameof(Operations))]
    public async Task Catalog_denial_precedes_plugin_and_payload_reads(string operation)
    {
        var store=new Store();using var host=await Host(store,MakeFacts(false,false));using var client=host.GetTestClient();using var response=await client.GetAsync(Path(operation),TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden,response.StatusCode);Assert.Equal(0,store.Opens);Assert.Empty(store.Calls);
    }
    [Theory,MemberData(nameof(Operations))]
    public async Task Missing_branch_rights_remain_not_authorized(string operation)
    {
        var store=new Store(); using var host=await Host(store,MakeFacts(false));
        using var response=await host.GetTestClient().GetAsync(Path(operation),TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden,response.StatusCode); Assert.Equal(0,store.Opens); Assert.Empty(store.Calls);
    }
    [Theory,MemberData(nameof(Operations))]
    public async Task Every_route_requires_authentication(string operation)
    {
        var store=new Store();using var host=await Host(store,authenticated:false);using var client=host.GetTestClient();using var response=await client.GetAsync(Path(operation),TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized,response.StatusCode);Assert.Equal(0,store.Opens);
    }
    [Theory]
    [InlineData("sessions","vpn_session_domain_invalid")]
    [InlineData("sessions/evidence","vpn_session_evidence_domain_invalid")]
    [InlineData("authorizations","vpn_audit_authorization_timeline_domain_invalid")]
    [InlineData("failed-authorizations/series","vpn_audit_failed_authorization_domain_invalid")]
    [InlineData("windows-authentication","windows_authentication_domain_invalid")]
    public async Task Disabled_module_ignores_domain_input_without_storage(string operation,string error)
    {
        var store=new Store(); using var host=await Host(store);
        using var response=await host.GetTestClient().GetAsync(Path(operation,"0"),TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode); Assert.DoesNotContain(error,await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)); Assert.Equal(0,store.Opens);
    }
    [Theory] [InlineData("session-sources")] [InlineData("windows-authentication-sources")]
    public async Task Disabled_discovery_never_reads_sources(string operation)
    {
        var store=new Store {Installed=true,Enabled=true}; using var host=await Host(store);
        using var response=await host.GetTestClient().GetAsync(Path(operation),TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);
        Assert.Contains("module_disabled",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)); Assert.Equal(0,store.Opens); Assert.Empty(store.Calls);
    }
    [Theory,MemberData(nameof(Operations))]
    public async Task Plugin_state_cannot_reenable_hidden_module(string operation)
    {
        var store=new Store {Installed=false,Enabled=false}; using var host=await Host(store);
        using var response=await host.GetTestClient().GetAsync(Path(operation),TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);
        Assert.Contains("module_disabled",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)); Assert.Equal(0,store.Opens); Assert.Empty(store.Calls);
    }
    [Theory] [InlineData("sessions")] [InlineData("sessions/evidence")]
    public async Task Missing_session_cannot_open_disabled_storage(string operation)
    {
        var store=new Store {Installed=true,Enabled=true,MissingSession=true}; using var host=await Host(store);
        using var response=await host.GetTestClient().GetAsync(Path(operation),TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);
        Assert.Contains("module_disabled",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)); Assert.Equal(0,store.Opens); Assert.Empty(store.Calls);
    }
    [Fact]
    public async Task Native_connections_use_accounting_projection_without_event_queries()
    {
        var store = new Store { AccountingReady = true };
        using var host = await Host(store);
        const string path = "/api/v2/reports/vpn.connections/data?domain=1&period=custom&from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z";
        using var response = await host.GetTestClient().GetAsync(path, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var payload = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Equal("Synthetic User", payload!["items"]![0]!["display_name"]!.ToString());
        Assert.Contains(store.Calls, call => call.Sql == VpnSql.ConnectionSessions);
        Assert.DoesNotContain(store.Calls, call => call.Sql == VpnSql.Entitlements);
        Assert.Null(payload["collections"]!["entitlements"]);
        Assert.Equal("domain_history", payload["coverage"]!["accounting_scope"]!.ToString());
        Assert.Equal(new[] { "accounting" }, payload["branches"]!.AsObject().Select(branch => branch.Key));
        Assert.DoesNotContain(store.Calls, call => call.Sql.StartsWith("module_disabled:", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Native_connections_publish_only_implemented_tabs()
    {
        var store = new Store { AccountingReady = true };
        using var host = await Host(store);
        using var client = host.GetTestClient();
        const string path = "/api/v2/reports/vpn.connections";
        using var declaration = await client.GetAsync(path, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, declaration.StatusCode);
        var payload = JsonNode.Parse(await declaration.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Equal(new[] { "employees", "daily", "departments" },
            payload!["views"]!.AsArray().Select(view => view!["key"]!.ToString()));
        Assert.Equal(new[] { "domain", "period", "q", "department", "status" },
            payload["params"]!.AsArray().Select(parameter => parameter!["key"]!.ToString()));
        int opened = store.Opens;
        using var inactive = await client.GetAsync(path + "/data?tab=authorizations", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, inactive.StatusCode);
        Assert.Equal(opened, store.Opens);
        const string window = "&period=custom&from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z";
        using var filter = await client.GetAsync(path + "/data?domain=1&department=Other" + window, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, filter.StatusCode);
        var filtered = JsonNode.Parse(await filter.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Empty(filtered!["items"]!.AsArray());
        using var retired = await client.GetAsync(path + "/data?domain=1&policy=Legacy" + window, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, retired.StatusCode);
    }

    [Theory] [InlineData("vpn.accounts")] [InlineData("vpn.connections")]
    public async Task V2_routes_are_disabled_after_access_checks(string report)
    {
        var store=new Store(); using(var host=await Host(store)) {
            foreach(var suffix in new[]{"","/data?typo=1","/export.csv","/rows/7/detail"}) {
                using var response=await host.GetTestClient().GetAsync("/api/v2/reports/"+report+suffix,TestContext.Current.CancellationToken);
                Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode); Assert.Contains("module_disabled",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            }
            Assert.Equal(0,store.Opens); Assert.Empty(store.Calls);
        }
        using var deniedHost=await Host(new Store(),MakeFacts(false));
        using var denied=await deniedHost.GetTestClient().GetAsync("/api/v2/reports/"+report+"/data",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden,denied.StatusCode);
    }
    [Theory]
    [InlineData("employees")] [InlineData("daily")] [InlineData("departments")] [InlineData("entitlements")]
    [InlineData("authorizations")] [InlineData("failed")] [InlineData("windows")] [InlineData("windows_heatmap")]
    [InlineData("session_overlap")] [InlineData("policy_denials")] [InlineData("policy_denials_growth")] [InlineData("policy_denials_events")]
    public async Task Every_connections_tab_is_disabled_without_storage(string tab)
    {
        var store=new Store(); using var host=await Host(store);
        using var response=await host.GetTestClient().GetAsync("/api/v2/reports/vpn.connections/data?tab="+tab,TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode); Assert.Equal(0,store.Opens); Assert.Empty(store.Calls);
    }
    [Theory] [InlineData("/api/v2/reports/vpn.accounts/rows/7/detail","report_detail_not_available")] [InlineData("/api/v2/reports/vpn.connections/rows/7/detail","report_detail_not_available")] [InlineData("/api/v2/reports/vpn.connections/export.csv","report_export_not_available")]
    public async Task Undeclared_operations_remain_disabled(string path,string error)
    {
        var store=new Store(); using var host=await Host(store);
        using var response=await host.GetTestClient().GetAsync(path,TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode); Assert.DoesNotContain(error,await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)); Assert.Equal(0,store.Opens);
    }
    [Fact] public async Task Disabled_export_cannot_return_a_file()
    {
        var store=new Store(); using var host=await Host(store);
        using var response=await host.GetTestClient().GetAsync("/api/v2/reports/vpn.accounts/export.csv",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode); Assert.Null(response.Content.Headers.ContentDisposition);
        Assert.Equal(0,store.Opens); Assert.Empty(store.Calls);
    }
}
