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
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Ad;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Infrastructure;
using Sli.Server.Reporting.V2;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Reporting;

// Behavioral vectors from tests/reporting/test_reporting_v2_field_access.py.
public sealed class ReportV2FieldAccessTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static readonly string[] AllFields = ["identity_basic", "technical", "security", "privilege", "hr", "contact"];
    static JsonObject O(string json) => ReportFixture.O(json);
    static IQueryCollection Query() => new QueryCollection();
    static AtomicReportGrant Grant(string[] fields, string scope = "{\"kind\":\"domain\",\"ids\":[1]}", string[]? actions = null)
        => new(ReportFixture.J(scope), fields.ToHashSet(), (actions ?? ["view", "export"]).ToHashSet(), 1, 1);
    static AccessDecision Access(ReportDefinition d, params AtomicReportGrant[] grants)
        => ReportFixture.Access() with { Reports = [new(d.AccessKey, true, grants)] };
    static AccessFacts Facts(string key, IEnumerable<string> fields)
    {
        var categories = fields.ToArray();
        var policies = AllFields.Select(f => "field." + f).Append("reports.export").Select(c => JsonSerializer.SerializeToElement(new { capability_key = c, effect = "allow", scope_json = new { kind = "all" } })).ToArray();
        var assignment = JsonSerializer.SerializeToElement(new { report_key = key, effect = "allow", allowed_actions = new[] { "view", "export" }, field_categories = categories, scope_json = new { kind = "domain", ids = new[] { 1 } } });
        var definition = JsonSerializer.SerializeToElement(new { report_key = key, version = 1, dataset_version = 1, definition_json = new { actions = new[] { "view", "export" } }, actions_json = new[] { "view", "export" }, fields_json = AllFields.Select(category => new { category }) });
        return new(false, "viewer", [], [], policies, [], [], [assignment], [definition]);
    }
    static ReportDefinition Definition() => new(O("""
        {"key":"file-audit.actions","access_rule":{"report_key":"file-audit.actions","scope":"domain","required_fields":["identity_basic"]},
         "params":[{"key":"department","kind":"text","required":true,"field_categories":["hr"]}],
         "columns":[{"key":"name","label":"Value"},{"key":"department","label":"Value","sortable":true,"field_categories":["hr"]}],
         "views":[{"key":"table","source":"items"},{"key":"restricted","source":"restricted","access_rule":{"report_key":"file-audit.actions","required_fields":["hr"]}}],
         "detail":{"query_available":true,"inline":"nested.reasons","columns":[],"access_rule":{"report_key":"file-audit.actions","required_fields":["hr"]}},
         "row_categories":{"nested.secret":["hr"]},"series_categories":{"hr_total":["hr"]},"metric_categories":{"hr_count":["hr"]},
         "limits":{"default":5,"max":10},"export":true}
        """));

    [Theory]
    [InlineData(0)][InlineData(1)][InlineData(2)][InlineData(3)]
    public void CategoriesCannotBorrowCoreScopeOrAction(int vector)
    {
        var d = Definition();
        var core = Grant(["identity_basic"], vector == 0 ? "{\"kind\":\"domain\",\"ids\":[1,2]}" : vector == 3 ? "{\"kind\":\"all\"}" : "{\"kind\":\"domain\",\"ids\":[1]}");
        var other = vector switch {
            1 => Grant(["hr"]),
            2 => Grant(["identity_basic", "hr"], "{\"kind\":\"domain\",\"ids\":[2]}", ["export"]),
            _ => Grant(["identity_basic", "hr"])
        };
        var projection = new ReportAccess(d, Access(d, core, other));
        Assert.False(projection.FieldsAllowed(["hr"]));
        Assert.False(projection.Declaration()["views"]![1]!["access"]!["allowed"]!.GetValue<bool>());
        var result = projection.Project(O("""{"state":"ok","items":[{"name":"Synthetic account","department":"hidden-marker"}]}"""));
        Assert.DoesNotContain("hidden-marker", result.ToJsonString());
    }

    [Fact]
    public void NestedInlineDetailSeriesAndItemsViewColumnsAreProjectedWithoutMutatingInput()
    {
        var d = Definition();
        d.Declaration["views"]![0]!["columns"] = JsonNode.Parse("""[{"key":"view_secret","field_categories":["hr"]}]""");
        var projection = new ReportAccess(d, Access(d, Grant(["identity_basic"])));
        var input = O("""{"state":"ok","items":[{"id":1,"nested":{"reasons":[{"value":"hidden-marker"}],"secret":"hidden-marker"},"view_secret":"hidden-marker"}],"series":{"hr_total":1},"collections":{"restricted":[{"value":"hidden-marker"}]}}""");
        var output = projection.Project(input);
        Assert.Equal("[{\"id\":1,\"nested\":{}}]", output["items"]!.ToJsonString());
        Assert.Empty(output["series"]!.AsObject()); Assert.Empty(output["collections"]!.AsObject());
        Assert.Contains("hidden-marker", input.ToJsonString());
        Assert.False(projection.Declaration()["detail"]!["access"]!["allowed"]!.GetValue<bool>());
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task DeniedViewOrDetailNeverExecutesReaderAndDefaultRemainsUsable(bool detail)
    {
        var d = Definition();
        await using var h = await ReportFixture.Start(Facts(d.Key, ["identity_basic"]), d);
        using var denied = await h.Client.GetAsync($"/api/v2/reports/{d.Key}/" + (detail ? "rows/1/detail" : "data?tab=restricted"), Ct);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        var body = await ReportFixture.Body(denied);
        Assert.Equal("denied", body["state"]!.ToString()); Assert.Equal("report_field_categories_not_allowed", body["reason"]!.ToString());
        Assert.Equal(0, h.Reader.Calls);
        using var allowed = await h.Client.GetAsync($"/api/v2/reports/{d.Key}/data", Ct);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode); Assert.Equal(1, h.Reader.Calls);
    }

    [Fact]
    public async Task DeniedDefaultViewNeverExecutesReader()
    {
        var d = Definition(); d.Declaration["views"]!.AsArray().RemoveAt(0);
        await using var h = await ReportFixture.Start(Facts(d.Key, ["identity_basic"]), d);
        using var response = await h.Client.GetAsync($"/api/v2/reports/{d.Key}/data", Ct);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Equal(0, h.Reader.Calls);
        Assert.Equal("report_field_categories_not_allowed", (await ReportFixture.Body(response))["reason"]!.ToString());
    }

    [Fact]
    public async Task SeparateReportRuleDeniesOnlyItsView()
    {
        var d = Definition(); d.Declaration["views"]![1]!["access_rule"]!["report_key"] = "fixture.detail";
        d.Declaration["params"] = new JsonArray();
        await using var h = await ReportFixture.Start(Facts(d.Key, ["identity_basic", "hr"]), d);
        using var ok = await h.Client.GetAsync($"/api/v2/reports/{d.Key}/data", Ct);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        using var denied = await h.Client.GetAsync($"/api/v2/reports/{d.Key}/data?tab=restricted", Ct);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        Assert.Equal("report_access_denied", (await ReportFixture.Body(denied))["reason"]!.ToString()); Assert.Equal(1, h.Reader.Calls);
    }

    [Theory]
    [InlineData("")][InlineData("/data")][InlineData("/export.csv")]
    public async Task CoreCategoryDenialUsesSafeReasonBeforeReader(string suffix)
    {
        var d = Definition(); await using var h = await ReportFixture.Start(Facts(d.Key, ["hr"]), d);
        using var response = await h.Client.GetAsync($"/api/v2/reports/{d.Key}{suffix}", Ct);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Equal(0, h.Reader.Calls);
        Assert.Equal("report_field_categories_not_allowed", (await ReportFixture.Body(response))["reason"]!.ToString());
    }

    [Fact]
    public async Task HiddenRequiredParameterDoesNotCloseReportAndCsvUsesPositionsForDuplicateLabels()
    {
        var d = Definition(); await using var h = await ReportFixture.Start(Facts(d.Key, ["identity_basic"]), d);
        h.Reader.Csv = "Value,Value\r\nSynthetic account,hidden-marker\r\n";
        using var data = await h.Client.GetAsync($"/api/v2/reports/{d.Key}/data", Ct);
        Assert.Equal(HttpStatusCode.OK, data.StatusCode);
        using var csv = await h.Client.GetAsync($"/api/v2/reports/{d.Key}/export.csv", Ct);
        Assert.Equal(HttpStatusCode.OK, csv.StatusCode);
        Assert.Equal("Value\r\nSynthetic account\r\n", await csv.Content.ReadAsStringAsync(Ct));
    }

    [Theory]
    [InlineData("")][InlineData("/data")]
    public async Task FilterOptionsUseDeclaredSourceKey(string suffix)
    {
        var d = Definition(); d.Declaration["params"] = JsonNode.Parse("""[{"key":"department","kind":"choice","options_from":"departments"}]""");
        var options = O("""{"departments":[{"value":"Synthetic department"}]}""");
        var reader = new ReportFixture.Reader { Options = options, Query = _ => new JsonObject { ["state"] = "ok", ["items"] = new JsonArray(), ["filter_options"] = options.DeepClone() } };
        await using var h = await ReportFixture.Start(Facts(d.Key, ["identity_basic"]), d, suppliedReader: reader);
        using var response = await h.Client.GetAsync($"/api/v2/reports/{d.Key}{suffix}", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Synthetic department", (await ReportFixture.Body(response))["filter_options"]!["departments"]![0]!["value"]!.ToString());
    }

    [Theory]
    [InlineData("enabled", "")][InlineData("enabled", "/data")]
    [InlineData("disabled", "")][InlineData("disabled", "/data")]
    [InlineData("unknown", "")][InlineData("unknown", "/data")]
    [InlineData("database_failure", "")][InlineData("database_failure", "/data")]
    [InlineData("runtime_failure", "")][InlineData("runtime_failure", "/data")]
    public async Task PluginAnnotationAndLookupFailuresPreserveFieldProjection(string state, string suffix)
    {
        var d = Definition(); d.Declaration["key"] = "vpn.connections"; d.Rule["report_key"] = "vpn.audit";
        var plugin = state.EndsWith("failure", StringComparison.Ordinal)
            ? await new ReportV2Metadata(new FailedConnections(state == "database_failure")).PluginAsync(d.Key, Ct)
            : O($$"""{"plugin_id":"sli.remote-access","state":"{{state}}","read_only":{{(state != "enabled" ? "true" : "false")}}}""");
        var reader = new ReportFixture.Reader { OwnerId = "sli.remote-access", ReportKey = d.Key, Options = O("""{"department":[{"value":"hidden-marker"}]}"""), Query = _ => O("""{"state":"ok","items":[{"id":1,"name":"Synthetic account","department":"hidden-marker"}],"metrics":[{"key":"hr_count","value":1}],"filter_options":{"department":[{"value":"hidden-marker"}]}}""") };
        await using var h = await ReportFixture.Start(Facts(d.AccessKey, ["identity_basic"]), d, suppliedReader: reader, metadata: new ReportFixture.Metadata { Plugin = plugin });
        using var response = await h.Client.GetAsync($"/api/v2/reports/{d.Key}{suffix}", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); var body = await ReportFixture.Body(response);
        Assert.True(JsonNode.DeepEquals(plugin, body["plugin"])); Assert.True(body["access"]!["allowed"]!.GetValue<bool>());
        Assert.Equal("[\"hr\"]", body["access"]!["hidden_categories"]!.ToJsonString());
        Assert.DoesNotContain("hidden-marker", body.ToJsonString()); Assert.DoesNotContain("lookup-failure-marker", body.ToJsonString());
        Assert.Empty(body["filter_options"]!.AsObject());
        if (suffix.Length > 0) { Assert.Single(body["items"]!.AsArray()); Assert.Empty(body["metrics"]!.AsArray()); }
        else { Assert.Single(body["columns"]!.AsArray()); Assert.Empty(body["params"]!.AsArray()); }
    }
    sealed class FailedConnections(bool database) : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => throw (database ? new NpgsqlException("lookup-failure-marker") : new InvalidOperationException("lookup-failure-marker"));
    }

    static async Task<IHost> AdHost(IAdV2Store store, ReportFixture.FactsRepo facts)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "true" }).Build();
        return await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s => {
            s.AddRouting(); s.AddLogging(); s.AddSingleton<IConfiguration>(config);
            s.AddSingleton(new AuthRequestPolicy(config)); s.AddSingleton(new TransportGate(config));
            s.AddSingleton<IPrincipalAuthenticator>(new ReportFixture.Auth()); s.AddSingleton<IAccessFactsRepository>(facts);
            s.AddSingleton(store); s.AddSingleton<IReportCatalogProvider>(new ReportRuleCatalog(new PluginGenerationReader(null)));
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => e.MapAdV2()); })).StartAsync(Ct);
    }
    sealed class UnreadStore : IAdV2Store
    {
        public int Reads;
        public Task<IReadOnlyList<JsonObject>> DomainsAsync(DomainGrant grant, CancellationToken ct) => Task.FromResult<IReadOnlyList<JsonObject>>([O("""{"id":1,"display_name":"example.test"}""")]);
        public Task<JsonObject> ReadAsync(AdV2Request request, Func<IEnumerable<string>, bool> fields, CancellationToken ct)
        { Reads++; throw new InvalidOperationException("denied tab read snapshot"); }
    }
    [Theory]
    [InlineData("all", "security")][InlineData("checks", "security")][InlineData("checks", "technical")]
    [InlineData("checks", "privilege")][InlineData("privileged", "security")][InlineData("privileged", "privilege")]
    public async Task UsersTabsDenyMissingAtomicCategoryBeforeSourceRead(string tab, string missing)
    {
        var store = new UnreadStore(); var facts = new ReportFixture.FactsRepo(Facts("ad.users.v2", AllFields.Except([missing])));
        using var host = await AdHost(store, facts); using var client = host.GetTestClient();
        using var metadata = await client.GetAsync("/api/v2/reports/ad.users.v2", Ct);
        Assert.Equal(HttpStatusCode.OK, metadata.StatusCode);
        var view = (await ReportFixture.Body(metadata))["views"]!.AsArray().Single(v => v!["key"]!.ToString() == tab);
        Assert.False(view!["access"]!["allowed"]!.GetValue<bool>());
        using var data = await client.GetAsync("/api/v2/reports/ad.users.v2/data?tab=" + tab, Ct);
        Assert.Equal(HttpStatusCode.Forbidden, data.StatusCode); Assert.Equal("denied", (await ReportFixture.Body(data))["state"]!.ToString()); Assert.Equal(0, store.Reads);
    }

    [Fact]
    public async Task UsersHiddenCategoriesCannotAffectSearchDetailsMetricsOptionsOrCsv()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db, """
            create table domains(id bigint primary key,fqdn text,is_archived boolean);
            insert into domains values(1,'example.test',false);
            create table platform_settings(key text,value text);
            insert into platform_settings values('reports.domain_fqdn','example.test');
            create table ad_context_runs(domain_id bigint,status text,observed_at_utc timestamptz);
            create table ad_snapshot_manifests(manifest_id uuid,domain_id bigint,slot_start_utc timestamptz,coverage_state text);
            insert into ad_snapshot_manifests values('00000000-0000-0000-0000-000000000001',1,now(),'complete');
            create table ad_snapshot_manifest_sources(manifest_id uuid,family text,source_state text,observed_at_utc timestamptz,payload_sha256 bytea,source_id text);
            create table users_report_v2_snapshots(snapshot_id bigint,domain_id bigint,payload_json jsonb,payload_sha256 bytea,scope_json jsonb);
            """, Ct);
        var snapshot = O("""{"metadata":{"observed_at":"2026-10-05T00:00:00Z","collection_status":"completed"},"users":[{"id":"fixture-user","entityId":1,"samAccountName":"fixture","displayName":"Synthetic account","enabled":true,"department":"hidden-marker","mail":"hidden-marker","description":"hidden-marker","lockedOut":true,"memberships":{"status":"partial","unresolved":["hidden-marker"],"effective":[{"id":"group","name":"hidden-marker","watchGroup":true}]}}],"groups":[{"id":"group","name":"hidden-marker"}]}""");
        async Task Seed()
        {
            await using var command = new NpgsqlCommand("""
                delete from users_report_v2_snapshots; delete from ad_snapshot_manifest_sources;
                insert into users_report_v2_snapshots values(1,1,@payload,decode(@hash,'hex'),'{}');
                insert into ad_snapshot_manifest_sources values('00000000-0000-0000-0000-000000000001','users_v2','complete',now(),decode(@hash,'hex'),'1');
                """, db);
            command.Parameters.AddWithValue("payload", NpgsqlTypes.NpgsqlDbType.Jsonb, snapshot.ToJsonString()); command.Parameters.AddWithValue("hash", AdJobPlugin.Digest(snapshot));
            await command.ExecuteNonQueryAsync(Ct);
        }
        await Seed();
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["ConnectionStrings:Sli"] = pg.ConnectionString, ["Sli:Storage:HistoryReadMode"] = "disabled" }).Build();
        var facts = new ReportFixture.FactsRepo(Facts("ad.users.v2", AllFields));
        using var host = await AdHost(new AdV2Store(new PostgresConnectionFactory(config), config), facts); using var client = host.GetTestClient();
        foreach (string category in new[] { "hr", "contact", "security", "privilege", "technical" })
        {
            facts.Value = Facts("ad.users.v2", AllFields.Except([category]));
            using var response = await client.GetAsync("/api/v2/reports/ad.users.v2/data?tab=all", Ct);
            if (category == "security") { Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); continue; }
            Assert.Equal(HttpStatusCode.OK, response.StatusCode); var body = await ReportFixture.Body(response); var row = Assert.Single(body["items"]!.AsArray())!.AsObject();
            string[] hidden = category switch { "hr" => ["department", "company", "title", "manager", "employee_id"], "contact" => ["mail", "phones"], "technical" => ["description", "sid", "guid", "dn", "ou", "created", "changed", "spn"], _ => ["direct_groups", "effective_count", "watch_groups"] };
            Assert.All(hidden, key => Assert.False(row.ContainsKey(key), category + ":" + key));
            if (category is "technical" or "privilege")
            {
                Assert.All(new[] { "reasons", "reason_keys", "reason_text", "information_limitations", "information_keys", "information_text", "review_details" }, key => Assert.False(row.ContainsKey(key)));
                Assert.All(body["metrics"]!.AsArray(), m => Assert.Equal("all", m!["key"]!.ToString()));
            }
            foreach (string key in category switch { "hr" => new[] { "department", "company" }, "technical" => ["ou", "reason"], "privilege" => ["group", "reason"], _ => Array.Empty<string>() })
                Assert.Null(body["filter_options"]![key]);
            if (category == "hr")
            {
                using var metadata = await client.GetAsync("/api/v2/reports/ad.users.v2", Ct);
                Assert.Equal(HttpStatusCode.OK, metadata.StatusCode);
                Assert.DoesNotContain((await ReportFixture.Body(metadata))["columns"]!.AsArray(), c => hidden.Contains(c!["key"]!.ToString()));
            }
        }
        // Isolate each hidden attribute so another visible attribute cannot satisfy the query.
        foreach (var (category, attribute) in new[] { ("hr", "department"), ("hr", "employeeID"), ("contact", "mail"), ("contact", "telephoneNumber"), ("technical", "sid") })
        {
            snapshot["users"] = JsonNode.Parse("""[{"id":"fixture-user","entityId":1,"displayName":"Synthetic account","samAccountName":"fixture","enabled":true}]""");
            snapshot["users"]![0]![attribute] = "hidden-marker"; snapshot["groups"] = new JsonArray(); await Seed();
            facts.Value = Facts("ad.users.v2", AllFields.Except([category]));
            using var searched = await client.GetAsync("/api/v2/reports/ad.users.v2/data?tab=all&q=hidden-marker", Ct);
            Assert.Equal(HttpStatusCode.OK, searched.StatusCode); var body = await ReportFixture.Body(searched);
            Assert.Empty(body["items"]!.AsArray()); Assert.Equal(0, body["filtered_count"]!.GetValue<int>());
            using var exported = await client.GetAsync("/api/v2/reports/ad.users.v2/export.csv?tab=all", Ct);
            Assert.Equal(HttpStatusCode.OK, exported.StatusCode); Assert.DoesNotContain("hidden-marker", await exported.Content.ReadAsStringAsync(Ct));
            // Retained shared snapshot still contains the source attribute, including after export.
            await using var stored = new NpgsqlCommand("select payload_json->'users'->0->>@attribute from users_report_v2_snapshots", db);
            stored.Parameters.AddWithValue("attribute", attribute); Assert.Equal("hidden-marker", await stored.ExecuteScalarAsync(Ct));
        }
    }
}
