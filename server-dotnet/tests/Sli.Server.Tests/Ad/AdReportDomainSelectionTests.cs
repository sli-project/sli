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
using Microsoft.Extensions.Primitives;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Access;
using Sli.Server.Ad;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Ad;

// Vectors from tests/reporting/test_ad_report_domain_selection.py.
public sealed class AdReportDomainSelectionTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static readonly long[] Registered = [11, 22];
    static readonly string[] Keys = ["ad.users.v2", "ad.computers.v6", "ad.infrastructure"];
    static readonly string[] Categories = ["identity_basic", "technical", "security", "privilege", "contact", "hr", "raw_evidence"];
    static string Name(long id) => id == 11 ? "alpha.example.test" : "beta.example.test";
    static JsonObject Obj(object value) => JsonSerializer.SerializeToNode(value)!.AsObject();
    static long[] Ids(JsonNode? nodes, string? field = null) => nodes!.AsArray().Select(n => long.Parse((field is null ? n : n![field])!.ToString())).ToArray();
    static AdV2Request Request(string key, long[] ids, string? tab = null) => new(key, "view", null, ids,
        key == "ad.computers.v6" ? Obj(new { view = "all" }) : new(), tab ?? (key == "ad.users.v2" ? "active" : "computers"), null, false, 100, null, "UTC") { QualifyNames = ids.Length > 1 };

    sealed class Auth : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c, CancellationToken ct) =>
            ValueTask.FromResult(AuthenticationResult.Success(new("session", 1, "operator")));
    }
    sealed class Facts(long[]? view = null, long[]? export = null, bool all = false, bool otherReport = false) : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal p, CancellationToken ct)
        {
            var definitions = Keys.Select(key => AdV2Endpoints.Definitions[key]!["access_key"]!.ToString()).Distinct().Select(key =>
                JsonSerializer.SerializeToElement(new { report_key = key, version = 1, dataset_version = 1,
                    definition_json = new { field_categories = Categories, actions = new[] { "view", "export" } },
                    fields_json = Categories.Select(category => new { category }), actions_json = new[] { "view", "export" } })).ToArray();
            var policies = Categories.Select(f => "field." + f).Concat(["workspace.view", "reports.export", "events.view", "evidence.exact"]).Select(key =>
                JsonSerializer.SerializeToElement(new { capability_key = key, effect = "allow", scope_json = new { kind = "all" } })).ToArray();
            var assignments = definitions.SelectMany(d => new[] { "view", "export" }.Select(action =>
            {
                string report = d.GetProperty("report_key").GetString()!;
                long[] ids = otherReport && report == AdV2Endpoints.Definitions["ad.computers.v6"]!["access_key"]!.ToString() ? [22] : action == "export" ? export ?? view ?? Registered : view ?? Registered;
                return JsonSerializer.SerializeToElement(new { report_key = report, effect = "allow",
                    scope_json = all ? (object)new { kind = "all" } : new { kind = "domain", ids },
                    field_categories = Categories, allowed_actions = action == "export" ? new[] { "view", "export" } : ["view"] });
            })).ToArray();
            return Task.FromResult(new AccessFacts(false, "operator", [], [], policies, [], [], assignments, definitions));
        }
    }
    sealed class Catalog : IReportCatalogProvider
    {
        public ReportCatalogSnapshot Capture() => new(Keys.Select(key => new ReportRule(key,
            AdV2Endpoints.Definitions[key]!["access_key"]!.ToString(), "domain", new HashSet<string>(), new HashSet<string>(), null, false) { OwnerId = "sli.ad" }),
            new Dictionary<string, PluginGeneration>(), new Dictionary<string, string>());
        public ReportCatalogSnapshot Recheck(ReportCatalogSnapshot captured) => captured;
    }
    sealed class Store(IAdV2Store? actual = null) : IAdV2Store
    {
        public readonly List<DomainGrant> Metadata = [];
        public readonly List<AdV2Request> Reads = [];
        public Exception? Failure;
        public long[] Archived = [];
        public Task<IReadOnlyList<JsonObject>> DomainsAsync(DomainGrant grant, CancellationToken ct)
        {
            Metadata.Add(grant);
            return Task.FromResult<IReadOnlyList<JsonObject>>(Registered.Where(id => grant.Kind == DomainGrantKind.All || grant.DomainIds.Contains(id)).Select(id =>
                Obj(new { id, display_name = Name(id), is_archived = Archived.Contains(id), is_preferred = id == 22,
                    observed_at_utc = DateTimeOffset.UtcNow.AddDays(id == 22 ? -2 : 0).ToString("O") })).ToArray());
        }
        public async Task<JsonObject> ReadAsync(AdV2Request request, Func<IEnumerable<string>, bool> fields, CancellationToken ct)
        {
            Reads.Add(request);
            if (actual is not null)
            {
                try { return await actual.ReadAsync(request, fields, ct); }
                catch (Exception error) { Failure = error; throw; }
            }
            var result = AdV2Store.Result(request.Key, "ok", request.Domains.Select(id => Obj(new { entity_id = id, domain_id = id, display_name = Name(id), entity_name = Name(id), title = Name(id) })));
            result["filtered_count"] = request.Domains.Length;
            result["metrics"] = new JsonArray(Obj(new { key = "all", label = "All", value = request.Domains.Length }));
            return result;
        }
    }
    static Task<IHost> Host(Store store, Facts? facts = null)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "true" }).Build();
        return new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s =>
        {
            s.AddRouting(); s.AddLogging(); s.AddSingleton<IConfiguration>(config);
            s.AddSingleton(new AuthRequestPolicy(config)); s.AddSingleton(new TransportGate(config));
            s.AddSingleton<IPrincipalAuthenticator, Auth>(); s.AddSingleton<IAccessFactsRepository>(facts ?? new Facts());
            s.AddSingleton<IAdV2Store>(store); s.AddSingleton<IReportCatalogProvider, Catalog>();
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => e.MapAdV2()); })).StartAsync(Ct);
    }
    public static IEnumerable<object[]> Routes() => Keys.SelectMany(key => new[] { "data", "export.csv" }.SelectMany(action => new[] { false, true }.Select(selected => new object[] { key, action, selected })));
    public static IEnumerable<object[]> DeniedRoutes() => Keys.SelectMany(key => new[] { "data", "export.csv" }.Select(action => new object[] { key, action }));
    [Theory, MemberData(nameof(Routes))]
    public async Task Rows_counts_metrics_metadata_and_csv_use_selected_report_scope(string key, string action, bool selected)
    {
        var store = new Store(); using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync($"/api/v2/reports/{key}/{action}" + (selected ? "?domain_id=22" : ""), Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        long[] expected = selected ? [22] : Registered;
        Assert.Equal(expected, Assert.Single(store.Reads).Domains);
        Assert.Equal(expected, Assert.Single(store.Metadata).DomainIds.Order().ToArray());
        string text = await response.Content.ReadAsStringAsync(Ct);
        if (action == "data")
        {
            var payload = JsonNode.Parse(text)!;
            Assert.Equal(expected, Ids(payload["items"], "domain_id"));
            Assert.Equal(expected.Length, (int)payload["filtered_count"]!);
            Assert.Equal(expected.Length, (int)payload["metrics"]![0]!["value"]!);
            Assert.Equal(expected, Ids(payload["domain_scope"]!["domain_ids"])); Assert.Equal(expected, Ids(payload["domains"], "id"));
            Assert.Equal(expected.Length, payload["domains"]!.AsArray().Select(d => d!["freshness"]!["observed_at_utc"]!.ToString()).Distinct().Count());
        }
        else
        {
            Assert.Equal(expected.Length.ToString(), Assert.Single(response.Headers.GetValues("X-Sli-Export-Rows")));
            foreach (long id in Registered) Assert.Equal(expected.Contains(id), text.Contains(Name(id)));
        }
    }
    [Theory, MemberData(nameof(DeniedRoutes))]
    public async Task Foreign_domain_is_denied_before_metadata_and_report_reads(string key, string action)
    {
        var store = new Store(); using var host = await Host(store, new Facts([11])); using var client = host.GetTestClient();
        using var response = await client.GetAsync($"/api/v2/reports/{key}/{action}?domain_id=22", Ct);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Empty(store.Metadata); Assert.Empty(store.Reads);
        Assert.Contains("domain_scope_denied", await response.Content.ReadAsStringAsync(Ct));
    }
    [Theory]
    [InlineData("")][InlineData("0")][InlineData("-1")][InlineData("all")][InlineData("11&domain_id=22")][InlineData("9223372036854775808")]
    public async Task Invalid_selection_is_rejected_before_any_read(string value)
    {
        var store = new Store(); using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v2/reports/ad.computers.v6/data?domain_id=" + value, Ct);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode); Assert.Empty(store.Metadata); Assert.Empty(store.Reads);
        Assert.Contains("domain_scope_invalid", await response.Content.ReadAsStringAsync(Ct));
    }
    [Fact]
    public void Zero_values_are_invalid_even_when_query_collection_contains_the_key()
    {
        var context = new DefaultHttpContext(); context.Request.Query = new QueryCollection(new Dictionary<string, StringValues> { ["domain_id"] = StringValues.Empty });
        Assert.Equal("domain_scope_invalid", Assert.Throws<AdInputException>(() => AdV2Endpoints.Parse(context.Request, "ad.computers.v6", "view", Registered)).Message);
    }
    [Fact]
    public async Task Export_uses_export_grants_and_other_reports_cannot_authorize_users()
    {
        foreach (var (key, action, facts) in new[] { ("ad.computers.v6", "export.csv", new Facts(export: [11])), ("ad.users.v2", "data", new Facts([11], otherReport: true)) })
        {
            var store = new Store(); using var host = await Host(store, facts); using var client = host.GetTestClient();
            using var response = await client.GetAsync($"/api/v2/reports/{key}/{action}?domain_id=22", Ct);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Empty(store.Metadata); Assert.Empty(store.Reads);
        }
    }
    [Theory][InlineData("")][InlineData("?domain_id=22")]
    public async Task All_grant_is_materialized_to_registered_domains(string query)
    {
        var store = new Store(); using var host = await Host(store, new Facts(all: true)); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v2/reports/ad.infrastructure/data" + query, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Equal(query.Length == 0 ? Registered : [22], Assert.Single(store.Reads).Domains);
    }
    [Theory][InlineData("domain=22")][InlineData("domain=22&domain_id=22")][InlineData("domain=22&domain_id=11")]
    public async Task Legacy_alias_preserves_selection_and_conflicts_fail_before_reads(string query)
    {
        var store = new Store(); using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v2/reports/ad.users.v2/data?" + query, Ct);
        bool conflict = query.EndsWith("11", StringComparison.Ordinal);
        Assert.Equal(conflict ? HttpStatusCode.BadRequest : HttpStatusCode.OK, response.StatusCode);
        if (conflict) { Assert.Empty(store.Metadata); Assert.Empty(store.Reads); }
        else Assert.Equal([22L], Assert.Single(store.Reads).Domains);
    }
    [Fact]
    public async Task Stale_grant_returns_empty_changes_without_reading_foreign_saved_snapshots()
    {
        var store = new Store(); using var host = await Host(store, new Facts([99])); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v2/reports/ad.users.v2/data?tab=changes", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Equal([99L], Assert.Single(store.Metadata).DomainIds); Assert.Empty(store.Reads);
        var payload = JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!;
        Assert.Empty(payload["domain_scope"]!["domain_ids"]!.AsArray()); Assert.Empty(payload["items"]!.AsArray()); Assert.Empty(payload["collections"]!["changes"]!.AsArray());
    }
    [Fact]
    public async Task Declaration_chooses_only_authorized_nonarchived_domain()
    {
        var store = new Store(); using var host = await Host(store, new Facts([11])); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v2/reports/ad.computers.v6", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); var payload = JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!;
        Assert.Equal(11, (int)payload["default_domain_id"]!); Assert.Equal("available", payload["default_domain_state"]!.ToString());
    }
    sealed class NoConnection : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => throw new InvalidOperationException("empty scope connected");
    }
    [Theory][InlineData("ad.users.v2")][InlineData("ad.computers.v6")][InlineData("ad.infrastructure")]
    public async Task Empty_scope_never_connects(string key)
    {
        var store = new AdV2Store(new NoConnection(), new ConfigurationBuilder().Build());
        var result = await store.ReadAsync(Request(key, []), _ => true, Ct);
        Assert.Empty(result["items"]!.AsArray()); Assert.Empty(result["coverage"]!["domains"]!.AsArray());
    }

    static async Task Seed(NpgsqlConnection db)
    {
        await PostCollectionPostgres.Sql(db, """
            create role adlog_user;
            create table domains(id bigint primary key,fqdn text);
            insert into domains values(11,'alpha.example.test'),(22,'beta.example.test');
            create table ad_snapshot_manifests(manifest_id uuid,domain_id bigint,slot_start_utc timestamptz,assembled_at_utc timestamptz,coverage_state text);
            create table ad_snapshot_manifest_sources(manifest_id uuid,family text,source_state text,observed_at_utc timestamptz,payload_sha256 bytea,source_id text);
            create table users_report_v2_snapshots(snapshot_id bigint,domain_id bigint,payload_json jsonb,payload_sha256 bytea,scope_json jsonb);
            create table computers_v6_source_snapshots(snapshot_uuid uuid,domain_id bigint,payload_json jsonb,payload_sha256 bytea,source_options_json jsonb);
            create table ad_context_entity_aliases(domain_id bigint,alias_type text,normalized_value text,entity_id bigint);
            create table platform_settings(key text,value text);
            create table findings(id bigint,title text,status text,summary text,why_it_matters text,recommended_action text,last_seen_utc timestamptz);
            create table finding_entities(finding_id bigint,entity_id bigint);
            create table entities_v2_active(id bigint,display_name text,entity_type_id bigint);
            create table storage_v2_entity_type(id bigint,value text);
            create function is_semantic_finding_published_v1(bigint) returns boolean language sql as 'select false';
            """, Ct);
        await PostCollectionPostgres.InstallSnapshotChangeStorageAsync(db, Ct);
        const string guid = "00000000-0000-0000-0000-000000000001";
        foreach (long domain in Registered)
        {
            await using var alias = new NpgsqlCommand("insert into ad_context_entity_aliases values(@domain,'object_guid',@guid,@domain)", db);
            alias.Parameters.AddWithValue("domain", domain); alias.Parameters.AddWithValue("guid", guid); await alias.ExecuteNonQueryAsync(Ct);
            foreach (int version in new[] { 1, 2 })
            {
                var manifest = Guid.NewGuid(); var snapshot = Guid.NewGuid();
                // Another domain's current snapshot falls between this domain's current and previous.
                var observed = DateTimeOffset.UtcNow.AddDays((domain == 22 ? -2 : 0) - 10 * (2 - version)).AddMinutes(-1);
                observed = observed.AddTicks(-(observed.Ticks % 10)); // PostgreSQL timestamp precision.
                foreach (string family in new[] { "users_v2", "computers_v6" })
                {
                    var payload = family == "users_v2"
                        ? Obj(new { metadata = new { observed_at = observed.ToString("O") }, groups = System.Array.Empty<object>(), users = new[] {
                            new { id = "user:" + domain, entityId = domain, domainId = domain, domainName = Name(domain), objectGuid = guid,
                                displayName = "shared", samAccountName = "shared", enabled = version == 2,
                                memberships = new { direct = System.Array.Empty<object>(), effective = System.Array.Empty<object>() },
                                sourceStates = new { directory = new { status = "observed", observed_at = observed.ToString("O") } } } } })
                        : Obj(new { metadata = new { completed_at = observed.ToString("O") }, objects = new[] {
                            new { id = "computer:" + domain, objectGuid = guid, name = "shared", enabled = version == 2 } } });
                    string table = family == "users_v2" ? "users_report_v2_snapshots" : "computers_v6_source_snapshots";
                    string column = family == "users_v2" ? "snapshot_id" : "snapshot_uuid";
                    string scope = family == "users_v2" ? "scope_json" : "source_options_json";
                    await using var insert = new NpgsqlCommand($$"""
                        insert into {{table}}({{column}},domain_id,payload_json,payload_sha256,{{scope}}) values(@id,@domain,@payload,decode(@hash,'hex'),'{}');
                        insert into ad_snapshot_manifest_sources values(@manifest,@family,'complete',@observed,decode(@hash,'hex'),@source);
                        """, db);
                    insert.Parameters.AddWithValue("id", family == "users_v2" ? (object)(domain * 10 + version) : snapshot);
                    insert.Parameters.AddWithValue("domain", domain); insert.Parameters.AddWithValue("payload", NpgsqlDbType.Jsonb, payload.ToJsonString());
                    insert.Parameters.AddWithValue("hash", AdJobPlugin.Digest(payload)); insert.Parameters.AddWithValue("manifest", manifest);
                    insert.Parameters.AddWithValue("family", family); insert.Parameters.AddWithValue("observed", observed);
                    insert.Parameters.AddWithValue("source", family == "users_v2" ? (domain * 10 + version).ToString() : snapshot.ToString());
                    await insert.ExecuteNonQueryAsync(Ct);
                }
                await using var publish = new NpgsqlCommand("insert into ad_snapshot_manifests values(@id,@domain,@observed,@observed,'complete')", db);
                publish.Parameters.AddWithValue("id", manifest); publish.Parameters.AddWithValue("domain", domain); publish.Parameters.AddWithValue("observed", observed);
                await publish.ExecuteNonQueryAsync(Ct);
                if (version == 2) await PostCollectionPostgres.PublishSnapshotChangesAsync(db, manifest, Ct);
            }
        }
    }

    [Fact]
    public async Task Real_inventory_keeps_domain_identity_source_times_counts_csv_and_comparison_pairs()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct); await Seed(db);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["ConnectionStrings:Sli"] = pg.ConnectionString }).Build();
        var actual = new AdV2Store(new PostgresConnectionFactory(config), config);
        foreach (var source in await AdV2Store.Snapshots(db, "computers_v6", Registered, Ct))
        {
            var previous = await AdV2Store.PreviousSnapshot(db, source, "computers_v6", Ct);
            Assert.NotNull(previous); Assert.Equal(source["domain_id"]!.ToString(), previous["domain_id"]!.ToString());
            Assert.False((bool)previous["snapshot"]!["objects"]![0]!["enabled"]!);
        }
        foreach (string key in new[] { "ad.users.v2", "ad.computers.v6" })
        foreach (long[] scope in new[] { Registered, new long[] { 22 } })
        {
            var request = Request(key, scope); var result = await actual.ReadAsync(request, _ => true, Ct); AdV2Result.Finish(result);
            Assert.Equal(scope, Ids(result["items"], "domain_id").Order().ToArray());
            Assert.Equal(scope, Ids(result["items"], "entity_id").Order().ToArray());
            Assert.Equal(scope.Length, (int)result["filtered_count"]!); Assert.Equal(scope, Ids(result["coverage"]!["domains"], "domain_id"));
            foreach (var row in result["items"]!.AsArray())
            {
                long id = (long)row!["domain_id"]!;
                Assert.Equal(Name(id), row["domain_name"]!.ToString());
                var sourceTime = result["coverage"]!["domains"]!.AsArray().Single(d => (long)d!["domain_id"]! == id)!["observed_at_utc"]!.ToString();
                Assert.Equal(DateTimeOffset.Parse(sourceTime), DateTimeOffset.Parse(row["observed_at_utc"]!.ToString()));
            }
            var expected = scope.Select(id => scope.Length > 1 ? Name(id) + "\\shared" : "shared").Order().ToArray();
            Assert.Equal(expected, result["items"]!.AsArray().Select(row => row!["display_name"]!.ToString()).Order().ToArray());
            if (key == "ad.users.v2")
            {
                Assert.Equal(expected, result["items"]!.AsArray().Select(row => row!["sam"]!.ToString()).Order().ToArray());
                Assert.Equal(scope.Length, result["items"]!.AsArray().Select(row => row!["observed_at_utc"]!.ToString()).Distinct().Count());
            }
            else
            {
                Assert.Equal(scope.Length, (int)result["summary"]!["total_computers"]!);
                Assert.Equal(1, (int)result["coverage"]!["stale_domain_count"]!);
                Assert.Equal(scope.Length, (int)result["metrics"]![0]!["value"]!);
            }
            var columns = AdV2Endpoints.Definitions[key]!["declaration"]!["columns"]!.AsArray();
            string csv = key == "ad.users.v2" ? AdV2Endpoints.Csv(columns, result["items"]!.AsArray()) : AdInventoryRows.ComputerCsv(result["items"]!.AsArray());
            Assert.Equal(scope.Length + 1, csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries).Length);
            foreach (string name in expected) Assert.Contains(name, csv);
            var changes = await actual.ReadAsync(request with { Tab = "changes" }, _ => true, Ct);
            Assert.Equal(scope.Length, (int)changes["filtered_count"]!);
            Assert.All(changes["items"]!.AsArray(), row => Assert.Equal("enabled_changed", row![key == "ad.users.v2" ? "type" : "change_type"]!.ToString()));
        }
        // Explicit selection and accessible mode differ even with a single allowed domain.
        var probe = new Store(actual); using var host = await Host(probe, new Facts([22])); using var client = host.GetTestClient();
        foreach (bool selected in new[] { false, true })
        {
            using var response = await client.GetAsync("/api/v2/reports/ad.computers.v6/data?view=all" + (selected ? "&domain_id=22" : ""), Ct);
            Assert.True(response.StatusCode == HttpStatusCode.OK, probe.Failure?.ToString() ?? await response.Content.ReadAsStringAsync(Ct)); var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!;
            Assert.Equal(selected ? "shared" : "beta.example.test\\shared", body["items"]![0]!["display_name"]!.ToString());
        }
        // Directory facts can fill a gap only when their run matches the computer manifest's attestation.
        await PostCollectionPostgres.Sql(db, """
            create table ad_context_runs(run_id uuid,domain_id bigint,bundle_sha256 bytea,status text,observed_at_utc timestamptz);
            create table ad_context_entity_versions(id bigint,entity_id bigint,source_run_id uuid,source_section text,
                valid_from_utc timestamptz,last_observed_at_utc timestamptz,valid_to_utc timestamptz,attributes_json jsonb);
            create table ad_context_evidence(source_run_id uuid,evidence_key text);
            with latest as (
                select distinct on (domain_id) domain_id,manifest_id,slot_start_utc
                from ad_snapshot_manifests order by domain_id,slot_start_utc desc
            )
            insert into ad_context_runs
                select manifest_id,domain_id,decode(repeat('11',32),'hex'),'completed',slot_start_utc from latest;
            insert into ad_snapshot_manifest_sources(manifest_id,family,source_state,observed_at_utc,payload_sha256,source_id)
                select run_id,'ad_context_base','complete',observed_at_utc,
                       case when domain_id=11 then bundle_sha256 else decode(repeat('22',32),'hex') end,run_id::text
                from ad_context_runs;
            insert into ad_context_entity_versions
                select domain_id,domain_id,run_id,'directory_accounts',observed_at_utc,observed_at_utc,null,
                       '{"record_key":"computer","identity":{"kind":"ad_computer","object_guid":"00000000-0000-0000-0000-000000000001"},
                         "attributes":{"operating_system":"Windows Server 2022","last_logon_timestamp_utc":"2026-11-01T12:00:00Z"}}'
                from ad_context_runs;
            insert into ad_context_evidence select run_id,'adctx:' || run_id::text || ':computer' from ad_context_runs;
            """, Ct);
        var enriched = await actual.ReadAsync(Request("ad.computers.v6", Registered), _ => true, Ct);
        var computers = enriched["items"]!.AsArray().ToDictionary(row => (long)row!["domain_id"]!);
        Assert.Equal("Windows Server 2022", computers[11]?["operating_system"]?.ToString());
        Assert.Equal(DateTimeOffset.Parse("2026-11-01T12:00:00Z"), AdInventoryRows.Date(computers[11]!["last_logon_utc"]));
        Assert.Null(computers[22]!["operating_system"]);
        Assert.Null(computers[22]!["last_logon_utc"]);

        // A corrupt domain is unavailable; its payload is never used and another domain survives.
        await PostCollectionPostgres.Sql(db, "update computers_v6_source_snapshots set payload_json=jsonb_set(payload_json,'{objects,0,name}','\"foreign-corrupt\"') where domain_id=22", Ct);
        var partial = await actual.ReadAsync(Request("ad.computers.v6", Registered), _ => true, Ct);
        Assert.Equal("partial", partial["state"]!.ToString()); Assert.Equal([11L], Ids(partial["items"], "domain_id"));
        Assert.Equal("complete", partial["coverage"]!["domains"]![0]!["state"]!.ToString());
        Assert.Equal("unavailable", partial["coverage"]!["domains"]![1]!["state"]!.ToString()); Assert.DoesNotContain("foreign-corrupt", partial.ToJsonString());
    }

    [Fact]
    public void User_projection_keeps_domain_and_source_time_for_identical_logins()
    {
        using var stream = typeof(AdReportDomainSelectionTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Ad.snapshot-reference.json")!;
        var reference = JsonNode.Parse(stream)!;
        var users = Registered.Select(domain =>
        {
            var bundles = reference["bundles"]!.AsObject().ToDictionary(p => p.Key, p => p.Value!.DeepClone().AsObject());
            bundles["ad_context_base"]["observed_at_utc"] = DateTimeOffset.UtcNow.AddDays(domain == 22 ? -1 : 0).ToString("O");
            var ids = reference["ids"]!.AsObject().ToDictionary(p => p.Key, p => p.Value!.GetValue<long>());
            return AdUsersSnapshot.Build(bundles, domain, Name(domain), ids)["users"]![0]!;
        }).ToArray();
        Assert.Equal(Registered, users.Select(u => (long)u["domainId"]!).ToArray());
        Assert.Equal(Registered.Select(Name), users.Select(u => u["domainName"]!.ToString()));
        Assert.Single(users.Select(u => u["samAccountName"]!.ToString()).Distinct());
        Assert.Equal(2, users.Select(u => u["sourceStates"]!["directory"]!["observed_at"]!.ToString()).Distinct().Count());
    }
}
