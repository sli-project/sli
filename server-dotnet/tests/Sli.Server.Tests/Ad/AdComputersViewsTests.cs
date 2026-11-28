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
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Ad;

// Vectors from tests/reporting/test_ad_computers_views.py. All snapshots are synthetic;
// PostgreSQL tests own a fresh temporary cluster and never use an inherited connection.
public sealed class AdComputersViewsTests(AdComputersViewsTests.Data data) : IClassFixture<AdComputersViewsTests.Data>
{
    const string Key = "ad.computers.v6";
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static readonly DateTimeOffset At = DateTimeOffset.Parse("2026-10-17T03:00:00Z");
    static JsonObject Computer() => JsonNode.Parse("""
        {"objectGuid":"synthetic-guid","name":"synthetic-host","deviceType":"server",
         "osName":"Windows Server 2022","enabled":true,"ou":"OU=synthetic"}
        """)!.AsObject();
    static JsonObject Snapshot(params JsonObject[] objects) => new()
    {
        ["metadata"] = new JsonObject { ["completed_at"] = AdInventoryRows.PythonIso(At) },
        ["objects"] = AdJson.Array(objects)
    };
    static AdV2Request Request(string tab = "changes", long[]? domains = null, JsonObject? parameters = null, int limit = 50, string? cursor = null)
        => new(Key, "view", null, domains ?? [2], parameters ?? new(), tab, null, false, limit, cursor, "UTC");

    [Fact]
    public async Task Inventory_uses_enrolled_computer_before_matching_registered_names_within_the_domain()
    {
        await data.Seed(2, Computer(), count: 4);
        await PostCollectionPostgres.Sql(data.Db, """
            insert into storage_v2_entity_type values(1,'ad_computer');
            insert into entities_v2 values(1,2,1),(2,2,1),(3,2,1),(4,2,1),(5,3,1);
            insert into ad_context_entity_aliases(domain_id,normalized_value,alias_type,entity_id) values
                (2,'short-host$','sam_account_name',2),(3,'short-host$','sam_account_name',5),
                (2,'ambiguous-host$','sam_account_name',4),(3,'ambiguous-host$','sam_account_name',5);
            insert into ad_context_entity_versions values
                (10,3,'directory_accounts',now(),null,now(),null,
                 '{"attributes":{"dns_host_name":"dns-host.example.test"}}');
            insert into sli_agents values
                ('00000000-0000-4000-8000-000000000001',null,now(),now(),'active','short-host','{"agent_version":"1.2.3"}'),
                ('00000000-0000-4000-8000-000000000002',null,now(),now()-interval '2 days','active','SHORT-HOST','{}'),
                ('00000000-0000-4000-8000-000000000003',null,now(),now(),'active','DNS-HOST.EXAMPLE.TEST.','{}'),
                ('00000000-0000-4000-8000-000000000004',null,now(),now(),'active','ambiguous-host','{"agent_version":"4.5.6"}');
            insert into sli_agent_group_approval_links values('fixture',1);
            insert into sli_agent_group_requests values(1,1);
            insert into sli_agent_audit values
                (1,'00000000-0000-4000-8000-000000000001','enrollment:fixture','issue',now(),'{}'),
                (2,'00000000-0000-4000-8000-000000000002','enrollment:fixture-2','issue',now(),'{"agent_version":"2.3.4"}');
            insert into sli_agent_snapshot_bindings values('00000000-0000-4000-8000-000000000002','sli.ad-snapshot','S-1-5-21-100000001-200000002-300000003');
            insert into sli_agent_update_results values('00000000-0000-4000-8000-000000000003','3.4.5',now(),'fixture','updated');
            """, Ct);
        try
        {
            var result = await data.Read(Request("computers"));
            var rows = result["items"]!.AsArray().ToDictionary(row => row!["entity_id"]!.GetValue<long>());
            Assert.Equal("1.2.3", rows[1]!["sli_agent"]?["version"]?.ToString());
            Assert.Equal("installed", rows[1]!["sli_agent"]!["state"]!.ToString());
            Assert.Equal("2.3.4", rows[2]!["sli_agent"]?["version"]?.ToString());
            Assert.Equal("silent", rows[2]!["sli_agent"]!["state"]!.ToString());
            Assert.NotNull(rows[2]!["sli_agent"]!["last_seen_utc"]);
            Assert.Equal("3.4.5", rows[3]!["sli_agent"]?["version"]?.ToString());
            Assert.Null(rows[4]!["sli_agent"]!["version"]);

            await PostCollectionPostgres.Sql(data.Db, """
                insert into domains(id,fqdn,domain_sid) values(5,'duplicate.example.test','S-1-5-21-100000001-200000002-300000003');
                """, Ct);
            result = await data.Read(Request("computers"));
            rows = result["items"]!.AsArray().ToDictionary(row => row!["entity_id"]!.GetValue<long>());
            Assert.Equal(4, rows.Count);
            Assert.Equal("installed", rows[1]!["sli_agent"]!["state"]!.ToString());
            Assert.Equal("unknown", rows[2]!["sli_agent"]!["state"]!.ToString());
            Assert.Null(rows[2]!["sli_agent"]!["version"]);
            Assert.Equal("3.4.5", rows[3]!["sli_agent"]?["version"]?.ToString());
            var checks = await data.Read(Request("checks"));
            var withoutAgent = checks["items"]!.AsArray().Single(row => row?["key"]?.ToString() == "no_sli_agent");
            Assert.Null(withoutAgent!["total"]);
        }
        finally
        {
            await PostCollectionPostgres.Sql(data.Db, """
                truncate sli_agent_update_results,sli_agent_snapshot_bindings,sli_agent_audit,sli_agent_group_requests,
                    sli_agent_group_approval_links,sli_agents,entities_v2,storage_v2_entity_type;
                delete from ad_context_entity_versions where id=10;
                delete from ad_context_entity_aliases where alias_type='sam_account_name';
                delete from domains where id=5;
                """, Ct);
        }
    }

    [Fact]
    public void Declaration_has_exact_tabs_overlay_name_and_hidden_all_default()
    {
        var declaration = AdV2Endpoints.Definitions[Key]!["declaration"]!;
        Assert.Equal(new[] { "checks", "changes", "computers" }, declaration["views"]!.AsArray().Select(v => v!["key"]!.ToString()));
        Assert.Null(declaration["columns"]![0]!["link"]);
        var view = declaration["params"]!.AsArray().Single(p => p!["key"]!.ToString() == "view")!;
        Assert.Equal("all", view["default"]!.ToString());
        Assert.True(view["hidden"]!.GetValue<bool>());
    }

    [Fact]
    public void Changes_preserve_actual_object_timestamp_and_never_invent_an_actor()
    {
        var row = Assert.Single(AdSnapshotChanges.CompareComputers(Snapshot(Computer()), Snapshot(), 2, "example.test", At));
        Assert.Equal("new_object", row["change_type"]!.ToString());
        Assert.Equal("server", row["computer_type"]!.ToString());
        Assert.Equal("Windows Server 2022", row["operating_system"]!.ToString());
        Assert.Equal("OU=synthetic", row["ou_path"]!.ToString());
        Assert.False(row["before"]!.GetValue<bool>());
        Assert.True(row["after"]!.GetValue<bool>());
        Assert.Null(row["actor"]);
        // A database timestamp is a DateTimeOffset here; the result remains JSON wire data.
        var wire = JsonNode.Parse(row.ToJsonString())!;
        Assert.Equal("2026-10-17T03:00:00+00:00", wire["observed_at_utc"]!.ToString());
    }

    [Fact]
    public void Only_observed_differences_are_changes_and_missing_does_not_mean_deleted()
    {
        var current = Computer(); current["enabled"] = false; current["userAccountControl"] = 524288;
        var previous = Computer(); previous["ou"] = "OU=previous"; previous["userAccountControl"] = 0;
        var rows = AdSnapshotChanges.CompareComputers(Snapshot(current), Snapshot(previous), 2, "example.test", At);
        Assert.Equal(new[] { "delegation_changed", "enabled_changed", "ou_changed" }, rows.Select(r => r["change_type"]!.ToString()).Order());
        Assert.All(rows, r => Assert.Null(r["actor"]));
        Assert.False(rows.Single(r => r["field"]!.ToString() == "enabled")["after"]!.GetValue<bool>());
        var missing = Assert.Single(AdSnapshotChanges.CompareComputers(Snapshot(), Snapshot(Computer()), 2, "example.test", At));
        Assert.Equal("missing_current", missing["change_type"]!.ToString());
        Assert.True(missing["before"]!.GetValue<bool>()); Assert.False(missing["after"]!.GetValue<bool>());
    }

    [Fact]
    public void Unknown_fields_do_not_become_false_changes()
    {
        var current = Computer(); current["userAccountControl"] = 524288;
        var previous = Computer(); previous["enabled"] = null;
        Assert.Empty(AdSnapshotChanges.CompareComputers(Snapshot(current), Snapshot(previous), 2, "example.test", At));
    }

    [Fact]
    public async Task Inventory_uses_directory_facts_observed_by_the_selected_manifest()
    {
        var computer = Computer();
        computer["deviceType"] = "unknown";
        computer["osName"] = null;
        computer["enabled"] = null;
        await data.Seed(2, computer, count: 2);
        var logon = data.Stamp.AddDays(-2);
        await data.SeedDirectoryFacts(logon);

        var result = await data.Read(Request("computers"));
        var rows = result["items"]!.AsArray();
        var observed = Assert.Single(rows, item => item!["object_guid"]!.ToString() == "synthetic-guid-0")!;
        Assert.Equal("Windows 11 Pro", observed["operating_system"]!.ToString());
        Assert.Equal("workstation", observed["computer_type"]!.ToString());
        Assert.True(observed["enabled"]!.GetValue<bool>());
        Assert.Equal(AdInventoryRows.PythonIso(logon), observed["last_logon_utc"]!.ToString());
        var missing = Assert.Single(rows, item => item!["object_guid"]!.ToString() == "synthetic-guid-1")!;
        Assert.Null(missing["operating_system"]);
        Assert.Null(missing["last_logon_utc"]);
    }

    [Fact]
    public async Task Agent_pair_query_sorts_filters_pages_and_does_not_confirm_missing_comparisons()
    {
        await data.Seed(2, Computer(), publishChanges: true);
        await data.Seed(3, Computer(), at: data.Stamp.AddHours(1), publishChanges: true);
        var request = Request(domains: [2, 3], parameters: new() { ["view"] = "attention" }, limit: 1);
        var first = await data.Read(request);
        Assert.Equal(3, first["items"]![0]!["domain_id"]!.GetValue<int>());
        Assert.True(first["has_more"]!.GetValue<bool>());
        Assert.True(JsonNode.DeepEquals(first["items"], first["collections"]!["changes"]));
        var second = await data.Read(request with { Cursor = first["next_cursor"]!.ToString() });
        Assert.Equal(2, second["items"]![0]!["domain_id"]!.GetValue<int>());
        Assert.False(second["has_more"]!.GetValue<bool>());
        Assert.Null(second["next_cursor"]);
        var filtered = await data.Read(request with { Params = new() { ["q"] = " LATER.EXAMPLE.TEST " } });
        Assert.Equal(1, filtered["filtered_count"]!.GetValue<int>());
        Assert.Equal(3, filtered["items"]![0]!["domain_id"]!.GetValue<int>());
        Assert.Equal("computer_changes_cursor_invalid", (await Assert.ThrowsAsync<AdInputException>(() => data.Read(request with { Cursor = "not-in-scope" }))).Message);
        Assert.Equal("computer_changes_cursor_invalid", (await Assert.ThrowsAsync<AdInputException>(() => data.Read(request with { Domains = [2], Cursor = first["items"]![0]!["row_id"]!.ToString() }))).Message);

        await PostCollectionPostgres.Sql(data.Db, "delete from ad_snapshot_manifests where domain_id=2 and slot_start_utc=(select min(slot_start_utc) from ad_snapshot_manifests where domain_id=2)", Ct);
        var missing = await data.Read(Request());
        Assert.Equal("not_collected", missing["state"]!.ToString());
        Assert.Null(missing["filtered_count"]);
        Assert.Empty(missing["items"]!.AsArray());

        await data.Seed(2, Computer(), publishChanges: true);
        await PostCollectionPostgres.Sql(data.Db, "update ad_snapshot_manifest_sources set observed_at_utc=null where manifest_id in(select manifest_id from ad_snapshot_manifests where domain_id=2)", Ct);
        var invalidClock = await data.Read(Request());
        Assert.Equal("not_collected", invalidClock["state"]!.ToString());
        Assert.Null(invalidClock["filtered_count"]);
    }

    [Fact]
    public async Task Inventory_preserves_scope_filters_paging_and_explicit_selection_coverage_gap()
    {
        var dc = Computer(); dc["userAccountControl"] = 8192;
        dc["lastLogonTimestamp"] = AdInventoryRows.PythonIso(data.Stamp);
        dc["sources"] = new JsonObject { ["os"] = new JsonObject { ["status"] = "observed" } };
        await data.Seed(2, dc, count: 2);
        await data.Seed(3, dc);
        var context = new DefaultHttpContext(); context.Request.QueryString = new("?tab=computers&domain_id=2&q=synthetic&type=domain_controller&limit=1");
        var request = AdV2Endpoints.Parse(context.Request, Key, "view", [2, 3]);
        Assert.Equal("all", request.Params["view"]!.ToString());
        Assert.Equal(new long[] { 2 }, request.Domains);
        var first = await data.Read(request);
        Assert.Equal("domain_controller", first["items"]![0]!["computer_type"]!.ToString());
        Assert.Empty(first["items"]![0]!["reasons"]!.AsArray());
        Assert.Equal(2, first["filtered_count"]!.GetValue<int>());
        Assert.True(first["has_more"]!.GetValue<bool>());
        var second = await data.Read(request with { Cursor = first["next_cursor"]!.ToString() });
        Assert.False(second["has_more"]!.GetValue<bool>());
        Assert.NotEqual(first["items"]![0]!["entity_id"]!.ToString(), second["items"]![0]!["entity_id"]!.ToString());
        Assert.Equal(2, second["items"]![0]!["domain_id"]!.GetValue<int>());
        Assert.Empty((await data.Read(request with { Params = new() { ["q"] = "absent-host" } }))["items"]!.AsArray());
        await data.Seed(2, dc, count: 5001);
        var bounded = await data.Read(request);
        Assert.True(bounded["coverage"]!["truncated"]!.GetValue<bool>());
        var empty = await data.Read(request with { Params = new() { ["q"] = "absent-host" } });
        Assert.Empty(empty["items"]!.AsArray());
        Assert.True(empty["coverage"]!["truncated"]!.GetValue<bool>());
    }

    [Fact]
    public async Task Checks_preview_keeps_safe_source_facts()
    {
        var obj = Computer(); obj["userAccountControl"] = 524288;
        await data.Seed(2, obj);
        var controller = Computer();
        controller["name"] = "synthetic-dc";
        controller["userAccountControl"] = 8192 | 524288;
        await data.Seed(3, controller);
        Assert.Equal("OU=synthetic", AdComputerPosture.ReviewObject(obj, At)["ou_path"]!.ToString());
        var result = await data.Read(Request("checks", domains: [2, 3]));
        var check = result["items"]!.AsArray().Single(r => r!["key"]!.ToString() == "unconstrained_delegation")!;
        var preview = Assert.Single(check["objects"]!.AsArray())!;
        Assert.Equal("Windows Server 2022", preview["operating_system"]!.ToString());
        Assert.Equal("OU=synthetic", preview["ou_path"]!.ToString());
        Assert.Equal(2, preview["domain_id"]!.GetValue<long>());
        var inventory = await data.Read(Request("computers", domains: [2, 3]));
        var controllerRow = inventory["items"]!.AsArray().Single(row => row?["computer_type"]?.ToString() == "domain_controller")!;
        Assert.True(controllerRow["delegation"]!["unconstrained"]!.GetValue<bool>());
        Assert.DoesNotContain(controllerRow["reasons"]!.AsArray(), reason => reason?["code"]?.ToString() == "unconstrained_delegation");
    }

    [Fact]
    public async Task Inventory_puts_disabled_accounts_after_enabled_accounts_before_paging_and_searches_name_dns_or_ip()
    {
        var disabled = Computer();
        disabled["name"] = "LAB-SIM-001";
        disabled["enabled"] = false;
        disabled["description"] = "synthetic-user";
        await data.Seed(2, disabled);
        var enabled = Computer();
        enabled["name"] = "synthetic-workstation";
        enabled["dnsHostName"] = "operator-workstation.example.test";
        enabled["ipv4s"] = new JsonArray("192.0.2.10");
        enabled["sources"] = new JsonObject
        {
            ["dns"] = new JsonObject { ["status"] = "observed", ["observed_at"] = AdInventoryRows.PythonIso(data.Stamp) }
        };
        await data.Seed(3, enabled);

        var request = Request("computers", domains: [2, 3], limit: 1);
        var first = await data.Read(request);
        Assert.Equal("synthetic-workstation", first["items"]![0]!["display_name"]!.ToString());
        var second = await data.Read(request with { Limit = 1, Domains = [2, 3], Cursor = first["next_cursor"]!.ToString() });
        Assert.Equal("LAB-SIM-001", second["items"]![0]!["display_name"]!.ToString());
        var matched = await data.Read(request with { Params = new() { ["q"] = "OPERATOR-WORKSTATION" } });
        Assert.Equal("synthetic-workstation", Assert.Single(matched["items"]!.AsArray())!["display_name"]!.ToString());
        var byAddress = await data.Read(request with { Params = new() { ["q"] = "192.0.2.10" } });
        Assert.Equal("synthetic-workstation", Assert.Single(byAddress["items"]!.AsArray())!["display_name"]!.ToString());
        var unmatched = await data.Read(request with { Params = new() { ["q"] = "synthetic-user" } });
        Assert.Empty(unmatched["items"]!.AsArray());
    }

    [Fact]
    public async Task Http_changes_and_csv_use_selected_tab_authorized_domain_and_columns()
    {
        var obj = Computer(); obj["name"] = "=synthetic";
        await data.Seed(2, obj, publishChanges: true);
        var store = new ScopedStore(data.Store);
        using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v2/reports/" + Key + "/data?tab=changes&domain_id=2", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!;
        Assert.Equal("new_object", result["collections"]!["changes"]![0]!["change_type"]!.ToString());
        Assert.Equal(new long[] { 2 }, Assert.Single(store.Reads).Domains);
        using var denied = await client.GetAsync("/api/v2/reports/" + Key + "/data?tab=changes&domain_id=3", Ct);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode); Assert.Single(store.Reads);
        using var csv = await client.GetAsync("/api/v2/reports/" + Key + "/export.csv?tab=changes&domain_id=2&limit=1&cursor=ignored", Ct);
        Assert.Equal(HttpStatusCode.OK, csv.StatusCode);
        string body = await csv.Content.ReadAsStringAsync(Ct);
        Assert.Contains("Было", body); Assert.Contains("Стало", body); Assert.Contains("'=synthetic", body);
        Assert.Equal(2, body.TrimStart('\ufeff').Split("\r\n", StringSplitOptions.RemoveEmptyEntries).Length);
        Assert.Equal("false", Assert.Single(csv.Headers.GetValues("X-Sli-Export-Truncated")));
        Assert.Equal("changes", store.Reads[^1].Tab); Assert.Null(store.Reads[^1].Cursor);
        using var limitedHost = await Host(store, fields: false); using var limited = limitedHost.GetTestClient();
        using var fieldDenied = await limited.GetAsync("/api/v2/reports/" + Key + "/data?tab=changes", Ct);
        Assert.Equal(HttpStatusCode.Forbidden, fieldDenied.StatusCode); Assert.Equal(2, store.Reads.Count);
    }

    public sealed class Data : IAsyncLifetime
    {
        readonly PostCollectionPostgres pg = new(canonicalSchema: true);
        NpgsqlConnection db = null!;
        internal NpgsqlConnection Db => db;
        internal AdV2Store Store { get; private set; } = null!;
        internal DateTimeOffset Stamp { get; } = DateTimeOffset.UtcNow.AddHours(-2);
        public async ValueTask InitializeAsync()
        {
            try
            {
                await pg.StartAsync(Ct); db = await pg.OpenAsync(Ct);
                await PostCollectionPostgres.Sql(db, """
                    create role adlog_user;
                    create table domains(id bigint primary key,fqdn text,domain_sid text,is_archived boolean not null default false);
                    insert into domains(id,fqdn,domain_sid) values
                        (2,'example.test','S-1-5-21-100000001-200000002-300000003'),(3,'later.example.test',null);
                    create table ad_snapshot_manifests(manifest_id uuid primary key,domain_id bigint,slot_start_utc timestamptz,assembled_at_utc timestamptz,coverage_state text);
                    create table ad_snapshot_manifest_sources(manifest_id uuid,family text,source_id text,payload_sha256 bytea,source_state text,observed_at_utc timestamptz);
                    create table computers_v6_source_snapshots(snapshot_uuid uuid primary key,domain_id bigint,payload_json jsonb,payload_sha256 bytea,source_options_json jsonb);
                    create table ad_context_entity_aliases(domain_id bigint,normalized_value text,alias_type text,entity_id bigint);
                    alter table ad_context_entity_aliases add alias_value text generated always as (normalized_value) stored;
                    create table ad_context_runs(run_id uuid,domain_id bigint,bundle_sha256 bytea,observed_at_utc timestamptz,status text);
                    create table ad_context_entity_versions(id bigint,entity_id bigint,source_section text,valid_from_utc timestamptz,
                        valid_to_utc timestamptz,last_observed_at_utc timestamptz,source_run_id uuid,attributes_json jsonb);
                    create table ad_context_evidence(source_run_id uuid,evidence_key text);
                    -- Empty supplemental findings source; these tests exercise AD snapshots.
                    create table findings(id bigint,title text,status text,summary text,why_it_matters text,recommended_action text,last_seen_utc timestamptz);
                    create table finding_entities(finding_id bigint,entity_id bigint);
                    create table entities_v2_active(id bigint,display_name text,entity_type_id bigint);
                    create table storage_v2_entity_type(id bigint,value text);
                    create table entities_v2(id bigint,domain_id bigint,entity_type_id bigint);
                    create table servers(id bigint,domain_id bigint);
                    create table sli_agents(id uuid,host_id uuid,created_at timestamptz,last_seen timestamptz,status text,registration_host_name text,rights_probe jsonb);
                    create table sli_agent_audit(id bigint,target text,actor text,action text,occurred_at timestamptz,details jsonb);
                    create table sli_agent_group_approval_links(enrollment_token_id text,request_id bigint);
                    create table sli_agent_group_requests(id bigint,computer_entity_id bigint);
                    create table sli_agent_removals(agent_id uuid,state text,reported_at timestamptz);
                    create table sli_agent_update_results(agent_id uuid,version text,observed_at timestamptz,package_sha256 text,status text);
                    create table sli_agent_snapshot_bindings(agent_id uuid,module_id text,domain_sid text);
                    create table core_entity_scope_resources(natural_key text,plugin_id text,source_instance_id text,entity_type text,resolution text,entity_id bigint,observed_at_utc timestamptz);
                    create table core_entity_associations(source_entity_id bigint,target_entity_id bigint,created_at_utc timestamptz,relation text);
                    create function is_semantic_finding_published_v1(bigint) returns boolean language sql as 'select false';
                    """, Ct);
                await PostCollectionPostgres.InstallSnapshotChangeStorageAsync(db, Ct);
                var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["ConnectionStrings:Sli"] = pg.ConnectionString }).Build();
                Store = new(new PostgresConnectionFactory(config), config);
            }
            catch { if (db is not null) await db.DisposeAsync(); await pg.DisposeAsync(); throw; }
        }
        internal Task<JsonObject> Read(AdV2Request request) => Store.ReadAsync(request, _ => true, Ct);
        internal async Task SeedDirectoryFacts(DateTimeOffset logon)
        {
            var run = Guid.NewGuid();
            var firstRun = Guid.NewGuid();
            await using var seed = new NpgsqlCommand("""
                insert into ad_context_runs values(@run,2,decode(repeat('1',64),'hex'),@at,'completed');
                insert into ad_snapshot_manifest_sources
                    select manifest_id,'ad_context_base',@run::text,decode(repeat('1',64),'hex'),'complete',@at
                    from ad_snapshot_manifests where domain_id=2 and slot_start_utc=@at;
                insert into ad_context_entity_versions values
                    (1,1,'directory_accounts',@before,null,@at,@first,@observed),
                    (2,2,'directory_accounts',@before,null,@at,@first,@unbound);
                insert into ad_context_evidence values(@run,'adctx:' || @run::text || ':fixture-observed');
                """, db);
            string Record(string key, string guid) => new JsonObject
            {
                ["record_key"] = key, ["identity"] = new JsonObject { ["kind"] = "ad_computer", ["object_guid"] = guid },
                ["attributes"] = new JsonObject { ["operating_system"] = "Windows 11 Pro", ["user_account_control"] = 4096,
                    ["last_logon_timestamp_utc"] = AdInventoryRows.PythonIso(logon) }
            }.ToJsonString();
            seed.Parameters.AddWithValue("run", run);
            seed.Parameters.AddWithValue("first", firstRun);
            seed.Parameters.AddWithValue("at", Stamp);
            seed.Parameters.AddWithValue("before", Stamp.AddDays(-1));
            seed.Parameters.AddWithValue("observed", NpgsqlTypes.NpgsqlDbType.Jsonb, Record("fixture-observed", "synthetic-guid-0"));
            seed.Parameters.AddWithValue("unbound", NpgsqlTypes.NpgsqlDbType.Jsonb, Record("fixture-unbound", "synthetic-guid-1"));
            await seed.ExecuteNonQueryAsync(Ct);
        }

        internal async Task Seed(long domain, JsonObject obj, DateTimeOffset? at = null, int count = 1, bool publishChanges = false)
        {
            var stamp = at ?? Stamp;
            await using var clean = new NpgsqlCommand("delete from ad_snapshot_manifest_sources where manifest_id in(select manifest_id from ad_snapshot_manifests where domain_id=@domain); delete from ad_snapshot_manifests where domain_id=@domain; delete from computers_v6_source_snapshots where domain_id=@domain; delete from ad_context_entity_aliases where domain_id=@domain", db);
            clean.Parameters.AddWithValue("domain", domain); await clean.ExecuteNonQueryAsync(Ct);
            for (int slot = 0; slot < 2; slot++)
            {
                var snapshot = Snapshot();
                if (slot == 1) for (int i = 0; i < count; i++)
                {
                    var item = (JsonObject)obj.DeepClone(); item["objectGuid"] = "synthetic-guid-" + i; snapshot["objects"]!.AsArray().Add(item);
                    await using var alias = new NpgsqlCommand("insert into ad_context_entity_aliases(domain_id,normalized_value,alias_type,entity_id) values($1,$2,'object_guid',$3)", db);
                    alias.Parameters.AddWithValue(domain); alias.Parameters.AddWithValue("synthetic-guid-" + i); alias.Parameters.AddWithValue((long)i + 1); await alias.ExecuteNonQueryAsync(Ct);
                }
                var id = Guid.NewGuid(); var snapshotId = Guid.NewGuid(); var observed = stamp.AddDays(slot - 1);
                snapshot["metadata"]!["completed_at"] = AdInventoryRows.PythonIso(observed);
                await using var seed = new NpgsqlCommand("""
                    insert into ad_snapshot_manifests values(@id,@domain,@at,@at,'complete');
                    insert into ad_snapshot_manifest_sources values(@id,'computers_v6',@source,decode(@hash,'hex'),'complete',@at);
                    insert into computers_v6_source_snapshots values(@snapshot,@domain,@payload,decode(@hash,'hex'),'{}');
                    """, db);
                seed.Parameters.AddWithValue("id", id); seed.Parameters.AddWithValue("domain", domain); seed.Parameters.AddWithValue("at", observed);
                seed.Parameters.AddWithValue("source", snapshotId.ToString()); seed.Parameters.AddWithValue("snapshot", snapshotId);
                seed.Parameters.AddWithValue("hash", AdJobPlugin.Digest(snapshot)); seed.Parameters.AddWithValue("payload", NpgsqlTypes.NpgsqlDbType.Jsonb, snapshot.ToJsonString());
                await seed.ExecuteNonQueryAsync(Ct);
                if (slot == 1 && publishChanges) await PostCollectionPostgres.PublishSnapshotChangesAsync(db, id, Ct);
            }
        }
        public async ValueTask DisposeAsync() { await db.DisposeAsync(); await pg.DisposeAsync(); }
    }

    sealed class ScopedStore(IAdV2Store inner) : IAdV2Store
    {
        internal readonly List<AdV2Request> Reads = [];
        public Task<IReadOnlyList<JsonObject>> DomainsAsync(DomainGrant grant, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<JsonObject>>(grant.Kind == DomainGrantKind.All || grant.DomainIds.Contains(2)
                ? [new JsonObject { ["id"] = 2, ["display_name"] = "example.test" }] : []);
        public Task<JsonObject> ReadAsync(AdV2Request request, Func<IEnumerable<string>, bool> fields, CancellationToken ct)
        { Reads.Add(request); return inner.ReadAsync(request, fields, ct); }
    }
    sealed class Auth : IPrincipalAuthenticator
    { public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c, CancellationToken ct) => ValueTask.FromResult(AuthenticationResult.Success(new("session", 1, "operator"))); }
    sealed class Facts(bool fields) : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct)
        {
            string[] categories = fields ? ["identity_basic", "technical", "security"] : ["identity_basic"];
            var definitions = new[] { JsonSerializer.SerializeToElement(new { report_key = Key, version = 1, dataset_version = 1,
                definition_json = new { field_categories = new[] { "identity_basic", "technical", "security" }, actions = new[] { "view", "export" } },
                fields_json = new[] { "identity_basic", "technical", "security" }.Select(category => new { category }), actions_json = new[] { "view", "export" } }) };
            var policies = categories.Select(f => "field." + f).Concat(["workspace.view", "reports.export"]).Select(key => JsonSerializer.SerializeToElement(new { capability_key = key, effect = "allow", scope_json = new { kind = "all" } })).ToArray();
            var assignments = new[] { JsonSerializer.SerializeToElement(new { report_key = Key, effect = "allow", scope_json = new { kind = "domain", ids = new[] { 2 } }, field_categories = categories, allowed_actions = new[] { "view", "export" } }) };
            return Task.FromResult(new AccessFacts(false, "operator", [], [], policies, [], [], assignments, definitions));
        }
    }
    sealed class Catalog : IReportCatalogProvider
    {
        public ReportCatalogSnapshot Capture() => new([new ReportRule(Key, Key, "domain", new HashSet<string>(), new HashSet<string>(), null, false) { OwnerId = "sli.ad" }], new Dictionary<string, PluginGeneration>(), new Dictionary<string, string>());
        public ReportCatalogSnapshot Recheck(ReportCatalogSnapshot captured) => captured;
    }
    static Task<IHost> Host(ScopedStore store, bool fields = true)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "true" }).Build();
        return new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s =>
        {
            s.AddRouting(); s.AddLogging(); s.AddSingleton<IConfiguration>(config); s.AddSingleton(new AuthRequestPolicy(config)); s.AddSingleton(new TransportGate(config));
            s.AddSingleton<IPrincipalAuthenticator>(new Auth()); s.AddSingleton<IAccessFactsRepository>(new Facts(fields)); s.AddSingleton<IAdV2Store>(store); s.AddSingleton<IReportCatalogProvider>(new Catalog());
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => e.MapAdV2()); })).StartAsync(Ct);
    }
}
