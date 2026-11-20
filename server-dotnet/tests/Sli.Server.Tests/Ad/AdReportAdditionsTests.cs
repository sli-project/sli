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
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Tests.Ad;

// Vectors from tests/reporting/test_ad_report_additions.py; all sources are synthetic.
public sealed class AdReportAdditionsTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-10-17T03:00:00Z");
    const string Guid1 = "00000000-0000-4000-8000-000000000001";
    const string Sid = "S-1-5-21-100000001-200000002-300000003-1001";
    const string AgentKey = "00000000-0000-4000-8000-000000000007";
    static JsonObject HostObject() => Obj(new { entity_id = 1, object_guid = Guid1, domain_id = 2 });
    static JsonObject Agent() => Obj(new { entity_id = 1, domain_id = 2, object_guid = Guid1,
        created_at = Iso(Now.AddDays(-10)), bound_at = Iso(Now.AddDays(-10)), last_seen = Iso(Now.AddMinutes(-3)), version = "1.2.3", status = "active" });
    static JsonObject Status(List<JsonObject>? agents, JsonObject? host = null, long domain = 2, DateTimeOffset? at = null) =>
        AdComputerPosture.Agent(host ?? HostObject(), domain, new(agents), at ?? Now);

    [Fact] public void Registry_matches_only_domain_and_explicit_identity_and_rejects_ambiguity()
    {
        Assert.Equal("installed", Status([Agent()]).Text("state"));
        Assert.Equal("absent", Status([Agent()], domain: 3).Text("state"));
        Assert.Equal("absent", Status([Agent()], Obj(new { object_guid = "different", display_name = "same" })).Text("state"));
        var conflicting = Agent(); conflicting["entity_id"] = 3;
        Assert.Equal("unknown", Status([Agent(), conflicting]).Text("state"));
    }

    [Fact] public void Unavailable_unbound_and_truncated_registry_never_proves_absence()
    {
        var unbound = Agent(); unbound["entity_id"] = null; unbound["object_guid"] = null;
        foreach (var registry in new List<JsonObject>?[] { null, [unbound], Enumerable.Range(0, 10001).Select(_ => Agent()).ToList() })
            Assert.Equal("unknown", Status(registry).Text("state"));
        Assert.Equal("absent", Status([]).Text("state"));
    }

    [Fact] public void Silent_and_future_signals_preserve_unknown_age_and_historical_registration()
    {
        var row = Agent(); row["last_seen"] = Iso(Now.AddDays(-3));
        var status = Status([row]); Assert.Equal("silent", status.Text("state")); Assert.Equal(3 * 86400, status.Int("age_seconds"));
        row["last_seen"] = Iso(Now.AddSeconds(1)); Assert.Null(Status([row])["age_seconds"]);
        foreach (string field in new[] { "created_at", "bound_at" })
        { row = Agent(); row[field] = Iso(Now.AddDays(1)); Assert.Equal("unknown", Status([row]).Text("state")); }
        Assert.Null(Status([Agent()])["version"]);
    }

    [Fact] public void Latest_present_instance_wins_and_only_confirmed_removal_proves_absence()
    {
        var removed = Agent(); removed["removal_state"] = "state_cleaned"; removed["removed_at"] = Iso(Now.AddHours(-1));
        Assert.Equal("absent", Status([removed]).Text("state"));
        Assert.Equal("installed", Status([removed], at: Now.AddDays(-1)).Text("state"));
        var live = Agent(); live["last_seen"] = Iso(Now.AddMinutes(-1));
        Assert.Equal(60, Status([removed, live]).Int("age_seconds"));
        var silent = Agent(); silent["last_seen"] = Iso(Now.AddDays(-3));
        Assert.Equal("installed", Status([silent, live]).Text("state"));
    }

    [Fact] public void Dns_requires_observed_source_and_valid_date_in_inventory_and_preview()
    {
        var raw = Computer(1); var dns = AdComputerPosture.Dns(raw);
        Assert.Equal("192.0.2.1", Assert.Single(dns["addresses"]!.AsArray())!.ToString());
        Assert.Equal(Iso(Now), dns.Text("observed_at_utc"));
        Assert.True(JsonNode.DeepEquals(dns, AdComputerPosture.ReviewObject(raw, Now)["dns_ip"]));
        raw["sources"]!["dns"]!["status"] = "failed";
        Assert.Empty(AdComputerPosture.Dns(raw)["addresses"]!.AsArray());
        raw.Remove("sources"); Assert.Null(AdComputerPosture.Dns(raw)["observed_at_utc"]);
        raw["sources"] = Obj(new { dns = new { status = "observed", observed_at = "invalid" } });
        Assert.Empty(AdComputerPosture.Dns(raw)["addresses"]!.AsArray());
    }

    [Theory][InlineData("absent", true)][InlineData("silent", false)][InlineData("installed", false)][InlineData("unknown", null)]
    public void No_agent_check_distinguishes_absent_silent_and_unknown(string state, bool? expected)
    {
        var raw = Computer(1); raw["sli_agent"] = Obj(new { state });
        Assert.Equal(expected, AdReviewChecks.Evaluate(false, raw, Now)["no_sli_agent"]);
    }

    [Fact] public async Task Optional_readers_fail_closed_without_private_details_and_keep_transaction_usable()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct); await using var tx = await db.BeginTransactionAsync(Ct);
        Assert.Null(await AdComputerPosture.AgentsAsync(db, [2], Ct));
        await PostCollectionPostgres.Sql(db,"savepoint missing_short_events",Ct);
        var missing=await Assert.ThrowsAsync<PostgresException>(()=>AdLastWorkplace.ReadAsync(db,[2],[Sid],Ct));
        Assert.Equal(PostgresErrorCodes.UndefinedTable,missing.SqlState);
        await PostCollectionPostgres.Sql(db,"rollback to savepoint missing_short_events",Ct);
        var facts = await new Facts(true, true, true, false).LoadAsync(new("session", 1, "operator"), Ct);
        var access = new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts));
        Assert.Empty(await AdLastWorkplace.NativeAsync(db, [2], [Sid], facts, access, "view", Ct));
        Assert.Equal(1L, (await ReadAsync(db, "select 1::bigint as value", Ct))[0].Int("value"));
    }

    [Fact] public async Task Native_reader_without_atomic_workstation_action_grant_never_touches_database()
    {
        Assert.Empty(await AdLastWorkplace.NativeAsync(null!, [2], [Sid], null, null, "view", Ct));
        foreach (var (native, split, action) in new[] { (false, false, "view"), (true, true, "view"), (true, false, "export") })
        {
            var facts = await new Facts(true, true, native, split).LoadAsync(new("session", 1, "operator"), Ct);
            var access = new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts));
            Assert.Empty(await AdLastWorkplace.NativeAsync(null!, [2], [Sid], facts, access, action, Ct));
        }
    }

    [Fact] public async Task Registry_uses_granted_provenance_and_inventory_exposes_live_version_and_dated_dns()
    {
        await using var pg = await Database(); await using var db = await pg.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db, """
            create role additions_reader;
            grant usage on schema public to additions_reader;
            grant select on all tables in schema public to additions_reader;
            set role additions_reader;
            """, Ct);
        await using (var tx = await db.BeginTransactionAsync(Ct))
        {
            var agent = Assert.Single((await AdComputerPosture.AgentsAsync(db, [2], Ct))!);
            Assert.Equal(1, agent.Int("entity_id")); Assert.Equal("1.2.3", agent.Text("version"));
            await tx.RollbackAsync(Ct);
        }
        var result = await Store(pg).ReadAsync(Request("ad.computers.v6", "computers"), _ => true, Ct);
        var item = Assert.Single(result["items"]!.AsArray())!;
        Assert.Equal("192.0.2.1", item["dns_ip"]!["addresses"]![0]!.ToString());
        Assert.Equal("1.2.3", item["sli_agent"]!.Text("version"));
        Assert.Equal("installed", item["sli_agent"]!.Text("state"));
        await PostCollectionPostgres.Sql(db, "reset role", Ct);
        foreach (string invalidProvenance in new[] { "plugin_id='synthetic.other'", "source_instance_id='synthetic-other'", "resolution='unresolved'" })
        {
            await using var tx = await db.BeginTransactionAsync(Ct);
            await PostCollectionPostgres.Sql(db, "update core_entity_scope_resources set " + invalidProvenance, Ct);
            var unmatched = Assert.Single((await AdComputerPosture.AgentsAsync(db, [2], Ct))!);
            Assert.Null(unmatched["entity_id"]);
            await tx.RollbackAsync(Ct);
        }
        await PostCollectionPostgres.Sql(db, "insert into core_entity_associations values(10,2,now(),'directory_computer')", Ct);
        await using (var tx = await db.BeginTransactionAsync(Ct))
        {
            Assert.Null(Assert.Single((await AdComputerPosture.AgentsAsync(db, [2], Ct))!)["entity_id"]);
        }
    }

    [Fact] public async Task Checks_enrich_current_previous_and_login_baseline_and_preserve_dns_preview()
    {
        await using var pg = await Database(); await using var db = await pg.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db, """
            insert into entities_v2 values(3,1,2,'synthetic-silent','synthetic-silent');
            insert into ad_context_entity_aliases values(3,2,'object_guid','00000000-0000-4000-8000-000000000003','00000000-0000-4000-8000-000000000003');
            update core_entity_associations set target_entity_id=3;
            update sli_agents set last_seen=now()-interval '3 days';
            """, Ct);
        await Snapshot(db, false, 2, Now.AddDays(-1), [Computer(1)]);
        await Snapshot(db, false, 3, Now, [Computer(1), Computer(2), Computer(3)]);
        var result = await Store(pg).ReadAsync(Request("ad.computers.v6", "checks") with { Principal = new("session", 1, "operator") }, _ => true, Ct);
        var check = result["items"]!.AsArray().Single(r => r!.Text("key") == "no_sli_agent")!;
        Assert.Equal(2, check.Int("total")); Assert.Equal(1, check.Int("new_count")); Assert.Equal("medium", check.Text("severity")); Assert.Null(check["change"]);
        Assert.All(check["objects"]!.AsArray(), o => Assert.Equal("absent", o!["sli_agent"]!.Text("state")));
        Assert.NotNull(check["objects"]![0]!["dns_ip"]);
        Assert.Equal("192.0.2.1", check["objects"]![0]!["dns_ip"]!["addresses"]![0]!.ToString());
        await PostCollectionPostgres.Sql(db, "drop table sli_agents", Ct);
        result = await Store(pg).ReadAsync(Request("ad.computers.v6", "checks"), _ => true, Ct);
        check = result["items"]!.AsArray().Single(r => r!.Text("key") == "no_sli_agent")!;
        Assert.Null(check["total"]); Assert.Null(check["new_count"]);
    }

    [Fact] public async Task Workplace_uses_domain_sid_interactive_projection_and_rejects_duplicate_accounts()
    {
        await using var pg = await Database(); await using var db = await pg.OpenAsync(Ct);
        var store = Store(pg);
        var result = await store.ReadAsync(Request("ad.users.v2", "all"), _ => true, Ct);
        Assert.Equal("synthetic-ad", Assert.Single(result["items"]!.AsArray())!["last_workplace"]!.Text("computer"));
        Assert.Equal("rdp", result["items"]![0]!["last_workplace"]!.Text("kind"));
        // Same SID, other domain: no observation may escape its snapshot's domain.
        await Snapshot(db, true, 2, Now.AddMinutes(1), [User(3, 3)]);
        result = await store.ReadAsync(Request("ad.users.v2", "all"), _ => true, Ct);
        Assert.Null(Assert.Single(result["items"]!.AsArray())!["last_workplace"]);
        await Snapshot(db, true, 3, Now.AddMinutes(2), [User(1), User(2)]);
        result = await store.ReadAsync(Request("ad.users.v2", "all"), _ => true, Ct);
        Assert.All(result["items"]!.AsArray(), r => Assert.Null(r!["last_workplace"]));
    }

    [Theory][InlineData(true, false, false)][InlineData(false, true, false)][InlineData(true, true, true)]
    public async Task Workplace_metadata_data_and_reader_require_both_atomic_field_categories(bool security, bool technical, bool visible)
    {
        await using var pg = await Database();
        using var host = await Endpoint(pg, security, technical, native: false); using var client = host.GetTestClient();
        using var metadata = await client.GetAsync("/api/v2/reports/ad.users.v2", Ct);
        Assert.Equal(HttpStatusCode.OK, metadata.StatusCode);
        var declaration = JsonNode.Parse(await metadata.Content.ReadAsStringAsync(Ct))!;
        Assert.Equal(visible, declaration["columns"]!.AsArray().Any(c => c!.Text("key") == "last_workplace"));
        using var data = await client.GetAsync("/api/v2/reports/ad.users.v2/data?tab=all&account_state=enabled&domain_id=2", Ct);
        Assert.Equal(security ? HttpStatusCode.OK : HttpStatusCode.Forbidden, data.StatusCode);
        if (security)
        {
            var body = JsonNode.Parse(await data.Content.ReadAsStringAsync(Ct))!;
            Assert.Equal(visible, Assert.Single(body["items"]!.AsArray())!.AsObject().ContainsKey("last_workplace"));
        }
    }

    [Fact] public async Task Native_workplace_requires_workstation_atomic_view_grant_and_newest_source_wins()
    {
        await using var pg = await Database();
        await using (var seed = await pg.OpenAsync(Ct))
            await PostCollectionPostgres.Sql(seed, """
                insert into sli_agents select '00000000-0000-4000-8000-000000000099',host_id,null,null,created_at,last_seen,status,assigned_modules from sli_agents;
                """, Ct);
        foreach (var (native, split, expected) in new[] { (false, false, "synthetic-ad"), (true, true, "synthetic-ad"), (true, false, "synthetic-ad") })
        {
            using var host = await Endpoint(pg, true, true, native, split); using var client = host.GetTestClient();
            using var response = await client.GetAsync("/api/v2/reports/ad.users.v2/data?tab=all&account_state=enabled&domain_id=2", Ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!;
            var workplace = Assert.Single(body["items"]!.AsArray())!["last_workplace"]!;
            Assert.Equal(expected, workplace.Text("computer"));
            Assert.Equal(expected == "synthetic-native" ? "local" : "rdp", workplace.Text("kind"));
            Assert.Equal(expected == "synthetic-native" ? Now.AddMinutes(1) : Now, workplace.Time("at_utc"));
        }
        await using var db = await pg.OpenAsync(Ct);
        await PostCollectionPostgres.Sql(db, "update sli_plugin_workstations.observations set observed_at='2026-10-17T02:59:00Z' where id='synthetic-1'", Ct);
        using var olderHost = await Endpoint(pg, true, true, true); using var olderClient = olderHost.GetTestClient();
        var older = JsonNode.Parse(await olderClient.GetStringAsync("/api/v2/reports/ad.users.v2/data?tab=all&account_state=enabled&domain_id=2", Ct))!;
        Assert.Equal("synthetic-ad", older["items"]![0]!["last_workplace"]!.Text("computer"));
    }

    static AdV2Request Request(string key, string tab) => new(key, "view", null, [2], new(), tab, null, false, 50, null, "UTC");
    static IConfiguration Config(PostCollectionPostgres pg) => new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["ConnectionStrings:Sli"] = pg.ConnectionString, ["Sli:AuthRequired"] = "true", ["Sli:Storage:ShortEventReads"] = "false" }).Build();
    static AdV2Store Store(PostCollectionPostgres pg) => new(new PostgresConnectionFactory(Config(pg)), Config(pg));
    static JsonObject Computer(int id) => Obj(new { id = "synthetic-computer-" + id, objectGuid = "00000000-0000-4000-8000-" + id.ToString("D12"), name = "synthetic-host-" + id,
        enabled = true, ipv4s = new[] { "192.0.2.1" }, sources = new { dns = new { status = "observed", observed_at = Iso(Now) } } });
    static JsonObject User(int id, int domain = 2) => Obj(new { id = "synthetic-user-" + id, entityId = id, domainId = domain, sid = Sid, samAccountName = "synthetic-account-" + id, displayName = "Synthetic account", enabled = true });

    static async Task Snapshot(NpgsqlConnection db, bool users, int id, DateTimeOffset at, JsonObject[] objects)
    {
        var payload = Obj(new { metadata = new { observed_at = Iso(at), completed_at = Iso(at), collection_status = "complete" } });
        payload[users ? "users" : "objects"] = Array(objects);
        var manifest = new Guid(id, 0, 0, new byte[8]); string family = users ? "users_v2" : "computers_v6";
        await using var command = new NpgsqlCommand(users ? """
            insert into users_report_v2_snapshots values(@id,2,@payload,@hash,'{}');
            """ : """
            insert into computers_v6_source_snapshots values(@manifest,2,@payload,@hash,'{}');
            """, db);
        command.Parameters.AddWithValue("id", id); command.Parameters.AddWithValue("manifest", manifest);
        command.Parameters.AddWithValue("payload", NpgsqlTypes.NpgsqlDbType.Jsonb, payload.ToJsonString()); command.Parameters.AddWithValue("hash", Convert.FromHexString(AdJobPlugin.Digest(payload)));
        await command.ExecuteNonQueryAsync(Ct);
        await using var source = new NpgsqlCommand("""
            insert into ad_snapshot_manifests values(@manifest,2,@at,@at,'complete') on conflict(manifest_id) do nothing;
            insert into ad_snapshot_manifest_sources values(@manifest,@family,@source,@hash,'complete',@at);
            """, db);
        source.Parameters.AddWithValue("manifest", manifest); source.Parameters.AddWithValue("at", at); source.Parameters.AddWithValue("family", family);
        source.Parameters.AddWithValue("source", users ? id.ToString() : manifest.ToString()); source.Parameters.AddWithValue("hash", Convert.FromHexString(AdJobPlugin.Digest(payload))); await source.ExecuteNonQueryAsync(Ct);
    }

    static async Task<PostCollectionPostgres> Database()
    {
        var pg = new PostCollectionPostgres(canonicalSchema: true);
        try
        {
            await pg.StartAsync(Ct); await using var db = await pg.OpenAsync(Ct);
            await PostCollectionPostgres.Sql(db, """
                create table domains(id bigint,fqdn text,is_archived boolean default false);
                insert into domains(id,fqdn) values(2,'example.test');
                create table platform_settings(key text,value text); insert into platform_settings values('reports.domain_fqdn','example.test');
                create table ad_context_runs(domain_id bigint,status text,observed_at_utc timestamptz);
                create table auth_users(id bigint,previous_login_at timestamptz); insert into auth_users values(1,'2026-10-16T15:00:00Z');
                create table ad_snapshot_manifests(manifest_id uuid primary key,domain_id bigint,slot_start_utc timestamptz,assembled_at_utc timestamptz,coverage_state text);
                create table ad_snapshot_manifest_sources(manifest_id uuid,family text,source_id text,payload_sha256 bytea,source_state text,observed_at_utc timestamptz);
                create table users_report_v2_snapshots(snapshot_id bigint,domain_id bigint,payload_json jsonb,payload_sha256 bytea,scope_json jsonb);
                create table computers_v6_source_snapshots(snapshot_uuid uuid,domain_id bigint,payload_json jsonb,payload_sha256 bytea,source_options_json jsonb);
                create table storage_v2_entity_type(id bigint,value text); insert into storage_v2_entity_type values(1,'ad_computer');
                create table entities_v2(id bigint,entity_type_id bigint,domain_id bigint,display_name text,natural_key text);
                insert into entities_v2 values(1,1,2,'synthetic-native','synthetic-host');
                create view entities_v2_active as select * from entities_v2;
                create table ad_context_entity_aliases(entity_id bigint,domain_id bigint,alias_type text,alias_value text,normalized_value text);
                insert into ad_context_entity_aliases values(1,2,'object_guid','00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000001');
                create table ad_context_entity_versions(entity_id bigint,source_section text,valid_to_utc timestamptz,attributes_json jsonb);
                create table sli_agents(id uuid,host_id uuid,source_agent_id uuid,source_host_id uuid,created_at timestamptz,last_seen timestamptz,status text,assigned_modules jsonb);
                insert into sli_agents values('00000000-0000-4000-8000-000000000007','00000000-0000-4000-8000-000000000008',null,null,now()-interval '10 days',now()-interval '3 minutes','active','[{"module_id":"sli.workstations"}]');
                create table sli_agent_audit(target text,actor text,occurred_at timestamptz,action text);
                create table sli_agent_group_approval_links(enrollment_token_id uuid,request_id bigint);
                create table sli_agent_group_requests(id bigint,computer_entity_id bigint);
                create table sli_agent_removals(agent_id uuid,state text,reported_at timestamptz);
                create table sli_agent_update_results(agent_id uuid,version text,observed_at timestamptz,package_sha256 text,status text);
                insert into sli_agent_update_results values('00000000-0000-4000-8000-000000000007','1.2.3',now(),'synthetic','ok');
                create table core_entity_scope_resources(natural_key text,plugin_id text,source_instance_id text,entity_type text,resolution text,entity_id bigint,observed_at_utc timestamptz,device_id text,collection_scope_id text);
                insert into core_entity_scope_resources select 'core:'||encode(sha256(convert_to('["device","sli.agent.key","agent-registry","'||id::text||'"]','UTF8')),'hex'),'sli.workstations',host_id::text,'device','resolved',10,now()-interval '10 days','synthetic-device','ad-domain:2' from sli_agents;
                create table core_entity_associations(source_entity_id bigint,target_entity_id bigint,created_at_utc timestamptz,relation text);
                insert into core_entity_associations values(10,1,now()-interval '10 days','directory_computer');
                create table findings(id bigint,title text,status text,summary text,why_it_matters text,recommended_action text,last_seen_utc timestamptz);
                create table finding_entities(finding_id bigint,entity_id bigint);
                create function is_semantic_finding_published_v1(bigint) returns boolean language sql as 'select true';
                create table servers(id bigint,domain_id bigint,role text);
                insert into servers values(1,2,'domain_controller');
                create table event_hot(event_id bigint,time_created_utc timestamptz,event_kind int,domain_id bigint,actor text,target text,source text,computer text,method jsonb,outcome jsonb,fields jsonb);
                create table event_cold_facts (like event_hot);
                create table event_cold_daily(day date,event_kind int,domain_id bigint,actor text,target text,source text,computer text,method jsonb,outcome jsonb,grouping_key bytea,event_count bigint,first_seen_utc timestamptz,last_seen_utc timestamptz);
                insert into event_cold_daily values('2026-10-17',4624,2,'S-1-5-21-100000001-200000002-300000003-1001',null,'synthetic-ad','dc01.example.test',
                    '{"$server_id":1,"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing","LogonType":"10"}','{}',decode('01','hex'),1,'2026-10-17T03:00:00Z','2026-10-17T03:00:00Z');
                create schema sli_plugin_workstations;
                create table sli_plugin_workstations.observations(id text,agent_key text,ad_computer_id bigint,family text,event_id int,observed_at timestamptz,observation jsonb);
                insert into sli_plugin_workstations.observations values('synthetic-1','00000000-0000-4000-8000-000000000007',1,'logons',4624,'2026-10-17T03:01:00Z','{"facts":{"relation_account_sid":"S-1-5-21-100000001-200000002-300000003-1001","logon_type":"2"}}');
                insert into sli_plugin_workstations.observations values
                  ('synthetic-ungranted','00000000-0000-4000-8000-000000000099',1,'logons',4624,'2026-10-17T03:03:00Z','{"facts":{"relation_account_sid":"S-1-5-21-100000001-200000002-300000003-1001","logon_type":"2"}}'),
                  ('synthetic-network','00000000-0000-4000-8000-000000000007',1,'logons',4624,'2026-10-17T03:04:00Z','{"facts":{"relation_account_sid":"S-1-5-21-100000001-200000002-300000003-1001","logon_type":"3"}}'),
                  ('synthetic-future','00000000-0000-4000-8000-000000000007',1,'logons',4624,now()+interval '1 day','{"facts":{"relation_account_sid":"S-1-5-21-100000001-200000002-300000003-1001","logon_type":"2"}}');
                """, Ct);
            await Snapshot(db, true, 1, Now.AddDays(-2), [User(1)]);
            await Snapshot(db, false, 1, Now.AddDays(-2), [Computer(1)]);
            return pg;
        }
        catch { await pg.DisposeAsync(); throw; }
    }

    sealed class Auth : IPrincipalAuthenticator
    { public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c, CancellationToken ct) => ValueTask.FromResult(AuthenticationResult.Success(new("session", 1, "operator"))); }
    sealed class Facts(bool security, bool technical, bool native, bool split) : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal p, CancellationToken ct)
        {
            string[] fields = ["identity_basic", .. security ? new[] { "security" } : [], .. technical ? new[] { "technical" } : []];
            string[] workstationFields = ["identity_basic", "security", "technical", "privilege"];
            var definitions = new[] { "ad.users.v2", "workstations.logons" }.Select(key => JsonSerializer.SerializeToElement(new { report_key = key, version = 1, dataset_version = 1,
                definition_json = new { field_categories = workstationFields, actions = new[] { "view" } }, fields_json = workstationFields.Select(category => new { category }), actions_json = new[] { "view" } })).ToArray();
            var assignments = new List<JsonElement> { JsonSerializer.SerializeToElement(new { report_key = "ad.users.v2", effect = "allow", scope_json = new { kind = "domain", ids = new[] { 2 } }, field_categories = fields, allowed_actions = new[] { "view" } }) };
            if (native) foreach (var categories in split ? new[] { new[] { "identity_basic", "technical" }, new[] { "security", "privilege" } } : new[] { workstationFields })
                assignments.Add(JsonSerializer.SerializeToElement(new { report_key = "workstations.logons", effect = "allow", scope_json = new { kind = "agent", ids = new[] { AgentKey } }, field_categories = categories, allowed_actions = new[] { "view" } }));
            var policies = workstationFields.Select(f => JsonSerializer.SerializeToElement(new { capability_key = "field." + f, effect = "allow", scope_json = new { kind = "all" } })).ToArray();
            return Task.FromResult(new AccessFacts(false, "operator", [], [], policies, [], [], assignments.ToArray(), definitions));
        }
    }
    sealed class Catalog : IReportCatalogProvider
    {
        public ReportCatalogSnapshot Capture() => new([new ReportRule("ad.users.v2", "ad.users.v2", "domain", new HashSet<string>(), new HashSet<string>(), null, false) { OwnerId = "sli.ad" }], new Dictionary<string, PluginGeneration>(), new Dictionary<string, string>());
        public ReportCatalogSnapshot Recheck(ReportCatalogSnapshot captured) => captured;
    }
    static async Task<IHost> Endpoint(PostCollectionPostgres pg, bool security, bool technical, bool native, bool split = false)
    {
        var config = Config(pg);
        return await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s =>
        {
            s.AddRouting(); s.AddLogging(); s.AddSingleton(config); s.AddSingleton(new AuthRequestPolicy(config)); s.AddSingleton(new TransportGate(config));
            s.AddSingleton<IPrincipalAuthenticator>(new Auth()); s.AddSingleton<IAccessFactsRepository>(new Facts(security, technical, native, split));
            s.AddSingleton<IAdV2Store>(Store(pg)); s.AddSingleton<IReportCatalogProvider>(new Catalog());
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => e.MapAdV2()); })).StartAsync(Ct);
    }
}
