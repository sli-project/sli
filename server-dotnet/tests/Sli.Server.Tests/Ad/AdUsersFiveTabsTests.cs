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
using Sli.Server.Ad;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Xunit;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Tests.Ad;

// Vectors from tests/reporting/test_users_five_tabs.py. Real projection, no replacement report rows.
public sealed class AdUsersFiveTabsTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    const string Observed = "2026-10-07T00:00:00Z";
    static JsonObject Policy(int password = 90, int inactivity = 60) => Obj(new { password_age = password, inactivity });
    static JsonObject Account(int id, bool? enabled = true, string? password = null, string? activity = null, bool locked = false) => Obj(new
    {
        id = "user:" + id, entityId = id, displayName = "Synthetic account " + id, samAccountName = "fixture-" + id,
        userPrincipalName = "synthetic-" + id + "@example.test", enabled, passwordLastSet = password, lastLogonTimestamp = activity, lockedOut = locked,
        privilegedMemberships = new object[0], memberships = new { status = "observed", direct = new object[0], effective = new object[0] }, sourceStates = new { directory = new { status = "observed" } }
    });
    static JsonObject Snapshot(params JsonObject[] users) => new()
    {
        ["metadata"] = Obj(new { observed_at = Observed, collection_status = "partial", coverage = new { state = "complete", privilege_state = "complete" } }),
        ["users"] = Array(users), ["groups"] = new JsonArray()
    };
    static JsonObject Source(JsonObject? snapshot, string state = "complete", long domain = 1) => new()
    { ["domain_id"] = domain, ["fqdn"] = "example.test", ["source_state"] = state, ["snapshot"] = snapshot?.DeepClone() };
    static AdV2Request Request(string tab, JsonObject? parameters = null, int limit = 100, string? cursor = null, string action = "view") => new("ad.users.v2", action, null, [1], parameters ?? new(), tab, null, false, limit, cursor, "UTC");
    static JsonObject Query(JsonObject snapshot, string tab, JsonObject? p = null, JsonObject? policy = null, int limit = 100, string? cursor = null) => AdUsersTabs.Query(Request(tab, p, limit, cursor), [Source(snapshot)], policy ?? Policy(), _ => true, findings: new Dictionary<long, long> { [1] = 2 });
    static long[] Ids(JsonObject result) => result["items"]!.AsArray().Select(r => r.Int("entity_id")).ToArray();
    static string[] Keys(JsonNode? node) => node!.AsArray().Select(n => n!.ToString()).ToArray();
    static Dictionary<string, long> Metrics(JsonObject result) => result["metrics"]!.AsArray().ToDictionary(m => m.Text("key")!, m => m.Int("value"));
    static string Csv(JsonObject result) => AdV2Endpoints.Csv(AdV2Endpoints.Definitions["ad.users.v2"]!["declaration"]!["columns"]!.AsArray(), result["items"]!.AsArray());

    [Fact] public void Owner_contract_supports_inventory_views_no_legacy_parameters_and_unique_columns()
    {
        var d = AdV2Endpoints.Definitions["ad.users.v2"]!["declaration"]!;
        foreach (string tab in new[] { "checks", "privileged", "changes", "all" })
            Assert.Contains(d["views"]!.AsArray(), v => v.Text("key") == tab);
        Assert.DoesNotContain(d["params"]!.AsArray(), p => p.Text("key") is "view" or "threshold");
        Assert.Equal(new[] { "domain", "domain_id" }, d["params"]!.AsArray().Where(p => p.Text("kind") == "domain").Select(p => p.Text("key")).Order());
        var keys = d["columns"]!.AsArray().Select(c => c.Text("key")).ToArray(); Assert.Equal(keys.Length, keys.Distinct().Count());
    }
    [Theory]
    [InlineData("all", "1,2,3", "ok")][InlineData("active", "1", "partial")][InlineData("disabled", "2", "partial")]
    [InlineData("privileged", "", "empty")][InlineData("risk", "", "partial")][InlineData("semantic", "1", "ok")]
    public void Each_slice_selects_its_own_population(string tab, string ids, string state)
    {
        var r = Query(Snapshot(Account(1), Account(2, false), Account(3, null)), tab);
        Assert.Equal(ids, string.Join(',', Ids(r))); Assert.Equal(Ids(r).Length, r.Int("filtered_count"));
        Assert.Equal(tab, r["coverage"].Text("tab")); Assert.Equal(state, r.Text("state"));
    }
    static JsonArray Direct() => Array(new[] { new { group_id = 10, group = "Synthetic privileged group", relation = "direct", basis = "privileged_membership" } });
    static JsonArray Effective(string relation) => Array(new[] { new { id = "group:10", name = "Synthetic nested group", watchGroup = true, relation } });
    [Fact] public void Privilege_preserves_direct_nested_and_primary_evidence_disabled_counts_filters_and_input()
    {
        var a = Account(1); a["privilegedMemberships"] = Direct(); a["memberships"]!["effective"] = Effective("nested");
        var b = Account(2, false); b["privilegedMemberships"] = Direct();
        var c = Account(3); c["adminCount"] = 1; c["memberships"]!["effective"] = Effective("nested");
        var onlyAdminCount = Account(4); onlyAdminCount["adminCount"] = 1;
        var s = Snapshot(a, b, c, onlyAdminCount); string original = s.ToJsonString(); var r = Query(s, "privileged");
        Assert.Equal(new long[] { 1, 2, 3 }, Ids(r)); Assert.Equal(new[] { "Synthetic privileged group" }, Keys(r["items"]![0]!["privilege_basis"]));
        Assert.Equal(new[] { "Synthetic nested group" }, Keys(r["items"]![0]!["nested_privilege_groups"]));
        Assert.Equal(1, r["coverage"].Int("disabled_privileged")); Assert.Equal("ok", r.Text("state")); Assert.Equal(original, s.ToJsonString());
        var filtered = Query(Snapshot(a, b), "privileged", Obj(new { group = "group:10", relation = "effective" }));
        Assert.Equal(new long[] { 1, 2 }, Ids(filtered));
        Assert.Contains(filtered["filter_options"]!["group"]!.AsArray(), g => g.Text("value") == "group:10" && g.Text("label") == "Synthetic privileged group");
        a["privilegedMemberships"] = new JsonArray(); b["privilegedMemberships"] = new JsonArray(); b["memberships"]!["effective"] = Effective("primary");
        r = Query(Snapshot(a, b), "privileged", Obj(new { group = "group:10", relation = "direct" }));
        Assert.Equal(new long[] { 1, 2 }, Ids(r)); Assert.Equal(1, r["coverage"].Int("disabled_privileged"));
    }
    [Fact] public void Risk_uses_prepared_policy_strict_boundaries_and_unknown_invalid_or_future_facts()
    {
        var s = Snapshot(Account(1, password: "2026-09-26T00:00:00Z", activity: Observed), Account(2, false, "2026-09-27T00:00:00Z", "2026-09-27T00:00:00Z"), Account(3, password: "invalid", activity: "2026-10-08T00:00:00Z"));
        var r = Query(s, "risk", Obj(new { threshold = "1" }), Policy(10, 10));
        Assert.Equal(new long[] { 1 }, Ids(r)); Assert.Equal("exceeded", r["items"]![0].Text("password_age_policy")); Assert.Equal("within_policy", r["items"]![0].Text("inactivity_policy"));
        Assert.Equal(1, r["coverage"].Int("unknown_accounts")); Assert.True(JsonNode.DeepEquals(Policy(10, 10), r["coverage"]!["hygiene_policy"]));
        r = Query(s, "risk", policy: Policy(120, 30)); Assert.True(JsonNode.DeepEquals(Policy(120, 30), r["coverage"]!["hygiene_policy"])); Assert.Empty(Ids(r));
    }
    [Fact] public void Zero_risks_and_search_scoped_unassessed_accounts_are_truthful()
    {
        var s = Snapshot(Account(1), Account(2, false)); var r = Query(s, "risk");
        Assert.Equal("partial", r.Text("state")); Assert.Empty(Ids(r)); Assert.Equal(0, r.Int("filtered_count")); Assert.Equal(0, r["coverage"].Int("risk_accounts"));
        Assert.Equal(2, r["coverage"].Int("unknown_accounts")); Assert.Equal(2, Metrics(r)["unknown"]);
        r = Query(s, "risk", Obj(new { q = "fixture-1" })); Assert.Equal(1, r["coverage"].Int("unknown_accounts")); Assert.Equal(0, r.Int("filtered_count"));
    }
    [Theory]
    [InlineData(true, "2026-10-06T00:00:00Z", "inactive_threshold")][InlineData(false, "2026-10-06T00:00:00Z", "")][InlineData(null, "2026-10-06T00:00:00Z", "")]
    [InlineData(true, "2026-01-01T00:00:00Z", "password_age,inactive_threshold")][InlineData(false, "2026-01-01T00:00:00Z", "password_age")][InlineData(null, "2026-01-01T00:00:00Z", "password_age")]
    public void Risk_requires_confirmed_policy_reason(bool? enabled, string password, string reasons)
    {
        var r = Query(Snapshot(Account(1, enabled, password, "2026-01-01T00:00:00Z")), "risk"); int count = reasons.Length > 0 ? 1 : 0;
        Assert.Equal(count, r.Int("filtered_count")); Assert.Equal(count, Ids(r).Length); Assert.Equal(count, Metrics(r)["attention"]);
        Assert.Equal(reasons.Split(',', StringSplitOptions.RemoveEmptyEntries), r["filter_options"]!["reason"]!.AsArray().Select(o => o.Text("value")));
        if (count == 0) return;
        var row = r["items"]![0]!; Assert.Equal(reasons, string.Join(',', Keys(row["reason_keys"]))); Assert.False(string.IsNullOrEmpty(row.Text("reason_text")));
        Assert.Equal(reasons, string.Join(',', row["reasons"]!.AsArray().Select(o => o.Text("key"))));
        Assert.Equal(reasons, string.Join(',', row["review_details"]!.AsArray().Where(o => o.Text("category") == "confirmed").Select(o => o.Text("key"))));
    }
    [Fact] public void Risk_filters_pages_metrics_and_export_agree_and_exclude_lockout_alone()
    {
        var s = Snapshot(Account(1, false, "2026-10-06T00:00:00Z", "2026-01-01T00:00:00Z", true), Account(2, true, "2026-10-06T00:00:00Z", "2026-01-01T00:00:00Z"), Account(3, false, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"), Account(4, null, "2026-10-06T00:00:00Z", "2026-01-01T00:00:00Z"), Account(5));
        var first = Query(s, "risk", limit: 1); var second = Query(s, "risk", limit: 1, cursor: first.Text("next_cursor"));
        Assert.Equal(new long[] { 2 }, Ids(first)); Assert.True(first["has_more"]!.GetValue<bool>()); Assert.Equal(new long[] { 3 }, Ids(second)); Assert.False(second["has_more"]!.GetValue<bool>());
        foreach (var page in new[] { first, second }) { Assert.Equal(2, page.Int("filtered_count")); Assert.Equal(new Dictionary<string, long> { ["attention"] = 2, ["information"] = 0, ["unknown"] = 1 }, Metrics(page)); }
        foreach (var (reason, id) in new[] { ("inactive_threshold", 2L), ("password_age", 3L) })
        { var r = Query(s, "risk", Obj(new { reason })); Assert.Equal(new[] { id }, Ids(r)); Assert.Equal(1, r.Int("filtered_count")); Assert.Equal(1, Metrics(r)["attention"]); }
        var exported = Query(s, "risk"); string csv = Csv(exported); Assert.Equal(2, Ids(exported).Length); Assert.Contains("Требует внимания", csv); Assert.Contains("fixture-2", csv); Assert.Contains("fixture-3", csv); Assert.DoesNotContain("fixture-1", csv); Assert.DoesNotContain("fixture-4", csv);
        string attention = AdV2Endpoints.Csv(new JsonArray(Obj(new { key = "reason_text", label = "Требует внимания" })), exported["items"]!.AsArray());
        Assert.All(attention.Split("\r\n").Skip(1).Take(2), text => Assert.False(string.IsNullOrEmpty(text)));
    }
    [Fact] public void Information_is_separate_from_confirmed_reasons_in_rows_filters_metrics_and_csv()
    {
        var s = Snapshot(Account(1), Account(2, password: "2026-01-01T00:00:00Z", locked: true), Account(3, password: "2026-10-06T00:00:00Z", activity: "2026-10-06T00:00:00Z"));
        var r = Query(s, "active"); var rows = r["items"]!.AsArray();
        Assert.Null(rows[0]!["reason_text"]); Assert.Empty(rows[0]!["reasons"]!.AsArray()); Assert.Equal(new[] { "password_age_unknown", "enabled_activity_unknown" }, Keys(rows[0]!["information_keys"]));
        Assert.Equal("unknown", rows[0].Text("password_age_policy")); Assert.Equal("unknown", rows[0].Text("inactivity_policy"));
        Assert.Equal(new[] { "locked_out", "password_age" }, Keys(rows[1]!["reason_keys"])); Assert.Equal(new[] { "enabled_activity_unknown" }, Keys(rows[1]!["information_keys"]));
        Assert.Equal(new[] { "confirmed", "information" }, rows[1]!["review_details"]!.AsArray().Select(d => d.Text("category")).Distinct().Order());
        Assert.Null(rows[2]!["reason_text"]); Assert.Null(rows[2]!["information_text"]); Assert.Equal(new Dictionary<string, long> { ["attention"] = 1, ["information"] = 2 }, Metrics(r));
        Assert.Equal(new[] { "locked_out", "password_age" }, r["filter_options"]!["reason"]!.AsArray().Select(o => o.Text("value")));
        Assert.Equal(new long[] { 1 }, Ids(Query(s, "active", Obj(new { information = "password_age_unknown" })))); Assert.Empty(Ids(Query(s, "active", Obj(new { reason = "password_age_unknown" }))));
        Assert.Equal(new long[] { 2 }, Ids(Query(s, "active", Obj(new { reason = "locked_out" }))));
        string csv = Csv(r); Assert.Contains("Ограничения сведений", csv); Assert.Contains("неизвестно", csv); Assert.Equal(3, csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries).Length - 1);
        var attention = AdV2Endpoints.Csv(new JsonArray(Obj(new { key = "reason_text", label = "Требует внимания" })), rows).Split("\r\n");
        var information = AdV2Endpoints.Csv(new JsonArray(Obj(new { key = "information_text", label = "Ограничения сведений" })), rows).Split("\r\n");
        Assert.Equal("", attention[1]); Assert.Contains("неизвестно", information[1]); Assert.DoesNotContain("неизвестно", attention[2]);
        var risk = Query(s, "risk"); Assert.Equal(new long[] { 2 }, Ids(risk)); Assert.Equal(2, Metrics(risk)["unknown"]);
    }
    public static IEnumerable<object[]> EmptyStates() => AdUsersTabs.Tabs.SelectMany(tab => new[] { ("complete", "empty"), ("partial", "partial"), ("stale", "stale"), ("failed", "error"), ("not_collected", "not_collected"), ("processing", "processing") }.Select(pair => new object[] { tab, pair.Item1, pair.Item2 }));
    [Theory][MemberData(nameof(EmptyStates))] public void Empty_population_does_not_hide_source_state(string tab, string source, string expected)
    { var s = Snapshot(); s["metadata"]!["coverage"]!["state"] = source; Assert.Equal(expected, Query(s, tab).Text("state")); }
    public static IEnumerable<object[]> MissingStates() => AdUsersTabs.Tabs.SelectMany(tab => new[] { ("not_collected", "not_collected"), ("unavailable", "error"), ("processing", "processing"), ("denied", "denied") }.Select(pair => new object[] { tab, pair.Item1, pair.Item2 }));
    [Theory][MemberData(nameof(MissingStates))] public void Missing_snapshots_preserve_state_and_unknown_count(string tab, string source, string expected)
    {
        var r = AdUsersTabs.Query(Request(tab), [Source(null, source)], Policy(), _ => true);
        Assert.Equal(expected, r.Text("state")); Assert.Empty(Ids(r)); Assert.Null(r["filtered_count"]);
    }
    [Fact] public void A_complete_marker_without_a_snapshot_cannot_claim_success()
    {
        var r = AdUsersTabs.Query(Request("all"), [Source(null)], Policy(), _ => true);
        Assert.Equal("error", r.Text("state")); Assert.Null(r["filtered_count"]); Assert.Empty(Ids(r));
    }
    [Fact] public void Missing_source_and_domain_details_survive_empty_results()
    {
        var s = Snapshot(); s["metadata"]!["coverage"]!["missing_sources"] = new JsonArray("fixture-source"); s["metadata"]!["coverage"]!["missing_domains"] = new JsonArray(1);
        var r = Query(s, "active"); Assert.Equal("partial", r.Text("state")); Assert.Equal("fixture-source", Assert.Single(r["state_details"]!["missing_sources"]!.AsArray())!.ToString()); Assert.Equal(1, Assert.Single(r["state_details"]!["missing_domains"]!.AsArray())!.GetValue<int>());
    }
    [Fact] public void Filters_paging_and_csv_stay_inside_the_selected_population()
    {
        var s = Snapshot(Account(1), Account(2), Account(3, false)); var first = Query(s, "active", limit: 1); var second = Query(s, "active", limit: 1, cursor: first.Text("next_cursor"));
        Assert.Equal(2, first.Int("filtered_count")); Assert.True(first["has_more"]!.GetValue<bool>()); Assert.Equal(new long[] { 2 }, Ids(second)); Assert.False(second["has_more"]!.GetValue<bool>());
        var disabled = Query(s, "disabled", Obj(new { q = "fixture-3" })); Assert.Equal(1, disabled.Int("filtered_count")); Assert.Equal(new long[] { 3 }, Ids(disabled));
        string csv = Csv(Query(s, "disabled")); Assert.Contains("fixture-3", csv); Assert.DoesNotContain("fixture-1", csv);
        Assert.Throws<AdInputException>(() => Query(s, "active", cursor: "-1"));
    }
    [Fact] public void Semantic_links_exact_entity_and_finding_count()
    { var r = Query(Snapshot(Account(1), Account(2)), "semantic"); Assert.Equal(new long[] { 1 }, Ids(r)); Assert.Equal(1, r["items"]![0].Int("queue_entity_id")); Assert.Equal(2, r["items"]![0].Int("finding_count")); }
    [Theory][InlineData("stale", "stale")][InlineData("inactive", "partial")][InlineData("unknown", "partial")]
    public void Semantic_worker_state_cannot_become_an_empty_success(string semantic, string expected)
    {
        var r = AdUsersTabs.Query(Request("semantic"), [Source(Snapshot())], Policy(), _ => true, semanticState: semantic);
        Assert.Equal(expected, r.Text("state")); Assert.Contains(r["limitations"]!.AsArray(), l => l.Text("code") == "semantic_incomplete");
    }

    [Fact] public void Snapshot_projection_retains_direct_privilege_basis()
    {
        using var stream = typeof(AdUsersFiveTabsTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Ad.snapshot-reference.json")!;
        var reference = JsonNode.Parse(stream)!;
        var bundles = reference["bundles"]!.AsObject().ToDictionary(p => p.Key, p => p.Value!.AsObject());
        var entities = bundles["ad_context_base"]["records"]!.AsArray().Where(r => r.Text("record_type") == "entity").ToArray();
        var user = entities.First(r => r!["identity"].Text("kind") == "ad_user");
        var group = entities.First(r => r!["identity"].Text("kind") == "ad_group");
        bundles["ad_privileged_membership"]["records"]!.AsArray().Add(Obj(new { record_type = "relation", source_record_key = user.Text("record_key"), target_record_key = group.Text("record_key") }));
        var ids = reference["ids"]!.AsObject().ToDictionary(p => p.Key, p => p.Value!.GetValue<long>());
        var snapshot = AdUsersSnapshot.Build(bundles, 7, "example.test", ids);
        var projected = snapshot["users"]!.AsArray().First(u => u.Int("entityId") == ids[user!["identity"].Text("object_guid")!]);
        var basis = Assert.Single(projected!["privilegedMemberships"]!.AsArray());
        Assert.Equal(ids[group!["identity"].Text("object_guid")!], basis.Int("group_id")); Assert.Equal(group["attributes"].Text("display_name"), basis.Text("group"));
        Assert.Equal("direct", basis.Text("relation")); Assert.Equal("privileged_membership", basis.Text("basis"));
    }

    [Fact] public async Task Postgres_store_uses_verified_snapshots_and_one_prepared_settings_policy_without_activity_tables()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct); await using var db = await pg.OpenAsync(Ct);
        await Seed(db, Snapshot(Account(1, password: "2026-07-01T00:00:00Z", activity: "2026-09-01T00:00:00Z"), Account(2)));
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["ConnectionStrings:Sli"] = pg.ConnectionString }).Build();
        var store = new AdV2Store(new PostgresConnectionFactory(config), config);
        var r = await store.ReadAsync(Request("risk"), fields => !fields.Contains("technical"), Ct);
        Assert.Equal(new long[] { 1 }, Ids(r)); Assert.Equal(new[] { "inactive_threshold" }, Keys(r["items"]![0]!["reason_keys"]));
        Assert.Equal(1, r["coverage"].Int("unknown_accounts")); Assert.True(JsonNode.DeepEquals(Policy(120, 30), r["coverage"]!["hygiene_policy"]));
        await PostCollectionPostgres.Sql(db, "update users_report_v2_snapshots set payload_json=jsonb_set(payload_json,'{users,0,enabled}','false')", Ct);
        var failure = await store.ReadAsync(Request("all"), _ => false, Ct);
        Assert.Empty(Ids(failure)); Assert.NotEqual("ok", failure.Text("state"));
    }
    [Fact] public async Task Semantic_SQL_counts_only_exact_open_published_unsuppressed_links_and_reports_reader_failure()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct); await using var db = await pg.OpenAsync(Ct);
        await Seed(db, Snapshot(Account(1), Account(2)));
        await PostCollectionPostgres.Sql(db, """
            create table findings_active(id bigint,status text,rule_code text,published boolean,suppressed boolean);
            create table finding_entities(finding_id bigint,entity_id bigint);
            create function is_semantic_finding_published_v1(bigint) returns boolean language sql as 'select published from findings_active where id=$1';
            create function semantic_finding_suppressed_v160(bigint,text) returns boolean language sql as 'select suppressed from findings_active where id=$1';
            insert into findings_active values(1,'new','synthetic',true,false),(2,'review','synthetic',true,false),
                (3,'closed','synthetic',true,false),(4,'active','synthetic',false,false),(5,'confirmed','synthetic',true,true),(6,'active','synthetic',true,false);
            insert into finding_entities values(1,1),(1,1),(2,1),(3,1),(4,1),(5,1),(6,99);
            """, Ct);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["ConnectionStrings:Sli"] = pg.ConnectionString }).Build();
        var store = new AdV2Store(new PostgresConnectionFactory(config), config);
        var r = await store.ReadAsync(Request("semantic"), fields => !fields.Contains("technical"), Ct);
        Assert.Equal(new long[] { 1 }, Ids(r)); Assert.Equal(2, r["items"]![0].Int("finding_count")); Assert.Equal(1, r["items"]![0].Int("queue_entity_id"));
        await PostCollectionPostgres.Sql(db, "drop table finding_entities", Ct);
        r = await store.ReadAsync(Request("semantic"), fields => !fields.Contains("technical"), Ct);
        Assert.Equal("error", r.Text("state")); Assert.Null(r["filtered_count"]); Assert.Empty(Ids(r));
        AdV2Result.Finish(r); Assert.Equal("semantic_unavailable", r["state_details"].Text("reason"));
    }
    static async Task Seed(Npgsql.NpgsqlConnection db, JsonObject snapshot)
    {
        await PostCollectionPostgres.Sql(db, """
            create table domains(id bigint,fqdn text);
            insert into domains values(1,'example.test');
            create table ad_snapshot_manifests(domain_id bigint,manifest_id uuid,coverage_state text,slot_start_utc timestamptz);
            insert into ad_snapshot_manifests values(1,'11111111-1111-1111-1111-111111111111','partial','2026-10-07T00:00:00Z');
            create table ad_snapshot_manifest_sources(manifest_id uuid,family text,source_state text,observed_at_utc timestamptz,payload_sha256 bytea,source_id text);
            create table users_report_v2_snapshots(domain_id bigint,snapshot_id bigint,payload_json jsonb,payload_sha256 bytea,scope_json jsonb);
            create table platform_settings(key text,value text);
            insert into platform_settings values('ad.password_max_age_days','120'),('ad.inactivity_days','30');
            create table runtime_worker_heartbeats(worker_name text,status text,heartbeat_at timestamptz,expected_interval_seconds int,details_json jsonb);
            insert into runtime_worker_heartbeats values('semantic','idle',now(),30,'{"runtime_mode":"findings-v1","manual_runtime":false}');
            """, Ct);
        await using var command = new Npgsql.NpgsqlCommand("""
            insert into users_report_v2_snapshots values(1,1,@payload,decode(@hash,'hex'),'{}');
            insert into ad_snapshot_manifest_sources values('11111111-1111-1111-1111-111111111111','users_v2','partial','2026-10-07T00:00:00Z',decode(@hash,'hex'),'1');
            """, db);
        command.Parameters.AddWithValue("payload", NpgsqlTypes.NpgsqlDbType.Jsonb, snapshot.ToJsonString()); command.Parameters.AddWithValue("hash", AdJobPlugin.Digest(snapshot)); await command.ExecuteNonQueryAsync(Ct);
    }

    sealed class Auth : IPrincipalAuthenticator
    { public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c, CancellationToken ct) => ValueTask.FromResult(AuthenticationResult.Success(new("session", 1, "operator"))); }
    sealed class Facts(string? missing = null) : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal p, CancellationToken ct)
        {
            var fields = new[] { "identity_basic", "security", "privilege", "technical", "hr", "contact" }.Where(f => f != missing).ToArray();
            JsonElement J(object o) => JsonSerializer.SerializeToElement(o);
            return Task.FromResult(new AccessFacts(false, "operator", [], [], fields.Select(f => "field." + f).Append("reports.export").Select(c => J(new { capability_key = c, effect = "allow", scope_json = new { kind = "all" } })).ToArray(), [], [],
                [J(new { report_key = "ad.users.v2", effect = "allow", allowed_actions = new[] { "view", "export" }, field_categories = fields, scope_json = new { kind = "domain", ids = new[] { 7, 8 } } })],
                [J(new { report_key = "ad.users.v2", version = 1, dataset_version = 1, actions_json = new[] { "view", "export" }, fields_json = fields.Select(category => new { category }), definition_json = new { actions = new[] { "view", "export" } } })]));
        }
    }
    sealed class Store : IAdV2Store
    {
        public int Reads; public AdV2Request? Last;
        public Task<IReadOnlyList<JsonObject>> DomainsAsync(DomainGrant grant, CancellationToken ct) => Task.FromResult<IReadOnlyList<JsonObject>>([Obj(new { id = 7, display_name = "example.test" }), Obj(new { id = 8, display_name = "example.test" })]);
        public Task<JsonObject> ReadAsync(AdV2Request r, Func<IEnumerable<string>, bool> fields, CancellationToken ct)
        { Reads++; Last = r; return Task.FromResult(AdUsersTabs.Query(r, [Source(Snapshot(Account(1)))], Policy(), fields)); }
    }
    static async Task<IHost> Host(Store store, string? missing = null)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "true" }).Build();
        return await new HostBuilder().ConfigureWebHost(w => w.UseTestServer().ConfigureServices(s =>
        {
            s.AddRouting(); s.AddLogging(); s.AddSingleton<IConfiguration>(config); s.AddSingleton(new AuthRequestPolicy(config)); s.AddSingleton(new TransportGate(config));
            s.AddSingleton<IPrincipalAuthenticator>(new Auth()); s.AddSingleton<IAccessFactsRepository>(new Facts(missing)); s.AddSingleton<IAdV2Store>(store);
            s.AddSingleton<IReportCatalogProvider>(new ReportRuleCatalog(new PluginGenerationReader(null)));
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => e.MapAdV2()); })).StartAsync(Ct);
    }
    [Theory][InlineData("active", "security", 400)][InlineData("disabled", "security", 400)][InlineData("risk", "security", 400)]
    [InlineData("privileged", "security", 403)][InlineData("privileged", "privilege", 403)][InlineData("semantic", null, 400)]
    public async Task Removed_tabs_and_missing_fields_reject_before_snapshot_reads(string tab, string? missing, int status)
    {
        var store = new Store(); using var host = await Host(store, missing); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v2/reports/ad.users.v2/data?tab=" + tab, Ct); Assert.Equal(status, (int)response.StatusCode); Assert.Equal(0, store.Reads);
        if (status == 403) Assert.Contains("denied", await response.Content.ReadAsStringAsync(Ct));
    }
    [Fact] public async Task Default_domain_scope_reads_every_granted_domain()
    {
        var store = new Store(); using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v2/reports/ad.users.v2/data?tab=all", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Equal(new long[] { 7, 8 }, store.Last!.Domains); Assert.Equal(1, store.Reads);
    }
}
