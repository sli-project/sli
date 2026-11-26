using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Ad;
using Sli.Server.Auth;
using Sli.Server.Tests.Agents;
using Xunit;
using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sli.Server.Access;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Infrastructure;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Tests.Ad;

// Port of tests/reporting/test_ad_review_checks.py. Every database is disposable,
// and every vector reads the production snapshot/event queries.
public sealed class AdReviewChecksTests : IClassFixture<AdReviewChecksTests.Database>
{
    static readonly IConfiguration Legacy = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:Storage:ShortEventReads"]="false" }).Build();
    readonly Database database;
    public AdReviewChecksTests(Database database) => this.database = database;
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-10-17T03:00:00Z");
    static string At(double days) => Now.AddDays(-days).ToString("O");
    static JsonObject User(int id = 1, int uac = 512) => new()
    {
        ["entityId"] = id, ["objectGuid"] = "synthetic-user-" + id,
        ["sid"] = "S-1-5-21-100000001-200000002-300000003-" + id,
        ["samAccountName"] = "synthetic-account-" + id, ["enabled"] = true,
        ["userAccountControl"] = uac, ["lockedOut"] = false, ["passwordLastSet"] = At(10),
        ["lastLogonTimestamp"] = At(2), ["servicePrincipalNames"] = new JsonArray(),
        ["memberships"] = JsonNode.Parse("""{"status":"observed","effective":[]}""")
    };
    static JsonObject Computer() => new()
    {
        ["objectGuid"] = "synthetic-computer-1", ["sid"] = User()["sid"]!.DeepClone(),
        ["name"] = "synthetic-host-1", ["enabled"] = true, ["deviceType"] = "workstation",
        ["lastLogonTimestamp"] = At(2), ["passwordLastSet"] = At(10), ["whenCreated"] = At(10),
        ["osName"] = "Windows 11 Enterprise", ["osVersion"] = "10.0 (26100)",
        ["trustedForDelegation"] = false, ["resourceBasedDelegationPresent"] = false,
        ["lapsPasswordExpiration"] = At(-1)
    };
    static JsonObject Event(int code) => new()
    {
        ["id"] = code, ["event_id"] = code, ["domain_id"] = 1,
        ["time_created_utc"] = Now.AddHours(-1).ToString("O"), ["target_user_sid"] = User()["sid"]!.DeepClone(),
        ["subject_user_name"] = "synthetic-operator", ["subject_domain_name"] = "example.test"
    };
    static JsonObject Privileged(int uac = 512)
    {
        var user = User(uac: uac);
        user["memberships"]!["effective"] = JsonNode.Parse("""[{"watchGroup":true,"relation":"nested"}]""");
        return user;
    }
    static JsonObject Row(JsonObject result, string key) => result["items"]!.AsArray().OfType<JsonObject>().Single(r => r.Text("key") == key);
    static void Number(JsonObject row, string key, int expected) => Assert.Equal(expected, row[key]!.GetValue<int>());

    public sealed class Database : IAsyncLifetime
    {
        internal readonly PostCollectionPostgres Pg = new(canonicalSchema: true);
        public async ValueTask InitializeAsync()
        {
            await Pg.StartAsync(CancellationToken.None);
            await using var db = await Pg.OpenAsync(CancellationToken.None);
            await PostCollectionPostgres.Sql(db, """
                create table domains(id bigint primary key,fqdn text);
                insert into domains values(1,'one.example.test'),(2,'two.example.test');
                create table auth_users(id bigint,previous_login_at timestamptz);
                create table platform_settings(key text,value text);
                create table ad_snapshot_manifests(manifest_id uuid,domain_id bigint,slot_start_utc timestamptz,assembled_at_utc timestamptz,coverage_state text);
                create table ad_snapshot_manifest_sources(manifest_id uuid,family text,source_id text,source_state text,observed_at_utc timestamptz,payload_sha256 bytea);
                create table users_report_v2_snapshots(snapshot_id bigint,domain_id bigint,payload_json jsonb,payload_sha256 bytea,scope_json jsonb);
                create table computers_v6_source_snapshots(snapshot_uuid uuid,domain_id bigint,payload_json jsonb,payload_sha256 bytea,source_options_json jsonb);
                create table ad_context_entity_aliases(domain_id bigint,alias_type text,normalized_value text,alias_value text,entity_id bigint);
                create table servers(id bigint,domain_id bigint,role text);
                insert into servers values(1,1,'domain_controller'),(2,2,'domain_controller');
                create table event_hot(event_id bigint,time_created_utc timestamptz,event_kind int,domain_id bigint,actor text,target text,source text,computer text,method jsonb,outcome jsonb,fields jsonb);
                create table event_cold_facts (like event_hot);
                create table event_cold_daily(day date,event_kind int,domain_id bigint,actor text,target text,source text,computer text,method jsonb,outcome jsonb,grouping_key bytea,event_count bigint,first_seen_utc timestamptz,last_seen_utc timestamptz);
                create table sli_agents(id uuid,host_id uuid,created_at timestamptz,last_seen timestamptz,status text);
                create table sli_agent_audit(target text,occurred_at timestamptz,actor text,action text);
                create table sli_agent_group_approval_links(enrollment_token_id uuid,request_id uuid);
                create table sli_agent_group_requests(id uuid,computer_entity_id bigint);
                create table core_entity_scope_resources(natural_key text,plugin_id text,source_instance_id text,entity_type text,resolution text,entity_id bigint,observed_at_utc timestamptz);
                create table core_entity_associations(source_entity_id bigint,target_entity_id bigint,relation text,created_at_utc timestamptz);
                create table sli_agent_removals(agent_id uuid,state text,reported_at timestamptz);
                create table entities_v2(id bigint,domain_id bigint,entity_type_id bigint);
                create table storage_v2_entity_type(id bigint,value text);
                create table sli_agent_update_results(agent_id uuid,version text,observed_at timestamptz,package_sha256 text,status text);
                """, CancellationToken.None);
        }
        public ValueTask DisposeAsync() => Pg.DisposeAsync();
    }
    async Task<NpgsqlConnection> Open()
    {
        var db = await database.Pg.OpenAsync(Ct);
        await db.BeginTransactionAsync(Ct); // Rollback on disposal keeps vectors independent.
        return db;
    }
    static async Task Seed(NpgsqlConnection db, bool users, JsonObject[] objects, int role = 0, string state = "complete", int domain = 1, JsonObject? metadata = null, string scope = "{}")
    {
        var payload = new JsonObject { [users ? "users" : "objects"] = Array(objects), ["metadata"] = metadata?.DeepClone() ?? new JsonObject() };
        var manifest = Guid.NewGuid();
        await using var command = new NpgsqlCommand($"""
            insert into ad_snapshot_manifests values(@manifest,@domain,@slot,@slot,'complete');
            insert into ad_snapshot_manifest_sources values(@manifest,@family,@id,@state,@at,decode(@hash,'hex'));
            insert into {(users ? "users_report_v2_snapshots" : "computers_v6_source_snapshots")} values(@snapshot,@domain,@payload,decode(@hash,'hex'),@scope);
            """, db);
        command.Parameters.AddWithValue("manifest", manifest); command.Parameters.AddWithValue("domain", (long)domain);
        // Slots must be retained relative to the test cluster's clock; object ages
        // and source observations stay at the frozen Python vector time.
        command.Parameters.AddWithValue("slot", DateTimeOffset.UtcNow.AddDays(-role - 1));
        command.Parameters.AddWithValue("family", users ? "users_v2" : "computers_v6");
        long id = role * 10 + domain;
        command.Parameters.AddWithValue("id", users ? id.ToString() : manifest.ToString());
        command.Parameters.AddWithValue("snapshot", users ? (object)id : manifest);
        command.Parameters.AddWithValue("state", state); command.Parameters.AddWithValue("at", Now.AddDays(-role));
        command.Parameters.AddWithValue("hash", AdJobPlugin.Digest(payload));
        command.Parameters.AddWithValue("payload", NpgsqlTypes.NpgsqlDbType.Jsonb, payload.ToJsonString());
        command.Parameters.AddWithValue("scope", NpgsqlTypes.NpgsqlDbType.Jsonb, scope);
        await command.ExecuteNonQueryAsync(Ct);
    }
    static async Task<JsonObject> Read(NpgsqlConnection db, bool users = true, long[]? domains = null, bool since = false)
    {
        var request = new AdV2Request(users ? "ad.users.v2" : "ad.computers.v6", "view", null, domains ?? [1], new(), "checks", null, false, 50, null, "UTC")
        { Principal = since ? new Principal("session", 1, "synthetic") : null };
        var sources = await AdV2Store.Snapshots(db, users ? "users_v2" : "computers_v6", request.Domains, Ct);
        return await AdReviewChecks.ReadAsync(db, request, sources, Ct,Legacy);
    }
    static async Task Login(NpgsqlConnection db)
    {
        await using var command = new NpgsqlCommand("insert into auth_users values(1,@at)", db);
        command.Parameters.AddWithValue("at", DateTimeOffset.UtcNow.AddDays(-2.5)); await command.ExecuteNonQueryAsync(Ct);
    }
    [Fact]
    public async Task Review_checks_propagate_permission_denial_instead_of_an_empty_event_list()
    {
        await using var db=await Open();
        await PostCollectionPostgres.Sql(db,"""
            create role synthetic_ad_review_reader;
            grant usage on schema public to synthetic_ad_review_reader;
            grant select on all tables in schema public to synthetic_ad_review_reader;
            revoke select on event_hot from synthetic_ad_review_reader;
            set local role synthetic_ad_review_reader;
            """,Ct);
        var error=await Assert.ThrowsAsync<PostgresException>(()=>Read(db));
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege,error.SqlState);
    }
    static async Task AddEvent(NpgsqlConnection db, JsonObject row)
    {
        await using var command = new NpgsqlCommand("""
            insert into event_hot values(@id,@at,@code,@domain,
                case when @code=4624 then @sid else 'example.test\synthetic-operator' end,coalesce(@object::text,@sid),'192.0.2.10','dc01.example.test',
                jsonb_build_object('$server_id',@domain::bigint,'$channel','Security','$provider','Microsoft-Windows-Security-Auditing','LogonType',@logon::text),
                '{}'::jsonb,jsonb_build_object('MemberSid',@member::text,'AttributeLDAPDisplayName',@facts::jsonb->>'attribute'));
            """, db);
        command.Parameters.AddWithValue("id", row.Int("id")); command.Parameters.AddWithValue("domain", row.Int("domain_id"));
        command.Parameters.AddWithValue("code", (int)row.Int("event_id"));
        command.Parameters.AddWithValue("at", DateTimeOffset.UtcNow.AddHours(-1));
        command.Parameters.AddWithValue("sid", (object?)row.Text("target_user_sid") ?? DBNull.Value);
        command.Parameters.AddWithValue("object",(object?)row["facts_json"]?.Text("object")??DBNull.Value);
        command.Parameters.AddWithValue("logon", NpgsqlTypes.NpgsqlDbType.Integer, row["logon_type"] is null ? DBNull.Value : (int)row.Int("logon_type"));
        command.Parameters.AddWithValue("member", NpgsqlTypes.NpgsqlDbType.Text, (object?)row.Text("membership_member_sid") ?? DBNull.Value);
        command.Parameters.AddWithValue("facts", NpgsqlTypes.NpgsqlDbType.Jsonb, row["facts_json"]?.ToJsonString() ?? "{}");
        await command.ExecuteNonQueryAsync(Ct);
    }

    [Theory][InlineData(true)][InlineData(false)]
    public async Task Empty_catalog_keeps_zero_counts_hygiene_and_localized_checks(bool users)
    {
        await using var db = await Open(); await Seed(db, users, []);
        var result = await Read(db, users); var rows = result["items"]!.AsArray();
        Assert.NotEmpty(rows); Assert.Contains(rows, row => row.Text("section") == "hygiene");
        foreach (var row in rows.OfType<JsonObject>())
        {
            Number(row, "total", 0);
            if (row.Text("section") == "hygiene") Assert.Equal("low", row.Text("severity"));
        }
        foreach (string locale in new[] { "ru", "en" })
        {
            var localized = result.DeepClone().AsObject();
            AdReviewChecks.Localize(localized, locale == "en");
            using var stream = typeof(AdV2Store).Assembly.GetManifestResourceStream("Sli.Server.Access.Administration.server." + locale + ".json")!;
            var catalog = JsonNode.Parse(stream)!;
            foreach (var row in localized["items"]!.AsArray().OfType<JsonObject>())
            {
                foreach (string field in new[] { "title", "why", "action", "remediation" })
                {
                    string code = $"reports.ad.checks.{(users ? "users" : "computers")}.{row.Text("key")}.{field}";
                    Assert.Equal(code, row["presentation_messages"]![field]!.Text("code"));
                    Assert.False(string.IsNullOrWhiteSpace(catalog[code]?.ToString()));
                    Assert.Equal(catalog[code]!.ToString(), row.Text(field));
                }
            }
        }
    }
    [Fact] public async Task Duplicate_objects_and_overlapping_checks_count_once_per_domain()
    {
        await using var db = await Open(); var objects = Enumerable.Range(1, 5).Select(i => User(i, 512 | 128 | 65536)).ToArray();
        await Seed(db, true, [..objects, objects[0]]); await Seed(db, true, [objects[0]], domain: 2);
        var result = await Read(db, domains: [1, 2]); var row = Row(result, "reversible_password");
        Number(row, "total", 6); Number(row, "remaining_objects", 3); Assert.Equal(3, row["objects"]!.AsArray().Count);
        Assert.All(row["objects"]!.AsArray(), o => { Assert.True(o.Int("domain_id") > 0); Assert.EndsWith("example.test", o.Text("domain_name")); });
        Number(result["coverage"]!.AsObject(), "population", 6); Number(result["coverage"]!.AsObject(), "affected_objects", 6);
    }
    [Fact] public async Task Review_accounts_page_unique_accounts_and_keep_other_checks_when_filtered()
    {
        await using var db = await Open();
        var overlapping = User(1, 512 | 128 | 65536);
        await Seed(db, true, [overlapping, overlapping, User(2, 512 | 65536)]);
        await Seed(db, true, [overlapping], domain: 2);
        var request = new AdV2Request("ad.users.v2", "view", null, [1, 2], new() { ["account_rows"] = "yes" },
            "checks", null, false, 1, null, "UTC") { QualifyNames = true };
        var sources = await AdV2Store.Snapshots(db, "users_v2", request.Domains, Ct);
        Task<JsonObject> Query(AdV2Request query) => AdReviewChecks.ReadAsync(db, query, sources, Ct, Legacy);
        var first = await Query(request);
        var row = Assert.Single(first["items"]!.AsArray())!;
        Assert.StartsWith("reversible_password", row["review_reasons"]![0].Text("key"));
        Assert.Contains(row["review_reasons"]!.AsArray(), reason => reason.Text("key") == "password_never_expires");
        var second = await Query(request with { Cursor = first.Text("next_cursor") });
        var nextRow = Assert.Single(second["items"]!.AsArray())!;
        Assert.NotEqual(row.Text("id"), nextRow.Text("id"));
        Assert.NotEqual(row.Int("domain_id"), nextRow.Int("domain_id"));
        Assert.Contains("\\", row.Text("sam"));

        var filtered = await Query(request with { Limit = 50, Params = new() { ["account_rows"] = "yes", ["check"] = "reversible_password" } });
        Assert.All(filtered["items"]!.AsArray(), item => Assert.Contains(item!["review_reasons"]!.AsArray(), reason => reason.Text("key") == "reversible_password"));
        var chips = filtered["filter_options"]!["check"]!.AsArray();
        Assert.Contains(chips, chip => chip.Text("value") == "password_never_expires" && chip.Int("count") > filtered.Int("filtered_count"));
        Assert.DoesNotContain(chips, chip => chip.Int("count") == 0);

        var store = new CheckStore(db);
        using var host = await Host(store);
        using var client = host.GetTestClient();
        client.DefaultRequestHeaders.AcceptLanguage.ParseAdd("en");
        const string path = "/api/v2/reports/ad.users.v2/data?tab=checks&account_rows=yes&domain=2&check=reversible_password";
        using var response = await client.GetAsync(path, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var localized = JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!;
        var localizedAccount = Assert.Single(localized["items"]!.AsArray())!;
        Assert.Equal(2, localizedAccount.Int("domain_id"));
        var reasonLabel = localizedAccount["review_reasons"]![0].Text("label");
        Assert.Contains(localized["filter_options"]!["check"]!.AsArray(), chip =>
            chip.Text("value") == "reversible_password" && chip.Text("label") == reasonLabel);
        Assert.Null(localizedAccount["department"]);

        var deniedStore = new CheckStore(db);
        using var deniedHost = await Host(deniedStore, false);
        using var deniedResponse = await deniedHost.GetTestClient().GetAsync(path, Ct);
        Assert.Equal(HttpStatusCode.Forbidden, deniedResponse.StatusCode);
        Assert.Empty(deniedStore.Reads);
    }
    [Fact] public async Task Established_protected_membership_does_not_put_an_account_in_default_review()
    {
        await using var db = await Open();
        var member = Privileged();
        await Seed(db, true, [member, User(2)], role: 1);
        await Seed(db, true, [member, User(2, 512 | 128)]);
        var request = new AdV2Request("ad.users.v2", "view", null, [1], new() { ["account_rows"] = "yes" },
            "checks", null, false, 50, null, "UTC");
        var sources = await AdV2Store.Snapshots(db, "users_v2", request.Domains, Ct);

        var review = await AdReviewChecks.ReadAsync(db, request, sources, Ct, Legacy);

        Assert.Equal(1, review.Int("filtered_count"));
        var account = Assert.Single(review["items"]!.AsArray())!;
        Assert.Equal(2, account.Int("entity_id"));
        Assert.Contains(account["review_reasons"]!.AsArray(), reason => reason.Text("key") == "reversible_password");
    }
    [Fact] public async Task Login_baseline_is_distinct_from_latest_pair_and_creation()
    {
        await using var db = await Open(); await Login(db);
        await Seed(db, true, [User(1, 640), User(2), User(3)], 2);
        await Seed(db, true, [User(1, 640), User(2), User(3), User(4, 640)], 1);
        await Seed(db, true, Enumerable.Range(1, 4).Select(i => User(i, 640)).ToArray());
        var row = Row(await Read(db, since: true), "reversible_password");
        Number(row, "total", 4); Number(row, "previous_total", 2); Number(row, "new_count", 3); Number(row, "delta", 2); Assert.Equal("new", row.Text("status"));
    }
    [Fact] public async Task Reduction_is_count_delta_even_when_every_object_is_new()
    {
        await using var db = await Open(); await Login(db);
        await Seed(db, true, [], 2); await Seed(db, true, [User(1, 640), User(2, 640)], 1); await Seed(db, true, [User(3, 640)]);
        var result = await Read(db, since: true); var row = Row(result, "reversible_password");
        Number(row, "delta", -1); Number(row, "new_count", 1); Assert.Equal("decreased", row.Text("status"));
        Assert.Equal("reports.ad.checks.status.decreased", row["presentation_messages"]!["status_text"]!.Text("code"));
        Number(row["presentation_messages"]!["status_text"]!["params"]!.AsObject(), "count", 1);
        AdReviewChecks.Localize(result,true); Assert.Equal("Decreased by 1",row.Text("status_text"));
    }
    [Theory][InlineData("partial", "complete")][InlineData("complete", "partial")]
    public async Task Partial_pair_cannot_claim_reduction(string prior, string current)
    {
        await using var db = await Open(); await Login(db); await Seed(db, true, [], 2);
        await Seed(db, true, [User(1, 640)], 1, prior); await Seed(db, true, [User()], state: current);
        var row = Row(await Read(db, since: true), "reversible_password");
        Assert.Null(row["previous_total"]); Assert.Equal("no_comparison", row.Text("status"));
        if (current == "partial") Assert.Null(row["new_count"]);
    }
    [Fact] public async Task Unknown_inputs_are_not_zero_and_unassessed_population_is_unique()
    {
        await using var db = await Open(); await Seed(db, false, [new() { ["objectGuid"] = "synthetic-unknown" }]);
        await PostCollectionPostgres.Sql(db, "drop table sli_agents", Ct); // No agent evidence in the Python summary vector.
        var result = await Read(db, false);
        Assert.All(result["items"]!.AsArray().OfType<JsonObject>(), row => { Assert.Null(row["total"]); Number(row, "not_evaluated_count", 1); });
        Number(result["coverage"]!.AsObject(), "not_evaluated_count", 1); Assert.Null(result["coverage"]!["footer_rows"]);
        Assert.Equal("partial", result.Text("state"));
    }
    [Fact] public async Task First_login_missing_domain_and_missing_current_family_remain_unknown()
    {
        await using var db = await Open(); await Seed(db, false, [Computer()]);
        var first = await Read(db, false);
        Assert.All(first["items"]!.AsArray(), row => { Assert.Null(row!["new_count"]); Assert.Equal(row["total"] is null ? "not_evaluated" : "no_comparison", row.Text("status")); });
        await Login(db);
        Assert.All((await Read(db, false, since: true))["items"]!.AsArray(), row => Assert.Null(row!["new_count"]));
        var missing = await Read(db, false, [1, 2]); Assert.Null(missing["coverage"]!["population"]); Assert.Null(missing["coverage"]!["not_evaluated_count"]); Assert.Equal("partial", missing.Text("state"));
        await Seed(db, true, [User()], 1);
        var absent = await Read(db); Assert.Equal("not_collected", absent.Text("state")); Assert.All(absent["items"]!.AsArray(), r => Assert.Null(r!["total"]));
    }
    [Fact] public void Age_thresholds_are_strict_and_nested_privileges_are_not_admin_count()
    {
        var user = User(); user["passwordLastSet"] = At(365); user["lastLogonTimestamp"] = At(90);
        var values = AdReviewChecks.Evaluate(true, user, Now); Assert.False(values["old_password"]); Assert.False(values["inactive_enabled"]);
        user["passwordLastSet"] = At(366); user["lastLogonTimestamp"] = At(91);
        values = AdReviewChecks.Evaluate(true, user, Now); Assert.True(values["old_password"]); Assert.True(values["inactive_enabled"]);
        var computer = Computer(); computer["passwordLastSet"] = At(60); Assert.False(AdReviewChecks.Evaluate(false, computer, Now)["old_machine_password"]);
        var privileged = Privileged(512 | 65536); privileged["enabled"] = false; privileged["servicePrincipalNames"] = new JsonArray("HTTP/synthetic.example.test");
        values = AdReviewChecks.Evaluate(true, privileged, Now, User(), true);
        foreach (string key in new[] { "new_privileged", "inactive_privileged", "spn_privileged", "privileged_password_never_expires" }) Assert.True(values[key]);
        user = User(); user["adminCount"] = 1; values = AdReviewChecks.Evaluate(true, user, Now, previousComplete: true);
        Assert.False(values["new_privileged"]); Assert.False(values["inactive_privileged"]);
    }
    [Fact] public void Disabled_logon_requires_matching_disable_and_reenable_cancels_evidence()
    {
        var user = User(); user["enabled"] = false; var disable = Event(4725); disable["time_created_utc"] = Now.AddHours(-2).ToString("O");
        var logon = Event(4624);
        Assert.Null(AdReviewChecks.Evaluate(true, user, Now, events: [logon])["disabled_logon"]);
        Assert.True(AdReviewChecks.Evaluate(true, user, Now, events: [disable, logon])["disabled_logon"]);
        Assert.Null(AdReviewChecks.Evaluate(true, user, Now, events: [disable, logon, Event(4722)])["disabled_logon"]);
        logon["target_user_sid"] = User(2)["sid"]!.DeepClone();
        Assert.Null(AdReviewChecks.Evaluate(true, user, Now, events: [disable, logon])["disabled_logon"]);
    }
    [Fact] public void Interactive_service_logon_requires_snapshot_classification_and_exact_logon_type()
    {
        var user = User(); user["objectClasses"] = new JsonArray("msDS-GroupManagedServiceAccount"); var logon = Event(4624); logon["logon_type"] = 10;
        Assert.True(AdReviewChecks.Evaluate(true, user, Now, events: [logon])["service_interactive_logon"]);
        logon["logon_type"] = 3; Assert.Null(AdReviewChecks.Evaluate(true, user, Now, events: [logon])["service_interactive_logon"]);
        logon["logon_type"] = 2; Assert.Null(AdReviewChecks.Evaluate(true, User(), Now, events: [logon])["service_interactive_logon"]);
        Assert.Null(AdReviewChecks.Evaluate(true, user, Now)["service_interactive_logon"]);
        Assert.Null(AdReviewChecks.Evaluate(true, User(), Now)["service_interactive_logon"]);
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task Actors_require_relevant_attribute_exact_sid_or_guid_and_same_domain(bool byGuid)
    {
        await using var db = await Open(); await Seed(db, true, [User(uac: 640)]); await AddEvent(db, Event(4724));
        Assert.Null(Row(await Read(db), "reversible_password")["change"]);
        var change = Event(5136); change["facts_json"] = new JsonObject { ["attribute"] = "userAccountControl" };
        if(byGuid){change["target_user_sid"] = null;change["facts_json"]!["object"] = "synthetic-user-1";}
        await AddEvent(db, change); var other = (JsonObject)change.DeepClone(); other["id"] = 99999; other["domain_id"] = 2; await AddEvent(db, other);
        var row = Row(await Read(db, domains: [1, 2]), "reversible_password");
        Number(row["change"]!.AsObject(), "event_db_id", 5136); Assert.Equal("example.test\\synthetic-operator", row["change"]!.Text("actor"));
        Assert.True(JsonNode.DeepEquals(row["change"], row["objects"]![0]!["change"]));
    }
    [Fact] public async Task Computer_posture_uses_creation_and_unknown_laps_metadata_stays_unknown()
    {
        await using var db = await Open(); var computer = Computer(); computer["osName"] = "Windows 8.1"; computer["osVersion"] = "6.3 (9600)";
        computer["trustedForDelegation"] = true; computer["resourceBasedDelegationPresent"] = true; computer["lapsPasswordExpiration"] = At(1);
        computer["whenCreated"] = At(.5); computer["lastLogonTimestamp"] = At(91); computer["passwordLastSet"] = At(61);
        await Seed(db, false, [computer]); Assert.All((await Read(db, false))["items"]!.AsArray().OfType<JsonObject>(), row => Number(row, "total", 1));
        computer["whenCreated"] = At(10); computer["lapsPasswordExpiration"] = null;
        var values = AdReviewChecks.Evaluate(false, computer, Now); Assert.False(values["new_computer"]); Assert.Null(values["laps"]);
    }
    [Fact] public async Task Service_exception_suppresses_only_hygiene_and_sources_are_immutable()
    {
        await using var db = await Open(); var user = User(uac: 640); user["objectClasses"] = new JsonArray("msDS-GroupManagedServiceAccount"); user["passwordLastSet"] = At(400); user["lastLogonTimestamp"] = At(100);
        await Seed(db, true, [user]);
        await PostCollectionPostgres.Sql(db, """insert into platform_settings values('ad.service_account_exceptions','[{"sid":"S-1-5-21-100000001-200000002-300000003-1"}]')""", Ct);
        var sources = await AdV2Store.Snapshots(db, "users_v2", [1], Ct); string original = Array(sources).ToJsonString();
        var request = new AdV2Request("ad.users.v2", "view", null, [1], new(), "checks", null, false, 50, null, "UTC");
        var result = await AdReviewChecks.ReadAsync(db, request, sources, Ct,Legacy);
        Number(Row(result, "old_password"), "total", 0); Number(Row(result, "inactive_enabled"), "total", 0); Number(Row(result, "reversible_password"), "total", 1);
        Assert.Equal(original, Array(sources).ToJsonString()); Assert.Contains(result.Text("state"), new[] { "stale", "partial" });
    }
    [Fact] public async Task Privilege_history_uses_predecessors_and_unrelated_group_add_is_not_an_actor()
    {
        await using var db = await Open(); await Login(db);
        await Seed(db, true, [User()], 3); await Seed(db, true, [User()], 2); await Seed(db, true, [User()], 1); await Seed(db, true, [Privileged()]);
        var unrelated = Event(4728); unrelated["membership_member_sid"] = User()["sid"]!.DeepClone(); unrelated["target_user_sid"] = User(99)["sid"]!.DeepClone(); await AddEvent(db, unrelated);
        var row = Row(await Read(db, since: true), "new_privileged");
        Number(row, "total", 1); Number(row, "new_count", 1); Number(row, "previous_total", 0); Assert.Equal("new", row.Text("status")); Assert.Null(row["change"]);
    }
    [Theory][InlineData(true, "directory", "user_count", 158)][InlineData(false, "ad", "object_count", 44)]
    public async Task Optional_partial_sources_preserve_attested_zeroes(bool users, string source, string countKey, int size)
    {
        await using var db = await Open(); var objects = Enumerable.Range(0, size).Select(i => { var o = users ? User(i + 1) : Computer(); if (users) o["objectClasses"] = new JsonArray("user"); else o["objectGuid"] = "synthetic-computer-" + i; return o; }).ToArray();
        var metadata = new JsonObject { [countKey] = size, ["collection_status"] = "partial", ["sources"] = new JsonArray(new JsonObject { ["name"] = source, ["status"] = "observed" }, new JsonObject { ["name"] = "exact_last_logon", ["status"] = "not_collected" }) };
        await Seed(db, users, objects, 1, "partial", metadata: metadata); await Seed(db, users, objects, state: "partial", metadata: metadata);
        var result = await Read(db, users); var row = Row(result, users ? "kerberos_no_preauth" : "new_computer");
        Number(row, "total", 0); Number(row, "previous_total", 0); Assert.Equal("unchanged", row.Text("status")); Assert.False(row["is_lower_bound"]!.GetValue<bool>());
        Assert.Equal("complete", result["coverage"]!["domains"]![0]!.Text("state")); Assert.Equal("partial", result["coverage"]!["domains"]![0]!.Text("snapshot_state"));
    }
    [Theory][InlineData(true)][InlineData(false)]
    public async Task Partial_population_needs_attestation_matching_count_and_no_truncation(bool users)
    {
        foreach (int variant in new[] { 0, 1, 2, 3 })
        {
            await using var db = await Open(); var metadata = new JsonObject { [users ? "user_count" : "object_count"] = variant == 1 ? 2 : 1,
                ["sources"] = new JsonArray(new JsonObject { ["name"] = users ? "directory" : "ad", ["status"] = variant == 0 ? "partial" : "observed" }) };
            if (variant >= 2) metadata["coverage"] = new JsonObject { ["truncated"] = true };
            await Seed(db, users, [users ? User() : Computer()], state: variant == 3 ? "complete" : "partial", metadata: metadata);
            Assert.True(Row(await Read(db, users), users ? "old_password" : "new_computer")["is_lower_bound"]!.GetValue<bool>());
        }
    }
    [Fact] public async Task Known_zero_is_lower_bound_when_only_some_objects_have_inputs()
    {
        await using var db = await Open(); var unknown = User(2); unknown["passwordLastSet"] = null;
        await Seed(db, true, [User(), unknown]); var row = Row(await Read(db), "old_password");
        Number(row, "total", 0); Assert.True(row["is_lower_bound"]!.GetValue<bool>()); Number(row, "assessed_count", 1); Number(row, "not_evaluated_count", 1); Assert.Equal("no_comparison", row.Text("status"));
        await PostCollectionPostgres.Sql(db, "delete from ad_snapshot_manifests; delete from ad_snapshot_manifest_sources; delete from users_report_v2_snapshots", Ct);
        await Seed(db, true, [unknown]); Assert.Null(Row(await Read(db), "old_password")["total"]);
    }
    [Fact] public async Task Unreadable_events_preserve_snapshot_findings_and_hide_details()
    {
        await using var db = await Open(); var computer = Computer(); computer["trustedForDelegation"] = true; await Seed(db, false, [computer]);
        await PostCollectionPostgres.Sql(db, "drop table event_hot", Ct);
        var result = await Read(db, false); Number(Row(result, "unconstrained_delegation"), "total", 1);
        Assert.Equal("unavailable", result["coverage"]!.Text("event_coverage")); Assert.DoesNotContain("event_hot", result.ToJsonString());
    }
    [Fact] public async Task Authentication_flood_does_not_displace_changes_and_computers_do_not_scan_logons()
    {
        await using var db = await Open();
        var known = Enumerable.Range(1, 158).Select(i => { var user = User(i, 640); user["objectClasses"] = new JsonArray("top", "user"); return user; }).ToArray();
        await Seed(db, true, known);
        var change = Event(5136); change["facts_json"] = new JsonObject { ["attribute"] = "userAccountControl" }; await AddEvent(db, change);
        await PostCollectionPostgres.Sql(db, """
            insert into event_hot select 100000+n,now(),4624,1,null,null,null,'dc01.example.test','{"$server_id":1,"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing"}','{}','{}' from generate_series(1,10001) n;
            """, Ct);
        var result = await Read(db); Number(Row(result, "reversible_password")["change"]!.AsObject(), "event_db_id", 5136); Assert.False(result["coverage"]!["events_truncated"]!.GetValue<bool>());
        var row = Row(result, "service_interactive_logon"); Number(row, "total", 0); Number(row, "not_evaluated_count", 0); Assert.False(row["is_lower_bound"]!.GetValue<bool>());
        var computer = Computer(); computer["trustedForDelegation"] = true;
        await Seed(db, false, [computer]); result = await Read(db, false); Assert.False(result["coverage"]!["events_truncated"]!.GetValue<bool>());
        Number(Row(result,"unconstrained_delegation")["change"]!.AsObject(),"event_db_id",5136);
    }
    [Fact] public async Task Historical_sources_require_same_scope_and_verified_source_checksum()
    {
        await using var db = await Open(); await Seed(db, false, [Computer()], 1, scope: "{\"different\":true}"); await Seed(db, false, [Computer()]);
        var source = Assert.Single(await AdV2Store.Snapshots(db, "computers_v6", [1], Ct)); Assert.Equal("synthetic-computer-1", source["snapshot"]!["objects"]![0]!.Text("objectGuid"));
        Assert.Null(await AdV2Store.PreviousSnapshot(db, source, "computers_v6", Ct));
        await PostCollectionPostgres.Sql(db, "update computers_v6_source_snapshots set payload_json=jsonb_set(payload_json,'{objects}','[]')", Ct);
        var corrupt = Assert.Single(await AdV2Store.Snapshots(db, "computers_v6", [1], Ct));
        Assert.Null(corrupt["snapshot"]); Assert.Equal("unavailable", corrupt.Text("source_state"));
        await PostCollectionPostgres.Sql(db, "update computers_v6_source_snapshots set payload_sha256=decode(repeat('00',32),'hex')", Ct);
        source = Assert.Single(await AdV2Store.Snapshots(db, "computers_v6", [1], Ct)); Assert.Null(source["snapshot"]);
    }
    sealed class FailureConnections : IPostgresConnectionFactory
    {
        public int Reads;
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) { Reads++; throw new InvalidOperationException("synthetic-private-database-detail"); }
    }
    [Theory][InlineData(true)][InlineData(false)]
    public async Task Field_denial_precedes_database_open_and_query_errors_are_safe(bool users)
    {
        var connections = new FailureConnections(); var store = new AdV2Store(connections, new ConfigurationBuilder().Build());
        var request = new AdV2Request(users ? "ad.users.v2" : "ad.computers.v6", "view", null, [1], new(), "checks", null, false, 50, null, "UTC");
        var denied = await store.ReadAsync(request, _ => false, Ct); Assert.Equal("denied", denied.Text("state")); Assert.Equal(0, connections.Reads);
        var error = await store.ReadAsync(request, _ => true, Ct); Assert.Equal("error", error.Text("state")); Assert.Empty(error["items"]!.AsArray());
        Assert.Equal("ad_review_unavailable", error["coverage"]!.Text("reason")); Assert.DoesNotContain("synthetic-private-database-detail", error.ToJsonString());
    }
    sealed class Auth : IPrincipalAuthenticator
    { public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c, CancellationToken ct) => ValueTask.FromResult(AuthenticationResult.Success(new("session", 1, "operator"))); }
    sealed class Facts(bool allowed) : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct)
        {
            string[] categories = allowed ? ["identity_basic", "technical", "security", "privilege"] : ["identity_basic"];
            var keys = new[] { "ad.users.v2", "ad.computers.v6" }.Select(k => AdV2Endpoints.Definitions[k]!.Text("access_key")!).ToArray();
            string[] defined = ["identity_basic", "technical", "security", "privilege", "contact", "hr", "raw_evidence", "computer_logon_observation"];
            var definitions = keys.Select(k => JsonSerializer.SerializeToElement(new { report_key = k, version = 1, dataset_version = 1, definition_json = new { field_categories = defined, actions = new[] { "view", "export" } }, fields_json = defined.Select(category => new { category }), actions_json = new[] { "view", "export" } })).ToArray();
            var policies = categories.Select(f => "field." + f).Concat(new[] { "workspace.view", "events.view", "evidence.exact" }).Select(k => JsonSerializer.SerializeToElement(new { capability_key = k, effect = "allow", scope_json = new { kind = "all" } })).ToArray();
            var assignments = keys.Select(k => JsonSerializer.SerializeToElement(new { report_key = k, effect = "allow", scope_json = new { kind = "domain", ids = new[] { 1, 2 } }, field_categories = categories, allowed_actions = new[] { "view" } })).ToArray();
            return Task.FromResult(new AccessFacts(false, "synthetic", [], [], policies, [], [], assignments, definitions));
        }
    }
    sealed class Catalog : IReportCatalogProvider
    {
        public ReportCatalogSnapshot Capture() => new(AdV2Endpoints.Definitions.Select(p => new ReportRule(p.Key, p.Value!.Text("access_key")!, "domain", new HashSet<string>(), new HashSet<string>(), null, false) { OwnerId = "sli.ad" }), new Dictionary<string, PluginGeneration>(), new Dictionary<string, string>());
        public ReportCatalogSnapshot Recheck(ReportCatalogSnapshot captured) => captured;
    }
    sealed class CheckStore(NpgsqlConnection db) : IAdV2Store
    {
        public readonly List<AdV2Request> Reads = [];
        public Task<IReadOnlyList<JsonObject>> DomainsAsync(DomainGrant grant, CancellationToken ct) => Task.FromResult<IReadOnlyList<JsonObject>>([new() { ["id"] = 1, ["display_name"] = "one.example.test" }, new() { ["id"] = 2, ["display_name"] = "two.example.test" }]);
        public async Task<JsonObject> ReadAsync(AdV2Request request, Func<IEnumerable<string>, bool> fields, CancellationToken ct)
        {
            Reads.Add(request);
            var sources = await AdV2Store.Snapshots(db, request.Key == "ad.users.v2" ? "users_v2" : "computers_v6", request.Domains, ct);
            return await AdReviewChecks.ReadAsync(db, request, sources, ct,Legacy);
        }
    }
    static async Task<IHost> Host(IAdV2Store store, bool allowed = true)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "true" }).Build();
        return await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(s =>
        {
            s.AddRouting(); s.AddLogging(); s.AddSingleton<IConfiguration>(config); s.AddSingleton(new AuthRequestPolicy(config)); s.AddSingleton(new TransportGate(config));
            s.AddSingleton<IPrincipalAuthenticator>(new Auth()); s.AddSingleton<IAccessFactsRepository>(new Facts(allowed)); s.AddSingleton(store); s.AddSingleton<IReportCatalogProvider>(new Catalog());
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => e.MapAdV2()); })).StartAsync(Ct);
    }
    [Theory][InlineData(true, "ru")][InlineData(false, "ru")][InlineData(true, "en")][InlineData(false, "en")]
    public async Task Http_checks_are_scoped_localized_without_diagnostic_blocks_and_do_not_require_hr(bool users, string locale)
    {
        await using var db = await Open(); await Seed(db, users, [users ? User() : Computer()], domain: 2);
        var store = new CheckStore(db); using var host = await Host(store); using var client = host.GetTestClient();
        client.DefaultRequestHeaders.AcceptLanguage.ParseAdd(locale);
        string path = "/api/v2/reports/" + (users ? "ad.users.v2" : "ad.computers.v6");
        using var response = await client.GetAsync(path + "/data?tab=checks&domain_id=2", Ct);
        Assert.True(response.StatusCode == HttpStatusCode.OK, await response.Content.ReadAsStringAsync(Ct)); var result = JsonNode.Parse(await response.Content.ReadAsStringAsync(Ct))!.AsObject();
        Assert.NotEmpty(result["items"]!.AsArray()); Assert.Equal(new long[] { 2 }, Assert.Single(store.Reads).Domains);
        Assert.Equal("sli.ad-review-checks.v1", result["coverage"]!.Text("contract_id")); Assert.Equal(2, result["coverage"]!["domains"]![0]!.Int("domain_id"));
        Assert.Empty(result["metrics"]!.AsArray()); Assert.Null(result["coverage"]!["footer_rows"]);
        var collection = result["collections"]!["checks"]!.AsArray();
        Assert.True(JsonNode.DeepEquals(result["items"], collection));
        Assert.DoesNotContain(collection, row => row.Text("section") == "not_evaluated");
        Assert.All(collection, row => { Assert.False(string.IsNullOrWhiteSpace(row.Text("title"))); Assert.False(string.IsNullOrWhiteSpace(row.Text("why"))); });
        using var stream = typeof(AdV2Store).Assembly.GetManifestResourceStream("Sli.Server.Access.Administration.server." + locale + ".json")!;
        var catalog = JsonNode.Parse(stream)!;
        foreach (var row in collection) foreach (string field in new[] { "title", "why", "action", "remediation", "status_text" })
            Assert.Equal(catalog[row!["presentation_messages"]![field]!.Text("code")!]!.ToString(), row.Text(field));
        using var denied = await client.GetAsync(path + "/data?tab=checks&domain_id=3", Ct); Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode); Assert.Single(store.Reads);
        var deniedStore = new CheckStore(db); using var deniedHost = await Host(deniedStore, false); using var deniedClient = deniedHost.GetTestClient();
        using var deniedFields = await deniedClient.GetAsync(path + "/data?tab=checks&domain_id=2", Ct); Assert.Equal(HttpStatusCode.Forbidden, deniedFields.StatusCode); Assert.Empty(deniedStore.Reads);
        Assert.Equal("checks", AdV2Endpoints.Definitions[users ? "ad.users.v2" : "ad.computers.v6"]!["declaration"]!["views"]!.AsArray().Single(v => v.Text("key") == "checks")!.Text("source"));
    }
}
