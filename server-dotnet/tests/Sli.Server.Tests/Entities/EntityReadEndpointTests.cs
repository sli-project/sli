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
using Sli.Server.Entities;
using Sli.Server.Storage.EventReports;
using Xunit;

namespace Sli.Server.Tests.Entities;

public sealed class EntityReadEndpointTests
{
    static JsonElement J(string value) => JsonDocument.Parse(value).RootElement.Clone();
    static JsonArray Rows(string value) => (JsonArray)JsonNode.Parse(value)!;
    static readonly string[] AllCaps = ["objects.view", "field.identity_basic", "field.technical", "field.security", "field.raw_evidence", "objects.groups", "field.privilege", "objects.privileges", "evidence.exact", "vpn.sessions.view", "vpn.session.evidence.read", "events.view", "semantic.review"];
    static AccessFacts Facts(string[]? caps = null, string? deny = null, bool vpnReport = true, string role = "viewer")
    {
        var grants = (caps ?? AllCaps).Select(c => J(JsonSerializer.Serialize(new { capability_key = c, effect = "allow", scope_json = new { kind = "all" } }))).ToList();
        if (deny is not null) grants.Add(J(deny));
        return new(false, role, [], [], grants, [], [], vpnReport ? [J("""{"report_key":"vpn.audit","effect":"allow","allowed_actions":["view"],"field_categories":[],"scope_json":{"kind":"domain","ids":[1]}}""")] : [],
            [J("""{"report_key":"vpn.audit","version":1,"dataset_version":1,"definition_json":{"actions":["view"]},"actions_json":["view"],"fields_json":[]}""")]);
    }
    sealed class Auth(string role, bool authenticated) : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct) => ValueTask.FromResult(authenticated ? AuthenticationResult.Success(new("session", 1, role)) : AuthenticationResult.Denied(401, "authentication_required"));
    }
    sealed class FactsReader(AccessFacts facts) : IAccessFactsRepository
    { public Task<AccessFacts> LoadAsync(Principal p, CancellationToken ct) => Task.FromResult(facts); }
    sealed class Store : IEntityReadStore
    {
        public readonly List<(string Sql, IReadOnlyDictionary<string, object> Args)> Reads = [];
        public bool TimeoutEvents, TimeoutSupplemental, Fail, HistoryUnavailable;
        public int EvidenceReads;
        public JsonArray? Candidates, HydratedRows;
        public double EvidenceConfidence = 1.0;
        public JsonArray? SearchRows { get; set; }
        public JsonArray? DirectoryRows { get; set; }
        public JsonArray? CountsRows { get; set; }
        public JsonArray? EntityRows { get; set; }
        public int EventCode = 4624;
        public bool Interpretation;
        public bool ForeignRelationProof;
        public Task<JsonArray> ReadAsync(string sql, IReadOnlyDictionary<string, object> args, int seconds, CancellationToken ct)
        {
            Reads.Add((sql, new Dictionary<string, object>(args)));
            Assert.InRange(seconds, 1, 5);
            if (Fail) throw new InvalidOperationException("private-db-password");
            if (HistoryUnavailable) throw new Sli.Server.Storage.Lifecycle.LifecycleBlocked("entity_history_readback_mismatch");
            JsonArray result;
            if (sql.Contains("resolve_entity_identity_v2(@id) limit 1", StringComparison.Ordinal))
                result = Convert.ToInt64(args["id"]) == 99 ? new() : Rows("""[{"id":1,"entity_type":"account","domain_id":1,"server_id":2}]""");
            else if (sql.Contains("count(*)::bigint", StringComparison.Ordinal)) result = CountsRows is null ? Rows("""[{"entity_type":"account","entity_count":2}]""") : (JsonArray)CountsRows.DeepClone();
            else if (sql.Contains("as object_type", StringComparison.Ordinal)) result = SearchRows is null ? Rows("""[{"id":1,"object_type":"account","domain_id":1,"server_id":2,"natural_key":"secret-key","display_name":"Account","first_seen_utc":null,"last_seen_utc":"2026-01-01T00:00:00Z"}]""") : (JsonArray)SearchRows.DeepClone();
            else if (sql.Contains("state.status as latest_state_status", StringComparison.Ordinal)) result = EntityRows is null ? Rows("""[{"id":1,"entity_type":"account","domain_id":1,"server_id":2,"natural_key":"secret-key","display_name":"Account","first_seen_utc":null,"last_seen_utc":"2026-01-01T00:00:00Z","latest_state_status":"locked","latest_state_summary":"Observed lock","latest_state_event_db_id":10,"latest_state_observed_at_utc":"2026-01-01T00:00:00Z"}]""") : (JsonArray)EntityRows.DeepClone();
            else if (sql.Contains("from entity_state_current", StringComparison.Ordinal))
            { if (TimeoutSupplemental) throw new TimeoutException(); result = Rows("""[{"state_type":"account_lock","status":"locked","projection_status":"normal","observed_at_utc":"2026-01-01T00:00:00Z","evidence_event_db_id":10,"rule_id":"rule","rule_version":"1","summary":"Observed lock"}]"""); }
            else if (sql.Contains("from ad_context_entity_versions", StringComparison.Ordinal))
            { if (TimeoutSupplemental) throw new TimeoutException(); result = DirectoryRows is not null ? (JsonArray)DirectoryRows.DeepClone() : Rows("""[{"context_evidence_id":4,"evidence_type":"entity_observation","source_pack_id":"sli.ad","source_run_id":"private-run","observed_at_utc":"2026-01-01T00:00:00Z","integrity_sha256":"private-hash","context_kind":"entity","subject_entity_id":1,"subject_display_name":"Account","related_entity_id":null,"related_display_name":null,"valid_from_utc":"2026-01-01T00:00:00Z","valid_to_utc":null,"source_section":"directory_accounts","attributes_json":{"identity":{"display_name":"Account","object_sid":"private-sid"},"attributes":{"enabled":true,"email":"private-mail","unknown_secret":"private-extra"}}}]"""); }
            else if (sql.Contains("select e.id as event_db_id,s.id as server_id", StringComparison.Ordinal))
            {
                if (TimeoutEvents) throw new TimeoutException();
                result = Candidates is null ? Rows("""[{"event_db_id":10,"server_id":2,"domain_id":1,"channel":"Security"},{"event_db_id":11,"server_id":3,"domain_id":2,"channel":"Other"}]""") : (JsonArray)Candidates.DeepClone();
            }
            else if (sql.Contains("cross join lateral public.short_event_entity_links339", StringComparison.Ordinal))
            {
                EvidenceReads++;
                if (HydratedRows is not null) return Task.FromResult((JsonArray)HydratedRows.DeepClone());
                result = new();
                foreach (long eventId in (long[])args["event_ids"]) {
                var row = new JsonObject { ["event_db_id"] = eventId, ["server"] = "dc", ["channel"] = "Security" };
                if (sql.Contains("e.event_id,e.time_created_utc as time_utc", StringComparison.Ordinal)) { row["event_id"] = EventCode; row["time_utc"] = "2026-01-01T00:00:00Z"; }
                if (sql.Contains("e.provider_name,link.link_role", StringComparison.Ordinal)) { row["provider_name"] = "Windows"; row["link_role"] = "actor"; row["confidence"] = EvidenceConfidence; }
                if (sql.Contains("as actor", StringComparison.Ordinal)) { row["actor"] = "private-actor"; row["target"] = "private-target"; }
                result.Add(row); }
            }
            else if (sql.Contains("storage_v2_observed_at_utc", StringComparison.Ordinal)) result = Rows("""[{"storage_v2_observed_at_utc":"2026-01-01T00:00:00Z"}]""");
            else if (sql.Contains("object_identity_links", StringComparison.Ordinal)) result = Rows("""[{"relation_type":"same_account","source_name":"private-link"}]""");
            else if (sql.Contains("findings_active", StringComparison.Ordinal)) result = Rows("""[{"id":5,"title":"Observed finding","severity":"high","status":"open","summary":"Observed","last_seen_utc":null,"evidence_event_id":10}]""");
            else if (sql.Contains("radius_vpn_session_rows_v1", StringComparison.Ordinal)) result = Rows("""[{"session_row_id":"session-1","entity_id":1,"domain_id":1,"generation":1,"lifecycle_state":"stopped","completeness":"complete","started_at_utc":"2026-01-01T00:00:00Z","last_observed_at_utc":"2026-01-01T00:02:00Z","stopped_at_utc":"2026-01-01T00:02:00Z","duration_seconds":120,"observation_count":2,"anomalies":[],"updated_at":"2026-01-01T00:02:00Z"}]""");
            else if (Interpretation && sql.Contains("select event.id as event_db_id,event.domain_id,event.server_id,event.channel,null::bigint as event_record_id", StringComparison.Ordinal))
            {
                Assert.IsType<DateTime>(args["start"]); Assert.IsType<DateTime>(args["end"]);
                result = Rows("""[{"event_db_id":10,"domain_id":1,"server_id":2,"channel":"Security","event_record_id":20,"event_id":4740,"time_created_utc":"2026-01-01T00:00:00Z","source_host":"dc","target_user_sid":"S-1-5-21-100000001-200000002-300000003-5","target_user_name":"Account","source_core_sha256":"abcd","source_facts_sha256":null}]""");
            }
            else if (Interpretation && sql.Contains("as history_event_present", StringComparison.Ordinal)) result = Rows("""[{"history_event_present":true}]""");
            else if (Interpretation && sql.Contains("select alias.normalized_value,alias.entity_id", StringComparison.Ordinal)) result = Rows("""[{"normalized_value":"s-1-5-21-100000001-200000002-300000003-5","entity_id":1}]""");
            else if (Interpretation && sql.Contains("select candidate.candidate_id,candidate.window_end_utc,", StringComparison.Ordinal))
            {
                result = Rows("""[{"candidate_id":"11111111-1111-1111-1111-111111111111","window_end_utc":"2026-01-01T00:00:00Z","evidence":[{"event_db_id":10,"server_id":2,"domain_id":1,"channel":"Security"}]}]""");
                if (ForeignRelationProof) result[0]!["evidence"]!.AsArray().Add(new JsonObject { ["event_db_id"] = 11, ["server_id"] = 9, ["domain_id"] = 2, ["channel"] = "Security" });
            }
            else if (Interpretation && sql.Contains("where candidate.candidate_id=any(@candidates)", StringComparison.Ordinal))
            {
                Assert.Equal(new[] { Guid.Parse("11111111-1111-1111-1111-111111111111") }, (Guid[])args["candidates"]);
                result = Rows("""[{"candidate_id":"11111111-1111-1111-1111-111111111111","rule_id":"investigation.account.unlock.after-lock","rule_version":2,"relation_kind":"unlock_after_lock","partition_key":"domain:1|account_sid:S-1-5-21-100000001-200000002-300000003-5","window_start_utc":"2026-01-01T00:00:00Z","window_end_utc":"2026-01-01T00:00:10Z","confidence":1.0,"explanation":"Observed relation","evidence":[{"event_db_id":10,"event_id":4740,"time_created_utc":"2026-01-01T00:00:00Z","semantic_type":"authentication.account.locked","source_host":"dc","server_id":2,"domain_id":1,"channel":"Security","evidence_order":0}]}]""");
            }
            else throw new InvalidOperationException("Unexpected entity SQL: " + sql);
            return Task.FromResult(result);
        }
    }
    sealed class EventReads : IEventReadService
    {
        public int DetailsCalls;
        public IReadOnlyList<AccessResource> EventResources { get; set; } = [new("server",2),new("domain",1),new("channel",Value:"Security")];
        public Task<IReadOnlyList<AccessResource>> ResourcesAsync(long id, CancellationToken ct) => Task.FromResult(EventResources);
        public async Task<Dictionary<long, JsonObject>> DetailsAsync(long[] ids, bool exact, Func<long, CancellationToken, Task<bool>> admitted, CancellationToken ct)
        {
            DetailsCalls++;
            var result = new Dictionary<long, JsonObject>(); foreach (long id in ids) { Assert.True(await admitted(id, ct)); result[id] = new() { ["event_data"] = JsonNode.Parse("""{"CallerComputerName":"workstation","Password":"private-raw-value"}""") }; } return result;
        }
        public Task<JsonObject> RelationsAsync(long id, Func<long, CancellationToken, Task<bool>> admitted, CancellationToken ct) => throw new NotSupportedException();
    }
    static async Task<IHost> Host(Store store, AccessFacts? facts = null, string role = "viewer", bool authenticated = true, EventReads? eventReads = null, string? contentRoot = null)
    {
        // Resource checks are exercised here; real SQL/ACLs are covered by EntityShortReadsPostgresTests.
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "true", ["Sli:Storage:ShortEventReads"] = "false" }).Build();
        return await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().UseContentRoot(contentRoot ?? RepositoryRoot()).ConfigureServices(services =>
        {
            services.AddRouting(); services.AddLogging(); services.AddSingleton<IConfiguration>(config); services.AddSingleton(new AuthRequestPolicy(config)); services.AddSingleton(new TransportGate(config));
            services.AddSingleton<IPrincipalAuthenticator>(new Auth(role, authenticated)); services.AddSingleton<IAccessFactsRepository>(new FactsReader(facts ?? Facts(role: role)));
            services.AddSingleton<IEntityReadStore>(store); services.AddEntityReads();
            services.AddSingleton<IEventReadService>(eventReads ?? new EventReads());
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(e => e.MapEntityReads()); })).StartAsync(TestContext.Current.CancellationToken);
    }
    static string RepositoryRoot()
    {
        for (var path = new DirectoryInfo(AppContext.BaseDirectory); path is not null; path = path.Parent)
            if (File.Exists(Path.Combine(path.FullName, "config", "plugin_packages", "sli.ad.json")) || Directory.Exists(Path.Combine(path.FullName, "config", "plugin_packages", "v3"))) return path.FullName;
        throw new InvalidOperationException("Repository root missing");
    }
    static readonly string[] Routes = ["/api/v1/objects", "/api/v1/objects/account/1", "/api/v1/entities", "/api/v1/entities/1", "/api/v1/entities/1/vpn-sessions?time_from=2026-01-01&time_to=2026-01-02"];
    // Parity vectors from tests/access/test_object_ad_relations_v4.py, at the SQL-store boundary.
    static JsonObject AdRelation(string section, int groupId, string name) => new()
    {
        ["context_evidence_id"] = groupId, ["context_kind"] = "relation", ["source_section"] = section,
        ["related_entity_id"] = groupId, ["related_display_name"] = name,
        ["valid_to_utc"] = null, ["observed_at_utc"] = "2026-10-02T12:00:00Z",
        ["attributes_json"] = new JsonObject { ["source_section"] = section, ["membership_type"] = "direct", ["record_key"] = "k" }
    };
    [Fact]
    public async Task GroupsReaderReceivesVpnRelationButNotPrivilegedMembership()
    {
        var store = new Store { DirectoryRows = new JsonArray(AdRelation("privileged_membership", 11, "Admins"), AdRelation("vpn_membership", 12, "VPN Users")) };
        using var host = await Host(store, Facts(["objects.view", "objects.groups", "field.identity_basic"])); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/objects/account/1", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        var item = Assert.Single(body["directory_context"]!["items"]!.AsArray())!;
        Assert.Equal("VPN Users", item["related_display_name"]!.ToString()); Assert.Equal("vpn", item["relation_class"]!.ToString());
        Assert.Equal(1, body["directory_context"]!["returned_count"]!.GetValue<int>());
        Assert.True(Assert.Single(body["tabs"]!.AsArray(), tab => tab!["id"]!.ToString() == "groups")!["available"]!.GetValue<bool>());
    }
    [Fact]
    public async Task PrivilegeReaderReceivesBothRelationClassesWithoutTechnicalSection()
    {
        var store = new Store { DirectoryRows = new JsonArray(AdRelation("privileged_membership", 11, "Admins"), AdRelation("vpn_membership", 12, "VPN Users")) };
        using var host = await Host(store, Facts(["objects.view", "objects.privileges", "field.privilege", "field.identity_basic"])); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/objects/account/1", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        var items = body["directory_context"]!["items"]!.AsArray().OfType<JsonObject>().ToArray();
        Assert.Equal(2, items.Length);
        Assert.Equal("privileged", Assert.Single(items, item => item["related_display_name"]!.ToString() == "Admins")["relation_class"]!.ToString());
        Assert.Equal("vpn", Assert.Single(items, item => item["related_display_name"]!.ToString() == "VPN Users")["relation_class"]!.ToString());
        Assert.All(items, item => { Assert.False(item.ContainsKey("source_section")); Assert.False(item["attributes"]!.AsObject().ContainsKey("source_section")); });
    }
    [Fact]
    public async Task RelationClassDefaultsToGroupAndIsAbsentFromEntityContext()
    {
        var store = new Store { DirectoryRows = new JsonArray(AdRelation("directory_group_graph", 13, "Plain"),
            new JsonObject { ["context_kind"] = "entity", ["source_section"] = "directory_accounts", ["attributes_json"] = new JsonObject() }) };
        using var host = await Host(store, Facts(["objects.view", "objects.groups", "field.identity_basic"])); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/objects/account/1", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        var items = body["directory_context"]!["items"]!.AsArray(); Assert.Equal(2, items.Count);
        Assert.Equal("group", items[0]!["relation_class"]!.ToString()); Assert.Equal("Plain", items[0]!["related_display_name"]!.ToString());
        Assert.False(items[1]!.AsObject().ContainsKey("relation_class"));
    }
    public static IEnumerable<object[]> SuccessRoutes => Routes.Select(r => new object[] { r });
    [Theory] [MemberData(nameof(SuccessRoutes))]
    public async Task RegisteredRouteReturnsRealProjectedData(string path)
    {
        var store = new Store(); using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost" + path, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.True(store.Reads.Count > 0);
        if (path == Routes[0]) { Assert.Equal("1", body["items"]![0]!["object_id"]!.ToString()); Assert.Equal("available", body["state"]!.ToString()); }
        if (path == Routes[1]) { Assert.Equal("employee_and_account_are_distinct_objects", body["identity_contract"]!.ToString()); Assert.Equal(8, ((JsonArray)body["tabs"]!).Count); Assert.Single((JsonArray)body["current_states"]!); Assert.Single((JsonArray)body["findings"]!); }
        if (path == Routes[2]) { Assert.Equal(2, body["total_entities"]!.GetValue<int>()); Assert.Equal("ok", body["state"]!.ToString()); }
        if (path == Routes[3]) { Assert.Equal("time_bounds_required", body["security_actions_state"]!.ToString()); Assert.Equal(2, ((JsonArray)body["events"]!).Count); Assert.NotNull(body["ad_context"]!["items"]![0]!["attributes"]!["enabled"]); }
        if (path == Routes[4]) { Assert.Equal("available", body["state"]!.ToString()); Assert.Equal("vpn_accounting_session", body["items"]![0]!["evidence_ref"]!["kind"]!.ToString()); }
    }
    [Theory] [MemberData(nameof(SuccessRoutes))]
    public async Task MissingCapabilityAndExplicitDenialStopBeforeAnyDataRead(string path)
    {
        foreach (var facts in new[] { Facts([]), Facts(deny: """{"capability_key":"objects.view","effect":"deny","scope_json":{"kind":"all"}}""") })
        {
            var store = new Store(); using var host = await Host(store, facts); using var client = host.GetTestClient();
            using var response = await client.GetAsync("https://localhost" + path, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Empty(store.Reads);
            var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!; Assert.Equal("objects.view", body["required_capability"]!.ToString());
        }
    }
    [Theory]
    [InlineData("/api/v1/objects?limit=x", "invalid literal for int() with base 10: 'x'")]
    [InlineData("/api/v1/objects?limit=", "invalid literal for int() with base 10: ''")]
    [InlineData("/api/v1/objects/account/no", "invalid_object_id")]
    [InlineData("/api/v1/objects/account", "invalid_object_path")]
    [InlineData("/api/v1/objects/a.b/1", "unsupported_object_type")]
    [InlineData("/api/v1/objects/ip/1", "object_type_mismatch")]
    [InlineData("/api/v1/entities?entity_type=missing", "unknown_entity_type")]
    [InlineData("/api/v1/entities/no", "invalid_entity_id")]
    [InlineData("/api/v1/entities/0", "invalid_entity_id")]
    [InlineData("/api/v1/entities/1?limit=bad", "invalid_entity_limit")]
    [InlineData("/api/v1/entities/1?before_event_db_id=10", "entity_cursor_requires_time_and_event_id")]
    [InlineData("/api/v1/entities/1?before_time_utc=2026-01-01&before_event_db_id=0", "invalid_entity_cursor")]
    [InlineData("/api/v1/entities/1?time_from=2026-01-01", "entity_time_context_requires_both_bounds")]
    [InlineData("/api/v1/entities/1?time_from=x&time_to=y", "invalid_datetime")]
    [InlineData("/api/v1/entities/1?time_from=x&time_from=y", "duplicate_time_from")]
    [InlineData("/api/v1/entities/1?timezone=bad", "invalid_timezone")]
    [InlineData("/api/v1/entities/1?time_from=2026-01-01&time_to=2026-03-01", "entity_time_context_period_too_wide")]
    [InlineData("/api/v1/entities/1/vpn-sessions", "entity_vpn_time_bounds_required")]
    [InlineData("/api/v1/entities/1/vpn-sessions?domain_id=1", "invalid_entity_vpn_context")]
    [InlineData("/api/v1/entities/1/vpn-sessions?limit=1&limit=2", "invalid_entity_vpn_context")]
    [InlineData("/api/v1/entities/1/vpn-sessions?time_from=2026-01-01&time_to=2026-01-02&limit=101", "entity_vpn_limit_invalid")]
    [InlineData("/api/v1/entities/1/vpn-sessions?time_from=2026-01-01&time_to=2026-01-02&limit=x", "invalid literal for int() with base 10: 'x'")]
    [InlineData("/api/v1/entities/1/vpn-sessions?time_from=2026-01-01&time_to=2026-03-01", "entity_vpn_period_too_wide")]
    public async Task InvalidInputHasReferenceErrorCode(string path, string error)
    {
        var store = new Store(); using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost" + path, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!; Assert.Equal(error, body["error"]!.ToString());
        if (error == "unknown_entity_type") { Assert.Equal("missing", Assert.Single(body["unknown_types"]!.AsArray())!.ToString()); Assert.Single(store.Reads); }
        if (error is "entity_time_context_requires_both_bounds" or "entity_time_context_period_too_wide") Assert.Empty(store.Reads);
    }
    [Theory]
    [InlineData("time_from=2026-01-01&time_to=2026-01-02&limit=101", "entity_vpn_limit_invalid")]
    [InlineData("time_from=2026-01-01&time_to=2026-03-01", "entity_vpn_period_too_wide")]
    public async Task InvalidVpnInputReturnsBadRequestWithoutAnInstalledPlugin(string query, string error)
    {
        var root = Directory.CreateTempSubdirectory("sli-entity-vpn-");
        try
        {
            Directory.CreateDirectory(Path.Combine(root.FullName, "config", "plugin_packages", "v3"));
            using var host = await Host(new Store(), contentRoot: root.FullName);
            using var client = host.GetTestClient();
            using var response = await client.GetAsync("https://localhost/api/v1/entities/1/vpn-sessions?" + query, TestContext.Current.CancellationToken);

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
            Assert.Equal(error, body["error"]!.ToString());
        }
        finally
        {
            root.Delete(recursive: true);
        }
    }
    [Theory] [InlineData("/api/v1/objects/account/99")] [InlineData("/api/v1/entities/99")] [InlineData("/api/v1/entities/99/vpn-sessions?time_from=2026-01-01&time_to=2026-01-02")]
    public async Task MissingIdentityIs404WithoutHydration(string path)
    {
        var store = new Store(); using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost" + path, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode); Assert.Single(store.Reads);
    }
    [Fact]
    public async Task RedactsProtectedFieldsBeforeHydrationAndKeepsAllowedMetadata()
    {
        var store = new Store(); using var host = await Host(store, Facts(["objects.view", "evidence.exact", "field.identity_basic"])); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/objects/account/1", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        foreach (string secret in new[] { "secret-key", "private-sid", "private-mail", "private-extra", "private-actor", "private-run", "private-hash", "private-link", "Observed lock", "Observed finding" }) Assert.DoesNotContain(secret, body);
        Assert.Equal(1, store.EvidenceReads);
        foreach (var (sql, _) in store.Reads.Where(r => r.Sql.Contains("where block.entity_id=@id and event.id=any(@event_ids)", StringComparison.Ordinal)))
        { Assert.DoesNotContain("as actor", sql); Assert.DoesNotContain("e.provider_name,link.link_role", sql); Assert.DoesNotContain("e.event_id,e.time_created_utc as time_utc", sql); }
    }
    [Fact]
    public async Task EachEvidenceResourceIsAdmittedBeforeReadingProtectedFields()
    {
        var store = new Store(); var caps = AllCaps.Where(c => c != "evidence.exact").ToArray();
        string policy = """{"capability_key":"evidence.exact","effect":"allow","scope_json":{"kind":"domain","ids":[1]}}""";
        var facts = Facts(caps) with { DirectCapabilities = Facts(caps).DirectCapabilities.Append(J(policy)).ToArray() };
        using var host = await Host(store, facts); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/entities/1?limit=1", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.True(body["events_scope_filtered"]!.GetValue<bool>()); Assert.True(body["has_more"]!.GetValue<bool>()); Assert.Equal(1, store.EvidenceReads);
        Assert.Equal(10, body["next_cursor"]!["event_db_id"]!.GetValue<int>());
    }
    public static IEnumerable<object[]> EventProjectionDenials =>
        new[] { "metadata", "technical", "security_metadata", "full" }
            .SelectMany(projection => new[] { "scoped", "evidence.exact", "all" }.Select(denial => new object[] { projection, denial }));

    [Theory] [MemberData(nameof(EventProjectionDenials))]
    public async Task EventProjectionContractFiltersBeforeHydrationAndSerializesOnlyAllowedValues(string projection, string denial)
    {
        bool technical = projection is "technical" or "full", security = projection is "security_metadata" or "full";
        var capabilities = new List<string> { "objects.view", "field.identity_basic" };
        if (technical) capabilities.Add("field.technical");
        if (security) capabilities.Add("field.security");
        if (denial != "scoped") capabilities.Add("evidence.exact");
        var facts = Facts(capabilities.ToArray());
        string policy = denial switch
        {
            "scoped" => """{"capability_key":"evidence.exact","effect":"allow","scope_json":{"kind":"domain","ids":[1]}}""",
            "evidence.exact" => """{"capability_key":"evidence.exact","effect":"deny","scope_json":{"kind":"domain","ids":[2]}}""",
            _ => """{"capability_key":"evidence.exact","effect":"deny","scope_json":{"kind":"all"}}"""
        };
        facts = facts with { DirectCapabilities = facts.DirectCapabilities.Append(J(policy)).ToArray() };
        var store = new Store { EvidenceConfidence = 0.0 };
        using var host = await Host(store, facts); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/entities/1", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.True(body["events_scope_filtered"]!.GetValue<bool>());
        if (denial == "all")
        {
            Assert.Empty(body["events"]!.AsArray()); Assert.Equal("forbidden", body["events_state"]!.ToString());
            Assert.Equal(0, store.EvidenceReads);
            return;
        }
        Assert.Equal("available", body["events_state"]!.ToString());
        var read = Assert.Single(store.Reads, r => r.Sql.Contains("cross join lateral public.short_event_entity_links339", StringComparison.Ordinal));
        Assert.Equal(new long[] { 10 }, Assert.IsType<long[]>(read.Args["event_ids"]));
        var expected = JsonNode.Parse("""{"event_db_id":10,"server":"dc","channel":"Security","event_id":null,"label":null,"time_utc":null,"provider_name":null,"link_role":null,"confidence":null,"actor":null,"target":null}""")!;
        if (security) { expected["event_id"] = 4624; expected["label"] = "Успешный вход"; expected["time_utc"] = "2026-01-01T00:00:00Z"; }
        if (technical) { expected["provider_name"] = "Windows"; expected["link_role"] = "actor"; expected["confidence"] = 0.0; }
        if (projection == "full") { expected["actor"] = "private-actor"; expected["target"] = "private-target"; }
        Assert.True(JsonNode.DeepEquals(expected, Assert.Single(body["events"]!.AsArray())));
    }

    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task EventProjectionContractMissingAndNullValuesAreNotInvented(bool explicitNull)
    {
        var row = new JsonObject { ["event_db_id"] = 10 };
        if (explicitNull) { row["event_id"] = null; row["confidence"] = null; row["link_role"] = null; }
        var store = new Store
        {
            Candidates = Rows("""[{"event_db_id":10,"domain_id":1,"server_id":2}]"""),
            HydratedRows = new JsonArray(row)
        };
        using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/entities/1", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        var item = Assert.Single(body["events"]!.AsArray())!.AsObject();
        Assert.Equal(10, item["event_db_id"]!.GetValue<int>());
        foreach (string field in new[] { "server", "channel", "event_id", "label", "time_utc", "provider_name", "link_role", "confidence", "actor", "target" })
        { Assert.True(item.ContainsKey(field)); Assert.Null(item[field]); }
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"event_db_id\":null}")]
    [InlineData("{\"event_db_id\":0}")]
    [InlineData("{\"event_db_id\":-1}")]
    public async Task EventProjectionContractRequiresPositiveExactIdentity(string candidate)
    {
        var row = JsonNode.Parse(candidate)!.AsObject();
        row["event_id"] = 4624; row["server_id"] = 2; row["domain_id"] = 1;
        var store = new Store { Candidates = new JsonArray(row), HydratedRows = new JsonArray(row.DeepClone()) };
        using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/entities/1", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal(0, store.EvidenceReads);
    }

    [Fact]
    public async Task ObjectWithoutExactEvidenceSerializesForbiddenAndHidesIdentityLinks()
    {
        var store = new Store();
        using var host = await Host(store, Facts(["objects.view", "field.identity_basic", "field.security"]));
        using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/objects/user/1", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Empty(body["identity_links"]!.AsArray()); Assert.Empty(body["events"]!.AsArray());
        Assert.Equal("forbidden", body["events_state"]!.ToString()); Assert.False(body["has_more_events"]!.GetValue<bool>());
        Assert.Contains("evidence.exact", body["limitations"]!.ToJsonString());
        Assert.Equal(new[] { "display_name", "enabled" }, body["directory_context"]!["items"]![0]!["attributes"]!.AsObject().Select(p => p.Key).Order());
        Assert.Equal(0, store.EvidenceReads);
    }
    [Fact]
    public async Task TimeoutInEvidencePreservesEntityAndIndependentState()
    {
        var store = new Store { TimeoutEvents = true }; using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/entities/1", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal("temporarily_unavailable", body["events_state"]!.ToString()); Assert.Single((JsonArray)body["current_states"]!); Assert.Equal(0, store.EvidenceReads);
        Assert.Equal("available", body["current_states_state"]!.ToString()); Assert.Equal("available", body["ad_context_state"]!.ToString());
        Assert.False(body["has_more"]!.GetValue<bool>());
        var state = body["current_states"]![0]!;
        Assert.Equal("account_lock", state["state_type"]!.ToString()); Assert.Equal("locked", state["status"]!.ToString());
        Assert.Equal("normal", state["projection_status"]!.ToString()); Assert.Equal(10, state["evidence_event_db_id"]!.GetValue<int>());
        Assert.Equal("rule", state["rule_id"]!.ToString()); Assert.Equal("1", state["rule_version"]!.ToString()); Assert.Equal("Observed lock", state["summary"]!.ToString());
    }
    [Fact]
    public async Task SupplementalTimeoutsPreserveObjectAndAvailableEvidence()
    {
        var store = new Store { TimeoutSupplemental = true }; using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/entities/1", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(1, body["entity"]!["id"]!.GetValue<int>());
        Assert.Empty(body["current_states"]!.AsArray()); Assert.Equal("temporarily_unavailable", body["current_states_state"]!.ToString());
        Assert.Equal("temporarily_unavailable", body["ad_context_state"]!.ToString());
        Assert.Equal("temporarily_unavailable", body["ad_context"]!["resolution"]!.ToString());
        Assert.Empty(body["ad_context"]!["items"]!.AsArray()); Assert.Equal(0, body["ad_context"]!["returned_count"]!.GetValue<int>());
        Assert.True(body["ad_context"]!["bounded"]!.GetValue<bool>());
        Assert.Equal("available", body["events_state"]!.ToString()); Assert.Equal(2, body["events"]!.AsArray().Count);
    }
    [Fact]
    public async Task ObjectScopeDenialIsNotFoundBeforeHydration()
    {
        var store = new Store(); using var host = await Host(store, Facts(deny: """{"capability_key":"objects.view","effect":"deny","scope_json":{"kind":"server","ids":[2]}}""")); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/entities/1", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode); Assert.Single(store.Reads);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal("entity_not_found", body["error"]!.ToString());
    }
    [Theory]
    [InlineData("{\"kind\":\"server\",\"ids\":[2]}", 200)]
    [InlineData("{\"kind\":\"server\",\"ids\":[9]}", 404)]
    public async Task ScopedObjectGrantUsesExactResourceBeforeHydration(string scope, int status)
    {
        var facts = Facts(AllCaps.Where(c => c != "objects.view").ToArray());
        facts = facts with { DirectCapabilities = facts.DirectCapabilities.Append(J("{\"capability_key\":\"objects.view\",\"effect\":\"allow\",\"scope_json\":" + scope + "}")).ToArray() };
        var store = new Store(); using var host = await Host(store, facts); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/entities/1", TestContext.Current.CancellationToken);
        Assert.Equal(status, (int)response.StatusCode);
        if (status == 404) Assert.Single(store.Reads);
        else Assert.Contains(store.Reads, r => r.Sql.Contains("state.status as latest_state_status", StringComparison.Ordinal));
    }
    [Theory]
    [InlineData("/api/v1/entities", "{\"kind\":\"server\",\"ids\":[2]}")]
    [InlineData("/api/v1/entities/1", "{\"kind\":\"server\",\"ids\":[]}")]
    public async Task ScopedListOrInvalidDenyStillStopsBeforeAnyDataRead(string path, string scope)
    {
        var store = new Store(); using var host = await Host(store, Facts(deny: "{\"capability_key\":\"objects.view\",\"effect\":\"deny\",\"scope_json\":" + scope + "}")); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost" + path, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Empty(store.Reads);
    }
    [Fact]
    public async Task FieldGrantsCannotHydrateEvidenceDeniedByItsOwnGate()
    {
        var store = new Store(); using var host = await Host(store, Facts(AllCaps.Where(c => c != "evidence.exact").ToArray())); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/entities/1", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Empty(body["events"]!.AsArray()); Assert.Equal("forbidden", body["events_state"]!.ToString());
        Assert.True(body["events_scope_filtered"]!.GetValue<bool>()); Assert.Equal(0, store.EvidenceReads);
    }
    [Fact]
    public async Task DeniedNewestCandidateDoesNotMakeFullAuthorizedPageLookComplete()
    {
        var candidates = new JsonArray(Enumerable.Range(1, 31).Reverse().Select(id => (JsonNode)new JsonObject
            { ["event_db_id"] = id, ["domain_id"] = id == 31 ? 2 : 1, ["server_id"] = 2, ["channel"] = "Security" }).ToArray());
        var store = new Store { Candidates = candidates };
        var facts = Facts(AllCaps.Where(c => c != "evidence.exact").ToArray());
        facts = facts with { DirectCapabilities = facts.DirectCapabilities.Append(J("""{"capability_key":"evidence.exact","effect":"allow","scope_json":{"kind":"domain","ids":[1]}}""")).ToArray() };
        using var host = await Host(store, facts); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/entities/1?limit=30", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(Enumerable.Range(1, 30).Reverse(), body["events"]!.AsArray().Select(e => e!["event_db_id"]!.GetValue<int>()));
        Assert.True(body["has_more"]!.GetValue<bool>()); Assert.Equal(1, body["next_cursor"]!["event_db_id"]!.GetValue<int>());
        Assert.Equal("2026-01-01T00:00:00Z", body["next_cursor"]!["time_utc"]!.ToString());
        var preflight = Assert.Single(store.Reads, r => r.Sql.Contains("select e.id as event_db_id,s.id as server_id", StringComparison.Ordinal));
        Assert.Equal(Enumerable.Range(1, 30).Reverse().Select(i => (long)i), (long[])Assert.Single(store.Reads, r => r.Sql.Contains("cross join lateral public.short_event_entity_links339", StringComparison.Ordinal)).Args["event_ids"]);
    }
    [Fact]
    public async Task EntityFiltersUseRepeatedAndCommaSeparatedTypesWithGlobalCounts()
    {
        var store = new Store { CountsRows = Rows("""[{"entity_type":"auth_session","entity_count":932374},{"entity_type":"ad_user","entity_count":1100},{"entity_type":"ad_computer","entity_count":526},{"entity_type":"log_source","entity_count":0}]"""),
            EntityRows = Rows("""[{"id":1472,"entity_type":"ad_user","natural_key":"sam:alice","display_name":"Alice","first_seen_utc":null,"last_seen_utc":null,"latest_state_status":null,"latest_state_summary":null,"latest_state_observed_at_utc":null,"latest_state_event_db_id":null}]""") };
        using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/entities?entity_type=ad_user,ad_computer&exclude_entity_type=auth_session&exclude_entity_type=log_source&limit=not-a-number&q=alice", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal("alice", body["query"]!.ToString()); Assert.Equal(50, body["limits"]!["items"]!.GetValue<int>());
        Assert.Equal(934000, body["total_entities"]!.GetValue<int>()); Assert.Equal("all_entities", body["type_counts_scope"]!.ToString());
        Assert.Equal(932374, body["type_counts"]![0]!["count"]!.GetValue<int>());
        Assert.Equal("ad_user", Assert.Single(body["items"]!.AsArray())!["type"]!.ToString());
        Assert.Equal(new[] { "ad_user", "ad_computer" }, body["filters"]!["entity_types"]!.AsArray().Select(t => t!.ToString()));
        Assert.Equal(new[] { "auth_session", "log_source" }, body["filters"]!["exclude_entity_types"]!.AsArray().Select(t => t!.ToString()));
        var search = Assert.Single(store.Reads, r => r.Sql.Contains("state.status as latest_state_status", StringComparison.Ordinal));
        Assert.Contains("entity_type.value=any(@types)", search.Sql); Assert.Contains("not(entity_type.value=any(@excluded))", search.Sql);
        Assert.Equal(new[] { "ad_user", "ad_computer" }, (string[])search.Args["types"]);
        Assert.Equal(new[] { "auth_session", "log_source" }, (string[])search.Args["excluded"]); Assert.Equal(51, search.Args["limit"]);
    }
    [Fact]
    public async Task ExactTimeContextRetainsMicrosecondsAndExclusiveBoundsInEvidenceQueries()
    {
        var store = new Store { EventCode = 4740 }; using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/entities/1?time_from=2026-09-10T12:00:00.123456Z&time_to=2026-09-11T12:00:00.654321Z&timezone=Asia/Bangkok", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal("2026-09-10T12:00:00.123456Z", body["context"]!["time_from_utc"]!.ToString());
        Assert.Equal("2026-09-11T12:00:00.654321Z", body["context"]!["time_to_utc_exclusive"]!.ToString()); Assert.Equal("Asia/Bangkok", body["context"]!["timezone"]!.ToString());
        var candidate = Assert.Single(store.Reads, r => r.Sql.Contains("select e.id as event_db_id,s.id as server_id", StringComparison.Ordinal));
        Assert.Equal(DateTimeOffset.Parse("2026-09-10T12:00:00.123456Z").UtcDateTime, candidate.Args["start"]);
        Assert.Equal(DateTimeOffset.Parse("2026-09-11T12:00:00.654321Z").UtcDateTime, candidate.Args["end"]);
        Assert.Equal(4740, body["events"]![0]!["event_id"]!.GetValue<int>()); Assert.Equal("Учетная запись заблокирована", body["events"]![0]!["label"]!.ToString());
    }
    [Fact]
    public async Task EntityHistoryCursorPreservesExactBeforeParameters()
    {
        var store = new Store(); using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/entities/1?before_time_utc=2026-07-18T13:08:19Z&before_event_db_id=5427398&limit=5", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var preflight = Assert.Single(store.Reads, r => r.Sql.Contains("select e.id as event_db_id,s.id as server_id", StringComparison.Ordinal));
        Assert.Equal(1, preflight.Args["id"]); Assert.Equal(6, preflight.Args["limit"]);
        Assert.Equal(DateTimeOffset.Parse("2026-07-18T13:08:19Z").UtcDateTime, preflight.Args["before"]); Assert.Equal(5427398L, preflight.Args["before_id"]);
        Assert.Single(store.Reads, r => r.Sql.Contains("cross join lateral public.short_event_entity_links339", StringComparison.Ordinal));
    }
    [Theory] [InlineData("/api/v1/entities/1")] [InlineData("/api/v1/objects/account/1")]
    public async Task Unverified_history_returns_unavailable_instead_of_missing_or_partial_data(string route)
    {
        var store = new Store { HistoryUnavailable = true }; using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost"+route,TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("entity_history_unavailable",body); Assert.DoesNotContain("readback_mismatch",body);
    }
    [Theory] [InlineData(false, true)] [InlineData(true, false)]
    public async Task VpnBranchesFailClosedWithoutSessionRead(bool report, bool capability)
    {
        var store = new Store(); using var host = await Host(store, Facts(capability ? AllCaps : AllCaps.Where(c => !c.StartsWith("vpn.", StringComparison.Ordinal)).ToArray(), vpnReport: report)); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost" + Routes[4], TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal("not_authorized", body["state"]!.ToString()); Assert.DoesNotContain(store.Reads, r => r.Sql.Contains("radius_vpn_session_rows_v1", StringComparison.Ordinal));
    }
    [Fact]
    public async Task FailedReadIs500AndDoesNotExposeExceptionOrPretendEmpty()
    {
        var store = new Store { Fail = true }; using var host = await Host(store); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/objects", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode); string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain("private-db-password", body); Assert.Contains("internal_server_error", body);
    }
    [Theory] [MemberData(nameof(SuccessRoutes))]
    public async Task UnauthenticatedRequestStopsBeforeRead(string path)
    {
        var store = new Store(); using var host = await Host(store, authenticated: false); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost" + path, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode); Assert.Empty(store.Reads);
    }
    static AccessFacts SecurityFacts(string[]? caps = null)
    {
        var facts = Facts(caps);
        return facts with
        {
            ReportAssignments = facts.ReportAssignments.Append(J("""{"report_key":"security.events.chains","effect":"allow","allowed_actions":["view"],"field_categories":["security","technical","raw_evidence"],"scope_json":{"kind":"domain","ids":[1]}}""")).ToArray(),
            Definitions = facts.Definitions.Append(J("""{"report_key":"security.events.chains","version":1,"dataset_version":1,"definition_json":{"actions":["view"]},"actions_json":["view"],"fields_json":[{"category":"security"},{"category":"technical"},{"category":"raw_evidence"}]}""")).ToArray()
        };
    }
    [Fact]
    public async Task ActionOwnServerDenyPreventsHydrationAndPublication()
    {
        var facts = SecurityFacts();
        facts = facts with { DirectCapabilities = facts.DirectCapabilities.Append(J("""{"capability_key":"events.view","effect":"deny","scope_json":{"kind":"server","ids":[2]}}""")).ToArray() };
        var eventReads = new EventReads();
        using var host = await Host(new Store { Interpretation = true }, facts, eventReads:eventReads);
        using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/entities/1?time_from=2026-01-01&time_to=2026-01-02", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Empty(body["security_actions"]!.AsArray());
        Assert.Empty(body["semantic_relations"]!.AsArray());
        Assert.Equal(0,eventReads.DetailsCalls);
    }
    [Fact]
    public async Task ActionResourceChangeCannotHydrateAnotherServerOrDomain()
    {
        var eventReads = new EventReads { EventResources = [new("server",9),new("domain",2),new("channel",Value:"Security")] };
        using var host = await Host(new Store { Interpretation=true },SecurityFacts(),eventReads:eventReads);
        using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/entities/1?time_from=2026-01-01&time_to=2026-01-02",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.InternalServerError,response.StatusCode);
        Assert.Equal(0,eventReads.DetailsCalls);
        Assert.DoesNotContain("resource_mismatch",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
    [Theory]
    [InlineData("2026-01-01", "2026-01-01", "2025-12-31T17:00:00Z", "2026-01-01T17:00:00Z")]
    [InlineData("2025-12-31T23:59:59.123456Z", "2026-01-01T01:00:00.987654Z", "2025-12-31T23:59:59.123456Z", "2026-01-01T01:00:00.987654Z")]
    public async Task BoundedCardComposesSourceActionsAndRelationsWithIndependentAuthorization(string from, string to, string start, string end)
    {
        var store = new Store { Interpretation = true }; using var host = await Host(store, SecurityFacts()); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/entities/1?time_from=" + from + "&time_to=" + to + "&timezone=Asia/Bangkok&limit=50", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal("available", body["security_actions_state"]!.ToString()); Assert.Equal(1, body["security_actions"]![0]!["affected_account"]!["entity_id"]!.GetValue<int>());
        Assert.Equal("workstation", body["security_actions"]![0]!["caller_computer"]!["hostname"]!.ToString());
        Assert.Equal("available", body["semantic_relations_state"]!.ToString()); Assert.Equal("exact_domain_account_sid", body["semantic_relations"]![0]!["identity_basis"]!["kind"]!.ToString());
        Assert.DoesNotContain("private-raw-value", body.ToJsonString()); Assert.DoesNotContain("partition_key", body.ToJsonString());
        var preflight = Assert.Single(store.Reads, r => r.Sql.Contains("select candidate.candidate_id,candidate.window_end_utc,", StringComparison.Ordinal));
        Assert.DoesNotContain("candidate.explanation", preflight.Sql); Assert.DoesNotContain("candidate.partition_key", preflight.Sql);
        var actions = Assert.Single(store.Reads, r => r.Sql.Contains("select event.id as event_db_id,event.domain_id,event.server_id,event.channel,null::bigint as event_record_id", StringComparison.Ordinal));
        foreach (var read in new[] { actions, preflight })
        {
            Assert.Equal(1, read.Args["id"]); Assert.Equal(1, read.Args["domain"]); Assert.Equal(51, read.Args["limit"]);
            // Date-only bounds use the requested zone; offset instants stay exact.
            Assert.Equal(DateTimeOffset.Parse(start).UtcDateTime, read.Args["start"]);
            Assert.Equal(DateTimeOffset.Parse(end).UtcDateTime, read.Args["end"]);
        }
    }
    [Fact]
    public async Task DeniedInterpretationDoesNotExposeItemsOrCountsOrReadTheirSources()
    {
        var store = new Store { Interpretation = true };
        using var host = await Host(store, SecurityFacts(AllCaps.Where(c => c is not ("events.view" or "semantic.review")).ToArray())); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/entities/1?time_from=2026-01-01&time_to=2026-01-01", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal("not_authorized", body["security_actions_state"]!.ToString()); Assert.Empty(body["security_actions"]!.AsArray());
        Assert.Equal("not_authorized", body["semantic_relations_state"]!.ToString()); Assert.Empty(body["semantic_relations"]!.AsArray());
        Assert.Null(body["total"]); Assert.Null(body["count"]);
        Assert.DoesNotContain(store.Reads, r => r.Sql.Contains("semantic_correlation_candidates", StringComparison.Ordinal) || r.Sql.Contains("select event.id as event_db_id,event.domain_id,event.server_id,event.channel,null::bigint as event_record_id", StringComparison.Ordinal));
    }
    [Fact]
    public async Task PartiallyAuthorizedRelationCannotReachMetadataOrCardItems()
    {
        var store = new Store { Interpretation = true, ForeignRelationProof = true }; using var host = await Host(store, SecurityFacts()); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/entities/1?time_from=2026-01-01&time_to=2026-01-01", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal("available", body["security_actions_state"]!.ToString()); Assert.Equal("empty", body["semantic_relations_state"]!.ToString());
        Assert.Empty(body["semantic_relations"]!.AsArray()); Assert.Null(body["total"]); Assert.Null(body["count"]);
        Assert.DoesNotContain("11111111-1111-1111-1111-111111111111", body.ToJsonString());
        Assert.DoesNotContain(store.Reads, r => r.Sql.Contains("where candidate.candidate_id=any(@candidates)", StringComparison.Ordinal));
    }
    [Fact]
    public async Task SemanticDenialDoesNotHideAuthorizedSourceActionsOrReadRelationMetadata()
    {
        var store = new Store { Interpretation = true }; using var host = await Host(store, SecurityFacts(AllCaps.Where(c => c != "semantic.review").ToArray())); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost/api/v1/entities/1?time_from=2026-01-01&time_to=2026-01-01", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal("available", body["security_actions_state"]!.ToString()); Assert.Equal("not_authorized", body["semantic_relations_state"]!.ToString());
        Assert.DoesNotContain(store.Reads, r => r.Sql.Contains("semantic_correlation_candidates", StringComparison.Ordinal));
    }
    public static IEnumerable<object[]> RoleRoutes => new[] { "viewer", "operator", "admin" }.SelectMany(role => Routes.Select(path => new object[] { role, path }));
    [Theory] [MemberData(nameof(RoleRoutes))]
    public async Task CoarseRoleDoesNotOverrideExplicitCapabilities(string role, string path)
    {
        var store = new Store(); using var host = await Host(store, Facts(role: role), role); using var client = host.GetTestClient();
        using var response = await client.GetAsync("https://localhost" + path, TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
