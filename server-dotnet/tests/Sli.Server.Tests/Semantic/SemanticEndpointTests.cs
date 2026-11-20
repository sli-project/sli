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
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

[Collection("Semantic producer environment")]
public sealed partial class SemanticEndpointTests
{
    private const string Id = "11111111-1111-1111-1111-111111111111";
    private const string Scope = "installation_id=11111111-1111-1111-1111-111111111111&plugin_id=sli.windows.ad-dc&source_instance_id=synthetic&source_generation=1&collection_scope_id=";
    private const string Review = "{\"verdict\":\"false_positive\",\"review_confidence\":\"high\",\"rationale\":\"Synthetic test rationale\",\"review_request_id\":\"22222222-2222-2222-2222-222222222222\"}";
    public static TheoryData<string, string, string?, string> Routes => new()
    {
        { "GET", "/api/v1/semantic/scenarios", null, "items" }, { "GET", "/api/v1/semantic/actions", null, "items" },
        { "GET", "/api/v1/semantic/calibration", null, "calibration_readiness" },
        { "GET", "/api/v1/semantic/relations?domain_id=1&time_from=2026-01-01T00:00:00Z&time_to=2026-01-02T00:00:00Z&timezone=UTC", null, "coverage" },
        { "GET", "/api/v1/semantic/sigma-rules", null, "sources" },
        { "GET", "/api/v1/semantic/attack-coverage?" + Scope + "&since=2026-01-01T00:00:00Z&until=2026-01-02T00:00:00Z&catalog_sha256=" + new string('a', 64), null, "items" },
        { "POST", "/api/v1/semantic/scenarios/" + Id + "/review", Review, "item" },
        { "GET", "/api/v1/platform-settings/semantic-control", null, "policies" },
        { "POST", "/api/v1/platform-settings/semantic-control", "{\"action\":\"policy_admission\",\"policy_id\":\"test\",\"policy_version\":1,\"enabled\":true,\"reason\":\"test\"}", "status" }
    };
    sealed class Authentication(string role, bool authenticated) : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c, CancellationToken ct) => ValueTask.FromResult(authenticated ? AuthenticationResult.Success(new("session", 1, role, "synthetic")) : AuthenticationResult.Denied(401, "authentication_required"));
    }
    sealed class Facts(bool owner, string role, string[] grants, ISemanticDatabase db) : IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal p, CancellationToken ct)
        {
            if (db is Database fixture) fixture.FactsLoaded++;
            return Task.FromResult(new AccessFacts(owner, role, [], [], grants.Select(key => JsonSerializer.SerializeToElement(new { capability_key = key, effect = "allow", scope_json = new { kind = "all" } })).Concat(db is Database configured ? configured.Policies : []).ToArray(), [], [], [],
            [JsonSerializer.SerializeToElement(new { report_key = "security.events.chains", version = 1L, dataset_version = 1L,
                fields_json = new[] { new { category = "security" }, new { category = "technical" }, new { category = "raw_evidence" } }, actions_json = new[] { "view" },
                definition_json = new { actions = new[] { "view" }, field_categories = new[] { "security", "technical", "raw_evidence" }, required_capabilities = Array.Empty<string>() } })]));
        }
    }
    internal sealed class Database : ISemanticDatabase, ISemanticSession
    {
        public int Opened, Committed; public bool Write; public bool DenyEvidence, Replay, Conflict, EmptyPreflight, FailAudit, Seeded; public long? DeniedEvidenceId; public JsonObject? Heartbeat; public readonly List<string> Queries = new();
        public readonly List<(string Sql, object?[] Values)> Calls = new();
        public int FactsLoaded;
        public JsonElement[] Policies = [];
        public readonly Dictionary<long, long> EventServers = new();
        public JsonArray? PreflightEvidence;
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct) { Opened++; Write = write; return Task.FromResult<ISemanticSession>(this); }
        public Task CommitAsync(CancellationToken ct) { Committed++; return Task.CompletedTask; }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            Queries.Add(sql);
            Calls.Add((sql, values));
            if (sql.Contains("from runtime_worker_heartbeats")) return Task.FromResult(Heartbeat is null ? new JsonArray() : new JsonArray(Heartbeat.DeepClone()));
            JsonArray Rows(string json) => JsonNode.Parse(json)!.AsArray();
            if (sql.StartsWith("with audit as") && FailAudit) throw new InvalidOperationException("synthetic_audit_failure");
            if (Seeded && sql.Contains("from semantic_security_scenarios scenario")) return Task.FromResult(new JsonArray(Scenario()));
            if (Seeded && sql.Contains("from canonical_actions action")) return Task.FromResult(new JsonArray(Action()));
            if (Seeded && sql.StartsWith("with current_supported")) return Task.FromResult(Rows("[{\"rule_id\":\"investigation.password.reset-then-logon\",\"rule_version\":2,\"lifecycle_status\":\"shadow\"}]"));
            if (Seeded && (sql.Contains("candidate_page as(select candidate.candidate_id",StringComparison.Ordinal) || sql.Contains("select candidate.candidate_id,candidate.rule_id",StringComparison.Ordinal))) return Task.FromResult(Relation());
            if (sql.StartsWith("with changed as(insert into semantic_suppressions") || sql.StartsWith("with changed as(update semantic_suppressions")) return Task.FromResult(Rows("[{\"id\":1}]"));
            if (sql.Contains("max(version)")) return Task.FromResult(Rows("[{\"runtime_marker\":306,\"semantic_marker\":29,\"identity_merge_schema_ready\":true}]"));
            if (sql.Contains("semantic_security_scenarios where scenario_id")) return Task.FromResult(Rows("[{\"scenario_id\":\"" + Id + "\",\"scenario_kind\":\"test\",\"updated_at\":\"2026-01-01T00:00:00Z\"}]"));
            if (sql.Contains("where review_request_id") && Replay || sql.StartsWith("with review as"))
                return Task.FromResult(Rows("[{\"review_id\":\"" + Id + "\",\"review_request_id\":\"22222222-2222-2222-2222-222222222222\",\"scenario_id\":\"" + Id + "\",\"verdict\":\"false_positive\",\"review_confidence\":\"high\",\"rationale\":\"" + (Conflict ? "different" : "Synthetic test rationale") + "\",\"reviewed_by\":\"synthetic\",\"reviewer_role\":\"operator\"}]"));
            if (sql.Contains("source_kind,definition_json,encode(definition_sha256")) return Task.FromResult(Rows("[{\"policy_id\":\"test\",\"policy_version\":1,\"source_kind\":\"canonical_action\",\"lifecycle_status\":\"shadow\"}]"));
            if (sql.Contains("attack_source_scopes")) return Task.FromResult(Rows("[{\"installation_id\":\"" + Id + "\",\"plugin_id\":\"sli.windows.ad-dc\",\"source_instance_id\":\"synthetic\",\"source_generation\":\"1\",\"collection_scope_id\":\"\",\"resources\":[{\"domain_id\":1,\"server_id\":1,\"channel\":\"Security\"}]}]"));
            if (sql.Contains("attack_catalogs")) return Task.FromResult(Rows("[{\"document_json\":{\"techniques\":{}}}]"));
            if (sql.Contains("select e.domain_id,e.server_id,c.value as channel",StringComparison.Ordinal)) return Task.FromResult(DenyEvidence || DeniedEvidenceId == (long)values[0]! ? new JsonArray() :
                new JsonArray(new JsonObject { ["domain_id"] = 1, ["server_id"] = EventServers.GetValueOrDefault((long)values[0]!, 1), ["channel"] = "Security" }));
            if (sql.StartsWith("with candidates as(select distinct item")) return Task.FromResult(EmptyPreflight ? new JsonArray() :
                new JsonArray(new JsonObject { ["item_id"] = Id, ["evidence_event_ids"] = PreflightEvidence?.DeepClone() ?? new JsonArray(7L, 8L) }));
            return Task.FromResult(new JsonArray());
        }
        private static JsonObject Scenario() => JsonNode.Parse("""
            {"scenario_id":"11111111-1111-1111-1111-111111111111","scenario_kind":"synthetic","result_class":"security_incident","scenario_status":"open",
              "partition_key":"synthetic","title":"Synthetic scenario","explanation":"Synthetic explanation","strict_keys_json":{},"confidence_factors_json":{},
              "first_seen_utc":"2026-01-01T00:00:00Z","last_seen_utc":"2026-01-01T00:00:01Z","updated_at":"2026-01-01T00:00:01Z",
              "risk_class":"high","raw_score":75.5,"display_score":76,"hard_critical":false,"confidence":"high","confidence_score":90,
              "coverage_status":"complete","step_count":2,"evidence_count":2,"contribution_count":1,"conclusion_state":"observed","completeness_snapshot_json":{},"review_count":0,
              "evidence":[{"normalized_event_id":"11111111-1111-1111-1111-111111111111","event_db_id":7,"evidence_order":0}]}
            """)!.AsObject();
        private static JsonObject Action() => JsonNode.Parse("""
            {"canonical_action_id":"11111111-1111-1111-1111-111111111111","action_kind":"account.password.reset","action_status":"observed","semantic_contract_version":1,
              "assembler_id":"semantic-action-assembler","assembler_version":"1.1","occurred_at_utc":"2026-01-01T00:00:00Z","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z",
              "attributes_json":{"synthetic":"private attributes"},"evidence":[{"normalized_event_id":"11111111-1111-1111-1111-111111111111","event_db_id":7,"evidence_order":0,"evidence_role":"primary","entity_role":null,"relation_confidence":1.0}]}
            """)!.AsObject();
        private static JsonArray Relation()
        {
            var rows = new JsonArray();
            for (int i = 0; i < 2; i++) rows.Add(new JsonObject { ["candidate_id"] = Id, ["rule_id"] = "investigation.password.reset-then-logon", ["rule_version"] = 2,
                ["relation_kind"] = "password.reset-then-logon", ["partition_key"] = "domain:1|account_sid:S-1-5-21-100000001-200000002-300000003-1001", ["window_start_utc"] = "2026-01-01T00:00:00Z", ["window_end_utc"] = "2026-01-01T00:00:01Z",
                ["confidence"] = 1.0, ["explanation"] = "Synthetic relation", ["evidence_order"] = i, ["event_db_id"] = 7 + i, ["event_id"] = i == 0 ? 4724 : 4624, ["time_created_utc"] = "2026-01-01T00:00:00Z",
                ["semantic_type"] = i == 0 ? "account.password.reset" : "authentication.session.created", ["source_host"] = "dc.example.test", ["server_id"] = 1, ["domain_id"] = 1, ["channel"] = "Security" });
            return rows;
        }
    }
    internal static async Task<IHost> Host(ISemanticDatabase db, bool owner = true, string role = "operator", bool authenticated = true, params string[] grants)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "true" }).Build();
        return await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services =>
        {
            services.AddRouting(); services.AddLogging(); services.AddSingleton<IConfiguration>(config); services.AddSingleton(new AuthRequestPolicy(config)); services.AddSingleton(new TransportGate(config));
            services.AddSingleton<IPrincipalAuthenticator>(new Authentication(role, authenticated)); services.AddSingleton<IAccessFactsRepository>(new Facts(owner, role, grants, db)); services.AddSingleton<ISemanticDatabase>(db); services.AddSemantic();
        }).Configure(app => { app.UseRouting(); app.UseEndpoints(routes => routes.MapSemantic()); })).StartAsync(TestContext.Current.CancellationToken);
    }
    private static HttpRequestMessage Request(string method, string path, string? body) => new(new HttpMethod(method), path) { Content = body is null ? null : new StringContent(body, System.Text.Encoding.UTF8, "application/json") };
    [Theory] [MemberData(nameof(Routes))]
    public async Task Every_route_dispatches_successfully_without_501(string method, string path, string? body, string field)
    {
        var db = new Database(); using var host = await Host(db); using var client = host.GetTestClient(); using var request = Request(method, path, body);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken); var text = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, text); Assert.NotEqual(501, (int)response.StatusCode); Assert.NotNull(JsonNode.Parse(text)![field]);
        Assert.Equal(path.Contains("/review") ? HttpStatusCode.Created : HttpStatusCode.OK, response.StatusCode);
        if (path.Contains("relations?")) Assert.Equal("empty", JsonNode.Parse(text)!.Text("state"));
        if (method == "POST") Assert.Equal(1, db.Committed);
    }
    [Theory] [MemberData(nameof(Routes))]
    public async Task Every_route_denies_before_data_access(string method, string path, string? body, string field)
    {
        _ = field; var db = new Database(); using var host = await Host(db, false); using var client = host.GetTestClient(); using var request = Request(method, path, body);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken); var text = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        if (path.Contains("sigma-") || path.Contains("attack-coverage")) { Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Contains("source_unavailable_or_denied", text); }
        else if (path.Contains("relations?")) { Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Contains("not_authorized", text); }
        else Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, db.Opened); Assert.Equal(0, db.Committed);
    }
    [Theory]
    [InlineData("GET", "/api/v1/semantic/scenarios?status=bad", null)]
    [InlineData("GET", "/api/v1/semantic/actions?action_kind=" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", null)]
    [InlineData("GET", "/api/v1/semantic/calibration?window_hours=bad", null)]
    [InlineData("GET", "/api/v1/semantic/relations?domain_id=0", null)]
    [InlineData("GET", "/api/v1/semantic/sigma-rules?plugin_id=x", null)]
    [InlineData("GET", "/api/v1/semantic/attack-coverage", null)]
    [InlineData("POST", "/api/v1/semantic/scenarios/bad/review", Review)]
    [InlineData("POST", "/api/v1/platform-settings/semantic-control", "{\"action\":\"bad\"}")]
    public async Task Invalid_input_is_400_without_data_mutation(string method, string path, string? body)
    {
        var db = new Database(); using var host = await Host(db); using var client = host.GetTestClient(); using var request = Request(method, path, body);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode); Assert.Equal(0, db.Opened); Assert.Equal(0, db.Committed);
    }
    [Theory] [InlineData(false, 200)] [InlineData(true, 400)]
    public async Task Review_request_replay_is_exact_and_conflicts_are_rejected(bool conflict, int status)
    {
        var db = new Database { Replay = true, Conflict = conflict }; using var host = await Host(db); using var client = host.GetTestClient();
        using var response = await client.PostAsync("/api/v1/semantic/scenarios/" + Id + "/review", new StringContent(Review, System.Text.Encoding.UTF8, "application/json"), TestContext.Current.CancellationToken);
        Assert.Equal(status, (int)response.StatusCode); Assert.Equal(0, db.Committed); Assert.DoesNotContain(db.Queries, x => x.StartsWith("with review as"));
    }
    [Theory] [InlineData("scenarios")] [InlineData("actions")]
    public async Task Exact_event_denial_never_reads_payload(string leaf)
    {
        var db = new Database { DenyEvidence = true }; using var host = await Host(db); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v1/semantic/" + leaf + "?event_db_id=7", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode); Assert.DoesNotContain(db.Queries, x => x.Contains("scenario.title") || x.Contains("action.attributes_json"));
    }
    [Fact] public async Task Cross_origin_review_never_authenticates_or_opens_database()
    {
        var db = new Database(); using var host = await Host(db); using var client = host.GetTestClient(); using var request = Request("POST", "/api/v1/semantic/scenarios/" + Id + "/review", Review); request.Headers.Add("Origin", "https://untrusted.invalid");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Equal(0, db.Opened);
    }
    [Theory] [MemberData(nameof(Routes))]
    public async Task Every_route_requires_authentication(string method, string path, string? body, string field)
    {
        _ = field; var db = new Database(); using var host = await Host(db, authenticated: false); using var client = host.GetTestClient(); using var request = Request(method, path, body);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode); Assert.Equal(0, db.Opened);
    }
    [Theory] [MemberData(nameof(Routes))]
    public async Task Owner_viewer_role_can_use_every_route(string method, string path, string? body, string field)
    {
        _ = field; var db = new Database(); using var host = await Host(db, role: "viewer"); using var client = host.GetTestClient(); using var request = Request(method, path, body);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
    [Theory] [InlineData("viewer")] [InlineData("operator")] [InlineData("admin")]
    public async Task Review_requires_explicit_capability_instead_of_operator_role(string role)
    {
        var db = new Database(); using var host = await Host(db, false, role, true, "semantic.review"); using var client = host.GetTestClient();
        using var response = await client.PostAsync("/api/v1/semantic/scenarios/" + Id + "/review", new StringContent(Review, System.Text.Encoding.UTF8, "application/json"), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode); Assert.Equal(1, db.Committed);
        var insert = Assert.Single(db.Calls, x => x.Sql.StartsWith("with review as")); Assert.Equal(role, insert.Values[^1]);
    }
    [Theory] [InlineData("GET", null)] [InlineData("POST", "{\"action\":\"bad\"}")]
    public async Task Access_manager_without_ownership_cannot_change_or_read_controls(string method, string? body)
    {
        var db = new Database(); using var host = await Host(db, false, "admin", true, "access.manage"); using var client = host.GetTestClient(); using var request = Request(method, "/api/v1/platform-settings/semantic-control", body);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode); Assert.Contains("platform_owner_required", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)); Assert.Equal(0, db.Opened);
    }
    [Theory]
    [InlineData("{\"verdict\":[],\"review_confidence\":\"high\",\"rationale\":\"synthetic\"}", "invalid_review_verdict")]
    [InlineData("{\"verdict\":\"false_positive\",\"review_confidence\":{},\"rationale\":\"synthetic\"}", "invalid_review_confidence")]
    [InlineData("{\"verdict\":\"false_positive\",\"review_confidence\":\"high\",\"rationale\":1}", "review_rationale_length")]
    [InlineData("{\"verdict\":\"false_positive\",\"review_confidence\":\"high\",\"rationale\":\"synthetic\",\"review_request_id\":123}", "invalid_review_request_id")]
    public async Task Typed_review_input_errors_keep_python_codes(string body, string code)
    {
        var db = new Database(); using var host = await Host(db); using var client = host.GetTestClient(); using var request = Request("POST", "/api/v1/semantic/scenarios/" + Id + "/review", body);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode); Assert.Equal(code, JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.Text("error")); Assert.Equal(0, db.Opened);
    }
    [Theory] [InlineData("{\"action\":{}}", "invalid_semantic_control_action")]
    [InlineData("{\"action\":\"revoke_suppression\",\"id\":true,\"reason\":\"synthetic\"}", "invalid_suppression")]
    [InlineData("{\"action\":\"policy_admission\",\"policy_id\":\"test\",\"policy_version\":true,\"enabled\":true,\"reason\":\"synthetic\"}", "invalid_policy_admission")]
    public async Task Typed_control_input_errors_keep_python_codes(string body, string code)
    {
        var db = new Database(); using var host = await Host(db); using var client = host.GetTestClient(); using var request = Request("POST", "/api/v1/platform-settings/semantic-control", body);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode); Assert.Equal(code, JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.Text("error")); Assert.Equal(0, db.Committed);
    }
    [Theory] [InlineData("create_suppression", "semantic_suppression_create", "1")] [InlineData("revoke_suppression", "semantic_suppression_revoke", "1")] [InlineData("policy_admission", "semantic_policy_admission", "test:1")]
    public async Task Every_control_mutation_audits_actor_target_and_reason_atomically(string action, string auditAction, string target)
    {
        var payload = new JsonObject { ["action"] = action, ["id"] = 1, ["policy_id"] = "test", ["policy_version"] = 1, ["enabled"] = true, ["semantic_type"] = "security.audit-policy.changed", ["domain_id"] = 1, ["scope_kind"] = "bucket", ["scope_value"] = "unknown", ["reason"] = "synthetic reason", ["expires_at"] = SemanticJson.Stamp(DateTimeOffset.UtcNow.AddDays(1)) };
        var db = new Database(); using var host = await Host(db); using var client = host.GetTestClient(); using var request = Request("POST", "/api/v1/platform-settings/semantic-control", payload.ToJsonString());
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.True(db.Write); Assert.Equal(1, db.Committed);
        var audit = Assert.Single(db.Calls, x => x.Sql.StartsWith("with audit as"));
        Assert.Equal("session", audit.Values[0]); Assert.Equal(1L, audit.Values[1]); Assert.Equal(auditAction, audit.Values[2]); Assert.Equal(target, audit.Values[3]); Assert.Equal("synthetic reason", audit.Values[4]);
        Assert.Equal("synthetic reason", ((JsonObject)audit.Values[5]!).Text("reason"));
    }
    [Fact] public async Task Failed_audit_never_commits_control_mutation()
    {
        var db = new Database { FailAudit = true }; using var host = await Host(db); using var client = host.GetTestClient(); using var request = Request("POST", "/api/v1/platform-settings/semantic-control", "{\"action\":\"policy_admission\",\"policy_id\":\"test\",\"policy_version\":1,\"enabled\":true,\"reason\":\"synthetic\"}");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode); Assert.Equal(0, db.Committed);
    }
    [Theory] [InlineData("scenarios")] [InlineData("actions")]
    public async Task Exact_context_checks_every_evidence_resource_before_payload(string leaf)
    {
        var db = new Database { DeniedEvidenceId = 8 }; using var host = await Host(db); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v1/semantic/" + leaf + "?event_db_id=7", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode); Assert.DoesNotContain(db.Queries, x => x.Contains("scenario.title") || x.Contains("action.attributes_json"));
    }
    [Theory] [InlineData("scenarios")] [InlineData("actions")]
    public async Task Exact_context_without_matches_has_metadata_only_zero_evidence_limits(string leaf)
    {
        var db = new Database { EmptyPreflight = true }; using var host = await Host(db); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v1/semantic/" + leaf + "?event_db_id=7", TestContext.Current.CancellationToken); var result = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Equal("no_exact_proof", result["limits"].Text("coverage_state")); Assert.Equal("metadata_only", result["limits"].Text("payload_state")); Assert.Equal(0, result["limits"].Number(leaf == "scenarios" ? "evidence_per_scenario" : "evidence_per_action"));
    }
    [Theory] [InlineData("scenarios", "limit=0", 30)] [InlineData("actions", "limit=0", 30)] [InlineData("scenarios", "scenario_id=" + Id, 1)]
    public async Task List_limits_match_python_zero_default_and_exact_selection(string leaf, string query, int limit)
    {
        var db = new Database(); using var host = await Host(db); using var client = host.GetTestClient(); using var response = await client.GetAsync("/api/v1/semantic/" + leaf + "?" + query, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); var result = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!; Assert.Equal(limit, result["limits"].Number("items"));
    }
    [Theory] [InlineData("id")] [InlineData("time")] [InlineData("naive_time")]
    public async Task Invalid_cursor_position_is_input_error_before_data_access(string invalid)
    {
        var position = new JsonObject { ["time"] = "2026-01-01T00:00:00Z", ["id"] = Id };
        if (invalid == "naive_time") position["time"] = "2026-01-01T00:00:00"; else position[invalid] = 123;
        string cursor = SemanticJson.Cursor(new JsonArray("scenarios", null, null, null, null, null), position);
        var db = new Database(); using var host = await Host(db); using var client = host.GetTestClient(); using var response = await client.GetAsync("/api/v1/semantic/scenarios?cursor=" + cursor, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode); Assert.Contains("invalid_cursor", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)); Assert.Equal(0, db.Opened);
    }
    [Fact] public async Task Controls_read_has_no_query_filters_and_ignores_them_like_python()
    {
        var db = new Database(); using var host = await Host(db); using var client = host.GetTestClient(); using var response = await client.GetAsync("/api/v1/platform-settings/semantic-control?window_hours=bad", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.False(db.Write); Assert.Equal(0, db.Committed);
    }
    [Theory] [InlineData("scenarios", false)] [InlineData("scenarios", true)] [InlineData("actions", false)] [InlineData("actions", true)]
    public async Task Stored_items_expose_react_fields_and_exact_context_redacts_payload(string leaf, bool exact)
    {
        var db = new Database { Seeded = true }; using var host = await Host(db); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v1/semantic/" + leaf + (exact ? "?event_db_id=7" : ""), TestContext.Current.CancellationToken);
        string text = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = JsonNode.Parse(text)!; Assert.Equal("available", result.Text("state")); var item = Assert.Single(result["items"]!.AsArray())!;
        Assert.Equal(leaf == "scenarios" ? "open" : "observed", item.Text("status")); Assert.Single(item["evidence"]!.AsArray());
        Assert.Null(item[leaf == "scenarios" ? "scenario_status" : "action_status"]); Assert.Null(item["attributes_json"]);
        if (exact)
        {
            Assert.Equal("metadata_only", item.Text("payload_state")); Assert.DoesNotContain("private attributes", text); Assert.DoesNotContain("Synthetic scenario", text);
            if (leaf == "actions") Assert.Empty(item["attributes"]!.AsObject());
            else { Assert.Empty(item["strict_keys"]!.AsObject()); Assert.Empty(item["confidence_factors"]!.AsObject()); }
            Assert.Equal("bounded_exact_matches", result["limits"].Text("coverage_state"));
        }
        else if (leaf == "scenarios") { Assert.Equal("Synthetic scenario", item.Text("title")); Assert.Equal(76, item.Number("display_score")); }
        else Assert.Equal("private attributes", item["attributes"].Text("synthetic"));
    }
    [Fact] public async Task Stored_relation_has_exact_identity_and_ordered_continuation_evidence()
    {
        var db = new Database { Seeded = true }; using var host = await Host(db); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v1/semantic/relations?domain_id=1&time_from=2026-01-01T00:00:00Z&time_to=2026-01-02T00:00:00Z&timezone=UTC", TestContext.Current.CancellationToken);
        string text = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = JsonNode.Parse(text)!; Assert.Equal("available", result.Text("state")); var item = Assert.Single(result["items"]!.AsArray())!;
        Assert.Equal("exact_domain_account_sid", item["identity_basis"].Text("kind")); Assert.Equal("unique", item.Text("continuation_state"));
        Assert.Equal("anchor", item["evidence"]![0].Text("evidence_role")); Assert.Equal("alternative_continuation", item["evidence"]![1].Text("evidence_role")); Assert.Equal(1, result["coverage"].Number("matched_relation_count"));
        Assert.False(db.Write); Assert.Equal(0, db.Committed);
    }
    [Fact] public async Task Calibration_ignores_other_routes_filters_like_python()
    {
        var db = new Database(); using var host = await Host(db); using var client = host.GetTestClient();
        using var response = await client.GetAsync("/api/v1/semantic/calibration?limit=bad&event_db_id=bad&window_hours=0", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Equal(24, JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.Number("window_hours"));
    }
    [Theory] [InlineData("/api/v1/semantic/scenarios/" + Id + "/review", "[]", "json_object_required")]
    [InlineData("/api/v1/platform-settings/semantic-control", "{", "invalid_json")]
    public async Task Invalid_json_envelopes_do_not_open_database(string path, string body, string code)
    {
        var db = new Database(); using var host = await Host(db); using var client = host.GetTestClient(); using var request = Request("POST", path, body);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode); Assert.Equal(code, JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.Text("error")); Assert.Equal(0, db.Opened);
    }
}
