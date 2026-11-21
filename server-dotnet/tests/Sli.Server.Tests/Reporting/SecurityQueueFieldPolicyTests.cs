using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Problems;
using Sli.Server.Investigations;
using Sli.Server.Reporting.V2;
using Sli.Server.Tests.Problems;
using Xunit;

namespace Sli.Server.Tests.Reporting;

// Behaviour vectors from tests/reporting/test_security_queue_field_policy.py.
public sealed class SecurityQueueFieldPolicyTests
{
    const string Report = "/api/v2/reports/security.problems";
    const string Detail = Report + "/rows/7/detail";
    static string Queue(bool legacy) => legacy ? "/api/findings?source=semantic-production" : Report + "/data";
    static string Finding(bool legacy) => legacy ? Queue(true) : With(Queue(false), "id=7");
    static string With(string path, string query) => path + (path.Contains('?') ? "&" : "?") + query;
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static JsonElement J(object value) => JsonSerializer.SerializeToElement(value);
    static JsonObject Raw() => JsonNode.Parse("""
        {"state":"available","status":"ok","source":"semantic_production_findings",
         "items":[{"id":7,"rule_code":"semantic.qw.password-brute-force","title":"Synthetic summary","summary":"Synthetic observation","status":"new",
          "severity":"high","evidence_count":2,"actor":"identity-marker","target":"identity-marker",
          "source":"technical-marker","assigned_to":"identity-marker","status_reason":"exact-marker",
          "unknown_future_field":"future-marker",
          "risk_acceptance":{"id":31,"finding_id":7,"state":"active","expires_at":"2026-10-08T00:00:00Z",
           "created_at":"2026-10-07T00:00:00Z","reason":"exact-marker","responsible_user_id":900004,
           "responsible_username":"identity-marker","created_by":"identity-marker","changed_by":"identity-marker","unknown_field":"future-marker"},
          "risk_audit":[{"id":31,"action":"create","actor":"identity-marker","occurred_at":"2026-10-07T00:00:00Z",
           "unknown_field":"future-marker","details":{"unknown_field":"future-marker","rule":{"id":31,"finding_id":7,
            "reason":"exact-marker","responsible_user_id":900004,"unknown_field":"future-marker"}}}],
          "review_hint":{"bucket":"unknown","event_db_id":"exact-marker"},
          "evidence":[{"event_db_id":900001,"event_record_id":900002,"event_id":4719,"hostname":"technical-marker",
           "channel":"technical-marker","note":"exact-marker","unknown_field":"future-marker"}],
          "entities":[{"display_name":"identity-marker","entity_role":"actor","unknown_field":"future-marker"}],
          "status_history":[{"id":900003,"new_status":"new","changed_by":"identity-marker","note":"exact-marker","unknown_field":"future-marker"}]}],
         "summary":[{"status":"new","severity":"high","count":1}],"lifecycle":{},
         "semantic_runtime":{"findings_state":"active"},"limitations":[]}
        """)!.AsObject();

    static AccessFacts Facts(string[]? fields = null, string scope = "{\"kind\":\"all\"}",
        bool assigned = true, string effect = "allow", string[]? actions = null, bool cases = false, bool capability = true)
    {
        fields ??= ["security"]; actions ??= ["view", "export"];
        string[] allFields = ["security", "raw_evidence", "identity_basic", "technical"];
        var grants = assigned ? new List<JsonElement> { J(new { report_key = "security.queue", effect, allowed_actions = actions, field_categories = fields, scope_json = JsonNode.Parse(scope) }) } : [];
        if (cases) grants.Add(J(new { report_key = "investigations.workspace", effect = "allow", allowed_actions = new[] { "view" }, field_categories = new[] { "security" }, scope_json = new { kind = "domain", ids = new[] { 1 } } }));
        return new(false, "viewer", [], [], allFields.Select(f => "field." + f).Append("evidence.exact")
            .Concat(capability ? ["investigations.view"] : []).Select(c => J(new { capability_key = c, effect = "allow", scope_json = new { kind = "all" } })).ToArray(), [], [], grants,
            new[] { "security.queue", "investigations.workspace" }.Select(key => J(new { report_key = key, version = 1, dataset_version = 1,
                definition_json = new { actions = new[] { "view", "export" } }, actions_json = new[] { "view", "export" }, fields_json = allFields.Select(category => new { category }) })).ToArray());
    }
    sealed class Repository : IProblemRepository
    {
        public readonly List<FindingQuery> Calls = [];
        public Func<int, JsonObject> Read = _ => Raw();
        public Task<JsonObject> FindingsAsync(FindingQuery q, ProblemAccess a, CancellationToken ct) { Calls.Add(q); return Task.FromResult(Read(Calls.Count)); }
        public Task<JsonObject> StatusAsync(long id, FindingStatusInput input, string actor, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> RiskAsync(long id, RiskInput input, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> ResponsiblesAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> RiskAuditAsync(long id, long? before, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> WatchListAsync(RegistryQuery q, ProblemAccess a, Principal p, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> WatchSaveAsync(string? id, WatchInput input, ProblemAccess a, Principal p, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> DecoyListAsync(RegistryQuery q, ProblemAccess a, Principal p, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> DecoySaveAsync(string? id, DecoyInput input, ProblemAccess a, Principal p, CancellationToken ct) => throw new NotSupportedException();
    }
    sealed class Evidence : ISecurityProblemEvidence
    {
        public readonly List<(ReportQueryContext Context, long Finding, JsonObject? Cursor)> Calls = [];
        public Task<JsonObject> PageAsync(ReportQueryContext context, long finding, JsonObject? cursor, CancellationToken ct)
        {
            Calls.Add((context, finding, cursor)); long after = cursor is null ? 0 : long.Parse(cursor["position"]!["native_key"]!.ToString());
            return Task.FromResult(new JsonObject { ["items"] = new JsonArray(new JsonObject {
                ["evidence_id"] = after + 1, ["event_db_id"] = 900001 + after, ["event_record_id"] = 900002 + after,
                ["event_id"] = 4719, ["hostname"] = "technical-marker", ["channel"] = "technical-marker", ["time_created_utc"] = "2026-10-07T00:00:00Z" }),
                ["total"] = 2, ["has_more"] = after == 0, ["watermark"] = "2026-10-07T00:00:00Z",
                ["next_position"] = new JsonObject { ["storage_kind"] = "core_event", ["native_key"] = (after + 1).ToString("D20") } });
        }
    }
    sealed class Fixture : IDisposable
    {
        public readonly Repository Repo = new(); public readonly Evidence Evidence = new();
        public readonly ReportFixture.FactsRepo Facts;
        readonly ServiceProvider services;
        public readonly Cases Cases = new();
        public Fixture(AccessFacts? facts = null)
        {
            Facts = new(facts ?? SecurityQueueFieldPolicyTests.Facts());
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:AuthRequired"] = "true" }).Build();
            services = new ServiceCollection().AddLogging().AddSingleton<IConfiguration>(config)
                .AddSingleton(new AuthRequestPolicy(config)).AddSingleton(new TransportGate(config))
                .AddSingleton<IPrincipalAuthenticator>(new ProblemEndpointTests.Authentication { Role = "viewer" })
                .AddSingleton<IAccessFactsRepository>(Facts).AddSingleton<IProblemRepository>(Repo)
                .AddSingleton<IInvestigationListRepository>(Cases)
                .AddSingleton<IReportDefinitionRegistry>(new ReportDefinitionRegistry())
                .AddSingleton<IReportCatalogProvider>(new ReportRuleCatalog(new PluginGenerationReader(null)))
                .AddSingleton<IReportV2Metadata>(new ReportFixture.Metadata()).AddSingleton<ReportV2Dispatcher>()
                .AddSingleton<IReportV2Reader>(new SecurityProblemsReader(Repo, Evidence)).BuildServiceProvider();
        }
        public async Task<(int Status, JsonObject Body)> Get(string path, string locale = "en")
        {
            var parts = path.Split('?', 2); var http = new DefaultHttpContext { RequestServices = services, RequestAborted = Ct };
            http.Request.Method = "GET"; http.Request.Scheme = "https"; http.Request.Path = parts[0];
            if (parts.Length > 1) http.Request.QueryString = new("?" + parts[1]);
            http.Request.Headers.AcceptLanguage = locale; http.Response.Body = new MemoryStream();
            if (parts[0] == "/api/findings") await ProblemEndpoints.HandleAsync(http);
            else if (parts[0] == "/api/v1/investigation-cases") await InvestigationListEndpoints.HandleAsync(http);
            else await ReportV2Endpoints.HandleAsync(http);
            return (http.Response.StatusCode, JsonNode.Parse(((MemoryStream)http.Response.Body).ToArray())!.AsObject());
        }
        public void Dispose() => services.Dispose();
    }
    sealed class Cases : IInvestigationListRepository
    {
        public int Calls;
        public Task<IReadOnlyList<InvestigationListRow>> ReadAsync(int limit, CancellationToken ct) { Calls++; return Task.FromResult<IReadOnlyList<InvestigationListRow>>([]); }
        public Task<IReadOnlyDictionary<long, IReadOnlyList<IReadOnlyList<AccessResource>>>> GroupsAsync(long[] ids, CancellationToken ct) =>
            Task.FromResult<IReadOnlyDictionary<long, IReadOnlyList<IReadOnlyList<AccessResource>>>>(new Dictionary<long, IReadOnlyList<IReadOnlyList<AccessResource>>>());
    }
    static JsonObject Row(JsonObject body) => Assert.Single(body["items"]!.AsArray())!.AsObject();

    [Theory][InlineData(false)][InlineData(true)]
    public async Task SecurityOnlyPreservesSummaryAndCountsAndRemovesAllDetailMarkers(bool legacy)
    {
        using var f = new Fixture(); var (status, body) = await f.Get(Finding(legacy)); Assert.Equal(200, status);
        var row = Row(body); Assert.Equal("Password guessing against an account", row["title"]!.ToString()); Assert.Equal(2, (int?)row["evidence_total"]);
        Assert.DoesNotContain("Synthetic summary", row.ToJsonString());
        Assert.True(row.ContainsKey("linked_case")); Assert.Null(row["linked_case"]);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"id":31,"finding_id":7,"state":"active","expires_at":"2026-10-08T00:00:00Z","created_at":"2026-10-07T00:00:00Z"}"""), row["risk_acceptance"]));
        foreach (string key in new[] { "risk_audit", "evidence", "status_history" }) Assert.False(row.ContainsKey(key));
        foreach (string marker in new[] { "exact-marker", "identity-marker", "technical-marker", "future-marker", "case-marker", "900001", "900002", "900003", "900004" }) Assert.DoesNotContain(marker, body.ToJsonString());
        Assert.Single(f.Repo.Calls);
    }
    [Theory][InlineData(false, "ru", false)][InlineData(false, "en", false)][InlineData(true, "ru", false)][InlineData(true, "en", false)]
    [InlineData(false, "ru", true)][InlineData(false, "en", true)][InlineData(true, "ru", true)][InlineData(true, "en", true)]
    public async Task LocalizedCatalogEnvelopesRespectIdentityPolicy(bool legacy, string locale, bool identity)
    {
        using var f = new Fixture(Facts(identity ? ["security", "identity_basic"] : ["security"]));
        f.Repo.Read = _ => {
            var raw = Raw();
            var row = raw["items"]![0]!;
            row["actor"] = "sid:fixture-host:S-1-5-18";
            if (!legacy) row["rule_code"] = "semantic.security.audit_controls_changed";
            return raw;
        };
        var (status, body) = await f.Get(Finding(legacy), locale); Assert.Equal(200, status); var row = Row(body);
        foreach (string field in new[] { "actor_text", "entity_text", "entity_messages" }) Assert.Equal(identity, row.ContainsKey(field));
        Assert.Equal(identity, row["presentation_messages"]!.AsObject().ContainsKey("actor_text"));
        if (identity) {
            var envelope = ProblemPresentation.Message("security.problems.entity.system", locale, new() { ["name"] = "FIXTURE-HOST" });
            Assert.True(JsonNode.DeepEquals(envelope, row["presentation_messages"]!["actor_text"]));
            Assert.Equal(envelope["text"]!.ToString(), row["actor_text"]!.ToString());
            Assert.Equal("identity-marker", Assert.Single(row["entity_messages"]!.AsArray())!.ToString());
        } else { Assert.DoesNotContain("FIXTURE-HOST", row.ToJsonString()); Assert.DoesNotContain("identity-marker", row.ToJsonString()); }
        Assert.True(JsonNode.DeepEquals(ProblemPresentation.Message("security.problems.status.new", locale), row["status_message"]));
        Assert.True(JsonNode.DeepEquals(ProblemPresentation.Message("reports.v2.security.problems.columns.severity.labels.high", locale), row["severity_message"]));
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task MissingDeniedActionlessAndCorelessGrantsNeverRead(bool legacy)
    {
        foreach (var facts in new[] { Facts(assigned: false), Facts(effect: "deny"), Facts(actions: []), Facts(fields: []) }) {
            using var f = new Fixture(facts); Assert.Equal(403, (await f.Get(Queue(legacy))).Status); Assert.Empty(f.Repo.Calls);
        }
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task FullGrantKeepsExactEvidenceAndAllowListsNestedRiskAndHistory(bool legacy)
    {
        using var f = new Fixture(Facts(["security", "raw_evidence", "identity_basic", "technical"], cases: true));
        var (status, body) = await f.Get(Finding(legacy)); Assert.Equal(200, status); var row = Row(body);
        Assert.Equal(900001, (int?)row["evidence"]![0]!["event_db_id"]); Assert.Equal(900002, (int?)row["evidence"]![0]!["event_record_id"]);
        Assert.Equal("exact-marker", row["status_history"]![0]!["note"]!.ToString()); Assert.Equal("exact-marker", row["risk_acceptance"]!["reason"]!.ToString());
        Assert.Equal(900004, (int?)row["risk_acceptance"]!["responsible_user_id"]); Assert.Equal(900004, (int?)row["risk_audit"]![0]!["details"]!["rule"]!["responsible_user_id"]);
        Assert.Null(row["linked_case"]); Assert.DoesNotContain("future-marker", body.ToJsonString());
    }
    [Theory][InlineData(false, "raw_evidence")][InlineData(true, "raw_evidence")][InlineData(false, "identity_basic")][InlineData(true, "identity_basic")]
    public async Task RiskReasonAndResponsibleHaveIndependentGrants(bool legacy, string category)
    {
        using var f = new Fixture(Facts(["security", category])); var response = await f.Get(Finding(legacy)); Assert.Equal(200, response.Status);
        var row = Row(response.Body); var risk = row["risk_acceptance"]!.AsObject(); Assert.Equal("active", risk["state"]!.ToString());
        Assert.Equal(category == "raw_evidence", risk.ContainsKey("reason"));
        foreach (string key in new[] { "responsible_user_id", "responsible_username", "created_by", "changed_by" }) Assert.Equal(category == "identity_basic", risk.ContainsKey(key));
        Assert.False(row.ContainsKey("risk_audit"));
        if (category == "raw_evidence") {
            Assert.Equal(900001, (int?)row["evidence"]![0]!["event_db_id"]);
            Assert.False(row["evidence"]![0]!.AsObject().ContainsKey("hostname")); Assert.False(row["evidence"]![0]!.AsObject().ContainsKey("channel"));
            Assert.False(row.ContainsKey("actor")); Assert.False(row.ContainsKey("status_history"));
        }
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task QueueWorksWithoutInvestigationCapabilityAndRiskCannotBypassIdentityDenial(bool legacy)
    {
        using var f = new Fixture(Facts(capability: false));
        foreach (string query in new[] { "", "risk=accepted" }) {
            var response = await f.Get(With(Queue(legacy), query)); Assert.Equal(200, response.Status);
            Assert.Null(Row(response.Body)["linked_case"]); Assert.Equal("active", Row(response.Body)["risk_acceptance"]!["state"]!.ToString());
            foreach (string marker in new[] { "identity-marker", "exact-marker", "technical-marker", "future-marker" }) Assert.DoesNotContain(marker, response.Body.ToJsonString());
        }
        Assert.Equal("accepted", f.Repo.Calls.Last().Risk); f.Repo.Calls.Clear();
        foreach (string query in new[] { "q=identity-marker", "entity_id=7&risk=accepted", "q=identity-marker&risk=accepted" }) Assert.Equal(403, (await f.Get(With(Queue(legacy), query))).Status);
        Assert.Empty(f.Repo.Calls);
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task DomainAndIdentityRiskFiltersReachReaderAndOutsideDomainNeverReads(bool legacy)
    {
        using var f = new Fixture(Facts(["security", "identity_basic"], "{\"kind\":\"domain\",\"ids\":[1,2]}"));
        foreach (string query in new[] { "", "entity_id=7&risk=accepted", "domain=1", "domain=2" }) {
            var path = query.StartsWith("entity_id") ? Finding(legacy) : Queue(legacy);
            var response = await f.Get(With(path, query)); Assert.Equal(200, response.Status); Assert.Equal(7, (int?)Row(response.Body)["id"]);
            var input = f.Repo.Calls.Last(); Assert.Equal(query.StartsWith("domain=") ? [long.Parse(query[7..])] : new long[] { 1, 2 }, input.Domains);
            if (query.StartsWith("entity_id")) { Assert.Equal(7, input.EntityId); Assert.Equal("accepted", input.Risk); Assert.Equal(900004, (int?)Row(response.Body)["risk_acceptance"]!["responsible_user_id"]); Assert.DoesNotContain("exact-marker", response.Body.ToJsonString()); }
        }
        f.Repo.Calls.Clear(); var denied = await f.Get(With(Queue(legacy), "domain=3")); Assert.Equal(403, denied.Status); Assert.Equal("report_scope_not_executable", denied.Body["error"]!.ToString()); Assert.Empty(f.Repo.Calls);
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task UnsupportedScopesCannotBecomeGlobal(bool legacy)
    {
        foreach (string scope in new[] { "{\"kind\":\"domain\",\"ids\":[]}", "{\"kind\":\"server\",\"ids\":[1]}", "{\"mode\":\"restricted\",\"clauses\":[{\"collection_scope_ids\":[\"ad-domain:1\"],\"device_ids\":[\"fixture-device\"]}]}" }) {
            using var f = new Fixture(Facts(scope: scope)); Assert.Equal(403, (await f.Get(Queue(legacy))).Status); Assert.Empty(f.Repo.Calls);
        }
    }
    [Fact]
    public async Task SeparateGrantCannotRestoreDeniedFields()
    {
        var facts = Facts(); facts = facts with { ReportAssignments = facts.ReportAssignments.Append(J(new { report_key = "security.queue", effect = "allow", allowed_actions = new[] { "view" }, field_categories = new[] { "raw_evidence" }, scope_json = new { kind = "all" } })).ToArray() };
        using var f = new Fixture(facts); var response = await f.Get(Queue(false)); Assert.Equal(200, response.Status); Assert.DoesNotContain("exact-marker", response.Body.ToJsonString());
    }
    [Fact]
    public async Task DeclarationAndDetailDenyWithoutRawAndEntityFilterRequiresIdentityBeforeAnyReads()
    {
        using var f = new Fixture(); var declaration = await f.Get(Report); Assert.Equal(200, declaration.Status);
        Assert.False(declaration.Body["detail"]!["access"]!["allowed"]!.GetValue<bool>()); Assert.Empty(declaration.Body["detail"]!["columns"]!.AsArray());
        foreach (var fields in new[] { new[] { "security", "identity_basic" }, new[] { "security", "raw_evidence" } }) {
            f.Facts.Value = Facts(fields);
            foreach (string query in fields.Contains("raw_evidence") ? new[] { "entity_id=7&risk=accepted" } : new[] { "", "entity_id=7&risk=accepted" }) Assert.Equal(403, (await f.Get(With(Detail, query))).Status);
        }
        Assert.Empty(f.Repo.Calls); Assert.Empty(f.Evidence.Calls);
    }
    [Theory][InlineData(1, 1)][InlineData(20, 20)][InlineData(200, 20)][InlineData(0, 0)][InlineData(201, 0)]
    public async Task DetailPageSizeIsValidatedAndBoundedBeforeReads(int limit, int expected)
    {
        using var f = new Fixture(Facts(["security", "raw_evidence"])); var response = await f.Get(With(Detail, "limit=" + limit));
        Assert.Equal(expected == 0 ? 400 : 200, response.Status);
        if (expected == 0) { Assert.Empty(f.Repo.Calls); Assert.Empty(f.Evidence.Calls); }
        else Assert.Equal(expected, Assert.Single(f.Evidence.Calls).Context.Paging.Limit);
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task EvidenceContinuationProjectsTechnicalFieldsAndRechecksFilteredMembership(bool technical)
    {
        using var f = new Fixture(Facts(technical ? ["security", "raw_evidence", "identity_basic", "technical"] : ["security", "raw_evidence", "identity_basic"], "{\"kind\":\"domain\",\"ids\":[1]}"));
        string path = With(Detail, "entity_id=7&risk=accepted"); var first = await f.Get(path); Assert.Equal(200, first.Status);
        Assert.True(first.Body["has_more"]!.GetValue<bool>()); Assert.Equal(2, (int?)first.Body["filtered_count"]);
        var second = await f.Get(With(path, "cursor=" + Uri.EscapeDataString(first.Body["next_cursor"]!.ToString()))); Assert.Equal(200, second.Status); Assert.False(second.Body["has_more"]!.GetValue<bool>());
        Assert.Equal(900001, (int?)Row(first.Body)["event_db_id"]); Assert.Equal(900002, (int?)Row(second.Body)["event_db_id"]);
        foreach (var body in new[] { first.Body, second.Body }) { var row = Row(body); Assert.Equal(4719, (int?)row["event_id"]); Assert.Equal(technical, row.ContainsKey("hostname")); Assert.Equal(technical, row.ContainsKey("channel")); Assert.Equal(technical, body.ToJsonString().Contains("technical-marker")); }
        Assert.Equal(2, f.Repo.Calls.Count); Assert.All(f.Repo.Calls, q => { Assert.Equal(7, q.FindingId); Assert.Equal(7, q.EntityId); Assert.Equal("accepted", q.Risk); Assert.Equal(new long[] { 1 }, q.Domains); Assert.True(q.Compact); });
        Assert.Equal(2, f.Evidence.Calls.Count); Assert.Null(f.Evidence.Calls[0].Cursor); Assert.Equal("00000000000000000001", f.Evidence.Calls[1].Cursor!["position"]!["native_key"]!.ToString());
        f.Repo.Read = _ => new() { ["items"] = new JsonArray() };
        Assert.Equal(404, (await f.Get(With(path, "cursor=" + Uri.EscapeDataString(first.Body["next_cursor"]!.ToString())))).Status); Assert.Equal(2, f.Evidence.Calls.Count);
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task DomainTimePopulationMembershipIsCheckedOnEveryPage(bool present)
    {
        using var f = new Fixture(Facts(["security", "raw_evidence"], "{\"kind\":\"domain\",\"ids\":[1]}"));
        f.Repo.Read = count => present && count == 1 ? Raw() : new() { ["items"] = new JsonArray() };
        string path = With(Detail, "population=attention&time_from=2026-10-01T00:00:00Z&time_to=2026-10-02T00:00:00Z");
        var first = await f.Get(path); Assert.Equal(present ? 200 : 404, first.Status);
        if (present) Assert.Equal(404, (await f.Get(With(path, "cursor=" + Uri.EscapeDataString(first.Body["next_cursor"]!.ToString())))).Status);
        Assert.Equal(present ? 1 : 0, f.Evidence.Calls.Count);
        Assert.All(f.Repo.Calls, q => { Assert.Equal(new long[] { 1 }, q.Domains); Assert.Equal("attention", q.Population); Assert.Equal("2026-10-01T00:00:00Z", q.From); Assert.Equal("2026-10-02T00:00:00Z", q.To); });
    }
    [Theory][InlineData(false)][InlineData(true)]
    public async Task DecoyReferencesRequireTechnicalFields(bool technical)
    {
        using var f = new Fixture(Facts(technical ? ["security", "technical"] : ["security"]));
        f.Repo.Read = _ => { var raw = Raw(); raw["items"]![0]!["decoy_id"] = "00000000-0000-4000-8000-000000000003"; raw["items"]![0]!["decoy_revision"] = 7; return raw; };
        var response = await f.Get(Queue(false)); Assert.Equal(200, response.Status); var row = Row(response.Body);
        Assert.Equal(technical, row.ContainsKey("decoy_id")); Assert.Equal(technical, row.ContainsKey("decoy_revision"));
    }
    [Fact]
    public void PassportDeclaresEveryEnforcedFieldClass()
    {
        var definition = new ReportDefinitionRegistry().Get("security.problems")!;
        var classes = definition.Declaration["intent"]!["field_classes"]!.AsArray().Select(n => n!.ToString()).ToHashSet();
        foreach (var field in definition.Rule["required_fields"]!.AsArray().Concat(definition.Declaration["row_categories"]!.AsObject().SelectMany(p => p.Value!.AsArray()))) Assert.Contains(field!.ToString(), classes);
    }
    [Fact]
    public async Task QueueExportIsUnavailableAndFutureCsvSinkReceivesProjectedRows()
    {
        using var f = new Fixture(); Assert.Equal(404, (await f.Get(Report + "/export.csv")).Status); Assert.Empty(f.Repo.Calls);
        var response = await f.Get(Queue(false)); var definition = new ReportDefinitionRegistry().Get("security.problems")!;
        string csv = ReportCsv.FromColumns(definition.Columns, response.Body["items"]!.AsArray().OfType<JsonObject>());
        Assert.Contains("Password guessing against an account", csv);
        Assert.DoesNotContain("Synthetic summary", csv);
        foreach (string marker in new[] { "exact-marker", "identity-marker", "technical-marker", "case-marker", "future-marker" }) Assert.DoesNotContain(marker, csv);
    }
    [Fact]
    public void LinkedCaseRequiresActualCaseResourcesAndExplicitDenyOverridesAllow()
    {
        var facts = Facts(cases: true);
        AccessDecision Compose(AccessFacts value) => new ReportEligibility().Compose(value, new CapabilityComposer().Compose(value));
        var access = Compose(facts); var item = JsonNode.Parse("""{"id":44,"public_id":"case-marker","status":"active","unknown_field":"future-marker"}""")!.AsObject();
        IReadOnlyList<IReadOnlyList<AccessResource>> own = [[new("domain", 1)]], foreign = [[new("domain", 2)]];
        Assert.Null(ProblemRepository.LinkedCase(item, new(access), foreign));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"id":44,"public_id":"case-marker","status":"active"}"""), ProblemRepository.LinkedCase(item, new(access), own)));
        var denied = facts with { DirectCapabilities = facts.DirectCapabilities.Append(J(new { capability_key = "investigations.view", effect = "deny", scope_json = new { kind = "domain", ids = new[] { 1 } } })).ToArray() };
        Assert.Null(ProblemRepository.LinkedCase(item, new(Compose(denied)), own));
        Assert.Null(ProblemRepository.LinkedCase(item, new(Compose(Facts())), own));
        Assert.Null(ProblemRepository.LinkedCase(item, new(Compose(Facts(cases: true, capability: false))), own));
    }
    [Fact]
    public async Task InvestigationAssignmentWorksWhileQueueIsDenied()
    {
        using var f = new Fixture(Facts(effect: "deny", cases: true));
        Assert.Equal(403, (await f.Get(Queue(false))).Status);
        var response = await f.Get("/api/v1/investigation-cases"); Assert.Equal(200, response.Status); Assert.Empty(response.Body["items"]!.AsArray());
        Assert.Equal(1, f.Cases.Calls); Assert.Empty(f.Repo.Calls);
    }
    [Fact]
    public async Task MixedProductionAndRetiredSourcesNeverRead()
    {
        using var f = new Fixture(); Assert.Equal(410, (await f.Get("/api/findings?source=semantic-production&source=legacy")).Status); Assert.Empty(f.Repo.Calls);
    }
}
