using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Ad;
using Sli.Server.Gpo;
using Sli.Server.Problems;
using Sli.Server.Reporting.V2;
using Sli.Server.Tests.Gpo;
using Sli.Server.Tests.Problems;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class ReportStatesV2Tests
{
    static JsonObject O(string json) => ReportFixture.O(json);
    static string State(JsonObject value) => value["state"]!.GetValue<string>();
    static void EqualJson(string expected, JsonNode? actual) => Assert.True(JsonNode.DeepEquals(JsonNode.Parse(expected), actual), actual?.ToJsonString());
    static readonly string[] States = ["ok", "empty", "denied", "not_collected", "partial", "processing", "stale", "error"];
    static ReportQueryContext Context(string key = "security.problems", AccessDecision? access = null)
    {
        var original = ReportFixture.Access();
        var grant = original.Reports.Single().Grants.Single() with { FieldCategories = new HashSet<string>(["security"]) };
        access ??= original with { Reports = [new("security.queue", true, [grant])] };
        return new(new ReportDefinitionRegistry().Get(key)!, access, new("session", 7, "viewer"),
            O("""{"period":{"from_utc":"2026-10-01T00:00:00Z","to_utc":"2026-10-02T00:00:00Z"}}"""),
            new(null, 100, "UTC", null, "asc", null), ReportScope.All, [7], "view", _ => true, []);
    }

    [Fact]
    public void EveryRegisteredReportDeclaresAndBuildsAllEightStates()
    {
        Assert.Equal(States.Order(), ReportResult.States.Order());
        var registry = new ReportDefinitionRegistry();
        foreach (var rule in new ReportRuleCatalog(new PluginGenerationReader(null)).Capture().Rules)
        {
            var definition = registry.Get(rule.RegistryKey)!;
            Assert.Equal(States.Order(), definition.Declaration["result_states"]!.AsArray().Select(n => n!.GetValue<string>()).Order());
            foreach (string state in States) Assert.Equal(state, State(ReportResult.Create(definition.Key, state)));
            Assert.Equal("report_state_invalid", Assert.Throws<ReportRequestException>(() => ReportResult.Create(definition.Key, "unavailable")).Message);
        }
    }

    [Theory]
    [InlineData("available", "ok")][InlineData("empty", "empty")][InlineData("not_authorized", "denied")]
    [InlineData("not_collected", "not_collected")][InlineData("processing", "processing")][InlineData("stale", "stale")]
    [InlineData("unavailable", "error")][InlineData("failed", "error")][InlineData("empty_unverified", "partial")]
    [InlineData("coverage_unverified", "partial")][InlineData("unexpected_state", "error")][InlineData(null, "error")]
    public void SourceVocabularyNeverTurnsUnknownIntoSuccess(string? raw, string expected) => Assert.Equal(expected, ReportResult.SourceState(raw));

    [Theory]
    [InlineData("{\"completeness\":\"not_proven\"}", "partial")]
    [InlineData("{\"state\":\"processing\"}", "processing")]
    [InlineData("{\"unprocessed_events\":2}", "processing")]
    [InlineData("{\"missing_sources\":[\"fixture-source\"]}", "partial")]
    [InlineData("{\"missing_domains\":[7]}", "partial")]
    [InlineData("{\"state\":\"failed\"}", "error")]
    [InlineData("{\"state\":\"not_collected\"}", "not_collected")]
    [InlineData("{\"state\":\"stale\",\"observed_at_utc\":\"2026-10-01T00:00:00Z\"}", "stale")]
    public void MissingOrPendingCoverageCannotBecomeEmptyAndDenialWins(string json, string expected)
    {
        var result = ReportResult.Create("events.journal", "empty", coverage: O(json));
        Assert.Equal(expected, State(result)); Assert.NotEmpty(result["state_details"]!["reason"]!.GetValue<string>());
        Assert.Equal("denied", State(ReportResult.Create("events.journal", "denied", coverage: O(json))));
    }

    [Fact]
    public void PartialNamesMissingCoverageAndStaleKeepsObservationTime()
    {
        var result = ReportResult.Create("events.journal", "ok", [new JsonObject { ["id"] = 1 }], O("""{"missing_sources":["fixture-source"],"missing_domains":[7]}"""));
        Assert.Equal("partial", State(result));
        EqualJson("[\"fixture-source\"]", result["state_details"]!["missing_sources"]); EqualJson("[7]", result["state_details"]!["missing_domains"]);
        result = ReportResult.Create("events.journal", "stale", coverage: O("""{"observed_at_utc":"2026-10-01T00:00:00Z"}"""));
        Assert.Equal("2026-10-01T00:00:00Z", result["state_details"]!["observed_at_utc"]!.GetValue<string>());
    }

    [Fact]
    public void TruncationKeepsStageAndLimitationsWithoutInventingSourceOutage()
    {
        var limitations = JsonNode.Parse("""[{"code":"history_limit","text":"Synthetic read limit reached."}]""")!.AsArray();
        var result = ReportResult.Create("events.journal", "partial", coverage: O("""{"stage":"history_read","truncated":true}"""), limitations: limitations);
        result["has_more"] = true;
        var details = result["state_details"]!;
        Assert.Equal("history_read", details["stage"]!.GetValue<string>());
        Assert.True(JsonNode.DeepEquals(limitations, details["limitations"]));
        Assert.Equal("result_truncated", details["reason"]!.GetValue<string>()); Assert.Empty(details["source_issues"]!.AsArray());
        result = ReportResult.Create("events.journal", "partial"); result["has_more"] = true;
        Assert.Equal("coverage_incomplete", result["state_details"]!["reason"]!.GetValue<string>());
    }

    [Fact]
    public void MissingSourceDoesNotClaimEventDateAsOutageStart()
    {
        var result = ReportResult.Create("events.journal", "partial", coverage: O("""{"missing_sources":["fixture-source"],"event_at_utc":"2020-01-01T00:00:00Z"}"""));
        EqualJson("""[{"source":"fixture-source","reason":"source_missing","since_utc":null}]""", result["state_details"]!["source_issues"]);
    }

    [Fact]
    public void SourceIssuesKeepConcreteNamesReasonsKnownStartAndDeduplicateMissing()
    {
        var result = ReportResult.Create("events.journal", "partial", coverage: O("""{"domains":[{"domain_id":7,"section_name":"domain_health","run_status":"failed","since_utc":"2026-10-01T00:00:00Z"},{"domain_id":8,"section_name":"domain_posture","run_status":null}],"missing":["8:domain_posture"]}"""));
        EqualJson("""[{"source":"7:domain_health","reason":"source_failed","since_utc":"2026-10-01T00:00:00Z"},{"source":"8:domain_posture","reason":"source_missing","since_utc":null}]""", result["state_details"]!["source_issues"]);
    }

    [Theory][InlineData("unavailable", "source_failed")][InlineData("denied", "access_denied")]
    public void UnavailableSourceHasConcreteNameAndPlainReason(string status, string reason)
    {
        var coverage = O("""{"domains":[{"domain_id":7,"domain_name":"fixture-source","section_name":"domain_health","run_status":"completed"}]}""");
        coverage["domains"]![0]!["section_status"] = status;
        var result = ReportResult.Create("events.journal", "partial", coverage: coverage);
        EqualJson($$"""[{"source":"7:domain_health","source_name":"fixture-source","reason":"{{reason}}","since_utc":null}]""", result["state_details"]!["source_issues"]);
    }

    [Fact]
    public void DomainCoverageIdentifiesMissingDomainAndSource()
    {
        var result = ReportResult.Create("events.journal", "empty", coverage: O("""{"domains":[{"domain_id":7,"run_status":"partial","section_name":"directory_accounts"}]}"""));
        Assert.Equal("partial", State(result)); EqualJson("[7]", result["state_details"]!["missing_domains"]);
        EqualJson("[\"directory_accounts\"]", result["state_details"]!["missing_sources"]);
    }

    [Fact]
    public void EventAgeAloneIsNotStalenessAndFreshnessUsesObservationTime()
    {
        var result = ReportResult.Create("events.journal", "ok", [new JsonObject { ["id"] = 1 }], O("""{"event_at_utc":"2020-01-01T00:00:00Z","freshness_threshold_seconds":60}"""));
        Assert.Equal("ok", State(result)); Assert.Null(result["state_details"]!["stale_since_utc"]);
        var coverage = O("""{"observed_at_utc":"2020-01-01T00:00:00Z","freshness_threshold_seconds":86400}""");
        result = ReportResult.Create("events.journal", "ok", coverage: coverage, now: DateTimeOffset.Parse("2026-10-02T00:00:00Z"));
        Assert.Equal("stale", State(result)); Assert.Equal("2020-01-02T00:00:00+00:00", result["state_details"]!["stale_since_utc"]!.GetValue<string>());
        coverage["state"] = "failed"; Assert.Equal("error", State(ReportResult.Create("events.journal", "ok", coverage: coverage)));
    }

    [Theory]
    [InlineData("not_authorized", "denied")][InlineData("not_collected", "not_collected")]
    [InlineData("empty", "empty")][InlineData("unavailable", "error")][InlineData("empty_unverified", "partial")]
    public void JournalAndProblemQueriesKeepReaderStates(string rawState, string expected)
    {
        var raw = new JsonObject { ["state"] = rawState, ["items"] = new JsonArray(), ["semantic_runtime"] = O("""{"findings_state":"active"}""") };
        Assert.Equal(expected, State(EventsJournalReader.Render(Context("events.journal"), raw, [])));
        var problems = SecurityProblemsReader.Render(Context(), raw);
        Assert.Equal(rawState == "empty" ? "partial" : expected, State(problems));
        if (rawState == "empty")
        {
            Assert.Equal("unavailable", problems["coverage"]!["password_detection"]!["availability"]!.GetValue<string>());
            Assert.Contains(problems["limitations"]!.AsArray(), n => n!["code"]!.GetValue<string>() == "password_coverage_incomplete");
        }
    }

    [Theory]
    [InlineData("unassigned", "report_access_denied")][InlineData("report_denied", "report_access_denied")]
    [InlineData("action_denied", "report_access_denied")][InlineData("missing_security", "report_field_categories_not_allowed")]
    [InlineData("grant_action_denied", "report_field_categories_not_allowed")]
    public async Task SecurityQueueRejectsUnauthorizedCallersBeforeReading(string denial, string reason)
    {
        var context = Context(); var report = context.Access.Reports.Single(); var grant = report.Grants.Single();
        var access = context.Access with { Reports = denial switch
        {
            "unassigned" => [], "report_denied" => [report with { Allowed = false }],
            "action_denied" => [report with { Grants = [grant with { AllowedActions = new HashSet<string>(["export"]) }] }],
            // .NET derives report actions from atomic grants. A separate view grant
            // keeps the report visible without authorizing its security fields.
            "grant_action_denied" => [report with { Grants = [grant with { AllowedActions = new HashSet<string>(["export"]) }, grant with { FieldCategories = new HashSet<string>() }] }],
            _ => [report with { Grants = [grant with { FieldCategories = new HashSet<string>(["identity_basic", "technical", "raw_evidence"]) }] }]
        }};
        var repository = new ProblemEndpointTests.Repository();
        var error = await Assert.ThrowsAsync<ReportRequestException>(() => new SecurityProblemsReader(repository, null!).QueryAsync(context with { Access = access }, TestContext.Current.CancellationToken));
        Assert.Equal(reason, error.Message); Assert.Equal(403, error.Status); Assert.Equal(0, repository.Calls);
    }

    [Fact]
    public void DeniedBoundaryRedactsCoverageAndDerivedStateDetails()
    {
        var projection = new ReportAccess(ReportFixture.Definition(), ReportFixture.Access());
        var denied = projection.Project(ReportResult.Create(ReportFixture.Key, "denied", coverage: O("""{"missing_sources":["private-fixture-marker"]}""")));
        Assert.Equal("denied", State(denied)); Assert.DoesNotContain("private-fixture-marker", denied.ToJsonString());
    }

    [Theory]
    [InlineData("available", false, "{}", "empty")][InlineData("available", true, "{}", "ok")]
    [InlineData("empty", false, "{\"observation_state\":\"available\",\"completeness\":\"unverified\"}", "empty")]
    [InlineData("available", true, "{\"observation_state\":\"available\",\"completeness\":\"unverified\"}", "ok")]
    [InlineData("available", true, "{\"observation_state\":\"partial\"}", "partial")]
    [InlineData("available", false, "{\"observation_state\":\"not_collected\"}", "not_collected")]
    [InlineData("available", false, "{\"observation_state\":\"unavailable\"}", "error")]
    [InlineData("available", false, "{\"completeness\":\"not_proven\"}", "partial")]
    [InlineData("empty_unverified", false, "{}", "partial")]
    public void LogonAdapterPreservesReaderCoverage(string raw, bool hasRows, string json, string expected)
    {
        List<JsonObject> rows = hasRows ? [new() { ["entity_id"] = 1 }] : [];
        var coverage = O(json); var result = AdLogonReports.Result("ad.computer-logons", raw, rows, coverage);
        Assert.Equal(expected, State(result)); Assert.True(JsonNode.DeepEquals(System.Text.Json.JsonSerializer.SerializeToNode(rows), result["items"]));
        Assert.True(JsonNode.DeepEquals(coverage["completeness"], result["coverage"]!["completeness"]));
    }

    [Theory]
    [InlineData("{\"state\":\"available\",\"source_completeness\":\"not_proven\"}", "ok")]
    [InlineData("{\"state\":\"empty_unverified\",\"source_completeness\":\"not_proven\"}", "ok")]
    [InlineData("{\"state\":\"available\",\"source_completeness\":\"not_proven\",\"missing_sources\":[\"fixture-source\"]}", "partial")]
    [InlineData("{\"state\":\"available\",\"completeness\":\"not_proven\"}", "partial")]
    [InlineData("{\"state\":\"partial\"}", "partial")][InlineData("{\"state\":\"processing\"}", "processing")]
    [InlineData("{\"state\":\"unavailable\"}", "error")]
    public async Task SecurityEventsCompletionIsDistinctFromSourceAuditCompleteness(string json, string expected)
    {
        var coverage = O(json);
        var raw = new JsonObject { ["state"] = "available", ["items"] = new JsonArray(new JsonObject { ["event_db_id"] = 7, ["time_created_utc"] = "2026-10-01T01:00:00Z" }), ["collection_coverage"] = coverage };
        var context = SecurityContext(); context.Params["domain"] = 7;
        var result = await new SecurityEventsReader(new EventStore(raw), new SecurityEventDomainOptionsTests.Names(), null!).QueryAsync(context, TestContext.Current.CancellationToken);
        Assert.Equal(expected, State(result)); Assert.Equal(7, result["items"]![0]!["event_db_id"]!.GetValue<int>());
        Assert.True(JsonNode.DeepEquals(coverage["source_completeness"], result["coverage"]!["source_completeness"]));
        Assert.True(JsonNode.DeepEquals(coverage["missing_sources"], result["coverage"]!["missing_sources"]));
    }

    static ReportQueryContext SecurityContext()
    {
        var context = Context("security.events.chains");
        var grant = context.Access.Reports.Single().Grants.Single() with { FieldCategories = new HashSet<string>(["security", "technical", "raw_evidence"]) };
        var access = new AccessDecision("viewer", new(false, new HashSet<string>(["events.view"]), new HashSet<string>(), [], new Dictionary<string, System.Text.Json.JsonElement>()), [new("security.events.chains", true, [grant])]);
        return context with { Access = access };
    }

    sealed class EventStore(JsonObject raw, JsonObject? second = null) : IAdReportStore
    {
        public Task<IReadOnlyList<long>> DomainsAsync(long after, CancellationToken ct) => Task.FromResult<IReadOnlyList<long>>(second is null ? [7] : [7, 8]);
        public Task<bool> HasSourceAsync(string kind, long domain, CancellationToken ct) => throw new InvalidOperationException("unexpected_source_probe");
        public Task<JsonObject> ReadAsync(AdReportRequest request, bool sensitive, CancellationToken ct) => Task.FromResult((JsonObject)(request.Domain == 8 ? second! : raw).DeepClone());
    }

    [Theory][InlineData("unavailable", "error")][InlineData("processing", "processing")][InlineData("not_collected", "partial")]
    public async Task OneDomainCannotHideAnotherDomainsFailureOrPendingCollection(string rawState, string expected)
    {
        var first = O("""{"state":"available","items":[{"event_db_id":7,"time_created_utc":"2026-10-01T01:00:00Z"}],"collection_coverage":{"state":"available","source_completeness":"not_proven"}}""");
        var second = new JsonObject { ["state"] = rawState, ["items"] = new JsonArray() };
        var result = await new SecurityEventsReader(new EventStore(first, second), new SecurityEventDomainOptionsTests.Names(), null!).QueryAsync(SecurityContext(), TestContext.Current.CancellationToken);
        Assert.Equal(expected, State(result)); Assert.Single(result["items"]!.AsArray());
    }

    [Fact]
    public void InactiveFindingsCannotClaimEmptyQueue()
    {
        Assert.Equal("partial", State(SecurityProblemsReader.Render(Context(), O("""{"state":"empty","items":[]}"""))));
    }

    [Theory][InlineData("processing", "processing")][InlineData("not_collected", "not_collected")][InlineData("unavailable", "error")]
    public async Task VpnBranchesAndMissingSnapshotsKeepCollectionStates(string raw, string expected)
    {
        Assert.Equal(expected, State(VpnReports.Branch(new() { ["state"] = raw }, true)));
        var request = new GpoRequest("all", "", null, null, "asc", 100, null, "UTC", DateTimeOffset.Parse("2026-10-01T00:00:00Z"), DateTimeOffset.Parse("2026-10-02T00:00:00Z"));
        var store = new GpoReportTests.Store { Pair = new() { ["state"] = raw, ["current"] = null } };
        Assert.Equal(expected, State(await GpoReport.QueryAsync(store, [7], request, TestContext.Current.CancellationToken)));
        Assert.Equal(expected, AdV2Store.SourceState([new() { ["source_state"] = raw }], 0));
    }

    [Theory][InlineData("available", "error")][InlineData("empty", "error")][InlineData("denied", "denied")]
    public async Task MissingGpoSnapshotCannotClaimSuccess(string raw, string expected)
    {
        var request = new GpoRequest("all", "", null, null, "asc", 100, null, "UTC", DateTimeOffset.Parse("2026-10-01T00:00:00Z"), DateTimeOffset.Parse("2026-10-02T00:00:00Z"));
        var store = new GpoReportTests.Store { Pair = new() { ["state"] = raw, ["current"] = null } };
        Assert.Equal(expected, State(await GpoReport.QueryAsync(store, [7], request, TestContext.Current.CancellationToken)));
    }

    [Theory][InlineData("completed", "empty")][InlineData("partial", "partial")][InlineData("failed", "error")]
    [InlineData("not_collected", "not_collected")][InlineData("processing", "processing")]
    public void ZeroUserRowsRespectSnapshotCollectionStatus(string status, string expected)
    {
        var source = new JsonObject { ["domain_id"] = 7, ["source_state"] = status, ["observed_at_utc"] = DateTimeOffset.UtcNow.ToString("O"),
            ["snapshot"] = new JsonObject { ["users"] = new JsonArray(), ["groups"] = new JsonArray(), ["metadata"] = new JsonObject { ["collection_status"] = status } } };
        var result = AdV2Store.Result("ad.users.v2", AdV2Store.SourceState([source], 0), coverage: AdV2Store.Coverage([source]));
        AdV2Result.Finish(result); Assert.Equal(expected, State(result));
    }
}
