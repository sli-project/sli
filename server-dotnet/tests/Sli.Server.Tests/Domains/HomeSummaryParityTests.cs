using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Domains;
using Xunit;

namespace Sli.Server.Tests.Domains;

// Vectors from tests/reporting/test_home_summary.py. Keep the real projection and
// authorization; replace only the external report/domain reads.
public sealed partial class HomeSummaryEndpointTests
{
    private sealed class SummaryDomains(bool populated = true) : IDomainRepository
    {
        public Task<IReadOnlyList<DomainItem>> ReadAsync(DomainGrant grant, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<DomainItem>>(new long[] { 7, 8 }
                .Where(id => populated && (grant.Kind == DomainGrantKind.All || grant.Kind == DomainGrantKind.Scoped && grant.DomainIds.Contains(id)))
                .Select(id => new DomainItem(id, $"domain-{id}.example.test", false,
                    new DomainFreshness(null, null, "partial", $"2026-10-0{id - 6}T00:00:00Z", null, null, null))).ToArray());
    }

    private static async Task<JsonObject> Summary(string query, HomeReport[] reports, bool populated = true)
    {
        var context = new DefaultHttpContext(); context.Request.QueryString = new QueryString(query);
        var payload = await new HomeSummaryService(new Reports(reports), new SummaryDomains(populated), new HomeSummaryReaders(new Rows()))
            .BuildAsync(new Principal("session", 1, "viewer"), HomeSummaryQuery.Parse(context.Request.Query, Now), TestContext.Current.CancellationToken);
        return JsonNode.Parse(payload.ToJsonString())!.AsObject();
    }

    private static HomeReport Synthetic(string key, Func<long[], HomeSummaryQuery, JsonObject> read, long[]? ids = null) =>
        Report(key, ids: ids) with { Reader = (_, domains, query, _) => Task.FromResult(read(domains, query)) };

    private static JsonObject Data(string state = "partial", long? attention = 4, string? observed = "2026-10-01T00:00:00Z") =>
        new() { ["state"] = state, ["coverage"] = new JsonObject { ["observed_at_utc"] = observed },
            ["metrics"] = attention.HasValue ? new JsonArray(new JsonObject { ["key"] = "attention", ["label"] = "Attention", ["value"] = attention.Value, ["tone"] = "warning" }) : new JsonArray(),
            ["items"] = new JsonArray() };

    private static JsonObject Problem(int id, string severity = "high", int repeat = 0, string? at = "2026-10-07T01:00:00Z", string status = "confirmed") =>
        new() { ["id"] = id, ["rule_code"] = "synthetic.rule", ["title"] = "Synthetic problem", ["summary"] = "Synthetic activity", ["why_it_matters"] = "Synthetic reason",
            ["recommended_action"] = "Review synthetic object", ["target"] = "synthetic-object", ["status"] = status,
            ["severity"] = severity, ["repeat_count"] = repeat, ["last_seen_utc"] = at };

    [Fact] public async Task V1SummaryBoundsQueueAndPreservesReaderScopeWithoutReadingOtherReports()
    {
        var calls = new List<(long[] Ids, string Contract)>();
        var reports = new[] { "security.problems", "ad.infrastructure", "ad.computers.v6" }.Select(key => Synthetic(key, (ids, query) =>
        {
            calls.Add((ids, query.Contract)); var data = Data();
            data["items"] = new JsonArray(Enumerable.Range(0, 7).Select(i => (JsonNode)Problem(i, status: "new")).ToArray()); return data;
        })).Append(Synthetic("vpn.connections", (_, _) => throw new InvalidOperationException("must not read"))).ToArray();
        var body = await Summary("", reports);
        Assert.Equal("sli.home-summary.v1", (string?)body["contract_id"]);
        Assert.Equal(3, body["freshness"]!.AsArray().Count); Assert.Equal(3, body["deviations"]!.AsArray().Count);
        Assert.Equal(4, body["reports"]!.AsArray().Count);
        Assert.Equal(5, body["action_queue"]!["items"]!.AsArray().Count); Assert.True((bool?)body["action_queue"]!["has_more"]);
        Assert.EndsWith("?status=new&severity=high", (string?)body["action_queue"]!["items"]![0]!["href"]);
        Assert.Equal(3, calls.Count); Assert.All(calls, c => Assert.Equal(new long[] { 7 }, c.Ids));
    }

    [Theory] [InlineData("v1")] [InlineData("v2")]
    public async Task SummaryPreservesDistinctClocksAndSourceExplanations(string version)
    {
        var details = JsonNode.Parse("""{"reason":"coverage_incomplete","source_issues":[{"source":"7:domain_health","reason":"source_failed","since_utc":null}]}""")!;
        var report = Synthetic("ad.infrastructure", (_, _) =>
        {
            var data = Data(observed: null);
            data["coverage"] = JsonNode.Parse("""{"event_at_utc":"2026-09-01T00:00:00Z","snapshot_at_utc":"2026-09-02T00:00:00Z","published_at_utc":"2026-10-07T00:00:00Z","last_successful_collection_utc":"2026-10-06T00:00:00Z"}""");
            data["state_details"] = details.DeepClone(); data["limitations"] = JsonNode.Parse("""[{"code":"coverage","text":"Synthetic source is incomplete."}]"""); return data;
        });
        var body = await Summary("?contract=" + version, [report]); var fresh = body["freshness"]![0]!;
        Assert.Equal("2026-09-01T00:00:00Z", (string?)fresh["event_at_utc"]);
        Assert.Equal("2026-09-02T00:00:00Z", (string?)fresh["snapshot_at_utc"]);
        Assert.Equal("2026-10-07T00:00:00Z", (string?)fresh["published_at_utc"]); Assert.Null(fresh["observed_at_utc"]);
        Assert.Equal("2026-10-06T00:00:00Z", (string?)fresh["last_successful_check_utc"]);
        Assert.Equal("coverage_incomplete", (string?)fresh["reason"]); Assert.True(JsonNode.DeepEquals(details, fresh["state_details"]));
        Assert.Equal("Synthetic source is incomplete.", (string?)fresh["limitation"]);
        if (version == "v2")
        {
            var reader = body["readers"]![0]!; Assert.All(fresh.AsObject(), p => Assert.True(JsonNode.DeepEquals(p.Value, reader[p.Key])));
            Assert.Equal("snapshot", (string?)reader["period_kind"]); Assert.Equal("home.state.partial", (string?)reader["message_code"]);
        }
    }

    [Theory] [InlineData("v1", false)] [InlineData("v1", true)] [InlineData("v2", false)] [InlineData("v2", true)]
    public async Task RequiredDomainNeverAutoSelectsAuthorizedOptions(string version, bool multiple)
    {
        var called = 0;
        var report = Synthetic("ad.infrastructure", (ids, query) =>
        {
            called++; Assert.NotNull(query.Domain); Assert.Equal(new[] { query.Domain.Value }, ids); return Data();
        }, multiple ? [7, 8] : [7]) with { RequiresDomain = true };
        var body = await Summary("?contract=" + version, [report]);
        Assert.Equal("domain_required", (string?)body["freshness"]![0]!["reason"]);
        // Multi-domain breakdowns have explicit per-domain selections; the aggregate must not pick one.
        Assert.Equal(multiple ? 2 : 0, called);
        await Summary("?contract=" + version + "&scope=domain&domain=7", [report]); Assert.Equal(multiple ? 3 : 1, called);
    }

    [Fact] public async Task HiddenMetricsAndUnexecutableReadersCannotContribute()
    {
        var calls = 0;
        var report = Synthetic("ad.infrastructure", (_, _) => { calls++; return Data(); }) with
        { MetricCategories = new Dictionary<string, IReadOnlySet<string>> { ["attention"] = new HashSet<string> { "secret_category" } } };
        var body = await Summary("", [report]); Assert.Empty(body["deviations"]!.AsArray()); Assert.Single(body["reports"]!.AsArray());
        report = report with { Decision = report.Decision with { Grants = report.Decision.Grants.Select(g => g with { AllowedActions = new HashSet<string>() }).ToArray() } };
        body = await Summary("", [report]); Assert.Equal("denied", (string?)body["freshness"]![0]!["state"]); Assert.Equal(1, calls);
    }

    [Theory] [InlineData("v1")] [InlineData("v2")]
    public async Task TimeoutDegradesOnlyAffectedReaderAndDoesNotInventZero(string version)
    {
        var healthy = 0;
        var broken = Synthetic("security.problems", (_, _) => throw new TimeoutException("private source"));
        var body = await Summary("?contract=" + version, [broken, Synthetic("ad.infrastructure", (_, _) => { healthy++; return Data(); })]);
        Assert.Equal("read_timeout", (string?)body["freshness"]![0]!["reason"]); Assert.Equal("partial", (string?)body["freshness"]![1]!["state"]);
        Assert.Equal(1, healthy); Assert.Equal("error", (string?)body["action_queue"]!["state"]); Assert.Empty(body["action_queue"]!["items"]!.AsArray());
        Assert.DoesNotContain("private source", body.ToJsonString());
        if (version == "v2") Assert.Null(body["problems_found"]!["count"]);
    }

    [Theory] [InlineData("empty")] [InlineData("partial")] [InlineData("stale")] [InlineData("processing")]
    [InlineData("not_collected")] [InlineData("error")] [InlineData("denied")]
    public async Task StatesWithoutAttentionMetricNeverInventSafeZero(string state)
    {
        var body = await Summary("?contract=v2", [Synthetic("security.problems", (_, _) => Data(state, null, null))]);
        Assert.Equal(state, (string?)body["problems_found"]!["state"]); Assert.Null(body["problems_found"]!["count"]);
        Assert.Equal("home.problems.unknown", (string?)body["problems_found"]!["message_code"]); Assert.NotEqual("ok", (string?)body["observation_health"]!["state"]);
    }

    [Fact] public async Task AttentionOrdersSeverityRepetitionTimeAndNumericIdentityAndUsesExactLinks()
    {
        var problems = Synthetic("security.problems", (_, _) =>
        {
            var data = Data("ok", 6); data["items"] = new JsonArray(Problem(1, "low"), Problem(2), Problem(3, "critical", at: "2026-10-01T01:00:00Z"),
                Problem(4, repeat: 3, at: "2026-10-01T01:00:00Z"), Problem(5, "medium"), Problem(6, repeat: 3, at: "2026-10-01T01:00:00+00:00")); return data;
        });
        var body = await Summary("?contract=v2&scope=domain&domain=7", [problems, Synthetic("ad.infrastructure", (_, _) => Data("stale"))]);
        Assert.Equal(new[] { "problem:3", "problem:6", "problem:4", "problem:2", "observation:ad.infrastructure" }, body["action_queue"]!["items"]!.AsArray().Select(i => (string?)i!["id"]));
        Assert.True((bool?)body["action_queue"]!["has_more"]); var item = body["action_queue"]!["items"]![0]!;
        Assert.Equal("synthetic-object", (string?)item["object"]); Assert.All(new[] { "what", "why", "next_step" }, key => Assert.False(string.IsNullOrEmpty((string?)item[key])));
        Assert.Equal("2026-10-01T01:00:00Z", (string?)item["observed_at_utc"]);
        Assert.Equal("/app/report/security.problems?tz=UTC&domain=7&id=3", (string?)item["href"]);
        Assert.Equal(6, (int?)body["problems_found"]!["count"]);
        Assert.Equal("/app/report/security.problems?tz=UTC&domain=7&population=attention", (string?)body["problems_found"]!["href"]);
    }

    [Fact] public async Task NonDecisionProblemsAreExcludedAndOtherDecisionsPrecedeFailedAdChecks()
    {
        var problems = Synthetic("security.problems", (_, _) => { var d = Data("ok"); d["items"] = new JsonArray(Problem(9, "low", at: "2026-10-01T00:00:00Z", status: "new"),
            Problem(1, "low", at: "2026-10-02T00:00:00Z", status: "new"), Problem(10, "critical", status: "active")); return d; });
        var checks = Synthetic("ad.infrastructure", (_, _) => { var d = Data("ok"); d["items"] = JsonNode.Parse("""[{"row_id":"7:check","qualification":"failed","label":"Synthetic check"},{"row_id":"7:passed","qualification":"passed"}]"""); return d; });
        var body = await Summary("?contract=v2", [problems, checks]);
        Assert.Equal(new[] { "problem:1", "problem:9", "ad-check:7:check" }, body["action_queue"]!["items"]!.AsArray().Select(i => (string?)i!["id"]));
        Assert.EndsWith("row_id=7%3Acheck", (string?)body["action_queue"]!["items"]![2]!["href"]);
    }

    [Fact] public async Task InactiveAnalysisWithZeroProblemsStillExplainsObservationBreak()
    {
        var body = await Summary("?contract=v2", [Synthetic("security.problems", (_, _) => { var d = Data(attention: 0); d["coverage"]!["state"] = "inactive"; return d; })]);
        Assert.Equal(0, (int?)body["problems_found"]!["count"]); Assert.Equal("partial", (string?)body["observation_health"]!["state"]);
        Assert.Equal(1, (int?)body["action_queue"]!["items"]![0]!["priority_group"]);
        Assert.Equal("home.attention.analysis_unconfirmed", (string?)body["action_queue"]!["items"]![0]!["message_code"]);
    }

    [Theory] [InlineData("v1", null)] [InlineData("v1", "7")] [InlineData("v1", "8")]
    [InlineData("v2", null)] [InlineData("v2", "7")] [InlineData("v2", "8")]
    public async Task EachReaderKeepsItsOwnRightsInAggregateAndDomainBreakdown(string version, string? selected)
    {
        var restricted = new List<long[]>();
        var general = Synthetic("ad.infrastructure", (ids, _) => Data(attention: ids.Sum(), observed: "[" + string.Join(", ", ids) + "]"), [7, 8]) with
        { Contributions = [new HomeContribution("synthetic", "attention", "home.kpi.privileged_changes", "home.unit.events")] };
        var report = Synthetic("ad.computers.v6", (ids, _) => { restricted.Add(ids); return Data(); });
        var body = await Summary("?contract=" + version + (selected is null ? "" : "&domain_id=" + selected), [general, report]);
        Assert.Equal(selected is null ? 15 : int.Parse(selected), (int?)body["metrics"]![0]!["items"]![0]!["value"]);
        Assert.Equal(selected is null ? new long[] { 7, 8 } : [long.Parse(selected)], body["domain_scope"]!["domain_ids"]!.AsArray().Select(n => (long)n!));
        foreach (var domain in body["domains"]!.AsArray())
        {
            var id = (int)domain!["id"]!; var summary = domain["summary"]!;
            Assert.Equal(id, (int?)summary["metrics"]![0]!["items"]![0]!["value"]); Assert.Equal($"[{id}]", (string?)summary["freshness"]![0]!["observed_at_utc"]);
            Assert.Equal($"2026-10-0{id - 6}T00:00:00Z", (string?)domain["freshness"]!["observed_at_utc"]);
            Assert.Equal(id == 7 ? "partial" : "denied", (string?)summary["metrics"]![1]!["state"]);
            if (version == "v2") Assert.Equal(id, (int?)summary["kpis"]![0]!["value"]);
        }
        Assert.All(restricted, ids => Assert.Equal(new long[] { 7 }, ids));
        if (selected is null && version == "v2")
        {
            Assert.Equal("accessible", (string?)body["context"]!["scope"]); Assert.Null(body["context"]!["domain_id"]); Assert.Null(body["context"]!["view"]);
            Assert.Equal("UTC", (string?)body["context"]!["time_zone"]); Assert.Equal("snapshot", (string?)body["context"]!["period"]!["kind"]);
            Assert.Equal(new long[] { 7, 8 }, body["readers"]![0]!["scope"]!["domain_ids"]!.AsArray().Select(n => (long)n!));
        }
    }

    [Theory] [InlineData("v1", "8")] [InlineData("v1", "9")] [InlineData("v2", "8")] [InlineData("v2", "9")]
    public async Task ForeignOrUnknownDomainIsRejectedBeforeAnyReader(string version, string selected)
    {
        var calls = 0; var report = Synthetic("ad.infrastructure", (_, _) => { calls++; return Data(); });
        var error = await Assert.ThrowsAsync<HomeQueryException>(() => Summary("?contract=" + version + "&domain_id=" + selected, [report]));
        Assert.Equal("domain_scope_denied", error.Message); Assert.Equal(403, error.Status); Assert.Equal(0, calls);
    }

    [Fact] public async Task NoDomainsOrNoDefinitionsNeverReadsUnscopedCounts()
    {
        var calls = 0; var report = Synthetic("ad.infrastructure", (_, _) => { calls++; return Data(); });
        var body = await Summary("?contract=v2", [report], false); Assert.Equal(0, calls);
        Assert.Empty(body["domains"]!.AsArray()); Assert.Equal("no_domains", (string?)body["domain_scope"]!["state"]); Assert.Equal("denied", (string?)body["metrics"]![0]!["state"]);
        body = await Summary("?contract=v2", []); Assert.All(new[] { "freshness", "reports", "deviations", "kpis" }, key => Assert.Empty(body[key]!.AsArray()));
    }

    [Theory] [InlineData("?domain_id=")] [InlineData("?domain_id=7&domain_id=8")] [InlineData("?domain_id=7&domain=7")]
    [InlineData("?domain_id=7&scope=domain")] [InlineData("?contract=v2&view=analyst")] [InlineData("?contract=v2&scope=domain&domain=7&domain=8")]
    [InlineData("?contract=v2&domain=7")]
    public async Task InvalidOrConflictingSelectionIsRejectedAtEndpoint(string query)
    {
        var rows = new Rows(); var (status, _) = await Request(query, rows); Assert.Equal(400, status); Assert.Empty(rows.Calls);
    }

    [Fact] public async Task ObservationPeriodLinksAndReaderReceiveTheSameExactWindow()
    {
        HomeSummaryQuery? received = null;
        var body = await Summary("?contract=v2&period=custom&from=2026-10-01&to=2026-10-01&tz=Asia/Bangkok",
            [Synthetic("security.problems", (_, q) => { received = q; return Data("empty"); }), Synthetic("ad.infrastructure", (_, _) => Data("empty"))]);
        Assert.Equal("2026-09-30T17:00:00Z", (string?)body["context"]!["period"]!["from_utc"]);
        Assert.Equal("2026-10-01T17:00:00Z", (string?)body["context"]!["period"]!["to_utc"]);
        Assert.Equal(DateTimeOffset.Parse("2026-09-30T17:00:00Z"), received!.Period!.From);
        Assert.Contains("time_from=2026-09-30T17%3A00%3A00Z&time_to=2026-10-01T17%3A00%3A00Z", (string?)body["problems_found"]!["href"]);
        Assert.Equal(new[] { "observations", "snapshot" }, body["readers"]!.AsArray().Take(2).Select(r => (string?)r!["period_kind"]));
    }

    private static HomeReport Plugin(HomeContribution contribution) => Report("synthetic.plugin") with { Contributions = [contribution] };
    private static HomeContribution Contribution(Func<long[], HomeSummaryQuery, JsonObject> read) => new("synthetic", "events", "home.kpi.privileged_changes", "home.unit.events")
        { PeriodKind = "observations", Reader = (_, ids, query, _) => Task.FromResult(read(ids, query)) };

    [Fact] public async Task RegisteredContributionUsesScopedCompletedWindowsAndPreservesZeroBaseline()
    {
        long[]? received = null; HomeSummaryQuery? receivedQuery = null;
        var report = Plugin(Contribution((ids, query) =>
        {
            received = ids; receivedQuery = query; var d = Data("ok", null);
            d["metrics"] = JsonNode.Parse("""[{"key":"events","value":4,"previous_value":0}]""");
            d["coverage"] = JsonNode.Parse("""{"complete":true,"sources":[7]}"""); d["previous_coverage"] = d["coverage"]!.DeepClone(); return d;
        }));
        var body = await Summary("?contract=v2", [report]); var kpi = body["kpis"]![0]!;
        Assert.Equal(4, (int?)kpi["value"]); Assert.Equal(4, (int?)kpi["comparison"]!["absolute_change"]); Assert.Null(kpi["comparison"]!["percent_change"]);
        Assert.Equal(new long[] { 7 }, received); Assert.Equal("observations", (string?)body["readers"]![0]!["period_kind"]);
        Assert.Contains(Uri.EscapeDataString(HomeWindow.Iso(receivedQuery!.Current.To)), (string?)kpi["href"]);
        Assert.Equal("synthetic.plugin", (string?)body["reports"]![0]!["key"]);
    }

    [Fact] public async Task DisabledOrFieldDeniedContributionsExplainWithoutCallingReader()
    {
        var calls = 0; var entry = Contribution((_, _) => { calls++; return Data(); }) with { Availability = () => "disabled" };
        var body = await Summary("?contract=v2", [Plugin(entry)]); var kpi = body["kpis"]![0]!;
        Assert.Null(kpi["value"]); Assert.Equal("home.plugin.disabled", (string?)kpi["message_code"]); Assert.Equal(0, calls);
        entry = entry with { Availability = null, RequiredFields = new HashSet<string> { "privilege" } };
        var restricted = Plugin(entry) with { Decision = Report("synthetic.plugin", ["identity_basic", "security", "technical"]).Decision };
        body = await Summary("?contract=v2", [restricted]); Assert.Equal("denied", (string?)body["kpis"]![0]!["state"]); Assert.Equal(0, calls);
    }

    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task ContributionAttentionAndHealthAreProjectedAndHookFailurePreservesKpi(bool failHook)
    {
        var candidate = JsonNode.Parse("""{"id":"synthetic:1","kind":"observation","priority_group":1,"severity":null,"needs_decision":false,"repeat_count":0,"observed_at_utc":null,"message_code":"home.attention.processing","href":"/app/report/synthetic.plugin"}""")!.AsObject();
        var entry = Contribution((_, _) => { var d = Data(); d["metrics"] = JsonNode.Parse("""[{"key":"events","value":2}]"""); return d; }) with
        { Attention = (_, _) => failHook ? throw new InvalidOperationException("private hook") : [candidate.DeepClone().AsObject()] };
        var body = await Summary("?contract=v2", [Plugin(entry)]); Assert.Equal(2, (int?)body["kpis"]![0]!["value"]);
        Assert.Equal("partial", (string?)body["observation_health"]!["state"]);
        if (failHook) Assert.Empty(body["action_queue"]!["items"]!.AsArray());
        else Assert.True(JsonNode.DeepEquals(candidate, body["action_queue"]!["items"]![0]));
        Assert.DoesNotContain("private hook", body.ToJsonString());
    }

    [Fact] public async Task DomainSwitcherCountsAndHealthRemainIndependentAndErrorsRemainUnknown()
    {
        var report = Synthetic("security.problems", (ids, _) => Data(ids.Contains(8) ? "partial" : "empty", ids.Contains(7) ? 12 : 0), [7, 8]);
        var body = await Summary("?contract=v2", [report]); Assert.Equal(12, (int?)body["problems_found"]!["count"]);
        Assert.Equal(new[] { 12, 0 }, body["domains"]!.AsArray().Select(d => (int)d!["summary"]!["problems_found"]!["count"]!));
        Assert.Equal(new[] { "ok", "partial" }, body["domains"]!.AsArray().Select(d => (string?)d!["summary"]!["observation_health"]!["state"]));
        report = Synthetic("security.problems", (_, _) => Data("error", null), [7, 8]);
        body = await Summary("?contract=v2", [report]); Assert.Null(body["problems_found"]!["count"]);
        Assert.All(body["domains"]!.AsArray(), d => Assert.Null(d!["summary"]!["problems_found"]!["count"]));
    }

    [Fact] public async Task PinnedAccessAliasUsesPublicReportRouteAndNeverIncludesDeniedPins()
    {
        var report = Report("security.problems") with { Definition = JsonSerializer.SerializeToElement(new { name = "Synthetic report", target_path = "/reports/old.html" }) };
        var denied = Report("hidden.report") with { Decision = new ReportDecision("hidden.report", false, []) };
        var body = await Summary("", [report, denied]); var pin = Assert.Single(body["pinned"]!.AsArray())!;
        Assert.Equal("security.problems", (string?)pin["key"]); Assert.Equal("/app/report/security.problems", (string?)pin["href"]);
    }

    [Fact] public void AdReaderFiltersExactControlFromAnEntityWithMultipleControls()
    {
        var entity = JsonNode.Parse("""{"entity_id":7,"domain_id":7,"domain_name":"example.test","entity_type":"domain","display_name":"example.test","source_section":"domain_posture","observed_at_utc":"2026-10-01T00:00:00Z","record":"{\"attributes\":{\"ldap_signing_requirement\":\"not_required\",\"ldap_channel_binding_requirement\":\"always\"}}"}""")!.AsObject();
        var rows = Sli.Server.Ad.AdInfrastructure.Compose([entity], new JsonObject { ["row_id"] = "7:domain.ldap_signing" });
        var row = Assert.Single(rows); Assert.Equal("7:domain.ldap_signing", (string?)row["row_id"]); Assert.Equal("failed", (string?)row["qualification"]);
    }
}
