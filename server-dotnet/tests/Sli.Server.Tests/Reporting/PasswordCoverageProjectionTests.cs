using System.Net;
using System.Text.Json.Nodes;
using Sli.Server.Infrastructure;
using Sli.Server.Problems;
using Sli.Server.Reporting.V2;
using Sli.Server.Tests.Problems;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed partial class PasswordCoverageReportTests
{
    static JsonObject SqlPage()
    {
        var row = Row(); row["domain_id"] = 7; row["frozen_episode_count"] = 0;
        row["status"] = "healthy"; row["reason"] = null;
        return new() { ["as_of"] = Stamp, ["rows"] = new JsonArray(row), ["has_more"] = false };
    }
    static JsonObject Summary() => new() {
        ["count_lower_bound"] = 9007199254740993L, ["count_exact"] = false,
        ["from"] = "2026-10-18T00:00:00Z", ["to"] = "2026-10-19T20:00:00Z",
        ["observation_window_from"] = "2026-10-19T01:00:00Z", ["as_of"] = Stamp
    };
    static JsonObject Project(JsonObject page) => ProblemRepository.ProjectPasswordCoverage(page, new HashSet<long> { 7 });
    static void AssertUnavailable(JsonObject result)
        => Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"availability":"unavailable","as_of":null,"rows":[],"has_more":false}"""), result), result.ToJsonString());
    [Fact]
    public void BigintLossEnclosureAndFrozenSnapshotArePreservedWithoutMutatingObservation()
    {
        var page = SqlPage(); var row = page["rows"]![0]!;
        row["loss"]!["too_late"] = Summary(); row["frozen_episode_count"] = 2;
        row["evidence_snapshot_as_of"] = "2026-10-19T00:00:00Z";
        var before = page.DeepClone(); var result = Project(page); var item = Assert.Single(result["rows"]!.AsArray())!;
        Assert.Equal("observed", result["availability"]!.ToString());
        Assert.Equal("7", item["domain_id"]!.GetValue<string>()); Assert.Equal("frozen", item["status"]!.ToString());
        Assert.Equal("2", item["frozen_episode_count"]!.GetValue<string>());
        Assert.Equal("2026-10-19T00:00:00Z", item["evidence_snapshot_as_of"]!.ToString());
        var summary = Summary(); summary["count_lower_bound"] = "9007199254740993";
        Assert.True(JsonNode.DeepEquals(summary, item["loss"]!["too_late"])); Assert.True(JsonNode.DeepEquals(before, page));
    }
    [Theory]
    [InlineData("2026-10-19T23:55:00Z", "stale", "attempt_stale")]
    [InlineData("2026-10-19T23:55:00.000001Z", "healthy", null)]
    [InlineData(null, "unknown", "checkpoint_absent")]
    public void OnlyCompletedAttemptsRefreshHealthAtTheExactTtlBoundary(string? completed, string status, string? reason)
    {
        var page = SqlPage(); page["rows"]![0]!["last_completed_at"] = completed;
        var row = Project(page)["rows"]![0]!;
        Assert.Equal(status, row["status"]!.ToString()); Assert.Equal(reason, row["reason"]?.ToString());
    }
    [Theory]
    [InlineData("foreign_domain")][InlineData("private_key")][InlineData("over256")][InlineData("unknown_reason")]
    [InlineData("bad_count")][InlineData("future_time")][InlineData("duplicate")][InlineData("bad_loss")]
    public void MalformedOrUnauthorizedPagesFailClosedWithoutEchoingPrivateData(string bad)
    {
        var page = SqlPage(); var row = page["rows"]![0]!;
        switch (bad) {
            case "foreign_domain": row["domain_id"] = 999; break;
            case "private_key": row["source_xml"] = "<private-secret/>"; break;
            case "over256": page["rows"] = new JsonArray(Enumerable.Range(0, 257).Select(_ => row.DeepClone()).ToArray()); break;
            case "unknown_reason": row["reason"] = "private-secret"; break;
            case "bad_count": row["frozen_episode_count"] = 0.5; break;
            case "future_time": row["last_completed_at"] = "2027-01-01T00:00:00Z"; break;
            case "duplicate": page["rows"]!.AsArray().Add(row.DeepClone()); break;
            case "bad_loss": row["loss"] = new JsonObject { ["private-secret"] = new JsonObject() }; break;
        }
        AssertUnavailable(Project(page));
    }
    static readonly string[] SemanticLossCodes = ["missing_target", "unclassified_failure", "ambiguous_failure", "conflicting_client", "missing_client"];
    public static IEnumerable<object[]> SemanticLossVectors() => SemanticLossCodes.SelectMany(code => new[] { "loss", "reason", "both" }.Select(placement => new object[] { code, placement }));
    [Theory][MemberData(nameof(SemanticLossVectors))]
    public void ApprovedSemanticLossKeepsExactCountsAndProducesPartialReport(string code, string placement)
    {
        var page = SqlPage(); var row = page["rows"]![0]!;
        if (placement != "loss") { row["reason"] = code; row["status"] = "partial"; }
        if (placement != "reason") row["loss"]![code] = Summary();
        var before = page.DeepClone(); var coverage = Project(page); var item = coverage["rows"]![0]!;
        Assert.Equal("observed", coverage["availability"]!.ToString()); Assert.Equal("partial", item["status"]!.ToString());
        Assert.Equal(placement == "loss" ? "recent_loss" : code, item["reason"]!.ToString());
        if (placement == "reason") Assert.Empty(item["loss"]!.AsObject());
        else { var expected = Summary(); expected["count_lower_bound"] = "9007199254740993"; Assert.True(JsonNode.DeepEquals(expected, item["loss"]![code])); }
        Assert.Null(item["loss"]!["xml_invalid"]); Assert.True(JsonNode.DeepEquals(before, page));
        var raw = Raw([]); raw["password_detection_coverage"] = coverage.DeepClone();
        var result = SecurityProblemsReader.Render(Context([7]), raw);
        Assert.Equal("partial", result["state"]!.ToString()); Assert.Empty(result["items"]!.AsArray());
        Assert.True(JsonNode.DeepEquals(coverage, result["coverage"]!["password_detection"]));
    }
    [Theory]
    [InlineData("future_event", "loss")][InlineData("future_event", "reason")]
    [InlineData("outside_horizon", "loss")][InlineData("outside_horizon", "reason")]
    [InlineData("private-unapproved-code", "loss")][InlineData("private-unapproved-code", "reason")]
    public void UnapprovedLossOrReasonCodesFailClosed(string code, string placement)
    {
        var page = SqlPage(); var row = page["rows"]![0]!;
        if (placement == "loss") row["loss"]![code] = Summary(); else row["reason"] = code;
        AssertUnavailable(Project(page));
    }
    public static IEnumerable<object[]> InvalidSummaryVectors() => SemanticLossCodes.SelectMany(code => new[] { "string_count", "extra_private_field" }.Select(bad => new object[] { code, bad }));
    [Theory][MemberData(nameof(InvalidSummaryVectors))]
    public void ApprovedCodesDoNotRelaxExactSummaryShape(string code, string bad)
    {
        var page = SqlPage(); var summary = Summary();
        if (bad == "string_count") summary["count_lower_bound"] = "1"; else summary["source_xml"] = "<private-not-exportable/>";
        page["rows"]![0]!["reason"] = code; page["rows"]![0]!["loss"]![code] = summary;
        AssertUnavailable(Project(page));
    }
    [Theory]
    [InlineData("ru", "empty", 0, "empty")][InlineData("en", "empty", 0, "empty")]
    [InlineData("ru", "ok", 0, "ok")][InlineData("en", "ok", 0, "ok")]
    [InlineData("ru", "empty", 2, "partial")][InlineData("en", "empty", 2, "partial")]
    [InlineData("ru", "ok", 2, "partial")][InlineData("en", "ok", 2, "partial")]
    public async Task CurrentDisablePreservesFrozenCoverageAndLocalizedWarnings(string locale, string state, int frozen, string expected)
    {
        var page = SqlPage(); var row = page["rows"]![0]!; row["policy_state"] = "disabled"; row["frozen_episode_count"] = frozen;
        row["evidence_snapshot_as_of"] = frozen == 0 ? null : "2026-10-18T00:00:00Z";
        var coverage = Project(page); var before = coverage.DeepClone(); var raw = Raw([], state);
        if (state == "ok") raw["items"] = new JsonArray(new JsonObject { ["id"] = 7, ["status"] = "new" });
        raw["password_detection_coverage"] = coverage;
        var reader = new ReportFixture.Reader { OwnerId = "sli.core", ReportKey = "security.problems", Query = c => SecurityProblemsReader.Render(c, raw) };
        await using var host = await ReportFixture.Start(ProblemEndpointTests.Facts(), new ReportDefinitionRegistry().Get("security.problems")!, suppliedReader: reader);
        host.Client.DefaultRequestHeaders.AcceptLanguage.ParseAdd(locale);
        using var response = await host.Client.GetAsync("/api/v2/reports/security.problems/data", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); var result = await ReportFixture.Body(response);
        Assert.Equal(expected, result["state"]!.ToString()); Assert.Equal(state == "ok" ? 1 : 0, result["items"]!.AsArray().Count);
        Assert.True(JsonNode.DeepEquals(before, result["coverage"]!["password_detection"]));
        var warnings = result["limitations"]!.AsArray().Where(l => l!["code"]!.ToString() == "password_coverage_incomplete").ToArray();
        if (frozen == 0) Assert.Empty(warnings);
        else Assert.Contains(locale == "ru" ? "не доказывает" : "does not prove", Assert.Single(warnings)!["text"]!.ToString());
        Assert.True(JsonNode.DeepEquals(before, coverage));
    }
    [Theory][InlineData("ru")][InlineData("en")]
    public async Task MissingCoverageWarningNeverClaimsAbsenceProof(string locale)
    {
        var reader = new ReportFixture.Reader { OwnerId = "sli.core", ReportKey = "security.problems", Query = c => SecurityProblemsReader.Render(c, Raw([])) };
        await using var host = await ReportFixture.Start(ProblemEndpointTests.Facts(), new ReportDefinitionRegistry().Get("security.problems")!, suppliedReader: reader);
        host.Client.DefaultRequestHeaders.AcceptLanguage.ParseAdd(locale);
        using var response = await host.Client.GetAsync("/api/v2/reports/security.problems/data", TestContext.Current.CancellationToken);
        var result = await ReportFixture.Body(response);
        var warning = Assert.Single(result["limitations"]!.AsArray(), l => l!["code"]!.ToString() == "password_coverage_incomplete");
        Assert.Contains(locale == "ru" ? "не доказывает" : "does not prove", warning!["text"]!.ToString());
    }
    sealed class NoDatabase : IPostgresConnectionFactory
    {
        public int Calls;
        public Task<Npgsql.NpgsqlConnection> OpenAsync(CancellationToken ct) { Calls++; throw new InvalidOperationException("unexpected_read"); }
    }
    [Fact]
    public async Task DeniedCoreFieldsNeverReadFindingsOrCatalog()
    {
        var c = Context([7]);
        c = c with { Access = c.Access with { Reports = c.Access.Reports.Select(r => r with { Grants = r.Grants.Select(g => g with { FieldCategories = new HashSet<string> { "technical" } }).ToArray() }).ToArray() } };
        var connections = new NoDatabase(); var reader = new SecurityProblemsReader(new ProblemRepository(connections, TimeProvider.System), new NoEvidence());
        var error = await Assert.ThrowsAsync<ReportRequestException>(() => reader.QueryAsync(c, TestContext.Current.CancellationToken));
        Assert.Equal(403, error.Status); Assert.Equal(0, connections.Calls);
    }
    sealed class NoEvidence : ISecurityProblemEvidence
    {
        public Task<JsonObject> PageAsync(ReportQueryContext c, long id, JsonObject? cursor, CancellationToken ct) => throw new InvalidOperationException("unexpected_evidence");
    }
    [Fact]
    public async Task NullInvalidAndEmptyDomainsNeverQueryCoverage()
    {
        var connections = new NoDatabase(); var repository = new ProblemRepository(connections, TimeProvider.System); var ct = TestContext.Current.CancellationToken;
        await Assert.ThrowsAsync<ArgumentNullException>(() => repository.ReadPasswordCoverageAsync(null!, ct));
        await Assert.ThrowsAsync<ArgumentException>(() => repository.ReadPasswordCoverageAsync([0], ct));
        Assert.Null(await repository.ReadPasswordCoverageAsync([], ct)); Assert.Equal(0, connections.Calls);
    }
}
