using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Problems;
using Sli.Server.Reporting.V2;
using Sli.Server.Tests.Problems;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed partial class PasswordCoverageReportTests
{
    internal const string Stamp = "2026-10-20T00:00:00.000000Z";
    internal static ReportQueryContext Context(long[]? domains = null, bool restricted = false)
    {
        var facts = ProblemEndpointTests.Facts();
        var access = new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts));
        if (restricted) access = access with { Reports = access.Reports.Select(r => r with {
            Grants = r.Grants.Select(g => g with { Scope = JsonSerializer.SerializeToElement(new { kind = "domain", ids = new[] { 7 } }) }).ToArray()
        }).ToArray() };
        return new(new ReportDefinitionRegistry().Get("security.problems")!, access, new("session", 7, "admin"),
            new(), new(null, 50, "UTC", null, "asc", "table"), ReportScope.All, domains, "view", _ => true, []);
    }
    internal static JsonObject Row() => new() {
        ["domain_id"] = "7", ["rule_id"] = "qw.password-brute-force", ["scope_ref"] = new string('a', 64),
        ["policy_state"] = "enabled", ["status"] = "partial", ["reason"] = "recent_loss",
        ["last_attempt_at"] = Stamp, ["last_completed_at"] = Stamp, ["last_successful_cutoff"] = Stamp,
        ["loss"] = new JsonObject(), ["frozen_episode_count"] = "0", ["evidence_snapshot_as_of"] = null
    };
    internal static JsonObject Raw(JsonArray rows, string state = "empty") => new() {
        ["state"] = state, ["items"] = new JsonArray(), ["semantic_runtime"] = new JsonObject { ["findings_state"] = "active" },
        ["password_detection_coverage"] = new JsonObject { ["availability"] = "observed", ["as_of"] = Stamp, ["rows"] = rows, ["has_more"] = false }
    };
    [Theory]
    [InlineData("error")][InlineData("stale")][InlineData("denied")]
    public void CoveragePreservesExistingStateAndIsOmittedForDenied(string state)
    {
        var result = SecurityProblemsReader.Render(Context([7]), Raw([], state));
        Assert.Equal(state, result["state"]!.ToString());
        if (state == "denied") Assert.Null(result["coverage"]!["password_detection"]);
    }
    [Fact]
    public void RestrictedProjectionIntersectsSelectedDomainsBeforeRepositoryRead()
        => Assert.Equal(new long[] { 7 }, SecurityProblemsReader.Input(Context([7, 999], true)).Domains);
    [Theory]
    [InlineData("partial")][InlineData("error")][InlineData("stale")][InlineData("unknown")][InlineData("frozen")]
    [InlineData(null)]
    public void MissingOrUnhealthyCoverageCannotProveAnEmptyQueue(string? status)
    {
        var row = Row(); row["status"] = status;
        var raw = Raw(status is null ? [] : new JsonArray(row));
        var result = SecurityProblemsReader.Render(Context([7]), raw);
        Assert.Equal("partial", result["state"]!.ToString());
        Assert.Contains(result["limitations"]!.AsArray(), l => l!["code"]!.ToString() == "password_coverage_incomplete");
        Assert.True(JsonNode.DeepEquals(raw["password_detection_coverage"], result["coverage"]!["password_detection"]));
    }
    [Theory]
    [InlineData("disabled", "empty")][InlineData("disabled_last_known", "partial")][InlineData("unknown", "partial")]
    public void CurrentDisableIsDistinctFromUnconfirmedPolicy(string policy, string expected)
    {
        var row = Row(); row["policy_state"] = policy;
        var result = SecurityProblemsReader.Render(Context([7]), Raw(new(row)));
        Assert.Equal(expected, result["state"]!.ToString());
        Assert.Equal(policy, result["coverage"]!["password_detection"]!["rows"]![0]!["policy_state"]!.ToString());
    }
    [Fact]
    public void EmptyScopeOmitsCoverageAndTruncatedHealthyPageIsPartial()
    {
        Assert.Null(SecurityProblemsReader.Render(Context([]), Raw(new(Row())))["coverage"]!["password_detection"]);
        var row = Row(); row["status"] = "healthy"; row["reason"] = null;
        var raw = Raw(new(row)); raw["password_detection_coverage"]!["has_more"] = true;
        Assert.Equal("partial", SecurityProblemsReader.Render(Context([7]), raw)["state"]!.ToString());
    }
}
