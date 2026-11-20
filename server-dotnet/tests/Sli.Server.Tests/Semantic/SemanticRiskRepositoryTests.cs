using System.Text.Json.Nodes;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticRiskRepositoryTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 19, 6, 0, 0, TimeSpan.Zero);
    private static readonly Guid EventId = Guid.Parse("00000000-0000-0000-0000-000000000001");

    private static JsonObject Factors(bool strong) => new()
    {
        ["identity_resolution"] = strong ? "exact" : "unresolved",
        ["state_confirmed"] = strong, ["multi_source_confirmed"] = strong,
        ["sequence_completeness"] = strong ? 100 : 10,
        ["time_quality"] = strong ? "good" : "poor", ["parser_quality"] = strong ? "good" : "poor"
    };

    private static SemanticProposal Proposal() => new(
        new SemanticPolicy("policy", 1, "correlation_candidate", new(), new string('2', 64),
            "authentication.privileged_session", "authentication.privileged_session", "security_incident",
            ["session_principal"], 1800, "Privileged session", "Exact session correlation", "high", 50m, 50,
            false, "Exact candidate", 1, [], null),
        "00000000-0000-0000-0000-000000000010", Now, "dc-1",
        new() { ["session_principal"] = "dc-1:0xabc" }, Factors(true), [EventId], [], []);

    [Theory]
    [InlineData("dc-1", true, null)]
    [InlineData("dc-2", true, "scenario_partition_does_not_match_correlation_candidate")]
    [InlineData("dc-1", false, "scenario_evidence_not_linked_to_source")]
    public async Task Candidate_source_requires_exact_partition_and_linked_evidence(string partition, bool linked, string? error)
    {
        var proposal = Proposal() with { Partition = partition };
        var session = new RepositorySession(proposal) { Linked = linked };
        if (error is null)
        {
            var scenario = await SemanticProduction.PersistProposal(session, proposal, TestContext.Current.CancellationToken);
            Assert.Equal(session.ScenarioId.ToString(), scenario.Text("scenario_id"));
            Assert.True(session.Refreshed);
        }
        else
        {
            var failure = await Assert.ThrowsAsync<InvalidDataException>(() =>
                SemanticProduction.PersistProposal(session, proposal, TestContext.Current.CancellationToken));
            Assert.Equal(error, failure.Message);
            Assert.False(session.Wrote);
        }
    }

    [Fact]
    public async Task Contribution_replay_conflict_is_fail_closed()
    {
        var proposal = Proposal();
        var session = new RepositorySession(proposal) { Replay = true, DisplayPointsDelta = 1 };
        var failure = await Assert.ThrowsAsync<InvalidDataException>(() =>
            SemanticProduction.PersistProposal(session, proposal, TestContext.Current.CancellationToken));
        Assert.Equal("risk_contribution_replay_conflict", failure.Message);
        Assert.False(session.Wrote);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Durable_refresh_keeps_the_weakest_step_confidence(bool weakFirst)
    {
        var proposal = Proposal();
        var weak = Factors(false);
        var session = new RepositorySession(proposal)
        {
            DurableFactors = weakFirst ? [weak.DeepClone(), Factors(true)] : [Factors(true), weak.DeepClone()],
            Coverage = "complete"
        };
        var scenario = await SemanticProduction.PersistProposal(session, proposal, TestContext.Current.CancellationToken);
        Assert.True(JsonNode.DeepEquals(weak, scenario["confidence_factors_json"]));
        Assert.Equal(7L, scenario.Number("confidence_score"));
        Assert.Equal("low", scenario.Text("confidence"));
        Assert.Equal("complete", scenario.Text("coverage_status"));
        Assert.Equal("high", scenario.Text("risk_class"));
        Assert.Equal(50m, scenario["raw_score"]!.GetValue<decimal>());
    }

    [Fact]
    public async Task Durable_refresh_rejects_a_scenario_without_steps()
    {
        var proposal = Proposal();
        var session = new RepositorySession(proposal) { DurableFactors = [] };
        var failure = await Assert.ThrowsAsync<InvalidDataException>(() =>
            SemanticProduction.PersistProposal(session, proposal, TestContext.Current.CancellationToken));
        Assert.Equal("semantic_scenario_no_durable_step", failure.Message);
        Assert.False(session.Refreshed);
    }

    private sealed class RepositorySession(SemanticProposal proposal) : ISemanticSession
    {
        internal readonly Guid ScenarioId = Guid.Parse("00000000-0000-0000-0000-000000000020");
        internal bool Linked = true, Replay, Wrote, Refreshed;
        internal int DisplayPointsDelta;
        internal string Coverage = "unknown";
        internal JsonArray? DurableFactors;
        private JsonObject? refreshed;

        private JsonObject Scenario => refreshed ?? new()
        {
            ["scenario_id"] = ScenarioId.ToString(), ["identity_key"] = proposal.Identity,
            ["scenario_kind"] = proposal.Policy.Kind, ["result_class"] = proposal.Policy.Result,
            ["partition_key"] = proposal.Partition, ["strict_keys_json"] = proposal.Strict.DeepClone(),
            ["merge_window_seconds"] = proposal.Policy.Window,
            ["first_seen_utc"] = SemanticJson.Stamp(Now), ["last_seen_utc"] = SemanticJson.Stamp(Now)
        };
        private JsonObject Contribution => new()
        {
            ["contribution_id"] = AuthAudit.Uuid5("adlog:risk-contribution:" + proposal.Contribution).ToString(),
            ["scenario_id"] = ScenarioId.ToString(), ["source_kind"] = "correlation_candidate",
            ["correlation_candidate_id"] = proposal.SourceId, ["policy_id"] = "policy", ["policy_version"] = 1,
            ["policy_sha256"] = new string('2', 64), ["risk_class"] = "high", ["raw_score"] = 50m,
            ["display_points"] = 50 + DisplayPointsDelta, ["hard_critical"] = false, ["rationale"] = "Exact candidate"
        };
        private static JsonArray Rows(JsonObject row) => new(row.DeepClone());

        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            JsonArray rows = [];
            if (sql.Contains("from semantic_correlation_candidates", StringComparison.Ordinal))
            {
                Assert.Equal(Guid.Parse(proposal.SourceId), values[0]);
                rows = Rows(new() { ["candidate_status"] = "matched", ["partition_key"] = "dc-1",
                    ["window_start_utc"] = SemanticJson.Stamp(Now), ["window_end_utc"] = SemanticJson.Stamp(Now) });
            }
            else if (sql.Contains("from semantic_correlation_candidate_evidence", StringComparison.Ordinal))
            {
                Assert.Equal(Guid.Parse(proposal.SourceId), values[0]);
                if (Linked) rows = Rows(new() { ["normalized_event_id"] = EventId.ToString() });
            }
            else if (sql.StartsWith("select * from semantic_risk_contributions", StringComparison.Ordinal))
            {
                if (Replay || Wrote) rows = Rows(Contribution);
            }
            else if (sql.StartsWith("select * from semantic_security_scenarios", StringComparison.Ordinal)) rows = Rows(Scenario);
            else if (sql == SemanticRiskSql.persist_step1)
                rows = Rows(new() { ["step_id"] = AuthAudit.Uuid5("adlog:scenario-step:" + proposal.Step).ToString(),
                    ["scenario_id"] = ScenarioId.ToString(), ["source_kind"] = proposal.Policy.Source,
                    ["occurred_at_utc"] = SemanticJson.Stamp(proposal.At), ["title"] = proposal.Policy.Title,
                    ["explanation"] = proposal.Policy.Explanation, ["confidence_factors_json"] = proposal.Factors.DeepClone() });
            else if (sql == SemanticRiskSql.refresh_scenario0) rows = Rows(Contribution);
            else if (sql == SemanticRiskSql.refresh_scenario1)
                foreach (var factors in DurableFactors ?? new JsonArray(proposal.Factors.DeepClone()))
                    rows.Add(new JsonObject { ["confidence_factors_json"] = factors!.DeepClone() });
            else if (sql == SemanticRiskSql.refresh_scenario2)
                rows = Rows(new() { ["coverage_status"] = Coverage, ["control_id"] = "synthetic", ["observed_at_utc"] = SemanticJson.Stamp(Now) });
            else if (sql == SemanticRiskSql.refresh_scenario3)
                rows = Rows(new() { ["first_seen_utc"] = SemanticJson.Stamp(Now), ["last_seen_utc"] = SemanticJson.Stamp(Now),
                    ["step_count"] = DurableFactors?.Count ?? 1, ["evidence_count"] = 1, ["expected_evidence_count"] = 1, ["contribution_count"] = 1 });
            else if (sql == SemanticRiskSql.refresh_scenario4)
            {
                refreshed = (JsonObject)Scenario.DeepClone();
                refreshed["risk_class"] = (string)values[2]!; refreshed["raw_score"] = (decimal)values[3]!;
                refreshed["confidence"] = (string)values[6]!; refreshed["confidence_score"] = (int)values[7]!;
                refreshed["confidence_factors_json"] = ((JsonObject)values[8]!).DeepClone();
                refreshed["coverage_status"] = (string)values[9]!;
                Refreshed = true;
            }
            else if (sql.TrimStart().StartsWith("insert into ", StringComparison.Ordinal)) Wrote = true;
            else if (sql.Contains("to_regclass(", StringComparison.Ordinal)) rows = Rows(new() { ["available"] = false });
            else if (!sql.Contains("pg_advisory_xact_lock(", StringComparison.Ordinal))
                throw new InvalidOperationException("Unexpected SQL: " + sql);
            return Task.FromResult(rows);
        }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("caller_owns_transaction");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
