using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Input/output vectors from tests/semantic/test_decision_chain.py.
public sealed class DecisionChainTests
{
    static readonly Guid ScenarioId = Guid.Parse("00000000-0000-0000-0000-000000000001");
    static readonly Guid JobId = Guid.Parse("00000000-0000-0000-0000-000000000002");
    static readonly string Sha = new('a', 64);
    static readonly SemanticPolicy Policy = new("test-policy", 1, "canonical_action", new(), Sha, "test", "test.kind", "security_incident",
        [], 300, "Test observation", "Deterministic policy qualification", "high", 50m, 50, false, "Test rationale", 1, [], null);
    static readonly SemanticProposal Proposal = new(Policy, "test-source", DateTimeOffset.Parse("2026-10-07T00:00:00Z"), "test", new(), new(), [], [], []);
    static JsonObject Scenario() => new()
    {
        ["scenario_id"] = ScenarioId.ToString(), ["scenario_key"] = "74657374", ["strict_keys_json"] = new JsonObject(),
        ["scenario_kind"] = "test.kind", ["title"] = "Test observation", ["risk_class"] = "high", ["confidence_score"] = 80,
        ["explanation"] = "Deterministic policy qualification", ["first_seen_utc"] = "2026-10-07T00:00:00Z", ["last_seen_utc"] = "2026-10-07T00:00:00Z"
    };
    static JsonObject Contribution() => new() { ["admitted"] = true, ["lifecycle_status"] = "shadow", ["policy_sha256"] = Sha, ["definition_sha256"] = Sha };

    sealed class PublicationSession : ISemanticSession
    {
        internal bool? Admitted = true;
        internal string RuleCode = "semantic.test.kind";
        internal int EvidenceCount = 1;
        internal readonly JsonArray Contributions = new(Contribution());
        internal readonly List<(string Sql, object?[] Args)> Calls = [];
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            Calls.Add((sql, values));
            JsonArray rows = [];
            if (sql == SemanticRiskSql.publish_enabled_scenario_finding0)
            {
                Assert.Contains("join semantic_policy_admission", sql); Assert.Contains("admission.enabled is true", sql);
                Assert.Contains("for share of policy", sql); Assert.DoesNotContain("for share of policy,admission", sql);
                rows.Add(new JsonObject { ["evaluation_mode"] = "enabled", ["conclusion_state"] = "observed", ["scenario_id"] = ScenarioId.ToString(), ["policy_admitted"] = Admitted });
            }
            else if (sql == SemanticRiskSql.publish_enabled_scenario_finding3) Assert.Contains("for share of policy", sql);
            else if (sql == SemanticRiskSql.publish_enabled_scenario_finding4) { Assert.Contains("for share of policy", sql); rows = (JsonArray)Contributions.DeepClone(); }
            else if (sql == SemanticRiskSql.publish_enabled_scenario_finding7) rows.Add(new JsonObject { ["id"] = 1 });
            else if (sql == SemanticRiskSql.publish_enabled_scenario_finding8) rows.Add(new JsonObject { ["id"] = 1, ["rule_code"] = RuleCode });
            else if (sql == SemanticRiskSql.publish_enabled_scenario_finding9) rows.Add(new JsonObject { ["event_id"] = 1 });
            else if (sql == SemanticRiskSql.publish_enabled_scenario_finding11) rows.Add(new JsonObject { ["count"] = EvidenceCount, ["max_event_id"] = 1 });
            else if (sql == SemanticRiskSql.publish_enabled_scenario_finding14) rows.Add(new JsonObject { ["finding_id"] = 1, ["finding_fingerprint"] = "semantic:74657374" });
            else if (sql.Contains("to_regclass(")) rows.Add(new JsonObject { ["available"] = false });
            else if (!(sql.Contains("pg_advisory_xact_lock(") || sql.StartsWith("select s.source_kind,d.document_json", StringComparison.Ordinal) ||
                new[] { SemanticRiskSql.publish_enabled_scenario_finding12, SemanticRiskSql.publish_enabled_scenario_finding13, SemanticRiskSql.publish_enabled_scenario_finding15 }.Contains(sql)))
                throw new InvalidOperationException("Unexpected publication query: " + sql);
            return Task.FromResult(rows);
        }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("Caller owns the transaction");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    [Theory] [InlineData(null)] [InlineData(false)]
    public async Task Enabled_lifecycle_requires_explicit_admission(bool? admitted)
    {
        var session = new PublicationSession { Admitted = admitted };
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticProduction.PublishFinding(session, Proposal, Scenario(), JobId, TestContext.Current.CancellationToken));
        Assert.Equal("finding_requires_enabled_observed_result", error.Message); Assert.Single(session.Calls);
    }

    [Theory]
    [InlineData("admitted", "null")] [InlineData("admitted", "false")]
    [InlineData("lifecycle_status", "\"test\"")] [InlineData("lifecycle_status", "\"disabled\"")]
    [InlineData("policy_sha256", "\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"")]
    public async Task Every_contributing_policy_must_be_admitted_and_unchanged(string field, string json)
    {
        var session = new PublicationSession(); var bad = Contribution(); bad[field] = JsonNode.Parse(json); session.Contributions.Add(bad);
        await RejectContributions(session);
    }
    [Fact] public async Task Missing_contributions_cannot_supply_risk()
    { var session = new PublicationSession(); session.Contributions.Clear(); await RejectContributions(session); }

    [Theory] [InlineData(null)] [InlineData("")]
    public async Task Two_missing_hashes_do_not_prove_an_immutable_policy(string? hash)
    {
        var session = new PublicationSession(); session.Contributions[0]!["policy_sha256"] = hash; session.Contributions[0]!["definition_sha256"] = hash;
        await RejectContributions(session);
    }
    static async Task RejectContributions(PublicationSession session)
    {
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => SemanticProduction.PublishFinding(session, Proposal, Scenario(), JobId, TestContext.Current.CancellationToken));
        Assert.Equal("finding_contributions_not_admitted", error.Message);
        Assert.DoesNotContain(session.Calls, call => call.Sql == SemanticRiskSql.publish_enabled_scenario_finding7);
    }
    [Theory] [InlineData("shadow")] [InlineData("enabled")]
    public async Task Admitted_deterministic_policy_publishes_high_risk_and_exact_evidence(string lifecycle)
    {
        var session = new PublicationSession(); session.Contributions[0]!["lifecycle_status"] = lifecycle;
        Assert.True(await SemanticProduction.PublishFinding(session, Proposal, Scenario(), JobId, TestContext.Current.CancellationToken));
        var insert = Assert.Single(session.Calls, call => call.Sql == SemanticRiskSql.publish_enabled_scenario_finding7);
        Assert.Equal("high", insert.Args[3]);
        var update = Assert.Single(session.Calls, call => call.Sql == SemanticRiskSql.publish_enabled_scenario_finding12);
        Assert.Equal(1, update.Args[11]); Assert.Equal(1L, update.Args[12]);
        Assert.Contains(session.Calls, call => call.Sql == SemanticRiskSql.publish_enabled_scenario_finding9 && call.Args.SequenceEqual(new object?[] { 1L, ScenarioId }));
    }

    [Fact]
    public async Task Agent_stop_counter_uses_retained_unique_evidence_and_is_stable_on_replay()
    {
        var scenario = Scenario(); scenario["scenario_kind"] = "qw.agent-tamper";
        var proposal = Proposal with { Policy = Policy with { Kind = "qw.agent-tamper" } };
        var session = new PublicationSession { RuleCode = "semantic.qw.agent-tamper", EvidenceCount = 3 };
        await SemanticProduction.PublishFinding(session, proposal, scenario, JobId, TestContext.Current.CancellationToken);
        await SemanticProduction.PublishFinding(session, proposal, scenario, JobId, TestContext.Current.CancellationToken);
        var updates = session.Calls.Where(call => call.Sql == SemanticRiskSql.publish_enabled_scenario_finding12).ToArray();
        Assert.Equal(2, updates.Length);
        foreach (var update in updates) { Assert.Equal(3, update.Args[11]); Assert.Equal(2, update.Args[14]); }
    }
}
