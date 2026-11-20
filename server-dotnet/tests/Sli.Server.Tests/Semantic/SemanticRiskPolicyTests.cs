using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticRiskPolicyTests
{
    private const string SourceId = "00000000-0000-0000-0000-000000000010";
    private static readonly DateTimeOffset Observed = DateTimeOffset.Parse("2026-07-19T00:00:00Z");

    // Vectors from tests/semantic/test_semantic_risk_policy1.py.
    private static JsonObject Definition() => JsonNode.Parse("""
        {
          "type":"scenario_policy",
          "source_selector":{"relation_kind":"authentication.session.has_special_privileges"},
          "scenario_kind":"authentication.privileged_session",
          "result_class":"security_incident",
          "strict_roles":["session_principal"],
          "merge_window_seconds":1800,
          "title":"Privileged session requires review",
          "explanation":"Exact host and session identity matched",
          "expected_evidence_count":2,
          "required_controls":["security-audit-logon"],
          "risk":{"class":"critical","raw_score":"80.5","display_points":90,
                  "hard_critical":true,"rationale":"Privileged session policy matched"}
        }
        """)!.AsObject();

    private static SemanticPolicy Compile(JsonObject definition, string source = "correlation_candidate", string id = "privileged-session-risk") =>
        SemanticPolicy.Compile(new JsonObject { ["policy_id"] = id, ["policy_version"] = 1, ["source_kind"] = source, ["definition_json"] = definition });

    private static SemanticPolicy ControlPolicy()
    {
        var definition = Definition();
        definition["source_selector"] = new JsonObject { ["control_id"] = "security-audit-logon" };
        definition["result_class"] = "control_gap";
        definition["strict_roles"] = new JsonArray();
        return Compile(definition, "control_health", "audit-gap");
    }

    [Fact]
    public void Policy_compiles_to_bounded_semantic_contract()
    {
        var policy = Compile(Definition());
        Assert.Equal("security_incident", policy.Result);
        Assert.Equal("critical", policy.Risk);
        Assert.Equal(80.5m, policy.Raw);
        Assert.Equal(new[] { "session_principal" }, policy.Roles);
        Assert.Equal(new[] { "security-audit-logon" }, policy.Controls);
        Assert.Null(policy.Lateness);
        Assert.Equal("authentication.session.has_special_privileges", policy.Selector);
        Assert.Equal(1800, policy.Window);
        Assert.Equal(2, policy.Expected);
        Assert.Equal(90, policy.Points);
        Assert.True(policy.Hard);
    }

    [Fact]
    public void Policy_rejects_executable_code_and_missing_strict_identity()
    {
        var malicious = Definition();
        malicious["python"] = "print('unsafe')";
        Assert.Equal("forbidden_semantic_dsl_field", Assert.Throws<InvalidDataException>(() => Compile(malicious, id: "unsafe")).Message);
        var missing = Definition();
        missing["strict_roles"] = new JsonArray();
        Assert.Equal("risk_policy_roles_invalid", Assert.Throws<InvalidDataException>(() => Compile(missing, id: "missing-key")).Message);
    }

    [Fact]
    public void Control_health_policy_has_explicit_control_gap_class()
    {
        var policy = ControlPolicy();
        Assert.Equal("control_gap", policy.Result);
        Assert.Equal("security-audit-logon", policy.Selector);
        Assert.Empty(policy.Roles);
    }

    [Fact]
    public void Canonical_action_policy_uses_declared_action_kind()
    {
        var definition = Definition();
        definition["source_selector"] = new JsonObject { ["action_kind"] = "eventlog.cleared" };
        definition["scenario_kind"] = "security.audit_log_cleared";
        definition["strict_roles"] = new JsonArray("source_host");
        definition["expected_evidence_count"] = 1;
        var policy = Compile(definition, "canonical_action", "audit-log-cleared");
        Assert.Equal("eventlog.cleared", policy.Selector);
        Assert.Equal(new[] { "source_host" }, policy.Roles);
    }

    [Fact]
    public void Canonical_action_policy_rejects_noncanonical_strict_role()
    {
        var definition = Definition();
        definition["source_selector"] = new JsonObject { ["action_kind"] = "eventlog.cleared" };
        definition["strict_roles"] = new JsonArray("windows_event_record");
        Assert.Equal("risk_policy_roles_invalid", Assert.Throws<InvalidDataException>(() => Compile(definition, "canonical_action", "invalid-action-role")).Message);
    }

    private sealed class ObservationSession(bool missing = false, bool wrongControl = false) : ISemanticSession
    {
        internal int Calls;
        internal JsonObject? Observation { get; set; } = missing ? null : new()
        {
            ["observation_id"] = SourceId, ["control_id"] = wrongControl ? "different-control" : "security-audit-logon",
            ["partition_key"] = "1", ["coverage_status"] = "unavailable",
            ["reason"] = "Synthetic audit coverage gap", ["observed_at_utc"] = SemanticJson.Stamp(Observed)
        };

        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            string statement = string.Join(' ', sql.ToLowerInvariant().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
            Assert.StartsWith("select ", statement);
            Assert.Contains("from semantic_control_health_observations where observation_id=$1", statement);
            Assert.DoesNotContain("for share", statement);
            Assert.DoesNotContain("for update", statement);
            Assert.Equal(Guid.Parse(SourceId), Assert.IsType<Guid>(Assert.Single(values)));
            Calls++;
            return Task.FromResult(Observation is null ? new JsonArray() : new JsonArray(Observation.DeepClone()));
        }

        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("caller_owns_transaction");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task Control_health_proposal_and_evidence_use_select_privileges(bool missing, bool wrongControl)
    {
        var session = new ObservationSession(missing, wrongControl);
        var ct = TestContext.Current.CancellationToken;
        if (missing || wrongControl)
        {
            var error = await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.Proposal(session, ControlPolicy(), SourceId, "shadow", ct));
            Assert.Equal("semantic_control_selector_mismatch", error.Message);
            Assert.Equal(1, session.Calls);
            return;
        }
        var proposal = await SemanticProduction.Proposal(session, ControlPolicy(), SourceId, "shadow", ct);
        await SemanticProduction.VerifyControlHealthEvidence(session, proposal, ct);
        Assert.Equal(2, session.Calls);
        Assert.Empty(proposal.Evidence);
        Assert.Empty(proposal.Native);
        var coverage = Assert.Single(proposal.Coverage)!;
        Assert.Equal(Observed, SigmaProjection.At(coverage, "observed_at_utc"));
        Assert.Equal(Observed, proposal.At);
        Assert.Equal("1", proposal.Partition);
        Assert.Equal("security-audit-logon", proposal.Strict.Text("control_id"));
    }

    [Theory]
    [InlineData("missing", "semantic_control_source_not_found")]
    [InlineData("partition", "semantic_control_partition_mismatch")]
    [InlineData("time", "semantic_control_time_mismatch")]
    [InlineData("control", "semantic_control_coverage_mismatch")]
    [InlineData("status", "semantic_control_coverage_mismatch")]
    [InlineData("reason", "semantic_control_coverage_mismatch")]
    [InlineData("event", "semantic_control_event_evidence_forbidden")]
    public async Task Persistence_rejects_control_health_evidence_conflicts_before_writes(string conflict, string expected)
    {
        var session = new ObservationSession();
        var ct = TestContext.Current.CancellationToken;
        var proposal = await SemanticProduction.Proposal(session, ControlPolicy(), SourceId, "shadow", ct);
        switch (conflict)
        {
            case "missing": session.Observation = null; break;
            case "partition": session.Observation!["partition_key"] = "2"; break;
            case "time": session.Observation!["observed_at_utc"] = SemanticJson.Stamp(Observed.AddSeconds(1)); break;
            case "control": session.Observation!["control_id"] = "different-control"; break;
            case "status": session.Observation!["coverage_status"] = "complete"; break;
            case "reason": session.Observation!["reason"] = "Different synthetic reason"; break;
            case "event": proposal = proposal with { Evidence = [Guid.Parse("11111111-1111-1111-1111-111111111111")] }; break;
        }
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => SemanticProduction.PersistProposal(session, proposal, ct));
        Assert.Equal(expected, error.Message);
        Assert.Equal(conflict == "event" ? 1 : 2, session.Calls);
    }
}
