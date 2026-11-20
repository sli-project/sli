using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public class SemanticIdentityConfidenceTests
{
    private const string Sid = "sid:S-1-5-21-100000001-200000002-300000003-1001";

    private static JsonObject Evidence(string role, string? value, string? state = null, string? metadataKey = null)
    {
        var quality = new JsonObject();
        if (state is not null) quality["identity_roles"] = new JsonObject
        {
            [role] = new JsonObject { ["key"] = metadataKey ?? value, ["state"] = state }
        };
        return new() { ["roles_json"] = new JsonObject { [role] = value }, ["quality_json"] = quality };
    }

    [Fact]
    public void Candidate_identity_confidence_uses_weakest_ladder_state()
    {
        Assert.Equal("partial", SemanticProduction.CandidateIdentityResolution(
            [Evidence("affected_entity", Sid, "resolved"), Evidence("affected_entity", "sam:example.test:alice", "provisional")], ["affected_entity"]));
    }

    [Fact]
    public void Candidate_identity_confidence_fails_closed_without_metadata()
    {
        Assert.Equal("unknown", SemanticProduction.CandidateIdentityResolution([Evidence("actor", "name:operator")], ["actor"]));
        Assert.Equal("unresolved", SemanticProduction.CandidateIdentityResolution([Evidence("actor", "name:operator", "unresolved")], ["actor"]));
    }

    [Fact]
    public void Candidate_session_scope_is_intrinsically_exact()
    {
        Assert.Equal("exact", SemanticProduction.CandidateIdentityResolution([Evidence("session_principal", "1:0xabc")], ["session_principal"]));
    }

    [Fact]
    public void Candidate_identity_metadata_must_match_strict_role()
    {
        var error = Assert.Throws<InvalidDataException>(() => SemanticProduction.CandidateIdentityResolution(
            [Evidence("actor", Sid, "resolved", "sid:S-1-5-21-100000001-200000002-300000003-1002")], ["actor"]));
        Assert.Equal("semantic_identity_metadata_conflict", error.Message);
    }

    [Theory]
    [InlineData("actor", null, "resolved", "unresolved")]
    [InlineData("session_principal", "", null, "unresolved")]
    [InlineData("session_principal", "  ", null, "unresolved")]
    [InlineData("actor", "  name:operator  ", " resolved ", "exact")]
    [InlineData("actor", "name:operator", "external", "exact")]
    [InlineData("actor", "name:operator", "unrecognized", "unknown")]
    public void Missing_roles_and_metadata_states_match_source(string role, string? value, string? state, string expected)
    {
        Assert.Equal(expected, SemanticProduction.CandidateIdentityResolution([Evidence(role, value, state, value?.Trim())], [role]));
    }

    [Fact]
    public void No_identity_observations_are_unknown_and_unknown_is_weaker_than_partial()
    {
        Assert.Equal("unknown", SemanticProduction.CandidateIdentityResolution([], ["actor"]));
        Assert.Equal("unknown", SemanticProduction.CandidateIdentityResolution([Evidence("actor", Sid, "resolved")], []));
        Assert.Equal("unknown", SemanticProduction.CandidateIdentityResolution(
            [Evidence("actor", Sid, "provisional"), Evidence("actor", Sid)], ["actor"]));
        Assert.Equal("unresolved", SemanticProduction.CandidateIdentityResolution(
            [Evidence("actor", Sid), Evidence("actor", Sid, "unresolved")], ["actor"]));
    }

    private sealed class ProposalSession(string source, JsonArray evidence) : ISemanticSession
    {
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            if (sql.Contains("join normalized_events")) return Task.FromResult((JsonArray)evidence.DeepClone());
            string table = source == "canonical_action" ? "canonical_actions" : "semantic_correlation_candidates";
            Assert.StartsWith($"select * from {table} where ", sql);
            return Task.FromResult(new JsonArray(new JsonObject
            {
                ["action_kind"] = "synthetic", ["relation_kind"] = "synthetic",
                ["action_status"] = "observed", ["candidate_status"] = "matched",
                ["partition_key"] = "dc.example.test", ["confidence"] = "high",
                ["occurred_at_utc"] = "2026-01-01T00:00:00Z", ["window_end_utc"] = "2026-01-01T00:00:00Z"
            }));
        }
        public Task CommitAsync(CancellationToken ct) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    [Theory]
    [InlineData("canonical_action")]
    [InlineData("correlation_candidate")]
    public async Task Proposal_uses_weakest_evidence_identity_for_both_source_kinds(string source)
    {
        var evidence = new JsonArray(Evidence("actor", Sid, "resolved"), Evidence("actor", Sid, "provisional"));
        for (int i = 0; i < evidence.Count; i++)
        {
            evidence[i]!["normalized_event_id"] = new Guid(i + 1, 0, 0, new byte[8]).ToString();
            evidence[i]!["roles_json"]!["source_host"] = "dc.example.test";
            evidence[i]!["quality_json"]!["event_data_encoding"] = "named";
        }
        var policy = new SemanticPolicy("synthetic", 1, source, new(), new string('a', 64), "synthetic", "synthetic", "security_incident", ["actor"], 300,
            "Synthetic", "Synthetic", "medium", 25m, 25, false, "Synthetic", 1, [], null);
        await using var session = new ProposalSession(source, evidence);
        var proposal = await SemanticProduction.Proposal(session, policy, "00000000-0000-0000-0000-000000000003", "shadow", TestContext.Current.CancellationToken);
        Assert.Equal("partial", proposal.Factors["identity_resolution"]!.GetValue<string>());
        Assert.Equal(Sid, proposal.Strict["actor"]!.GetValue<string>());
        Assert.Equal(2, proposal.Evidence.Length);
    }
}
