using System.Text.Json.Nodes;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Vpn;

public sealed class RadiusSessionReconciliationTests
{
    const string Observation = "11111111-1111-1111-1111-111111111111";
    const string Evidence = "22222222-2222-2222-2222-222222222222";
    static readonly string Session = "radius-session:" + new string('a', 64);
    static readonly string Corpus = new('b', 64);
    static readonly string Input = new('c', 64);
    static RadiusUnresolvedCandidate Candidate() => new(Observation, Evidence, "identity_unresolved");
    static RadiusExactResolutionProposal Proposal() => new(Observation, Session, "entity:101", Input);
    static Dictionary<string, RadiusExactResolutionProposal> Proposals() => new() { [Observation] = Proposal() };
    static JsonObject Original() => new()
    {
        ["observation_id"] = Observation,
        ["lifecycle_event"] = "start",
        ["identity_state"] = "unresolved",
        ["timestamp_state"] = "ready",
        ["session_identity_key"] = null,
        ["exact_principal_key"] = null,
        ["observed_at_utc"] = "2026-08-02T00:00:00Z",
        // The .NET fold reads the evidence hash under this manifest column name.
        ["canonical_record_sha256"] = new string('e', 64)
    };

    [Fact]
    public void Attempt_is_stable_and_retries_only_on_new_boundary()
    {
        var first = Assert.Single(RadiusSessionReconciliation.BuildAttempts([Candidate()], Proposals(), Corpus, "resolver-v1"));
        Assert.Equal("projected", first.Outcome);
        Assert.Equal("285412ee7ff67aaba25f69d281cea0c3f7f1480cacae5a96dd14eb6e4f9cdc57", first.AttemptKey);
        Assert.Equal(Observation, first.ObservationId);
        Assert.Equal(Evidence, first.EvidenceUid);
        Assert.Equal(Corpus, first.EvidenceCorpusSha256);
        Assert.Equal("resolver-v1", first.ResolverContractId);
        Assert.Equal(Input, first.ResolutionInputSha256);
        Assert.Equal(first, Assert.Single(RadiusSessionReconciliation.BuildAttempts([Candidate()], Proposals(), Corpus, "resolver-v1")));
        Assert.Empty(RadiusSessionReconciliation.BuildAttempts([Candidate()], Proposals(), Corpus, "resolver-v1", [first.AttemptKey]));
        // A proposal alone must not change the retry boundary.
        Assert.Empty(RadiusSessionReconciliation.BuildAttempts([Candidate()], new Dictionary<string, RadiusExactResolutionProposal>(), Corpus, "resolver-v1", [first.AttemptKey]));

        var changed = Assert.Single(RadiusSessionReconciliation.BuildAttempts([Candidate()], new Dictionary<string, RadiusExactResolutionProposal>(), new string('d', 64), "resolver-v1", [first.AttemptKey]));
        Assert.NotEqual(first.AttemptKey, changed.AttemptKey);
        Assert.Equal("still_unresolved", changed.Outcome);
        Assert.Null(changed.ResolutionInputSha256);
        var resolverChanged = Assert.Single(RadiusSessionReconciliation.BuildAttempts([Candidate()], Proposals(), Corpus, "resolver-v2", [first.AttemptKey]));
        Assert.NotEqual(first.AttemptKey, resolverChanged.AttemptKey);
        Assert.Equal("projected", resolverChanged.Outcome);
    }

    [Fact]
    public void Overlay_preserves_facts_and_does_not_mutate_original()
    {
        var original = Original();
        var before = original.DeepClone();
        var resolved = RadiusSessionReconciliation.ApplyExactResolution(original, Proposal());
        Assert.True(JsonNode.DeepEquals(before, original));
        Assert.NotSame(original, resolved);
        var expected = Original();
        expected["identity_state"] = "exact";
        expected["session_identity_key"] = Session;
        expected["exact_principal_key"] = "entity:101";
        Assert.True(JsonNode.DeepEquals(expected, resolved));
        var session = Assert.Single(RadiusSessionFold.Fold([resolved]));
        Assert.Equal("missing_stop", session["completeness"]!.ToString());
        Assert.Equal(new string('e', 64), Assert.Single(session["evidence_sha256s"]!.AsArray())!.ToString());
        resolved["observed_at_utc"] = null;
        Assert.True(JsonNode.DeepEquals(before, original));
    }

    [Fact]
    public void Exact_observation_and_unrelated_proposal_fail_closed()
    {
        var exact = Original();
        exact["identity_state"] = "exact";
        exact["session_identity_key"] = Session;
        exact["exact_principal_key"] = "entity:101";
        var before = exact.DeepClone();
        Assert.Equal("reconciliation_exact_observation_override_forbidden", Assert.Throws<VpnInputException>(() => RadiusSessionReconciliation.ApplyExactResolution(exact, Proposal())).Message);
        Assert.True(JsonNode.DeepEquals(before, exact));
        Assert.Equal("reconciliation_proposal_without_candidate", Assert.Throws<VpnInputException>(() => RadiusSessionReconciliation.BuildAttempts([], Proposals(), Corpus, "resolver-v1")).Message);
    }

    [Theory]
    [InlineData("observation", "reconciliation_proposal_observation_mismatch")]
    [InlineData("session", "reconciliation_session_key_invalid")]
    [InlineData("principal", "reconciliation_principal_key_invalid")]
    [InlineData("hash", "reconciliation_resolution_input_hash_invalid")]
    public void Invalid_exact_proposal_is_rejected_by_planner_and_overlay(string field, string error)
    {
        var proposal = field switch
        {
            "observation" => Proposal() with { ObservationId = Evidence },
            "session" => Proposal() with { SessionIdentityKey = "radius-session:invalid" },
            "principal" => Proposal() with { ExactPrincipalKey = "entity:0" },
            _ => Proposal() with { ResolutionInputSha256 = "invalid" }
        };
        var original = Original();
        var before = original.DeepClone();
        Assert.Equal(error, Assert.Throws<VpnInputException>(() => RadiusSessionReconciliation.ApplyExactResolution(original, proposal)).Message);
        Assert.True(JsonNode.DeepEquals(before, original));
        Assert.Equal(error, Assert.Throws<VpnInputException>(() => RadiusSessionReconciliation.BuildAttempts([Candidate()], new Dictionary<string, RadiusExactResolutionProposal> { [Observation] = proposal }, Corpus, "resolver-v1")).Message);
    }

    [Fact]
    public void All_candidates_are_processed_in_stable_order_without_an_arbitrary_limit()
    {
        var candidates = Enumerable.Range(1, 60).Select(i => new RadiusUnresolvedCandidate($"observation-{i:D3}", Evidence, "identity_unresolved")).ToArray();
        var forward = RadiusSessionReconciliation.BuildAttempts(candidates, new Dictionary<string, RadiusExactResolutionProposal>(), Corpus, "resolver-v1");
        var reverse = RadiusSessionReconciliation.BuildAttempts(candidates.Reverse(), new Dictionary<string, RadiusExactResolutionProposal>(), Corpus, "resolver-v1");
        Assert.Equal(60, forward.Count);
        Assert.Equal(forward, reverse);
        Assert.All(forward, attempt => Assert.Equal("still_unresolved", attempt.Outcome));
    }
}
