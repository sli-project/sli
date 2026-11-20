using Sli.Server.Agents.Radius;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class RadiusSessionReconciliationProductionTests
{
    private const string AcceptId = "11111111-1111-1111-1111-111111111111";
    private const string AccountingId = "22222222-2222-2222-2222-222222222222";
    private const string ObservationId = "33333333-3333-3333-3333-333333333333";
    private static readonly DateTimeOffset Observed = new(2026, 8, 11, 5, 0, 0, TimeSpan.Zero);

    private static string Line(string packet, string dn = "", string classValue = "opaque-class", string status = "",
        string session = "opaque-session", string nas = "vpn-gateway")
    {
        var fields = Enumerable.Repeat("", 66).ToArray();
        fields[1] = "NPS"; fields[2] = "08/11/2026"; fields[3] = "12:00:00"; fields[4] = packet;
        fields[6] = dn; fields[11] = nas; fields[26] = classValue; fields[31] = status; fields[35] = packet == "4" ? session : "";
        if (packet != "4") fields[11] = "";
        return string.Join(',', fields.Select(value => value.Contains(',') ? "\"" + value.Replace("\"", "\"\"") + "\"" : value));
    }
    private static VerifiedEvidenceRecord Accept(string dn = "CN=User,DC=example,DC=test", string id = AcceptId) => new(id, Line("2", dn));
    private static VerifiedEvidenceRecord Accounting(string classValue = "opaque-class") => new(AccountingId, Line("4", classValue: classValue, status: "1"));
    private static ImmutableTerminalObservation Observation() => new(ObservationId, AccountingId, "start", "ready", Observed);
    private static Task<ExactReconciliationBatch> Build(IEnumerable<VerifiedEvidenceRecord> records,
        IEnumerable<ImmutableTerminalObservation>? observations = null, Func<string, string, Task<string?>>? lookup = null) =>
        RadiusSessionReconciliationProduction.BuildAsync(records, observations ?? [Observation()], "radius.example.test", " EXAMPLE.TEST ",
            "N. Central Asia Standard Time", 420, lookup ?? ((_, _) => Task.FromResult<string?>("entity:101")));

    [Fact]
    public async Task ExactBatchUsesAccessAcceptClassAndPreservesTerminalFact()
    {
        var observation = Observation();
        var original = observation with { };
        var result = await Build([Accept(), Accounting()], [observation], (organization, dn) =>
        {
            Assert.Equal("example.test", organization);
            Assert.Equal("CN=User,DC=example,DC=test", dn);
            return Task.FromResult<string?>("entity:101");
        });

        var proposal = Assert.Single(result.Proposals).Value;
        Assert.Equal(1, result.AccessAcceptCount);
        Assert.Equal(0, result.UnresolvedAccessAcceptCount);
        Assert.Equal(1, result.ReconciledCount);
        Assert.Equal(2, result.EvidenceRecordCount);
        Assert.Equal(ObservationId, proposal.ObservationId);
        Assert.Equal("entity:101", proposal.ExactPrincipalKey);
        // Byte-exact hashes obtained from the frozen Python implementation with these synthetic inputs.
        Assert.Equal("radius-session:293d6391cfb8092f1202561c9d6268cf3241d5585ea45a64a2850f35b53804e0", proposal.SessionIdentityKey);
        Assert.Equal("421618e390eebe55ea002664ab0ec0989482f672ec232b65e810e776242d36c4", proposal.ResolutionInputSha256);
        Assert.Equal("7be6ee54a2ba9ee1a56e8c7443db0cab785b2e3ddc55a205e45ec15f9f256d0b", result.EvidenceCorpusSha256);
        Assert.Equal(new UnresolvedCandidate(ObservationId, AccountingId, "identity_unresolved"), Assert.Single(result.Candidates));
        Assert.Equal(original, observation);
        var attempt = Assert.Single(RadiusSessionReconciliationProduction.BuildAttempts(result, "resolver-v1"));
        Assert.Equal("projected", attempt.Outcome);
        Assert.Equal("747a63849e1ef2cf1a28909b1feba0d01eda9afe45b6330c04d35798e86c615b", attempt.AttemptKey);
        Assert.Equal(proposal.ResolutionInputSha256, attempt.ResolutionInputSha256);
    }

    [Fact]
    public async Task MissingClassCandidateStaysUnresolved()
    {
        var result = await Build([Accounting("missing-class")], lookup: (_, _) => throw new InvalidOperationException("lookup must not run without Access-Accept"));
        Assert.Equal(new UnresolvedCandidate(ObservationId, AccountingId, "identity_unresolved"), Assert.Single(result.Candidates));
        Assert.Empty(result.Proposals);
        Assert.Equal(0, result.ReconciledCount);
        var attempt = Assert.Single(RadiusSessionReconciliationProduction.BuildAttempts(result, "resolver-v1"));
        Assert.Equal("still_unresolved", attempt.Outcome);
        Assert.Equal(AccountingId, attempt.EvidenceUid);
        Assert.Null(attempt.ResolutionInputSha256);
        Assert.Empty(RadiusSessionReconciliationProduction.BuildAttempts(result, "resolver-v1", [attempt.AttemptKey]));
        Assert.Single(RadiusSessionReconciliationProduction.BuildAttempts(result, "resolver-v2", [attempt.AttemptKey]));
    }

    [Fact]
    public async Task OneClassWithConflictingExactPrincipalsRejectsTheWholeBatch()
    {
        var error = await Assert.ThrowsAsync<ArgumentException>(() => Build([
            Accept("CN=First,DC=example,DC=test"),
            Accept("CN=Second,DC=example,DC=test", "44444444-4444-4444-4444-444444444444"), Accounting()
        ], lookup: (_, dn) => Task.FromResult<string?>(dn.StartsWith("CN=First", StringComparison.Ordinal) ? "entity:101" : "entity:202")));
        Assert.Equal("production_reconciliation_class_identity_conflict", error.Message);
    }

    [Theory]
    [InlineData("lifecycle", "lifecycle_mismatch")]
    [InlineData("timestamp_state", "timestamp_ready_required")]
    [InlineData("timestamp", "timestamp_mismatch")]
    [InlineData("missing_timestamp", "timestamp_invalid")]
    [InlineData("missing_evidence", "observation_evidence_missing")]
    public async Task ExactBridgeCannotRewriteTerminalFacts(string change, string suffix)
    {
        var observation = Observation();
        observation = change switch
        {
            "lifecycle" => observation with { LifecycleEvent = "stop" },
            "timestamp_state" => observation with { TimestampState = "unresolved" },
            "timestamp" => observation with { ObservedAtUtc = Observed.AddSeconds(1) },
            "missing_timestamp" => observation with { ObservedAtUtc = null },
            _ => observation with { EvidenceUid = "44444444-4444-4444-4444-444444444444" }
        };
        var error = await Assert.ThrowsAsync<ArgumentException>(() => Build([Accept(), Accounting()], [observation]));
        Assert.Equal("production_reconciliation_" + suffix, error.Message);
    }

    [Theory]
    [InlineData(true, "evidence_duplicate")]
    [InlineData(false, "observation_duplicate")]
    public async Task DuplicateImmutableIdsAreRejected(bool duplicateEvidence, string suffix)
    {
        var error = await Assert.ThrowsAsync<ArgumentException>(() => duplicateEvidence
            ? Build([Accept(), Accounting(), Accounting()])
            : Build([Accept(), Accounting()], [Observation(), Observation()]));
        Assert.Equal("production_reconciliation_" + suffix, error.Message);
    }

    [Fact]
    public async Task EvidenceOrderAndEquivalentTimestampOffsetsDoNotChangeTheProof()
    {
        var records = new[] { Accept(), Accept("CN=Other,DC=example,DC=test", "44444444-4444-4444-4444-444444444444"), Accounting() };
        var forward = await Build(records);
        var reversed = await Build(records.Reverse(), [Observation() with { ObservedAtUtc = Observed.ToOffset(TimeSpan.FromHours(7)) }]);
        Assert.Equal(forward.EvidenceCorpusSha256, reversed.EvidenceCorpusSha256);
        Assert.Equal(forward.Proposals[ObservationId], reversed.Proposals[ObservationId]);
        Assert.Equal(2, forward.AccessAcceptCount);
        Assert.Equal(1, forward.ReconciledCount);
    }

    [Fact]
    public async Task UnresolvedAccessAcceptDoesNotPromoteAccountingUserNameOrDn()
    {
        var result = await Build([Accept(), Accounting()], lookup: (_, _) => Task.FromResult<string?>(null));
        Assert.Equal(1, result.AccessAcceptCount);
        Assert.Equal(1, result.UnresolvedAccessAcceptCount);
        Assert.Empty(result.Proposals);
        Assert.Equal("still_unresolved", Assert.Single(RadiusSessionReconciliationProduction.BuildAttempts(result, "resolver-v1")).Outcome);
    }
}
