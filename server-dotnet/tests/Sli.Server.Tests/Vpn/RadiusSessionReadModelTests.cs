using System.Text.Json.Nodes;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Vpn;

// Parity with tests/sources/test_radius_session_read_model.py; row folding vectors
// already covered by VpnModelTests remain there.
public sealed class RadiusSessionReadModelTests
{
    static JsonObject Input(string id, string lifecycle, int minute) => VpnRouteTests.Json(new
    {
        observation_id = id,
        lifecycle_event = lifecycle,
        identity_state = "exact",
        timestamp_state = "ready",
        session_identity_key = "radius-session:" + new string('a', 64),
        exact_principal_key = "entity:11111111-1111-1111-1111-111111111111",
        observed_at_utc = $"2026-07-30T04:{minute:00}:00Z",
        canonical_record_sha256 = new string('e', 64)
    });

    [Fact]
    public void Complete_session_summary_counts_exact_ready_inputs_without_active_claim()
    {
        var result = RadiusSessionFold.FoldWithSummary([
            Input("three", "stop", 30), Input("one", "start", 10), Input("two", "interim_update", 20)
        ]);

        Assert.Equal("sli.radius-session-read-model.v1", result.ContractId);
        Assert.Equal(3, result.InputObservations);
        Assert.Equal(3, result.ExactReadyObservations);
        Assert.Equal(0, result.UnresolvedIdentityObservations);
        Assert.Equal(0, result.UnresolvedTimestampObservations);
        Assert.Equal(1, result.CompleteSessions);
        Assert.Equal(0, result.PartialSessions);
        Assert.Equal(0, result.OpenObservedSessions);
        Assert.Equal("closed", Assert.Single(result.Sessions)["lifecycle_state"]!.ToString());
    }

    [Fact]
    public void Unresolved_facts_are_counted_but_never_merged()
    {
        var identity = Input("identity", "start", 1);
        identity["identity_state"] = "unresolved";
        identity["session_identity_key"] = null;
        identity["exact_principal_key"] = null;
        var timestamp = Input("timestamp", "start", 2);
        timestamp["timestamp_state"] = "unresolved";
        timestamp["observed_at_utc"] = null;

        var result = RadiusSessionFold.FoldWithSummary([identity, timestamp]);

        Assert.Empty(result.Sessions);
        Assert.Equal(2, result.InputObservations);
        Assert.Equal(0, result.ExactReadyObservations);
        Assert.Equal(1, result.UnresolvedIdentityObservations);
        Assert.Equal(1, result.UnresolvedTimestampObservations);
        Assert.Equal(0, result.CompleteSessions);
        Assert.Equal(0, result.PartialSessions);
        Assert.Equal(0, result.OpenObservedSessions);
    }

    [Theory]
    [InlineData("start", 1)]
    [InlineData("interim_update", 1)]
    [InlineData("stop", 0)]
    public void Partial_session_summary_counts_open_observations(string lifecycle, int open)
    {
        var result = RadiusSessionFold.FoldWithSummary([Input("partial", lifecycle, 1)]);
        Assert.Equal(1, result.InputObservations);
        Assert.Equal(1, result.ExactReadyObservations);
        Assert.Equal(0, result.CompleteSessions);
        Assert.Equal(1, result.PartialSessions);
        Assert.Equal(open, result.OpenObservedSessions);
    }

    [Theory]
    [InlineData("2026-07-30T04:00:00")]
    [InlineData("2026-07-30T04:00:00.000000")]
    public void Naive_ready_timestamp_is_rejected(string value)
    {
        var item = Input("naive", "start", 0);
        item["observed_at_utc"] = value;
        Assert.Equal("observed_at_utc_timezone_required",
            Assert.Throws<VpnInputException>(() => RadiusSessionFold.Fold([item])).Message);
    }

    [Theory]
    [InlineData(null, "ready_timestamp_value_required")]
    [InlineData("not-a-timestamp", "observed_at_utc_invalid")]
    public void Missing_or_invalid_ready_timestamp_fails_closed(string? value, string error)
    {
        var item = Input("timestamp", "start", 0);
        item["observed_at_utc"] = value;
        Assert.Equal(error, Assert.Throws<VpnInputException>(() => RadiusSessionFold.Fold([item])).Message);
    }

    [Theory]
    [InlineData("2026-07-30T04:00:00Z")]
    [InlineData("2026-07-30T07:00:00+03:00")]
    [InlineData("2026-07-30T01:00:00-03:00")]
    public void Explicit_timezone_is_normalized_to_utc(string value)
    {
        var item = Input("aware", "start", 0);
        item["observed_at_utc"] = value;
        Assert.Equal("2026-07-30T04:00:00Z",
            Assert.Single(RadiusSessionFold.Fold([item]))["started_at_utc"]!.ToString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Exact_ready_lifecycle_requires_evidence_sha256(string? digest)
    {
        var item = Input("exact", "start", 1);
        item["canonical_record_sha256"] = digest;
        Assert.Equal("evidence_sha256_required",
            Assert.Throws<VpnInputException>(() => RadiusSessionFold.Fold([item])).Message);
    }
}
