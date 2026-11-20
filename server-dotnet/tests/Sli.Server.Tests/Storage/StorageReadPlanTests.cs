using Sli.Server.Storage.History;
using Sli.Server.Storage.Lifecycle;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Input/output vectors from tests/storage/test_storage_read_plan.py.
public sealed class StorageReadPlanTests
{
    static readonly DateTimeOffset Now = new(2026, 7, 28, 12, 0, 0, TimeSpan.Zero);

    static void Segment(StorageReadSegment segment, string tier, string representation, int fromDays, int toDays,
        bool ready, string availability, string? blocker = null)
    {
        Assert.Equal(tier, segment.Tier); Assert.Equal(representation, segment.Representation);
        Assert.Equal(Now.AddDays(-fromDays), segment.TimeFromUtc); Assert.Equal(Now.AddDays(-toDays), segment.TimeToUtc);
        Assert.Equal(ready, segment.Ready); Assert.Equal(availability, segment.Availability);
        Assert.Equal(blocker, segment.Blocker); Assert.Null(segment.SourceLink);
    }

    [Fact]
    public void Ninety_day_session_analytics_splits_between_hot_and_warm()
    {
        var plan = StorageReadPlanner.Plan("session_analytics", Now.AddDays(-90), Now, Now,
            new(7, 365, false, null, false), warmReadEnabled: true, warmAvailable: true);
        Assert.Equal("session_analytics", plan.QueryKind); Assert.True(plan.Complete); Assert.Empty(plan.Blockers);
        Assert.Collection(plan.Segments,
            s => Segment(s, "clickhouse_warm", "session", 90, 7, true, "derived_only_available"),
            s => Segment(s, "postgres_hot", "atomic_event", 7, 0, true, "atomic_evidence_available"));
    }

    [Fact]
    public void Warm_read_is_disabled_by_default_and_fails_closed()
    {
        var plan = StorageReadPlanner.Plan("session_analytics", Now.AddDays(-30), Now, Now, warmAvailable: true);
        Assert.False(plan.Complete); Assert.Equal(["warm_read_disabled"], plan.Blockers);
        Assert.Collection(plan.Segments,
            s => Segment(s, "clickhouse_warm", "session", 30, 7, false, "data_unavailable", "warm_read_disabled"),
            s => Segment(s, "postgres_hot", "atomic_event", 7, 0, true, "atomic_evidence_available"));
    }

    [Fact]
    public void Atomic_evidence_never_uses_session_only_warm_tier()
    {
        var plan = StorageReadPlanner.Plan("atomic_evidence", Now.AddDays(-90), Now, Now,
            warmReadEnabled: true, warmAvailable: true, archiveAvailable: true);
        Assert.True(plan.Complete); Assert.Empty(plan.Blockers);
        Assert.Collection(plan.Segments,
            s => Segment(s, "canonical_archive", "full_payload", 90, 7, true, "source_archived"),
            s => Segment(s, "postgres_hot", "atomic_event", 7, 0, true, "atomic_evidence_available"));
    }

    [Theory]
    [InlineData("4624", false)]
    [InlineData("4624", true)]
    [InlineData("4634", true)]
    public void No_archive_descriptor_reports_derived_only_without_raw_link(string eventKey, bool archiveAvailable)
    {
        var plan = StorageReadPlanner.Plan("atomic_evidence", Now.AddDays(-30), Now, Now,
            warmReadEnabled: true, warmAvailable: true, archiveAvailable: archiveAvailable,
            descriptorSource: "sli.windows.ad-dc", descriptorStream: "Security", descriptorEventKey: eventKey);
        Assert.False(plan.Complete); Assert.Equal(["atomic_evidence_unavailable_derived_only"], plan.Blockers);
        Assert.Collection(plan.Segments,
            s => Segment(s, "clickhouse_warm", "session", 30, 7, false, "derived_only_available", "atomic_evidence_unavailable_derived_only"),
            s => Segment(s, "postgres_hot", "atomic_event", 7, 0, true, "atomic_evidence_available"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Session_analytics_older_than_365_days_requires_archive(bool archiveAvailable)
    {
        var plan = StorageReadPlanner.Plan("session_analytics", Now.AddDays(-400), Now, Now,
            warmReadEnabled: true, warmAvailable: true, archiveAvailable: archiveAvailable);
        Assert.Equal(archiveAvailable, plan.Complete);
        Assert.Equal(archiveAvailable ? [] : new[] { "canonical_archive_unavailable" }, plan.Blockers);
        Assert.Collection(plan.Segments,
            s => Segment(s, "canonical_archive", "full_payload", 400, 365, archiveAvailable,
                archiveAvailable ? "source_archived" : "data_unavailable", archiveAvailable ? null : "canonical_archive_unavailable"),
            s => Segment(s, "clickhouse_warm", "session", 365, 7, true, "derived_only_available"),
            s => Segment(s, "postgres_hot", "atomic_event", 7, 0, true, "atomic_evidence_available"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void Read_plan_rejects_ambiguous_time(int field)
    {
        DateTime[] times = [Now.AddDays(-30).UtcDateTime, Now.UtcDateTime, Now.UtcDateTime];
        times[field] = DateTime.SpecifyKind(times[field], DateTimeKind.Unspecified);
        Assert.Contains("timezone-aware", Assert.Throws<ArgumentException>(() =>
            StorageReadPlanner.Plan("atomic_evidence", times[0], times[1], times[2])).Message);
    }

    [Theory]
    [InlineData(7, 7, "greater than")]
    [InlineData(7, 6, "greater than")]
    [InlineData(0, 365, "positive")]
    public void Read_plan_rejects_invalid_retention_windows(int hotDays, int warmDays, string message)
    {
        Assert.Contains(message, Assert.Throws<ArgumentException>(() => StorageReadPlanner.Plan("atomic_evidence",
            Now.AddDays(-30), Now, Now, new LifecyclePolicy(hotDays, warmDays, false, null, false))).Message);
    }

    [Theory]
    [InlineData(7, 0, "postgres_hot", "atomic_event")]
    [InlineData(365, 7, "clickhouse_warm", "session")]
    [InlineData(400, 365, "canonical_archive", "full_payload")]
    public void Exact_cutoffs_produce_one_nonempty_segment(int fromDays, int toDays, string tier, string representation)
    {
        var plan = StorageReadPlanner.Plan("session_analytics", Now.AddDays(-fromDays), Now.AddDays(-toDays), Now,
            warmReadEnabled: true, warmAvailable: true, archiveAvailable: true);
        Assert.True(plan.Complete); Assert.Empty(plan.Blockers);
        var segment = Assert.Single(plan.Segments);
        Segment(segment, tier, representation, fromDays, toDays, true,
            tier == "postgres_hot" ? "atomic_evidence_available" : tier == "clickhouse_warm" ? "derived_only_available" : "source_archived");
    }

    [Fact]
    public void Offset_times_normalize_to_utc_and_empty_window_is_complete()
    {
        var plan = StorageReadPlanner.Plan("atomic_evidence", Now.AddDays(-1).ToOffset(TimeSpan.FromHours(7)),
            Now.ToOffset(TimeSpan.FromHours(-4)), Now.ToOffset(TimeSpan.FromHours(3)));
        Segment(Assert.Single(plan.Segments), "postgres_hot", "atomic_event", 1, 0, true, "atomic_evidence_available");
        Assert.Equal(TimeSpan.Zero, plan.Segments[0].TimeFromUtc.Offset);
        Assert.Equal(TimeSpan.Zero, plan.Segments[0].TimeToUtc.Offset);
        var empty = StorageReadPlanner.Plan("atomic_evidence", Now, Now, Now);
        Assert.True(empty.Complete); Assert.Empty(empty.Segments); Assert.Empty(empty.Blockers);
    }

    [Fact]
    public void Unavailable_warm_tier_and_archive_report_ordered_blockers()
    {
        var plan = StorageReadPlanner.Plan("session_analytics", Now.AddDays(-400), Now, Now, warmReadEnabled: true);
        Assert.False(plan.Complete);
        Assert.Equal(["canonical_archive_unavailable", "warm_tier_unavailable"], plan.Blockers);
        Assert.False(plan.Segments[1].Ready);
        var atomic = StorageReadPlanner.Plan("atomic_evidence", Now.AddDays(-30), Now, Now, warmReadEnabled: true, warmAvailable: true);
        Assert.False(atomic.Complete); Assert.Equal(["canonical_archive_unavailable"], atomic.Blockers);
    }

    [Fact]
    public void Invalid_query_window_and_partial_descriptor_are_rejected()
    {
        Assert.Contains("unknown storage read query kind", Assert.Throws<ArgumentException>(() =>
            StorageReadPlanner.Plan("unknown", Now.AddDays(-1), Now, Now)).Message);
        Assert.Contains("must not be after", Assert.Throws<ArgumentException>(() =>
            StorageReadPlanner.Plan("atomic_evidence", Now, Now.AddDays(-1), Now)).Message);
        Assert.Equal("descriptor_source_stream_and_event_key_must_be_supplied_together", Assert.Throws<ArgumentException>(() =>
            StorageReadPlanner.Plan("atomic_evidence", Now.AddDays(-1), Now, Now, descriptorSource: "sli.windows.ad-dc")).Message);
    }
}
