using Sli.Server.Storage.Lifecycle;

namespace Sli.Server.Storage.History;

internal sealed record StorageReadSegment(string Tier, DateTimeOffset TimeFromUtc, DateTimeOffset TimeToUtc,
    string Representation, bool Ready, string? Blocker, string Availability, string? SourceLink = null);
internal sealed record StorageReadPlan(string QueryKind, IReadOnlyList<StorageReadSegment> Segments,
    bool Complete, IReadOnlyList<string> Blockers);

// Port of storage_policy.plan_storage_read. Planning neither executes nor enables a storage route.
internal static class StorageReadPlanner
{
    static readonly Lazy<LifecycleCatalog> Catalog = new(() => new());

    internal static StorageReadPlan Plan(string queryKind, DateTime timeFromUtc, DateTime timeToUtc, DateTime nowUtc,
        LifecyclePolicy? policy = null, bool warmReadEnabled = false, bool warmAvailable = false,
        bool archiveAvailable = false, string? descriptorSource = null, string? descriptorStream = null,
        string? descriptorEventKey = null) => Plan(queryKind,
            Aware(timeFromUtc, "time_from_utc"), Aware(timeToUtc, "time_to_utc"), Aware(nowUtc, "now_utc"),
            policy, warmReadEnabled, warmAvailable, archiveAvailable, descriptorSource, descriptorStream, descriptorEventKey);

    static DateTimeOffset Aware(DateTime value, string name) => value.Kind == DateTimeKind.Unspecified
        ? throw new ArgumentException(name + " must be timezone-aware") : new DateTimeOffset(value).ToUniversalTime();

    internal static StorageReadPlan Plan(string queryKind, DateTimeOffset timeFromUtc, DateTimeOffset timeToUtc,
        DateTimeOffset nowUtc, LifecyclePolicy? policy = null, bool warmReadEnabled = false, bool warmAvailable = false,
        bool archiveAvailable = false, string? descriptorSource = null, string? descriptorStream = null,
        string? descriptorEventKey = null)
    {
        if (queryKind is not ("session_analytics" or "atomic_evidence"))
            throw new ArgumentException("unknown storage read query kind: " + queryKind);
        string?[] descriptor = [descriptorSource, descriptorStream, descriptorEventKey];
        if (descriptor.Any(v => v is not null) && descriptor.Any(string.IsNullOrEmpty))
            throw new ArgumentException("descriptor_source_stream_and_event_key_must_be_supplied_together");
        var start = timeFromUtc.ToUniversalTime(); var end = timeToUtc.ToUniversalTime(); var now = nowUtc.ToUniversalTime();
        if (start > end) throw new ArgumentException("time_from_utc must not be after time_to_utc");
        if (start == end) return new(queryKind, [], true, []);
        policy ??= new(7, 365, false, null, false);
        if (policy.HotDays <= 0) throw new ArgumentException("db_retention_days must be positive");
        if (policy.WarmDays <= policy.HotDays)
            throw new ArgumentException("warm_retention_days must be greater than db_retention_days");

        // Descriptor identity, not the numeric Event ID, determines whether raw evidence exists.
        bool Same(string? left, string? right) => string.Equals(left?.Trim(), right?.Trim(), StringComparison.OrdinalIgnoreCase);
        bool noArchive = descriptor.All(v => v is not null) && Catalog.Value.Entries.Any(e =>
            Same(e["source"]?.ToString(), descriptorSource) && Same(e["stream"]?.ToString(), descriptorStream) &&
            Same(e["event_key"]?.ToString(), descriptorEventKey) &&
            e["lifecycle"]?["promotion"]?["archive_requirement"]?.ToString() == "no_archive" &&
            e["lifecycle"]?["promotion"]?["read_representation"]?.ToString() == "derived_only");
        var hotCutoff = now.AddDays(-policy.HotDays); var warmCutoff = now.AddDays(-policy.WarmDays);
        var segments = new List<StorageReadSegment>();
        void Append(string tier, DateTimeOffset from, DateTimeOffset to, string representation,
            bool ready, string? blocker, string availability)
        {
            if (from < to) segments.Add(new(tier, from, to, representation, ready, blocker, availability));
        }
        var archiveEnd = end < hotCutoff ? end : hotCutoff;
        if (start < archiveEnd)
        {
            if (noArchive || queryKind == "session_analytics")
            {
                var coldEnd = archiveEnd < warmCutoff ? archiveEnd : warmCutoff;
                if (noArchive)
                    Append("clickhouse_warm", start, coldEnd, "session", false, "data_unavailable", "data_unavailable");
                else
                    Append("canonical_archive", start, coldEnd, "full_payload", archiveAvailable,
                        archiveAvailable ? null : "canonical_archive_unavailable", archiveAvailable ? "source_archived" : "data_unavailable");
                var warmStart = start > warmCutoff ? start : warmCutoff;
                if (noArchive && queryKind == "atomic_evidence")
                    Append("clickhouse_warm", warmStart, archiveEnd, "session", false,
                        "atomic_evidence_unavailable_derived_only", "derived_only_available");
                else
                {
                    bool ready = warmReadEnabled && warmAvailable;
                    string? blocker = !warmReadEnabled ? "warm_read_disabled" : !warmAvailable ? "warm_tier_unavailable" : null;
                    Append("clickhouse_warm", warmStart, archiveEnd, "session", ready, blocker,
                        ready ? "derived_only_available" : "data_unavailable");
                }
            }
            else
                Append("canonical_archive", start, archiveEnd, "full_payload", archiveAvailable,
                    archiveAvailable ? null : "canonical_archive_unavailable", archiveAvailable ? "source_archived" : "data_unavailable");
        }
        Append("postgres_hot", start > hotCutoff ? start : hotCutoff, end, "atomic_event", true, null, "atomic_evidence_available");
        string[] blockers = segments.Select(s => s.Blocker).OfType<string>().Distinct(StringComparer.Ordinal).ToArray();
        return new(queryKind, segments.AsReadOnly(), blockers.Length == 0, Array.AsReadOnly(blockers));
    }
}
