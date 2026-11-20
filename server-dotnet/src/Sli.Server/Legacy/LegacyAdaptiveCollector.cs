using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;

namespace Sli.Server.Legacy;

public sealed record LegacyAdaptivePlan(string Server, string[] Channels, IReadOnlyDictionary<string, int> ChannelLimits,
    bool RecoveryMode, string Reason, string AdaptiveStateMode = "update", bool Archive = true, string CollectionMode = "auto");

// A channel result is supplied after import, so history measures persisted events.
public sealed record LegacyChannelRun(string Server, string Channel, string Status, int Count, int Inserted, int Skipped,
    int LimitUsed, DateTimeOffset Started, DateTimeOffset Finished, int QueryDurationMs, int ImportDurationMs,
    string CollectionMode, string RequestedCollectionMode, string CollectorBackend,
    string? PartialKind = null, bool Truncated = false, DateTimeOffset? LatestEventTime = null, long? LatestRecordId = null);

public sealed class LegacyAdaptiveCollector
{
    public LegacyAdaptiveCollector(IPostgresConnectionFactory connections, LegacySettings settings) { }

    public Task<LegacyAdaptivePlan> PlanAsync(string server, CancellationToken ct)
    {
        throw new InvalidOperationException("module_disabled");
    }

    public Task RecordAsync(LegacyChannelRun run, int? jobId, string mode, CancellationToken ct)
    {
        throw new InvalidOperationException("module_disabled");
    }
}
