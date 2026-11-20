using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Legacy;

public sealed record LegacyAdaptiveCollectionPlan(string Server, string[] Channels, Dictionary<string, int> ChannelLimits,
    bool RecoveryMode, int SecurityLimit, string Reason, string[] FairnessChannels, string? FairnessReason);

// Planning reads PostgreSQL state; it neither starts acquisition nor changes a cursor.
public sealed class LegacyAdaptiveCollection
{
    readonly LegacySettings settings;
    public LegacyAdaptiveCollection(ISemanticDatabase database, LegacySettings settings, TimeProvider clock) { this.settings=settings; }

    internal static readonly string[] DefaultChannels = ["Security", "System", "Directory Service",
        "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-TaskScheduler/Operational", "DNS Server"];

    public Task<LegacyAdaptiveCollectionPlan> GetPlanAsync(string server, CancellationToken ct)
    {
        throw new InvalidOperationException("module_disabled");
    }

    internal LegacyAdaptiveCollectionPlan BuildPlan(string server, long? lag, JsonArray adaptive, IReadOnlyList<string> fairness)
    {
        var state = adaptive.OfType<JsonObject>().FirstOrDefault(r => S(r["channel"]) == "Security");
        bool fast = Enabled("ADLOG_SECURITY_RECOVERY_FAST");
        int minimum = Integer("ADLOG_SECURITY_MIN_EVENTS", 100);
        int maximum = Math.Max(minimum, Integer("ADLOG_SECURITY_RECOVERY_MAX_LIMIT", Integer("ADLOG_SECURITY_MAX_LIMIT", fast ? 50000 : 5000)));
        int start = Math.Clamp(Integer("ADLOG_SECURITY_RECOVERY_START_LIMIT", Integer("ADLOG_SECURITY_MAX_EVENTS", fast ? 20000 : 500)), minimum, maximum);
        int limit = (int)Math.Clamp(N(state?["current_limit"], start), minimum, maximum);
        bool previous = Flag(state?["recovery_mode"]), securityRecovery = previous;
        int enter = Integer("ADLOG_SECURITY_RECOVERY_LAG_MINUTES", 60), exit = Integer("ADLOG_SECURITY_RECOVERY_EXIT_LAG_MINUTES", 15);
        string reason = "normal";
        if (lag > enter) { securityRecovery = true; reason = $"security_lag>{enter}m"; }
        else if (lag < exit) { securityRecovery = false; reason = $"security_lag<{exit}m"; }
        if (securityRecovery && !previous && fast && start > limit) { limit = start; reason += ";fast_recovery_start_limit"; }
        var recoveryChannels = DefaultChannels.Where(c => c != "Security" && adaptive.OfType<JsonObject>().Any(r => S(r["channel"]) == c && Flag(r["recovery_mode"]))).ToArray();
        string[] fair = securityRecovery ? fairness.ToArray() : [];
        string? fairnessReason = fair.Length > 0 ? $"stale_non_security_channels>{Integer("ADLOG_CHANNEL_FAIRNESS_STALE_MINUTES", 60)}m" : null;
        if (fair.Length > 0) reason += $";fairness_channels={fair.Length}";
        if (recoveryChannels.Length > 0) reason += $";non_security_recovery={recoveryChannels.Length}";
        var channels = (securityRecovery ? new[] { "Security" } : DefaultChannels).Concat(recoveryChannels).Concat(fair).Distinct().ToArray();
        int secondary = Integer("ADLOG_NON_SECURITY_MAX_EVENTS", 500);
        var limits = channels.ToDictionary(c => c, c => c == "Security" ? limit : c == "DNS Server" ? Integer("ADLOG_DNS_MAX_EVENTS", 200) : secondary);
        foreach (string channel in recoveryChannels)
            limits[channel] = (int)Math.Clamp(N(adaptive.OfType<JsonObject>().First(r => S(r["channel"]) == channel)["current_limit"], secondary), 1, Math.Max(1, Integer("ADLOG_NON_SECURITY_RECOVERY_MAX_EVENTS", 50000)));
        // This is the reference fairness sample size, never a process lifetime or timeout.
        foreach (string channel in fair.Except(recoveryChannels))
            limits[channel] = Math.Min(limits[channel], Integer("ADLOG_CHANNEL_FAIRNESS_MAX_EVENTS", Math.Min(100, secondary)));
        return new(server, channels, limits, securityRecovery || recoveryChannels.Length > 0, limit,
            reason + ";backend=postgres_runtime", fair, fairnessReason);
    }

    static bool Flag(JsonNode? value) => B(value) || N(value) != 0;
    bool Enabled(string key) => settings.Get(key)?.Trim().ToLowerInvariant() is not ("0" or "false" or "no" or "off");
    int Integer(string key, int fallback) => int.TryParse(settings.Get(key), out int value) ? value : fallback;
}
