using System.Globalization;
using System.Text.Json.Nodes;

namespace Sli.Server.Sources;

// Batch sizes and source-reported timeout metadata are the frozen collector contract.
// They do not impose execution deadlines on the .NET worker.
public sealed record CollectorAdaptiveOptions
{
    public int RecoveryOn { get; init; } = 60;
    public int RecoveryOff { get; init; } = 15;
    public int GrowAfter { get; init; } = 1;
    public bool FastRecovery { get; init; } = true;
    public int SecurityStart { get; init; } = 20_000;
    public int SecurityMin { get; init; } = 100;
    public int SecurityMax { get; init; } = 50_000;
    public int SecurityTarget { get; init; } = 50_000;
    public int SecurityStep { get; init; } = 10_000;
    public double SecurityFactor { get; init; } = 2;
    public int SecurityTimeout { get; init; } = 900;
    public int DnsSize { get; init; } = 200;
    public int OtherSize { get; init; } = 500;
    public int OtherTimeout { get; init; } = 300;
    public int OtherRecoveryMax { get; init; } = 50_000;
    public int OtherStep { get; init; } = 1_000;
    public bool FairnessEnabled { get; init; } = true;
    public int FairnessStale { get; init; } = 60;
    public int FairnessSize { get; init; } = 100;
    public int FairnessTimeout { get; init; } = 120;

    public static CollectorAdaptiveOptions FromEnvironment(Func<string, string?>? get = null)
    {
        get ??= Environment.GetEnvironmentVariable;
        int I(string key, int fallback) => int.TryParse(get(key), out int n) ? n : fallback;
        bool B(string key) => get(key)?.Trim().ToLowerInvariant() is not ("0" or "false" or "no" or "off");
        bool fast = B("ADLOG_SECURITY_RECOVERY_FAST");
        int maximum = I("ADLOG_SECURITY_RECOVERY_MAX_LIMIT", I("ADLOG_SECURITY_MAX_LIMIT", fast ? 50_000 : 5_000));
        int other = I("ADLOG_NON_SECURITY_MAX_EVENTS", 500), timeout = I("ADLOG_CHANNEL_TIMEOUT_SECONDS", 300);
        return new() {
            RecoveryOn = I("ADLOG_SECURITY_RECOVERY_LAG_MINUTES", 60), RecoveryOff = I("ADLOG_SECURITY_RECOVERY_EXIT_LAG_MINUTES", 15),
            GrowAfter = I("ADLOG_SECURITY_GROW_AFTER_COMPLETED", 1), FastRecovery = fast,
            SecurityStart = I("ADLOG_SECURITY_RECOVERY_START_LIMIT", I("ADLOG_SECURITY_MAX_EVENTS", fast ? 20_000 : 500)),
            SecurityMin = I("ADLOG_SECURITY_MIN_EVENTS", 100), SecurityMax = maximum,
            SecurityTarget = I("ADLOG_SECURITY_RECOVERY_TARGET_LIMIT", maximum), SecurityStep = I("ADLOG_SECURITY_GROW_STEP", fast ? 10_000 : 500),
            SecurityFactor = Math.Max(1, double.TryParse(get("ADLOG_SECURITY_RECOVERY_RAMP_FACTOR"), CultureInfo.InvariantCulture, out double factor) ? factor : fast ? 2 : 1),
            SecurityTimeout = I("ADLOG_SECURITY_TIMEOUT_SECONDS", 900), DnsSize = I("ADLOG_DNS_MAX_EVENTS", 200),
            OtherSize = other, OtherTimeout = timeout, OtherRecoveryMax = I("ADLOG_NON_SECURITY_RECOVERY_MAX_EVENTS", 50_000),
            OtherStep = I("ADLOG_NON_SECURITY_RECOVERY_GROW_STEP", 1_000), FairnessEnabled = B("ADLOG_CHANNEL_FAIRNESS_ENABLED"),
            FairnessStale = I("ADLOG_CHANNEL_FAIRNESS_STALE_MINUTES", 60), FairnessSize = I("ADLOG_CHANNEL_FAIRNESS_MAX_EVENTS", Math.Min(100, other)),
            FairnessTimeout = I("ADLOG_CHANNEL_FAIRNESS_TIMEOUT_SECONDS", Math.Min(120, timeout))
        };
    }
}

public sealed record CollectorAdaptivePlan(string Server, string[] Channels, Dictionary<string, int> ChannelLimits,
    Dictionary<string, int> ChannelTimeouts, bool RecoveryMode, int SecurityLimit, string Reason,
    string[] FairnessChannels, string? FairnessReason, string[] RecoveryChannels);

public sealed class CollectorAdaptive(CollectorAdaptiveOptions options, TimeProvider? timeProvider = null)
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;
    public static readonly IReadOnlyList<string> DefaultChannels = Array.AsReadOnly(new[] {
        "Security", "System", "Directory Service", "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-TaskScheduler/Operational", "DNS Server" });
    internal static int N(JsonNode? value, int fallback = 0) => int.TryParse(value?.ToString(), out int n) ? n : fallback;
    internal static bool B(JsonNode? value) => value is JsonValue v && v.TryGetValue<bool>(out bool b) && b;
    internal static string S(JsonNode? value) => value?.ToString() ?? "";
    private int Bounded(JsonNode? value) => Math.Max(options.SecurityMin, Math.Min(options.SecurityMax, N(value, options.SecurityStart)));

    public CollectorAdaptivePlan BuildPlan(string server, int? lag, JsonObject? state = null,
        string[]? fairnessChannels = null, IReadOnlyDictionary<string, JsonObject>? channelStates = null)
    {
        int start = Bounded(JsonValue.Create(options.SecurityStart)), current = Bounded(state?["current_limit"] ?? JsonValue.Create(start));
        bool previousRecovery = B(state?["recovery_mode"]), securityRecovery = previousRecovery;
        string reason = "normal";
        if (lag > options.RecoveryOn) { securityRecovery = true; reason = $"security_lag>{options.RecoveryOn}m"; }
        else if (lag < options.RecoveryOff) { securityRecovery = false; reason = $"security_lag<{options.RecoveryOff}m"; }
        if (securityRecovery && !previousRecovery && options.FastRecovery && start > current) {
            current = start; reason += ";fast_recovery_start_limit";
        }
        var recovering = DefaultChannels.Where(c => c != "Security" && channelStates is not null
            && channelStates.TryGetValue(c, out var s) && B(s["recovery_mode"])).ToArray();
        string[] fairness = securityRecovery ? fairnessChannels ?? [] : [];
        string? fairnessReason = null;
        if (fairness.Length > 0) { fairnessReason = $"stale_non_security_channels>{options.FairnessStale}m"; reason += $";fairness_channels={fairness.Length}"; }
        if (recovering.Length > 0) reason += $";non_security_recovery={recovering.Length}";
        reason += ";backend=postgres_runtime";
        string[] channels = (securityRecovery ? new[] { "Security" } : DefaultChannels).Concat(recovering).Concat(fairness).Distinct().ToArray();
        var sizes = channels.ToDictionary(c => c, _ => options.OtherSize);
        var timeouts = channels.ToDictionary(c => c, _ => options.OtherTimeout);
        sizes["Security"] = current; timeouts["Security"] = options.SecurityTimeout;
        if (sizes.ContainsKey("DNS Server")) sizes["DNS Server"] = options.DnsSize;
        foreach (string c in recovering) sizes[c] = Math.Min(options.OtherRecoveryMax, Math.Max(1, N(channelStates![c]["current_limit"], options.OtherSize)));
        foreach (string c in fairness.Where(c => !recovering.Contains(c))) {
            sizes[c] = Math.Min(sizes[c], options.FairnessSize); timeouts[c] = Math.Min(timeouts[c], options.FairnessTimeout);
        }
        return new(server, channels, sizes, timeouts, securityRecovery || recovering.Length > 0, current, reason, fairness, fairnessReason, recovering);
    }

    public JsonObject SecurityTransition(JsonObject? state, string status, int inserted, int skipped, int? lagMinutes,
        int? previousLimit, string? partialKind = null)
    {
        int previous = Bounded(previousLimit is not null and not 0 ? JsonValue.Create(previousLimit.Value) : state?["current_limit"]);
        int current = previous, consecutive = N(state?["consecutive_completed"]);
        bool recovery = B(state?["recovery_mode"]);
        string action = "keep", reason = "stable";
        if (status == "partial_timeout" && partialKind == "failure") { consecutive = 0; reason = "functional_partial_failure"; }
        else if (status is "partial_timeout" or "timeout") {
            current = Math.Max(options.SecurityMin, Math.Max(1, previous / 2)); consecutive = 0; recovery = true;
            action = "decrease_limit"; reason = status;
        }
        else if (status == "completed") {
            consecutive++;
            if (consecutive >= options.GrowAfter) {
                if (options.FastRecovery && (lagMinutes is null || lagMinutes > options.RecoveryOn)) {
                    current = Math.Min(options.SecurityMax, Math.Min(options.SecurityTarget,
                        Math.Max((int)(previous * options.SecurityFactor), Math.Max(previous + options.SecurityStep, previous))));
                    reason = "completed_fast_recovery";
                }
                else { current = Math.Min(options.SecurityMax, previous + options.SecurityStep); reason = "completed_streak"; }
                consecutive = 0; action = current != previous ? "increase_limit" : "keep";
            }
            else reason = $"completed_streak_{consecutive}";
        }
        else if (status == "failed") { consecutive = 0; reason = "functional_failure"; }
        if (lagMinutes > options.RecoveryOn) recovery = true;
        else if (status == "completed" && lagMinutes < options.RecoveryOff) recovery = false;
        var result = Transition(previous, current, consecutive, recovery, status, lagMinutes, action, reason);
        result["inserted"] = inserted; result["skipped"] = skipped;
        return result;
    }

    public JsonObject NonSecurityTransition(JsonObject? state, string status, int? previousLimit, bool truncated, string? partialKind = null)
    {
        int baseline = Math.Max(1, options.OtherSize);
        int previous = Math.Max(1, previousLimit is not null and not 0 ? previousLimit.Value : N(state?["current_limit"], baseline));
        int current = previous;
        bool recovery = B(state?["recovery_mode"]);
        string action = "keep", reason = "stable";
        if (truncated) {
            current = Math.Min(options.OtherRecoveryMax, Math.Max(baseline, Math.Max(previous * 2, previous + options.OtherStep)));
            recovery = true; action = current > previous ? "increase_limit" : "keep"; reason = "bounded_limit_before_source_boundary";
        }
        else if (status == "completed") { current = baseline; recovery = false; action = "exit_recovery"; reason = "source_boundary_reached"; }
        else if (status is "timeout" or "partial_timeout" && partialKind != "failure") {
            current = Math.Max(baseline, previous / 2); recovery = true; action = current < previous ? "decrease_limit" : "keep"; reason = status;
        }
        return Transition(previous, current, 0, recovery, status, null, action, reason);
    }

    private JsonObject Transition(int previous, int current, int consecutive, bool recovery, string status, int? lag, string action, string reason) => new() {
        ["previous_limit"] = previous, ["current_limit"] = current, ["consecutive_completed"] = consecutive, ["recovery_mode"] = recovery,
        ["last_status"] = status, ["last_lag_minutes"] = lag, ["action"] = action, ["reason"] = reason,
        ["last_action"] = $"{action}:{reason}; {previous}->{current}; recovery={(recovery ? "on" : "off")}",
        ["updated_at"] = clock.GetUtcNow().ToString("O")
    };
}
