using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Operations;

namespace Sli.Server.Vpn;

// Mirrors worker_guard's component admission and recent-failure backoff.
// The host's PostgreSQL advisory lock remains the authority for live owners.
internal static class RadiusPluginLaunchGuard
{
    internal static bool Allowed(string component, JsonObject? state)
    {
        if (component is not ("radius-acquisition" or "radius-session-observation") || state is null) return false;
        var value = (Text(state, "desired_activation"), Text(state, "component_runtime"), Text(state, "admission_mode"));
        return value is ("enabled_manual", "running", "open")
            || component == "radius-session-observation" && value is ("disabled", "draining", "drain_only");
    }

    internal static string HeartbeatDirectory => Environment.GetEnvironmentVariable("SLI_PLUGIN_HEARTBEAT_DIR")
        ?? Path.Combine(AppContext.BaseDirectory, "data", "runtime");

    internal static async Task<int> RunAsync(string component, Func<Task<int>> run, DateTimeOffset now, string? directory = null)
    {
        var block = ReadRecentBlock(component, now, directory);
        if (block is null) return await run();
        block["decision"] = "refused_plugin_component_recent_failure";
        Console.Error.WriteLine(block.ToJsonString());
        return 10;
    }

    internal static JsonObject? ReadRecentBlock(string component, DateTimeOffset now, string? directory = null)
    {
        if (component is not ("radius-acquisition" or "radius-session-observation")) return null;
        return RecentBlock(component, OperationsFiles.ReadJson(Path.Combine(directory ?? HeartbeatDirectory, "plugin-" + component + ".json"), 65536), now);
    }

    internal static JsonObject? RecentBlock(string component, JsonObject? heartbeat, DateTimeOffset now)
    {
        if (heartbeat is null || Text(heartbeat, "plugin_id") != "sli.remote-access"
            || Text(heartbeat, "component_id") != component || Text(heartbeat, "status") != "blocked") return null;
        string? text = Text(heartbeat, "heartbeat_at_utc");
        // A timestamp without a zone is not trusted evidence of a recent block.
        if (text is null || !Regex.IsMatch(text, @"(?:Z|[+-]\d{2}:\d{2})\z", RegexOptions.CultureInvariant)
            || !DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out var stamp)) return null;
        double age = (now - stamp).TotalSeconds;
        // This is the reference retry policy after failure, not a running-cycle deadline.
        if (age < 0 || age >= 1800) return null;
        return new JsonObject {
            ["heartbeat_age_seconds"] = (long)Math.Round(age),
            ["retry_after_seconds"] = (long)Math.Round(1800 - age),
            ["phase"] = heartbeat["phase"]?.DeepClone()
        };
    }

    private static string? Text(JsonObject value, string key) => value[key] is JsonValue node && node.TryGetValue<string>(out var text) ? text : null;
}
