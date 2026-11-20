using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

/// <summary>The existing Python Defender payload. Null remains unknown and is never coerced to healthy.</summary>
public static class ProtectionSnapshot
{
    private static readonly string[] Components = ["antivirus_enabled", "real_time_protection_enabled",
        "behavior_monitor_enabled", "ioav_protection_enabled", "nis_enabled", "tamper_protected"];

    public static JsonObject Unavailable() => new()
    {
        ["state"] = "unavailable",
        ["components"] = new JsonObject(Components.Select(key => new KeyValuePair<string, JsonNode?>(key, null))),
    };

    public static JsonObject Validate(JsonObject value)
    {
        if (!JsonRead.HasExactly(value, "state", "components")
            || !JsonRead.TryString(value["state"], out var state) || state is not ("available" or "unavailable")
            || value["components"] is not JsonObject components || !JsonRead.HasExactly(components, Components)
            || components.Any(pair => pair.Value is not null && (pair.Value is not JsonValue item || !item.TryGetValue<bool>(out _)))
            || state == "unavailable" && components.Any(pair => pair.Value is not null))
            throw new AgentException("agent_workstations_protection_invalid");
        return (JsonObject)value.DeepClone();
    }

    public static JsonObject FromDefenderOutput(int exitCode, string output)
    {
        if (exitCode != 0 || output.Length > 4096) return Unavailable();
        try
        {
            return Validate(new JsonObject { ["state"] = "available", ["components"] = JsonNode.Parse(output) });
        }
        catch (Exception exception) when (exception is JsonException or AgentException or ArgumentException)
        {
            return Unavailable();
        }
    }
}
