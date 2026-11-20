using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

/// <summary>
/// The normalized module configuration of <c>sli.windows.ad-dc</c>. The server hands it over already normalized
/// (<c>server/sli/plugins/ad/agent_policy.py: build_ad_policy</c>) and compares the packet's context with it.
/// </summary>
public sealed record AdDcConfig(
    string SourceName,
    string ConnectAddress,
    string PolicyRevision,
    int BatchSize,
    IReadOnlyDictionary<string, string> ChannelGenerations,
    IReadOnlyDictionary<string, bool> Channels,
    IReadOnlyList<int>? AllowEventIds,
    int? InitialReadHours)
{
    /// <summary>The channels in rotation order: all of them, or the original three for an older policy.</summary>
    public IReadOnlyList<string> RotationChannels => DcCursor.Channels.Where(Channels.ContainsKey).ToList();

    public const int MaxPayloadBytes = 44 * 1024;
    // Local PostgreSQL capacity: 8-event packets reach 1124 packets/minute.
    // Add 20% and round up to a 16-packet catch-up cycle: 1360/minute.
    public const int DefaultRateLimitPerMinute = 1360;
    private static readonly string[] Allowed =
        ["source_name", "connect_address", "policy_revision", "batch_size", "channel_generations", "channels", "allow_event_ids", "initial_read_hours"];

    /// <summary><c>null</c> means <c>"all"</c>: no lower time bound on the first read.</summary>
    public static AdDcConfig Parse(JsonObject? config, EventCatalog catalog)
    {
        static AgentException Invalid() => new("agent_ad_dc_config_invalid");

        config ??= [];
        if (config.Any(pair => !Allowed.Contains(pair.Key))) throw Invalid();

        string Text(string name, string? fallback = null)
        {
            if (!config.ContainsKey(name) && fallback is not null) return fallback;
            if (!JsonRead.TryString(config[name], out var value) || string.IsNullOrWhiteSpace(value) || JsonRead.CodePoints(value) > 128) throw Invalid();
            return value;
        }

        var source = Text("source_name");
        var address = Text("connect_address");
        var revision = Text("policy_revision", "1");
        var batch = 32;
        if (config.ContainsKey("batch_size"))
        {
            if (!JsonRead.TryInteger(config["batch_size"], out var value) || value < 1 || value > 128) throw Invalid();
            batch = (int)value;
        }
        int? hours = 24;
        if (config.ContainsKey("initial_read_hours"))
        {
            if (JsonRead.TryString(config["initial_read_hours"], out var all) && all == "all") hours = null;
            else if (JsonRead.TryInteger(config["initial_read_hours"], out var value) && value >= 0 && value <= 876000) hours = (int)value;
            else throw Invalid();
        }
        var generations = new Dictionary<string, string>();
        if (config.ContainsKey("channel_generations"))
        {
            if (config["channel_generations"] is not JsonObject items) throw Invalid();
            foreach (var (channel, generation) in items)
            {
                if (!DcCursor.Channels.Contains(channel) || !JsonRead.TryString(generation, out var text) || string.IsNullOrWhiteSpace(text) || JsonRead.CodePoints(text) > 128) throw Invalid();
                generations[channel] = text;
            }
        }
        var channels = DcCursor.Channels.ToDictionary(name => name, _ => true);
        if (config.ContainsKey("channels"))
        {
            if (config["channels"] is not JsonObject items) throw Invalid();
            foreach (var (channel, enabled) in items)
            {
                if (!DcCursor.Channels.Contains(channel) || enabled is not JsonValue flag
                    || flag.GetValueKind() is not (System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False)) throw Invalid();
                channels[channel] = flag.GetValue<bool>();
            }
            // A policy signed before the later channels existed lists exactly the original three. It keeps rotating over
            // those three, as the server expects from that agent; the later channels are not enabled behind its back.
            if (items.Count == DcCursor.LegacyChannelCount && DcCursor.Channels.Take(DcCursor.LegacyChannelCount).All(items.ContainsKey))
                channels = DcCursor.Channels.Take(DcCursor.LegacyChannelCount).ToDictionary(name => name, name => channels[name]);
        }
        List<int>? allow = null;
        if (config.ContainsKey("allow_event_ids") && !JsonRead.IsNull(config["allow_event_ids"]))
        {
            if (config["allow_event_ids"] is not JsonArray list || list.Count > 512) throw Invalid();
            allow = [];
            foreach (var item in list)
            {
                if (!JsonRead.TryInteger(item, out var id) || id < int.MinValue || id > int.MaxValue || !catalog.KnownEventIds.Contains((int)id)) throw Invalid();
                allow.Add((int)id);
            }
        }
        return new AdDcConfig(source, address, revision, batch, generations, channels, allow, hours);
    }

    /// <summary>Shape of the Python <c>module.config</c>, used to compare with the server's policy.</summary>
    public JsonObject ToJson() => new()
    {
        ["source_name"] = SourceName,
        ["connect_address"] = ConnectAddress,
        ["policy_revision"] = PolicyRevision,
        ["batch_size"] = BatchSize,
        ["channel_generations"] = Sorted(ChannelGenerations, value => JsonValue.Create(value)),
        ["channels"] = Sorted(Channels, value => JsonValue.Create(value)),
        ["allow_event_ids"] = AllowEventIds is null ? null : new JsonArray(AllowEventIds.Select(id => (JsonNode?)JsonValue.Create(id)).ToArray()),
        ["initial_read_hours"] = InitialReadHours is { } hours ? JsonValue.Create(hours) : JsonValue.Create("all"),
    };

    private static JsonObject Sorted<T>(IReadOnlyDictionary<string, T> items, Func<T, JsonNode?> convert)
    {
        var result = new JsonObject();
        foreach (var (key, value) in items) result[key] = convert(value);
        return result;
    }
}
