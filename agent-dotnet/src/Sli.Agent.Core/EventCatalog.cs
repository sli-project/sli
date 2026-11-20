using System.Numerics;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

/// <summary>
/// The shared event meanings table shipped inside the agent and used by server policy generation.
/// </summary>
public sealed class EventCatalog
{
    private readonly HashSet<(string Channel, string Provider, int EventId)> _identities;
    private readonly HashSet<Guid> _replicationRights;
    private static readonly Regex GuidToken = new(@"(?<![0-9a-z-])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-z-])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public string PackId => AdDcModule.PackId;
    public IReadOnlyList<string> Channels { get; }
    public IReadOnlySet<int> KnownEventIds { get; }

    private EventCatalog(JsonArray events)
    {
        _identities = events.Where(item => item!["layer"]!.GetValue<string>() is "fact" or "summary")
            .Select(item => (item!["channel"]!.GetValue<string>(), item["provider"]!.GetValue<string>().ToLowerInvariant(), item["event_id"]!.GetValue<int>()))
            .ToHashSet();
        Channels = DcCursor.Channels.Where(channel => _identities.Any(item => item.Channel == channel)).ToArray();
        // Old signed policies may still list not_collected events. Accept the policy, but never send those events.
        KnownEventIds = events.Select(item => item!["event_id"]!.GetValue<int>()).ToHashSet();
        _replicationRights = events.Where(item => item!["event_id"]!.GetValue<int>() == 4662)
            .SelectMany(item => item!["replication_rights"]!.AsArray()).Select(item => Guid.Parse(item!.GetValue<string>())).ToHashSet();
    }

    public static EventCatalog Load()
    {
        using var stream = typeof(EventCatalog).Assembly.GetManifestResourceStream("event_storage_meanings.json")
            ?? throw new AgentException("agent_ad_dc_pack_invalid");
        var root = JsonNode.Parse(stream) as JsonObject ?? throw new AgentException("agent_ad_dc_pack_invalid");
        if (root["version"]?.GetValue<int>() != 1 || root["events"] is not JsonArray events)
            throw new AgentException("agent_ad_dc_pack_invalid");
        return new EventCatalog(events);
    }

    public bool Contains(string channel, string? provider, BigInteger? eventId) =>
        eventId is { } id && id >= int.MinValue && id <= int.MaxValue
        && _identities.Contains((channel, (provider ?? "None").ToLowerInvariant(), (int)id));

    public bool AcceptsPayload(JsonObject payload)
    {
        if (!JsonRead.TryString(payload["channel"], out var channel)
            || !JsonRead.TryString(payload["provider_name"], out var provider)
            || !JsonRead.TryInteger(payload["event_id"], out var id) || !Contains(channel, provider, id)) return false;
        if (id != 4662) return true;
        if (!JsonRead.TryString(payload["xml"], out var xml)) return false;
        XNamespace ns = EventXml.Namespace;
        return EventXml.ParseBounded(xml).Elements(ns + "EventData").Elements(ns + "Data")
            .Where(data => data.Attribute("Name")?.Value == "Properties")
            .SelectMany(data => GuidToken.Matches(data.Value).Cast<Match>())
            .Any(match => _replicationRights.Contains(Guid.Parse(match.Value)));
    }

    public IReadOnlyList<int> EventIds(string channel) =>
        _identities.Where(item => item.Channel == channel).Select(item => item.EventId).Distinct().Order().ToList();
}
