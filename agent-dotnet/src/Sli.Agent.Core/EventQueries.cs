using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

/// <summary>
/// A compact Event Log prefilter from the collection table, with cursor and time bounds.
/// Exact identity and replication-right checks run before an event enters a packet.
/// </summary>
public static class EventQueries
{
    /// <summary>The catalog filter for Security; other channels are read unfiltered and admitted later by identity.</summary>
    public static string? CatalogFilter(string channel, ChannelProgress progress, EventCatalog catalog)
    {
        if (channel != "Security") return null;
        var groups = new List<List<int>>();
        foreach (var id in catalog.EventIds(channel))
        {
            // Keep 4662 separate so its neighbouring file-access events never widen the DC query.
            if (groups.Count > 0 && id - groups[^1][^1] <= 16 && id != 4662 && groups[^1][^1] != 4662) groups[^1].Add(id);
            else groups.Add([id]);
        }
        var terms = groups.Select(group => group.Count == 1
            ? $"EventID={group[0]}"
            : $"(EventID >= {group[0]} and EventID <= {group[^1]})").ToList();
        // A pre-upgrade bookmark may point at a filtered-out event: keep that anchor queryable.
        if (progress.Bookmark.Length > 0 && progress.RecordId is { } anchor) terms.Add($"EventRecordID={anchor}");
        return string.Join(" or ", terms);
    }

    public static string Build(string channel, ChannelProgress progress, EventCatalog catalog)
    {
        var filter = CatalogFilter(channel, progress, catalog);
        var hasBookmark = progress.Bookmark.Length > 0;
        var after = progress.RecordId;
        var selector = hasBookmark || after is null ? "*" : $"*[System[EventRecordID > {after}]]";
        if (filter is not null)
        {
            var bound = hasBookmark || after is null ? string.Empty : $" and EventRecordID > {after}";
            selector = $"*[System[({filter}){bound}]]";
        }
        var bounds = new List<string>();
        if (progress.SinceUtc is not null && !hasBookmark) bounds.Add($"TimeCreated[@SystemTime >= '{UtcText(progress.SinceUtc)}']");
        if (progress.BeforeUtc is not null) bounds.Add($"TimeCreated[@SystemTime < '{UtcText(progress.BeforeUtc)}']");
        if (bounds.Count == 0) return selector;
        if (after is not null && !hasBookmark) bounds.Add($"EventRecordID > {after}");
        if (filter is not null) bounds.Add($"({filter})");
        return "*[System[" + string.Join(" and ", bounds) + "]]";
    }

    private static string UtcText(string text)
    {
        if (!Iso8601.TryParseUtc(text, out var value)) throw new AgentException("agent_ad_dc_cursor_invalid");
        return Iso8601.Format(value).Replace("+00:00", "Z", StringComparison.Ordinal);
    }
}
