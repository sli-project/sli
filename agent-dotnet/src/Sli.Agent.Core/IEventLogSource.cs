namespace Sli.Agent.Core;

/// <summary>One event as read: its XML and the bookmark that marks the position right after it.</summary>
public sealed record EventRow(string Xml, string Bookmark);

/// <summary>
/// A bounded read. <see cref="BookmarkRecovered"/> says the saved anchor was gone and the source resumed by record id,
/// so continuity across it is unknown (the Python <c>BookmarkRecoveryBatch</c>).
/// </summary>
public sealed record SourceBatch(IReadOnlyList<EventRow> Rows, bool BookmarkRecovered = false);

/// <summary>Reads the next events of a channel after a saved position. Windows implements it with the Event Log API.</summary>
public interface IEventLogSource
{
    /// <exception cref="EventLogReadException">A native failure; the module turns it into a gap packet without data.</exception>
    SourceBatch Read(string channel, ChannelProgress progress, int limit);
}
