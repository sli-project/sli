using System.ComponentModel;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using Sli.Agent.Core;

namespace Sli.Agent.Windows;

/// <summary>
/// Reads a Windows Event Log channel with <see cref="EventLogReader"/> and resumes from a saved <see cref="EventBookmark"/>
/// (<c>sli_collect/bookmarked_eventlog.py: read_local</c>). The public API cannot make the bookmark seek strict, so the anchor
/// event is read back and its record id compared: a mismatch is a lost anchor, answered by resuming from the record id and
/// saying so (<see cref="SourceBatch.BookmarkRecovered"/>). Failures become allowlisted diagnostics, never event content.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class EventLogBookmarkSource(EventCatalog catalog, bool filterSecurity = true,
    WorkstationPolicy? workstation = null) : IEventLogSource
{
    /// <summary>The Python agent waits 1 s at the tail and 5 s while scanning a time-bounded first read.</summary>
    private static readonly TimeSpan TailWait = TimeSpan.FromSeconds(1);

    private static readonly TimeSpan ScanWait = TimeSpan.FromSeconds(5);

    public SourceBatch Read(string channel, ChannelProgress progress, int limit)
    {
        var stage = "query";
        try
        {
            if (progress.Bookmark.Length == 0) return new SourceBatch(ReadRows(channel, progress, limit, ref stage, anchor: null)!);
            var rows = ReadRows(channel, progress, limit, ref stage, progress.RecordId);
            if (rows is not null) return new SourceBatch(rows);
            // The anchor is gone: resume by record id, without the first-read time bound, and declare an unknown gap.
            var retry = progress with { Bookmark = string.Empty, SinceUtc = null };
            stage = "query";
            return new SourceBatch(ReadRows(channel, retry, limit, ref stage, anchor: null) ?? [], BookmarkRecovered: true);
        }
        catch (EventLogReadException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new EventLogReadException(Diagnose(exception, channel, progress, stage));
        }
    }

    /// <summary>Returns null when the saved anchor cannot be confirmed.</summary>
    private List<EventRow>? ReadRows(string channel, ChannelProgress progress, int limit, ref string stage, long? anchor)
    {
        var selector = workstation is not null ? EventQueries.BuildWorkstation(channel, progress, workstation)
            : filterSecurity ? EventQueries.Build(channel, progress, catalog)
            : progress.RecordId is { } id ? $"*[System[EventRecordID {(progress.Bookmark.Length > 0 ? ">=" : ">")} {id.ToString(System.Globalization.CultureInfo.InvariantCulture)}]]" : "*";
        var query = new EventLogQuery(channel, PathType.LogName, selector) { TolerateQueryErrors = false };
        using var reader = new EventLogReader(query) { BatchSize = Math.Clamp(limit, 1, 1024) };
        var wait = progress.SinceUtc is not null || progress.BeforeUtc is not null ? ScanWait : TailWait;
        if (anchor is { } expected)
        {
            stage = "bookmark";
            var bookmark = new EventBookmark(progress.Bookmark);
            stage = "seek";
            try
            {
                reader.Seek(bookmark, 0);
            }
            catch (EventLogException)
            {
                // Whatever the reason the anchor cannot be reached, the recovery read decides: if the log itself is
                // unreadable it fails the same way and is reported as a read error, never as a silent gap.
                return null;
            }
            stage = "anchor";
            using var first = reader.ReadEvent(wait);
            if (first?.RecordId != expected) return null;
        }
        stage = "read";
        var rows = new List<EventRow>();
        while (rows.Count < limit)
        {
            using var record = reader.ReadEvent(wait);
            if (record is null) break;
            stage = "render";
            rows.Add(new EventRow(record.ToXml(), record.Bookmark.BookmarkXml));
            stage = "read";
        }
        return rows;
    }

    private static int? WinError(Exception exception) => exception.HResult >> 16 == unchecked((short)0x8007) ? exception.HResult & 0xFFFF : null;

    private static EventLogDiagnostic Diagnose(Exception exception, string channel, ChannelProgress progress, string stage)
    {
        var name = exception.GetType().Name;
        var winError = exception is Win32Exception native ? native.NativeErrorCode : WinError(exception);
        return new EventLogDiagnostic(name.Length <= 64 ? name : "Exception", winError is >= 0 ? winError : null, exception.HResult, channel, progress.RecordId,
            progress.Bookmark.Length > 0, stage);
    }
}
