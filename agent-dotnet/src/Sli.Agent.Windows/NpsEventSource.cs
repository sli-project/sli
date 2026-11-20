using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using System.Text.Json.Nodes;
using Sli.Agent.Core;

namespace Sli.Agent.Windows;

/// <summary>NPS reads every Security record, as Python does. No missing-anchor recovery or invented tail coverage.</summary>
[SupportedOSPlatform("windows")]
public sealed class NpsEventSource : INpsEventSource
{
    public SourceBatch Read(JsonObject progress, int limit) => new NpsBookmarkSource(new Readers()).Read(progress, limit);
    private sealed class Readers : INpsEventLogReaders
    {
        public INpsEventLogReader Open(string selector, int batchSize) => new Reader(new EventLogReader(
            new EventLogQuery("Security", PathType.LogName, selector) { TolerateQueryErrors = false }) { BatchSize = batchSize });
    }
    private sealed class Reader(EventLogReader reader) : INpsEventLogReader
    {
        public void Seek(string bookmark) => reader.Seek(new EventBookmark(bookmark), 0);
        public EventRow? Read()
        {
            using var record = reader.ReadEvent(TimeSpan.FromSeconds(1));
            return record is null ? null : new(record.ToXml(), record.Bookmark.BookmarkXml);
        }
        public void Dispose() => reader.Dispose();
    }
}
