using System.Globalization;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

public interface INpsEventLogReader : IDisposable
{
    void Seek(string bookmark);
    EventRow? Read();
}
public interface INpsEventLogReaders
{
    INpsEventLogReader Open(string selector, int batchSize);
}

/// <summary>Strict Python read_local semantics behind a native reader boundary, testable on Linux.</summary>
public sealed class NpsBookmarkSource(INpsEventLogReaders readers) : INpsEventSource
{
    public SourceBatch Read(JsonObject progress, int limit)
    {
        try
        {
            var after = progress["record_id"]?.GetValue<long>();
            var bookmark = progress["bookmark"]!.GetValue<string>();
            var selector = bookmark.Length > 0 || after is null ? "*" : $"*[System[EventRecordID > {after.Value.ToString(CultureInfo.InvariantCulture)}]]";
            using var reader = readers.Open(selector, limit);
            if (bookmark.Length > 0)
            {
                reader.Seek(bookmark);
                var anchor = reader.Read();
                if (anchor is null || !JsonRead.TryInteger(EventXml.Parse(anchor.Xml, "", "", "Security")["record_id"], out var id) || id != after
                    || progress["anchor_sha256"] is { } expected && NpsModule.Hash(anchor.Xml) != expected.GetValue<string>())
                    throw new EventLogReadException(code: "agent_nps_read_failed");
            }
            var rows = new List<EventRow>();
            while (rows.Count < limit)
            {
                var row = reader.Read();
                if (row is null) break;
                rows.Add(row);
            }
            return new(rows);
        }
        catch (Exception e) when (e is not OperationCanceledException) { throw new EventLogReadException(code: "agent_nps_read_failed"); }
    }
}
