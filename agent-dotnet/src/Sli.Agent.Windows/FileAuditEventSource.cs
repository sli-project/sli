using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Agent.Windows;

/// <summary>Only a proved missing/replaced anchor permits a new file-audit generation.</summary>
[SupportedOSPlatform("windows")]
public sealed class FileAuditEventSource(FileAuditPolicy policy) : IFileAuditEventSource
{
    private readonly string _filter = Filter(policy);

    internal static string Filter(FileAuditPolicy policy)
    {
        var ids = policy.Workstation
            ? FileAuditPolicy.Events.Concat(FileAuditPolicy.ContextEvents.Where(id => id != 1102))
                .Concat([4658,4664])
            : FileAuditPolicy.ServerFileEvents.Concat(policy.OptionalEvents ? [4658] : Array.Empty<int>());
        return "(Provider[@Name='" + FileAuditPolicy.Provider + "'] and (" +
            string.Join(" or ",ids.Select(id => $"EventID={id}")) +
            ")) or (Provider[@Name='Microsoft-Windows-Eventlog'] and EventID=1102)";
    }
    public SourceBatch Read(JsonObject progress,int limit)
    {
        try { return ReadCore(progress,limit); }
        catch (Exception e) when (e is not OperationCanceledException and not FileAuditJournalGap)
        {
            if (ProveGap(progress)) throw new FileAuditJournalGap();
            throw new EventLogReadException(code:"file_audit_read_failed");
        }
    }
    private SourceBatch ReadCore(JsonObject progress,int limit)
    {
        var after=progress["record_id"]?.GetValue<long>(); var bookmark=progress["bookmark"]!.ToString();
        var bound=after is null ? "" : $" and EventRecordID {(bookmark.Length>0 ? ">=" : ">")} {after.Value.ToString(CultureInfo.InvariantCulture)}";
        var time=bookmark.Length == 0 && progress["since_utc"] is not null ? $" and TimeCreated[@SystemTime >= '{Iso8601.Format(Iso8601.ParseUtc(progress["since_utc"]!.ToString())).Replace("+00:00","Z",StringComparison.Ordinal)}']" : "";
        // Keep an old anchor queryable even when it predates this selector.
        var filter=bookmark.Length>0 && after is not null ? $"({_filter}) or EventRecordID={after.Value.ToString(CultureInfo.InvariantCulture)}" : _filter;
        using var reader=new EventLogReader(new EventLogQuery("Security",PathType.LogName,$"*[System[({filter}){bound}{time}]]")) {BatchSize=limit};
        if (bookmark.Length>0)
        {
            reader.Seek(new EventBookmark(bookmark),0); using var anchor=reader.ReadEvent(TimeSpan.FromSeconds(1));
            if (anchor is null || anchor.RecordId != after) throw new EventLogReadException();
            if (progress["anchor_sha256"] is not null && Hash(anchor.ToXml()) != progress["anchor_sha256"]!.ToString()) throw new FileAuditJournalGap();
        }
        var rows=new List<EventRow>();
        var wait=progress.ContainsKey("since_utc") ? TimeSpan.FromSeconds(5) : TimeSpan.FromSeconds(1);
        while (rows.Count<limit) { using var record=reader.ReadEvent(wait); if (record is null) break; rows.Add(new(record.ToXml(),record.Bookmark.BookmarkXml)); }
        return new(rows);
    }
    private static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    private static bool ProveGap(JsonObject progress)
    {
        if (progress["record_id"] is null) return false;
        try
        {
            var after=progress["record_id"]!.GetValue<long>();
            using var newestReader=new EventLogReader(new EventLogQuery("Security",PathType.LogName,"*") {ReverseDirection=true});
            using var oldestReader=new EventLogReader(new EventLogQuery("Security",PathType.LogName,"*"));
            using var newest=newestReader.ReadEvent(TimeSpan.FromSeconds(1)); using var oldest=oldestReader.ReadEvent(TimeSpan.FromSeconds(1));
            if (newest is null || oldest is null) return false;
            if (newest.RecordId<after || oldest.RecordId>after) return true;
            if (progress["anchor_sha256"] is null) return false;
            using var anchorReader=new EventLogReader(new EventLogQuery("Security",PathType.LogName,$"*[System[EventRecordID={after.ToString(CultureInfo.InvariantCulture)}]]"));
            using var anchor=anchorReader.ReadEvent(TimeSpan.FromSeconds(1)); return anchor is not null && Hash(anchor.ToXml()) != progress["anchor_sha256"]!.ToString();
        }
        catch (Exception e) when (e is not OperationCanceledException) { return false; }
    }
}
