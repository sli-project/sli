using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Server.SourcePacks;

public sealed record RawEvent(string Position, JsonObject Payload)
{
    public string Fingerprint() => Convert.ToHexStringLower(SHA256.HashData(
        Encoding.UTF8.GetBytes(CanonicalJson.Serialize(Payload, ensureAscii: false))));
}

public sealed record CollectResult(IReadOnlyList<RawEvent> Events, string? NextCursor, bool HasMore = false);
public interface ICollector
{
    CollectResult Collect(string? cursor, int limit);
}

public sealed record CollectorSpec(string Kind, string Entry, string? Schedule = null)
{
    // A declaration is validated without loading code or contacting a source.
    public static CollectorSpec? Parse(JsonNode? value)
    {
        if (value is null || value is JsonObject { Count: 0 }) return null;
        if (value is not JsonObject obj) throw new ArgumentException("collector must be an object");
        string kind = obj["kind"]?.ToString().Trim() ?? "";
        if (kind is not ("pull" or "push" or "file")) throw new ArgumentException("collector kind is not supported");
        string entry = obj["entry"]?.ToString().Trim() ?? "";
        int separator = entry.IndexOf(':');
        if (separator <= 0 || separator == entry.Length - 1 ||
            !(entry[..separator].StartsWith("server.source_packs.", StringComparison.Ordinal) ||
              entry[..separator].StartsWith("sli_source_packs.", StringComparison.Ordinal)))
            throw new ArgumentException("collector entry is not allowed");
        string? schedule = obj["schedule"]?.ToString().Trim();
        return new(kind, entry, string.IsNullOrEmpty(schedule) ? null : schedule);
    }

    public ICollector Load(string path, int year, string? timezone = null) => Entry switch
    {
        LinuxAuth.CollectorEntry => new FileLineCollector(path, line => LinuxAuth.ParseLine(line, year, timezone)),
        _ => throw new NotSupportedException("source_pack_collector_not_implemented")
    };
}

public interface ICursorStore
{
    string? Get(string packId);
    void Set(string packId, string? cursor);
}

public sealed class MemoryCursorStore : ICursorStore
{
    private readonly Dictionary<string, string?> values = new(StringComparer.Ordinal);
    public string? Get(string packId) => values.GetValueOrDefault(packId);
    public void Set(string packId, string? cursor) => values[packId] = cursor;
}

public sealed record RunReport(string PackId, int Received, int Accepted, int Duplicates,
    string? CursorBefore, string? CursorAfter, bool HasMore);

public static class CollectorHost
{
    // One explicit pass; the requested batch size does not limit the lifetime of a process.
    public static RunReport RunOnce(string packId, ICollector collector, ICursorStore cursors,
        Func<string, IReadOnlyList<RawEvent>, int> sink, int limit = 1000)
    {
        if (limit < 1) throw new ArgumentException("collector limit out of bounds");
        string? before = cursors.Get(packId);
        var result = collector.Collect(before, limit);
        if (result.Events.Count > limit) throw new ArgumentException("collector returned more events than requested");
        var known = new HashSet<string>(StringComparer.Ordinal);
        var fresh = result.Events.Where(e => known.Add(e.Fingerprint())).ToArray();
        int accepted = fresh.Length > 0 ? sink(packId, fresh) : 0;
        cursors.Set(packId, result.NextCursor ?? before);
        return new(packId, result.Events.Count, accepted, result.Events.Count - fresh.Length,
            before, cursors.Get(packId), result.HasMore);
    }
}

public sealed class FileLineCollector(string path, Func<string, JsonObject?>? parse = null) : ICollector
{
    public CollectResult Collect(string? cursor, int limit)
    {
        long offset = string.IsNullOrEmpty(cursor) ? 0 : long.Parse(cursor, CultureInfo.InvariantCulture);
        var events = new List<RawEvent>();
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        file.Seek(offset, SeekOrigin.Begin);
        using var line = new MemoryStream();
        while (events.Count < limit)
        {
            line.SetLength(0);
            int current;
            while ((current = file.ReadByte()) >= 0)
            {
                line.WriteByte((byte)current);
                if (current == '\n') break;
            }
            if (current != '\n') break; // Keep the cursor before a partial final line.
            long position = offset;
            offset += line.Length;
            string text = Encoding.UTF8.GetString(line.GetBuffer(), 0, (int)line.Length).TrimEnd('\r', '\n');
            JsonObject? payload = parse is null ? new JsonObject { ["line"] = text } : parse(text);
            if (payload is not null) events.Add(new(position.ToString(CultureInfo.InvariantCulture), payload));
        }
        return new(events, offset.ToString(CultureInfo.InvariantCulture), file.ReadByte() >= 0);
    }
}
