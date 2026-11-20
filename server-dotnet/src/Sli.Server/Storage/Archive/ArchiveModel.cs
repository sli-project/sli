using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Server.Storage.Archive;

internal sealed record ArchiveSet(Guid Id, string Kind, long FirstId, long LastId, int Rows, int Version = 1);
internal sealed record ArchiveBlock(Guid SetId, string Kind, int Version, int Index, long FirstId, long LastId,
    int Rows, long RawBytes, long CompressedBytes, string RawSha256, string ArchiveSha256,
    string ObjectLocation, string State, DateTime CreatedAt, DateTime? VerifiedAt = null);
internal sealed record ArchiveDirectResult(Guid EventSetId, Guid? LinkSetId, IReadOnlyList<JsonObject> VerifiedLinkRows);

internal interface IArchiveManifestStore
{
    Task EnsureSetAsync(ArchiveSet set, CancellationToken ct);
    Task<ArchiveBlock?> GetAsync(Guid id, string kind, int index, CancellationToken ct);
    Task<ArchiveBlock> StageAsync(ArchiveBlock block, CancellationToken ct);
    Task<ArchiveBlock> MarkPublishedAsync(ArchiveBlock block, CancellationToken ct);
    Task<ArchiveBlock?> FindPublishedAsync(string kind, long eventId, CancellationToken ct);
    Task<IReadOnlyList<ArchiveBlock>> FindPublishedRangeAsync(string kind, long firstId, long lastId, CancellationToken ct);
    Task<IReadOnlyList<ArchiveBlock>> FindPublishedRangeAsync(string kind, long firstId, long lastId, int limit, CancellationToken ct);
}

internal static class ArchiveCodec
{
    internal const int MaxRawBytes = 64 * 1024 * 1024, MaxCompressedBytes = 64 * 1024 * 1024, MaxRows = 100000;
    internal static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));
    internal static byte[] Canonical(JsonNode node) => new UTF8Encoding(false, true).GetBytes(CanonicalJson.Serialize(node, ensureAscii: false));
    internal static void Kind(string kind) { if (kind is not ("event" or "link_detail" or "entity_detail")) throw new InvalidDataException("archive_kind_unsupported"); }
    internal static long Id(JsonObject row, string kind)
    {
        if (!long.TryParse(row[kind == "link_detail" ? "event_id" : "id"]?.ToJsonString(), NumberStyles.None, CultureInfo.InvariantCulture, out var id) || id <= 0)
            throw new InvalidDataException("archive_event_id_invalid");
        return id;
    }
    internal static (byte[] Raw, long First, long Last) Encode(string kind, IReadOnlyList<JsonObject> rows) => EncodeCancellable(kind,rows,CancellationToken.None);
    internal static (byte[] Raw, long First, long Last) EncodeCancellable(string kind, IReadOnlyList<JsonObject> rows, CancellationToken ct)
    {
        Kind(kind);
        if (rows.Count is < 1 or > MaxRows) throw new InvalidDataException("archive_rows_out_of_bounds");
        var candidates = new List<(long Id, JsonObject Row, byte[] Canonical)>();
        long total = 0;
        int overhead = Encoding.UTF8.GetByteCount("{\"kind\":\"" + kind + "\",\"row\":") + 2;
        foreach (var row in rows)
        {
            var canonical = Canonical(row);
            total += canonical.Length + overhead;
            if (total > MaxRawBytes) throw new InvalidDataException("archive_raw_out_of_bounds");
            candidates.Add((Id(row,kind),row,canonical));
        }
        ct.ThrowIfCancellationRequested();
        var ordered = candidates.OrderBy(x => x.Id).ThenBy(x => x.Canonical, Comparer<byte[]>.Create((a,b) => a.AsSpan().SequenceCompareTo(b))).ToArray();
        if (kind == "event" && ordered.Select(x => x.Id).Distinct().Count() != rows.Count) throw new InvalidDataException("archive_duplicate_event");
        if (kind == "entity_detail" && ordered.Select(x => x.Id).Distinct().Count() != rows.Count) throw new InvalidDataException("archive_duplicate_entity");
        using var stream = new MemoryStream();
        foreach (var item in ordered)
        {
            var bytes = Canonical(new JsonObject { ["kind"] = kind, ["row"] = item.Row.DeepClone() });
            if (stream.Length + bytes.Length + 1 > MaxRawBytes) throw new InvalidDataException("archive_raw_out_of_bounds");
            stream.Write(bytes); stream.WriteByte(10);
        }
        return (stream.ToArray(), ordered[0].Id, ordered[^1].Id);
    }
    internal static byte[] Compress(byte[] raw)
    {
        using var stream = new MemoryStream();
        using (var gzip = new GZipStream(stream, CompressionLevel.Optimal, true)) gzip.Write(raw);
        var bytes = stream.ToArray();
        // BCL gzip has mtime=0. Explicitly fix the OS marker for reproducible objects across hosts.
        Array.Clear(bytes, 4, 4); bytes[9] = 255;
        if (bytes.Length > MaxCompressedBytes) throw new InvalidDataException("archive_compressed_out_of_bounds");
        return bytes;
    }
    internal static byte[] Decompress(byte[] compressed, long expected)
    {
        if (expected is < 1 or > MaxRawBytes) throw new InvalidDataException("archive_raw_out_of_bounds");
        using var input = new MemoryStream(compressed, false);
        using var gzip = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        byte[] buffer = new byte[8192]; int read;
        while ((read = gzip.Read(buffer)) != 0)
        { if (output.Length + read > expected) throw new InvalidDataException("archive_decompressed_size_mismatch"); output.Write(buffer, 0, read); }
        if (output.Length != expected) throw new InvalidDataException("archive_decompressed_size_mismatch");
        return output.ToArray();
    }
    internal static Guid SetId(string identity, string kind, long first, long last)
    {
        var ns = Guid.Parse("6ba7b811-9dad-11d1-80b4-00c04fd430c8");
        var name = FormattableString.Invariant($"adlog:direct:{identity}:{kind}:{first}:{last}");
        var bytes = SHA1.HashData([..ns.ToByteArray(bigEndian: true), ..Encoding.UTF8.GetBytes(name)]);
        bytes[6] = (byte)((bytes[6] & 15) | 0x50); bytes[8] = (byte)((bytes[8] & 63) | 0x80);
        return new Guid(bytes.AsSpan(0,16), bigEndian: true);
    }
}
