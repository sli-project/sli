using System.Buffers.Binary;
using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Storage.Archive;

// Wire-compatible with storage_v2_compact_archive.py. This block holds metadata only.
internal static class CompactLinkMetadata
{
    internal static (byte[] Compressed, JsonObject Evidence) Encode(IEnumerable<JsonObject> rows)
    {
        var ordered = rows.Select(row => (Identity: Identity(row), Row: row)).OrderBy(x => x.Identity).ToArray();
        if (ordered.Length == 0) throw new InvalidDataException("link metadata block cannot be empty");
        bool wide = ordered[^1].Identity.EventId > int.MaxValue;
        int version = wide ? 2 : 1, recordSize = wide ? 28 : 24;
        string[] dictionary = ordered.Select(x => ExtractedFrom(x.Row)).Distinct().Order(StringComparer.Ordinal).ToArray();
        if (dictionary.Length > ushort.MaxValue) throw new InvalidDataException("extracted_from dictionary exceeds uint16 capacity");
        var extractedIds = dictionary.Select((value, index) => (value, index)).ToDictionary(x => x.value, x => (ushort)x.index);
        long baseTimestamp = Timestamp(ordered[0].Row);
        using var identities = new MemoryStream();
        using var identityWriter = new BinaryWriter(identities, Encoding.UTF8, true);
        using var records = new MemoryStream();
        using var writer = new BinaryWriter(records, Encoding.UTF8, true);
        (long EventId, int EntityId, ushort RoleId)? previous = null;
        foreach (var item in ordered)
        {
            if (item.Identity == previous) throw new InvalidDataException("duplicate link identity");
            previous = item.Identity;
            float confidence = item.Row["confidence"] is null ? 1f : (float)double.Parse(item.Row["confidence"]!.ToString(), CultureInfo.InvariantCulture);
            if (!(confidence >= 0 && confidence <= 1)) throw new InvalidDataException("confidence must be between 0 and 1");
            WriteIdentity(identityWriter, item.Identity, wide);
            WriteIdentity(writer, item.Identity, wide);
            writer.Write(confidence);
            writer.Write(extractedIds[ExtractedFrom(item.Row)]);
            writer.Write(checked(Timestamp(item.Row) - baseTimestamp));
        }
        string identityHash = ArchiveCodec.Hash(identities.ToArray());
        var header = new JsonObject
        {
            ["format"] = $"storage-v2-link-metadata-v{version}", ["rows"] = ordered.Length,
            ["record_size"] = recordSize, ["base_timestamp_us"] = baseTimestamp,
            ["extracted_from"] = new JsonArray(dictionary.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray()),
            ["identity_sha256"] = identityHash
        };
        byte[] headerBytes = ArchiveCodec.Canonical(header);
        using var rawStream = new MemoryStream();
        using (var rawWriter = new BinaryWriter(rawStream, Encoding.UTF8, true))
        {
            rawWriter.Write(Encoding.ASCII.GetBytes($"SLILNK{version}\0"));
            rawWriter.Write((uint)headerBytes.Length);
            rawWriter.Write(headerBytes);
            rawWriter.Write(records.ToArray());
        }
        byte[] raw = rawStream.ToArray();
        using var compressedStream = new MemoryStream();
        using (var gzip = new GZipStream(compressedStream, CompressionLevel.Optimal, true)) gzip.Write(raw);
        byte[] compressed = compressedStream.ToArray();
        Array.Clear(compressed, 4, 4); compressed[9] = 255;
        return (compressed, new JsonObject
        {
            ["rows"] = ordered.Length, ["raw_bytes"] = raw.Length, ["compressed_bytes"] = compressed.Length,
            ["raw_sha256"] = ArchiveCodec.Hash(raw), ["compressed_sha256"] = ArchiveCodec.Hash(compressed),
            ["identity_sha256"] = identityHash, ["content_persisted"] = false
        });
    }

    internal static IReadOnlyList<JsonObject> Decode(byte[] compressed)
    {
        try { return DecodeCore(compressed); }
        catch (Exception error) when (error is JsonException or InvalidOperationException or FormatException or OverflowException or ArgumentException or EndOfStreamException)
        { throw new InvalidDataException("invalid compact link metadata block", error); }
    }

    static IReadOnlyList<JsonObject> DecodeCore(byte[] compressed)
    {
        using var input = new MemoryStream(compressed, false);
        using var gzip = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzip.CopyTo(output);
        byte[] raw = output.ToArray();
        if (raw.Length < 12 || !(raw.AsSpan(0, 8).SequenceEqual("SLILNK1\0"u8) || raw.AsSpan(0, 8).SequenceEqual("SLILNK2\0"u8)))
            throw new InvalidDataException("invalid compact link metadata magic");
        bool wide = raw[6] == '2';
        int version = wide ? 2 : 1, recordSize = wide ? 28 : 24;
        uint headerLength = BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(8));
        if (headerLength > raw.Length - 12) throw new InvalidDataException("invalid compact link metadata header");
        var header = JsonNode.Parse(raw.AsSpan(12, (int)headerLength)) as JsonObject
            ?? throw new InvalidDataException("invalid compact link metadata header");
        if (header["format"]?.GetValue<string>() != $"storage-v2-link-metadata-v{version}" || header["record_size"]?.GetValue<int>() != recordSize)
            throw new InvalidDataException("unsupported compact link metadata format");
        int offset = 12 + (int)headerLength, count = header["rows"]?.GetValue<int>() ?? -1;
        if (count < 0 || raw.Length - offset != (long)count * recordSize)
            throw new InvalidDataException("compact link metadata row framing mismatch");
        var dictionary = header["extracted_from"] as JsonArray ?? [];
        long baseTimestamp = header["base_timestamp_us"]!.GetValue<long>();
        using var payload = new MemoryStream(raw, offset, raw.Length - offset, false);
        using var reader = new BinaryReader(payload);
        using var identities = new MemoryStream();
        using var identityWriter = new BinaryWriter(identities);
        var decoded = new List<JsonObject>();
        (long EventId, int EntityId, ushort RoleId)? previous = null;
        for (int i = 0; i < count; i++)
        {
            (long EventId, int EntityId, ushort RoleId) identity = (wide ? reader.ReadInt64() : reader.ReadInt32(), reader.ReadInt32(), reader.ReadUInt16());
            float confidence = reader.ReadSingle();
            ushort extractedId = reader.ReadUInt16();
            long delta = reader.ReadInt64();
            if (previous is not null && identity.CompareTo(previous.Value) <= 0)
                throw new InvalidDataException("compact link identities are not strictly ordered");
            previous = identity;
            if (extractedId >= dictionary.Count) throw new InvalidDataException("compact link dictionary reference is out of range");
            WriteIdentity(identityWriter, identity, wide);
            var timestamp = DateTimeOffset.UnixEpoch.AddTicks(checked((baseTimestamp + delta) * 10));
            string format = timestamp.Ticks % TimeSpan.TicksPerSecond == 0 ? "yyyy-MM-dd'T'HH:mm:ss'Z'" : "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'";
            decoded.Add(new JsonObject
            {
                ["event_id"] = identity.EventId, ["entity_id"] = identity.EntityId, ["role_id"] = (int)identity.RoleId,
                ["confidence"] = (double)confidence, ["extracted_from"] = dictionary[extractedId]?.DeepClone(),
                ["created_at"] = timestamp.ToString(format, CultureInfo.InvariantCulture)
            });
        }
        if (ArchiveCodec.Hash(identities.ToArray()) != header["identity_sha256"]?.GetValue<string>())
            throw new InvalidDataException("compact link identity SHA-256 mismatch");
        return decoded;
    }

    static (long EventId, int EntityId, ushort RoleId) Identity(JsonObject row)
    {
        long eventId = Number(row, "event_id", long.MaxValue, "event identity exceeds positive int64 capacity");
        long entityId = Number(row, "entity_id", int.MaxValue, "entity identity exceeds positive int32 capacity");
        long roleId = Number(row, "role_id", ushort.MaxValue, "role_id exceeds uint16 capacity", allowZero: true);
        return (eventId, (int)entityId, (ushort)roleId);
    }

    static long Number(JsonObject row, string key, long max, string error, bool allowZero = false)
    {
        if (!long.TryParse(row[key]?.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out long value) || value < (allowZero ? 0 : 1) || value > max)
            throw new InvalidDataException(error);
        return value;
    }

    static string ExtractedFrom(JsonObject row) => row["extracted_from"]?.GetValue<string>() ?? "";

    static long Timestamp(JsonObject row)
    {
        string value = row["created_at"]?.GetValue<string>() ?? "";
        if (!Regex.IsMatch(value, @"(?:Z|[+-]\d{2}:\d{2})$", RegexOptions.CultureInvariant))
            throw new InvalidDataException("created_at must include timezone");
        if (!DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed))
            throw new InvalidDataException("created_at must be an ISO timestamp");
        // Match Python's round(datetime.timestamp() * 1_000_000).
        return checked((long)Math.Round((parsed.UtcTicks - DateTimeOffset.UnixEpoch.Ticks) / (double)TimeSpan.TicksPerSecond * 1_000_000));
    }

    static void WriteIdentity(BinaryWriter writer, (long EventId, int EntityId, ushort RoleId) identity, bool wide)
    {
        if (wide) writer.Write(identity.EventId); else writer.Write(checked((int)identity.EventId));
        writer.Write(identity.EntityId); writer.Write(identity.RoleId);
    }
}
