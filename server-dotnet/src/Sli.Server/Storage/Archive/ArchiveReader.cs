using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sli.Server.Storage.Archive;

internal sealed class ArchiveReader(string? root, IArchiveManifestStore manifest)
{
    readonly ArchiveObjectStore? objects = root is null ? null : new(root,initialize:false);
    internal byte[] VerifyFile(ArchiveBlock block, bool requirePublished = true)
    {
        ArchiveCodec.Kind(block.Kind);
        if ((requirePublished && block.State != "published") || block.State == "quarantined" || block.Version != 1 || block.Index < 0 || block.Rows is < 1 or > ArchiveCodec.MaxRows || block.FirstId <= 0 || block.LastId < block.FirstId)
            throw new InvalidDataException("archive_manifest_invalid");
        if (objects is not null) objects.RequirePath(block.ObjectLocation);
        else
        {
            // Link hydration can use the persisted manifest without a configured
            // archive root. Still reject relative paths and every reparse ancestor.
            if (block.Kind != "link_detail") throw new InvalidDataException("event_archive_root_required");
            if (!Path.IsPathFullyQualified(block.ObjectLocation)) throw new InvalidDataException("archive_object_outside_root");
            new ArchiveObjectStore(Path.GetDirectoryName(block.ObjectLocation)!, initialize:false).RequirePath(block.ObjectLocation);
        }
        var compressed = ArchiveObjectStore.ReadBounded(block.ObjectLocation, block.CompressedBytes);
        if (!string.Equals(ArchiveCodec.Hash(compressed), block.ArchiveSha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("archive_compressed_hash_mismatch");
        var raw = ArchiveCodec.Decompress(compressed, block.RawBytes);
        if (!string.Equals(ArchiveCodec.Hash(raw), block.RawSha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("archive_raw_hash_mismatch");
        return raw;
    }
    internal IReadOnlyList<JsonObject> ReadBlockRows(ArchiveBlock block) => ReadBlockRowsCancellable(block,CancellationToken.None);
    internal IReadOnlyList<JsonObject> ReadBlockRowsCancellable(ArchiveBlock block, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        byte[] raw = VerifyFile(block);
        ct.ThrowIfCancellationRequested();
        if (raw[^1] != 10) throw new InvalidDataException("archive_jsonl_invalid");
        var rows = new List<JsonObject>();
        try
        {
            foreach (var line in new UTF8Encoding(false,true).GetString(raw).Split('\n').SkipLast(1))
            {
                if (rows.Count >= block.Rows || JsonNode.Parse(line) is not JsonObject envelope || envelope["kind"]?.GetValue<string>() != block.Kind || envelope["row"] is not JsonObject row)
                    throw new InvalidDataException("archive_envelope_invalid");
                rows.Add((JsonObject)row.DeepClone());
            }
        }
        catch (Exception error) when (error is JsonException or DecoderFallbackException or InvalidOperationException)
        { throw new InvalidDataException("archive_jsonl_invalid", error); }
        if (rows.Count != block.Rows) throw new InvalidDataException("archive_row_count_mismatch");
        var encoded = ArchiveCodec.EncodeCancellable(block.Kind, rows, ct);
        if (encoded.First != block.FirstId || encoded.Last != block.LastId || !encoded.Raw.AsSpan().SequenceEqual(raw)) throw new InvalidDataException("archive_row_contract_mismatch");
        return rows;
    }
    internal async Task<IReadOnlyList<JsonObject>> ReadRowsForEventAsync(string kind, long id, CancellationToken ct)
    {
        ArchiveCodec.Kind(kind);
        var block = await manifest.FindPublishedAsync(kind, id, ct) ?? throw new FileNotFoundException("archive_published_block_unavailable");
        var rows = ReadBlockRows(block).Where(x => ArchiveCodec.Id(x, kind) == id).ToArray();
        if (rows.Length == 0 || (kind == "event" && rows.Length != 1)) throw new InvalidDataException("archive_event_missing_or_duplicate");
        return rows;
    }

    internal async Task<Dictionary<long,JsonObject>> ReadEventsManyAsync(IEnumerable<long> ids, int maxBlocks, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var requested = ids.ToHashSet();
        if (requested.Count == 0) return [];
        if (maxBlocks is < 1 or > 64) throw new ArgumentOutOfRangeException(nameof(maxBlocks), "event archive max_blocks must be between 1 and 64");
        var blocks = await manifest.FindPublishedRangeAsync("event",requested.Min(),requested.Max(),maxBlocks+1,ct);
        if (blocks.Count > maxBlocks) throw new InvalidDataException("event_archive_block_limit");
        var result = new Dictionary<long,JsonObject>();
        foreach (var block in blocks)
        {
            if (block.Kind != "event") throw new InvalidDataException("event_archive_kind_invalid");
            foreach (var row in ReadBlockRowsCancellable(block,ct))
            {
                ct.ThrowIfCancellationRequested();
                long id = ArchiveCodec.Id(row,"event");
                if (requested.Contains(id) && !result.TryAdd(id,row)) throw new InvalidDataException("event_archive_duplicate");
            }
        }
        if (result.Count != requested.Count) throw new KeyNotFoundException("event archive is missing requested identities");
        return result;
    }

    internal async Task<Dictionary<long, JsonObject>> ReadEntityDetailsManyAsync(IEnumerable<long> entityIds, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var requested = entityIds.ToHashSet();
        var result = new Dictionary<long, JsonObject>();
        if (requested.Count == 0) return result;
        var blocks = await manifest.FindPublishedRangeAsync("entity_detail", requested.Min(), requested.Max(), ct);
        foreach (var block in blocks)
        {
            if (block.Kind != "entity_detail") throw new InvalidDataException("archive_kind_mismatch");
            foreach (var row in ReadBlockRowsCancellable(block, ct))
            {
                ct.ThrowIfCancellationRequested();
                long id = ArchiveCodec.Id(row, "entity_detail");
                if (requested.Contains(id)) result[id] = row;
            }
        }
        if (result.Count != requested.Count) throw new KeyNotFoundException("entity_archive_requested_identities_missing");
        ct.ThrowIfCancellationRequested();
        return result;
    }

    internal async Task<Dictionary<long, List<JsonObject>>> ReadLinkDetailsManyAsync(IEnumerable<long> eventIds, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var requested = eventIds.ToHashSet();
        var result = new Dictionary<long, List<JsonObject>>();
        if (requested.Count == 0) return result;
        var blocks = await manifest.FindPublishedRangeAsync("link_detail", requested.Min(), requested.Max(), ct);
        foreach (var block in blocks)
        {
            if (block.Kind != "link_detail") throw new InvalidDataException("archive_kind_mismatch");
            foreach (var row in ReadBlockRowsCancellable(block, ct))
            {
                ct.ThrowIfCancellationRequested();
                long id = ArchiveCodec.Id(row, "link_detail");
                if (!requested.Contains(id)) continue;
                if (!result.TryGetValue(id, out var details)) result[id] = details = [];
                details.Add(row);
            }
        }
        ct.ThrowIfCancellationRequested();
        return result;
    }

    internal JsonObject ReadEventFromBlock(ArchiveBlock block, long id, Dictionary<ArchiveBlock, IReadOnlyList<JsonObject>> cache, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (!cache.TryGetValue(block, out var rows)) cache.Add(block, rows = ReadBlockRowsCancellable(block, ct));
        return rows.SingleOrDefault(x => ArchiveCodec.Id(x, "event") == id)?.DeepClone().AsObject()
            ?? throw new InvalidDataException("archive_event_missing_or_duplicate");
    }
    internal async Task<IReadOnlyDictionary<long, JsonObject>> ReadEventsManyAsync(IEnumerable<long> eventIds, CancellationToken ct)
    {
        var result = new Dictionary<long, JsonObject>();
        var cache = new Dictionary<ArchiveBlock, IReadOnlyList<JsonObject>>();
        foreach (long id in eventIds.Distinct().Order())
        {
            if (id <= 0) throw new ArgumentOutOfRangeException(nameof(eventIds));
            var block = await manifest.FindPublishedAsync("event", id, ct) ?? throw new KeyNotFoundException("event archive is missing requested identities");
            result.Add(id, ReadEventFromBlock(block, id, cache, ct));
        }
        return result;
    }
}
