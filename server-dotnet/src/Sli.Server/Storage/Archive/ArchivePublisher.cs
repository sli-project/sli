using System.Text.Json.Nodes;

namespace Sli.Server.Storage.Archive;

internal sealed class ArchivePublisher
{
    readonly IArchiveManifestStore manifest;
    readonly ArchiveObjectStore objects;
    readonly ArchiveReader reader;
    internal ArchivePublisher(string authorizedArchiveRoot, IArchiveManifestStore manifest, Action<string>? syncDirectory = null)
    { this.manifest = manifest; objects = new(authorizedArchiveRoot, syncDirectory); reader = new(authorizedArchiveRoot, manifest); }

    internal async Task<ArchiveDirectResult> PublishDirectAsync(string batchIdentity, IReadOnlyList<JsonObject> sourceEvents,
        IReadOnlyList<JsonObject> linkDetails, CancellationToken ct, Action? ownershipCheck = null)
    {
        var identity = batchIdentity.Trim();
        if (identity.Length == 0) throw new InvalidDataException("archive_batch_identity_required");
        var events = ArchiveCodec.Encode("event", sourceEvents);
        // Validate the entire requested batch before its first durable side effect.
        var links = linkDetails.Count == 0 ? default : ArchiveCodec.Encode("link_detail", linkDetails);
        var ids = sourceEvents.Select(x => ArchiveCodec.Id(x, "event")).ToHashSet();
        if (linkDetails.Any(x => !ids.Contains(ArchiveCodec.Id(x,"link_detail")))) throw new InvalidDataException("archive_link_outside_batch");
        Guid eventId = ArchiveCodec.SetId(identity, "event", events.First, events.Last);
        ownershipCheck?.Invoke();
        await PublishAsync(eventId, "event", events.Raw, events.First, events.Last, sourceEvents.Count, ct);
        if (linkDetails.Count == 0) return new(eventId, null, []);
        Guid linkId = ArchiveCodec.SetId(identity, "link_detail", events.First, events.Last);
        ownershipCheck?.Invoke();
        var block = await PublishAsync(linkId, "link_detail", links.Raw!, links.First, links.Last, linkDetails.Count, ct);
        var verified = reader.ReadBlockRows(block);
        if (!ArchiveCodec.Encode("link_detail", verified).Raw.AsSpan().SequenceEqual(links.Raw)) throw new InvalidDataException("archive_link_replay_mismatch");
        return new(eventId, linkId, verified);
    }

    internal async Task<ArchiveBlock> PublishEntityDetailsAsync(Guid setId, IReadOnlyList<JsonObject> rows, CancellationToken ct)
    {
        var encoded = ArchiveCodec.EncodeCancellable("entity_detail", rows, ct);
        return await PublishAsync(setId, "entity_detail", encoded.Raw, encoded.First, encoded.Last, rows.Count, ct);
    }

    async Task<ArchiveBlock> PublishAsync(Guid setId, string kind, byte[] raw, long first, long last, int rows, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        await manifest.EnsureSetAsync(new(setId, kind, first, last, rows), ct);
        var existing = await manifest.GetAsync(setId, kind, 0, ct);
        string rawHash = ArchiveCodec.Hash(raw);
        if (existing is not null)
        {
            if (existing.State is not ("staging" or "verified" or "published") || existing.Version != 1 || existing.RawBytes != raw.Length || !string.Equals(existing.RawSha256, rawHash, StringComparison.OrdinalIgnoreCase) || existing.Rows != rows || existing.FirstId != first || existing.LastId != last)
                throw new InvalidDataException("archive_identity_conflict");
            objects.RequirePath(existing.ObjectLocation);
            // The prior manifest's physical gzip/hash is authoritative, including Python-written objects.
            // Do not compare it with newly generated deflate bytes.
            if (File.Exists(existing.ObjectLocation))
            {
                var restored = reader.VerifyFile(existing, requirePublished: false);
                if (!restored.AsSpan().SequenceEqual(raw)) throw new InvalidDataException("archive_retry_payload_mismatch");
                if (existing.State == "published") return existing;
                objects.SyncPublicationDirectories(existing.ObjectLocation);
                return await manifest.MarkPublishedAsync(existing, ct);
            }
            if (existing.State == "published") throw new InvalidDataException("archive_published_object_missing");
            string oldName = Path.GetFileName(existing.ObjectLocation);
            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            if (!string.Equals(objects.Final(oldName), Path.GetFullPath(existing.ObjectLocation), comparison)) throw new InvalidDataException("archive_staged_location_invalid");
            string oldPartial = objects.Partial(oldName);
            if (File.Exists(oldPartial))
            {
                try
                {
                    var restored = reader.VerifyFile(existing with { ObjectLocation = oldPartial }, requirePublished: false);
                    if (!restored.AsSpan().SequenceEqual(raw)) throw new InvalidDataException("archive_retry_payload_mismatch");
                }
                catch (InvalidDataException)
                {
                    // Keep the manifest's physical identity authoritative. Quarantine the bad
                    // partial without replacing existing evidence, then fail this attempt.
                    objects.QuarantinePartial(oldName);
                    throw;
                }
                var oldCompressed = ArchiveObjectStore.ReadBounded(oldPartial, existing.CompressedBytes);
                objects.Publish(oldPartial, existing.ObjectLocation, oldCompressed);
                var recovered = await manifest.MarkPublishedAsync(existing, ct);
                _ = reader.ReadBlockRows(recovered);
                return recovered;
            }
        }
        var compressed = ArchiveCodec.Compress(raw);
        string hash = ArchiveCodec.Hash(compressed);
        if (existing is not null && !string.Equals(existing.ArchiveSha256, hash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("archive_staged_physical_encoding_unavailable");
        string name = FormattableString.Invariant($"{kind}-{setId:D}-{0:D8}-{first}-{last}-{hash[..16]}.jsonl.gz");
        string final = objects.Final(name), prepared = objects.Prepare(name, compressed);
        var block = new ArchiveBlock(setId, kind, 1, 0, first, last, rows, raw.Length, compressed.Length, rawHash, hash, final, "staging", DateTime.UtcNow, DateTime.UtcNow);
        // Verify both compressed and raw bytes before recording durable staging metadata.
        var roundtrip = reader.VerifyFile(block with { ObjectLocation = prepared }, requirePublished: false);
        if (!roundtrip.AsSpan().SequenceEqual(raw)) throw new InvalidDataException("archive_roundtrip_mismatch");
        block = await manifest.StageAsync(block, ct);
        objects.Publish(prepared, final, compressed);
        block = await manifest.MarkPublishedAsync(block, ct);
        _ = reader.ReadBlockRows(block);
        return block;
    }
}
