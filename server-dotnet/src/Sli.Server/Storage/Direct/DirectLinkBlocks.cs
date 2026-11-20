namespace Sli.Server.Storage.Direct;

internal sealed record DirectLinkIdentity(long EventId, int EntityId, int RoleId);
internal sealed record DirectLinkBlockData(int EntityId, int BlockNo, long[] EventIds, short[] RoleIds, byte[] IdentitySha256);

// Pure block contract shared with the PostgreSQL writer. Hash keeps the legacy
// int32 encoding until a block actually needs int64 event identities.
internal static partial class DirectLinkBlock
{
    internal const int BlockSize = 512;
    internal static (int[] Entities,(int Entity,long Event,short Role)[] Pending) VerifiedReplayPlan(
        IReadOnlyList<(int Entity,long Event,short Role)> links,IReadOnlySet<(int Entity,long Event,short Role)> known) =>
        (links.Select(x=>x.Entity).Distinct().Order().ToArray(),links.Where(x=>!known.Contains(x)).ToArray());

    private static DirectLinkIdentity Identity(DirectLinkIdentity row)
    {
        if (row.EventId <= 0) throw new InvalidDataException("event identity exceeds positive int64 capacity");
        if (row.EntityId <= 0) throw new InvalidDataException("entity identity exceeds positive int32 capacity");
        if (row.RoleId is < 0 or > short.MaxValue) throw new InvalidDataException("role_id exceeds PostgreSQL smallint capacity");
        return row;
    }

    private static DirectLinkIdentity[] Incoming(IEnumerable<DirectLinkIdentity> rows)
    {
        var result = rows.Select(Identity).ToArray();
        if (result.Distinct().Count() != result.Length) throw new InvalidDataException("duplicate event/entity/role identity");
        return result;
    }

    private static IEnumerable<DirectLinkIdentity> Identities(IEnumerable<DirectLinkBlockData> blocks) =>
        blocks.SelectMany(block => block.EventIds.Zip(block.RoleIds,
            (id, role) => new DirectLinkIdentity(id, block.EntityId, role)));

    internal static IReadOnlyList<DirectLinkBlockData> Build(IEnumerable<DirectLinkIdentity> rows, int blockSize = BlockSize)
    {
        if (blockSize is < 1 or > BlockSize) throw new InvalidDataException("block_size must be between 1 and 512");
        var blocks = new List<DirectLinkBlockData>();
        foreach (var entity in Incoming(rows).OrderBy(x => x.EventId).ThenBy(x => x.RoleId).GroupBy(x => x.EntityId).OrderBy(x => x.Key))
        {
            int number = 0;
            foreach (var chunk in entity.Chunk(blockSize))
            {
                var pairs = chunk.Select(x => (x.EventId, RoleId: checked((short)x.RoleId))).ToArray();
                blocks.Add(new(entity.Key, number++, pairs.Select(x => x.EventId).ToArray(), pairs.Select(x => x.RoleId).ToArray(), Hash(entity.Key, pairs)));
            }
        }
        return blocks;
    }

    internal static void Validate(IReadOnlyList<DirectLinkBlockData> blocks)
    {
        var next = new Dictionary<int, int>();
        var previous = new Dictionary<int, (long EventId, short RoleId)>();
        foreach (var block in blocks)
        {
            if (block.BlockNo != next.GetValueOrDefault(block.EntityId)) throw new InvalidDataException("link block numbers are not contiguous from zero");
            next[block.EntityId] = block.BlockNo + 1;
            if (block.EventIds.Length is < 1 or > BlockSize) throw new InvalidDataException("link block size is outside the storage contract");
            if (block.EventIds.Length != block.RoleIds.Length) throw new InvalidDataException("link block parallel arrays have different lengths");
            var rows = block.EventIds.Zip(block.RoleIds, (id, role) => (EventId: id, RoleId: role)).ToArray();
            if (previous.TryGetValue(block.EntityId, out var prior) && Compare(prior, rows[0]) >= 0)
                throw new InvalidDataException("link block ranges overlap or are out of order");
            if (!Hash(block.EntityId, rows).AsSpan().SequenceEqual(block.IdentitySha256)) throw new InvalidDataException("link block identity SHA-256 mismatch");
            previous[block.EntityId] = rows[^1];
        }
    }

    internal static IReadOnlyList<DirectLinkBlockData> Append(IEnumerable<DirectLinkBlockData> existing, IEnumerable<DirectLinkIdentity> rows)
    {
        var current = existing.ToArray();
        var known = Identities(current).ToHashSet();
        var added = Incoming(rows).Except(known).ToArray();
        var maxima = current.GroupBy(x => x.EntityId).ToDictionary(x => x.Key, x => x.Last().EventIds[^1]);
        if (added.Any(x => maxima.TryGetValue(x.EntityId, out long max) && x.EventId <= max))
            throw new InvalidDataException("late or replayed non-identical link requires deterministic entity rebuild");
        return Build(known.Concat(added));
    }

    internal static IReadOnlyList<DirectLinkBlockData> AppendTail(DirectLinkBlockData? tail, IEnumerable<DirectLinkIdentity> rows)
    {
        var incoming = Incoming(rows);
        if (incoming.Length == 0) return [];
        if (incoming.Select(x => x.EntityId).Distinct().Count() != 1) throw new InvalidDataException("tail append accepts exactly one entity");
        if (tail is null) return Build(incoming);
        Validate([tail with { BlockNo = 0 }]);
        if (incoming[0].EntityId != tail.EntityId) throw new InvalidDataException("tail entity does not match incoming rows");
        if (incoming.Any(x => Compare((x.EventId, checked((short)x.RoleId)), (tail.EventIds[^1], tail.RoleIds[^1])) <= 0))
            throw new InvalidDataException("late or replayed non-identical link requires deterministic entity rebuild");
        return Build(Identities([tail]).Concat(incoming)).Select(x => x with { BlockNo = x.BlockNo + tail.BlockNo }).ToArray();
    }

    internal static IReadOnlyList<DirectLinkBlockData> RebuildSuffix(IReadOnlyList<DirectLinkBlockData> existing, IEnumerable<DirectLinkIdentity> rows)
    {
        if (existing.Count == 0) throw new InvalidDataException("suffix rebuild requires existing blocks");
        var incoming = Incoming(rows);
        var first = existing[0];
        if (existing.Any(x => x.EntityId != first.EntityId) || incoming.Any(x => x.EntityId != first.EntityId))
            throw new InvalidDataException("suffix entity does not match incoming rows");
        Validate(existing.Select(x => x with { BlockNo = x.BlockNo - first.BlockNo }).ToArray());
        return Build(Identities(existing).Concat(incoming)).Select(x => x with { BlockNo = x.BlockNo + first.BlockNo }).ToArray();
    }

    internal static void ValidateNoOrphans(IEnumerable<DirectLinkBlockData> blocks, IReadOnlySet<long> eventIds, IReadOnlySet<int> entityIds)
    {
        foreach (var block in blocks)
        {
            if (!entityIds.Contains(block.EntityId)) throw new InvalidDataException($"orphan entity_id {block.EntityId}");
            foreach (long id in block.EventIds)
                if (!eventIds.Contains(id)) throw new InvalidDataException($"orphan event_id {id}");
        }
    }
}
