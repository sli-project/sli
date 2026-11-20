using System.Text.Json.Nodes;
using Sli.Server.Storage.Archive;
using Sli.Server.Storage.Direct;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Vectors from tests/storage/test_storage_v2_link_blocks.py.
public sealed class LinkBlockTests
{
    static DirectLinkIdentity Row(long id, int entity = 7, int role = 2) => new(id, entity, role);
    static void EqualBlocks(IReadOnlyList<DirectLinkBlockData> expected, IReadOnlyList<DirectLinkBlockData> actual)
    {
        Assert.Equal(expected.Count, actual.Count);
        for (int i = 0; i < expected.Count; i++)
        {
            Assert.Equal(expected[i].EntityId, actual[i].EntityId);
            Assert.Equal(expected[i].BlockNo, actual[i].BlockNo);
            Assert.Equal(expected[i].EventIds, actual[i].EventIds);
            Assert.Equal(expected[i].RoleIds, actual[i].RoleIds);
            Assert.Equal(expected[i].IdentitySha256, actual[i].IdentitySha256);
        }
    }
    static void Error(string message, Action action) => Assert.Contains(message, Assert.Throws<InvalidDataException>(action).Message);

    [Fact]
    public void Blocks_are_stable_sorted_parallel_and_bounded()
    {
        var rows = Enumerable.Range(1, 600).Reverse().Select(x => Row(x));
        var blocks = DirectLinkBlock.Build(rows);
        Assert.Equal(new[] { 0, 1 }, blocks.Select(x => x.BlockNo));
        Assert.Equal(Enumerable.Range(1, 512).Select(x => (long)x), blocks[0].EventIds);
        Assert.Equal(Enumerable.Range(513, 88).Select(x => (long)x), blocks[1].EventIds);
        Assert.All(blocks, block => {
            Assert.Equal(block.EventIds.Length, block.RoleIds.Length);
            Assert.All(block.RoleIds, role => Assert.Equal(2, role));
            Assert.Equal(32, block.IdentitySha256.Length);
        });
        EqualBlocks(blocks, DirectLinkBlock.Build(rows.Reverse()));
        DirectLinkBlock.Validate(blocks);
    }

    [Fact]
    public void Retry_is_idempotent_and_late_identity_is_rejected()
    {
        var blocks = DirectLinkBlock.Build([Row(10), Row(20)]);
        EqualBlocks(blocks, DirectLinkBlock.Append(blocks, [Row(10), Row(20)]));
        Assert.Equal(new long[] { 10, 20, 30 }, Assert.Single(DirectLinkBlock.Append(blocks, [Row(30)])).EventIds);
        Error("late", () => DirectLinkBlock.Append(blocks, [Row(15)]));
    }

    [Fact]
    public void Duplicates_invalid_roles_and_orphans_are_rejected()
    {
        Error("duplicate", () => DirectLinkBlock.Build([Row(1), Row(1)]));
        Error("duplicate", () => DirectLinkBlock.Append([], [Row(1), Row(1)]));
        Error("smallint", () => DirectLinkBlock.Build([Row(1, role: 32768)]));
        var blocks = DirectLinkBlock.Build([Row(1)]);
        DirectLinkBlock.ValidateNoOrphans(blocks, new HashSet<long> { 1 }, new HashSet<int> { 7 });
        Error("orphan event", () => DirectLinkBlock.ValidateNoOrphans(blocks, new HashSet<long>(), new HashSet<int> { 7 }));
        Error("orphan entity", () => DirectLinkBlock.ValidateNoOrphans(blocks, new HashSet<long> { 1 }, new HashSet<int>()));
    }

    [Fact]
    public async Task Event_first_lookup_is_exact_and_archive_backed()
    {
        string root = Path.Combine(Path.GetTempPath(), "link-block-parity-" + Guid.NewGuid().ToString("N"));
        try
        {
            var manifest = new ArchivePublisherTests.MemoryManifest();
            var publisher = new ArchivePublisher(root, manifest);
            JsonObject[] links = [
                new() { ["event_id"] = 1L, ["entity_id"] = 7, ["role_id"] = 2, ["confidence"] = 1.0, ["extracted_from"] = "xml", ["created_at"] = "2026-07-14T00:00:00Z" },
                new() { ["event_id"] = 2L, ["entity_id"] = 7, ["role_id"] = 2, ["confidence"] = 0.8, ["extracted_from"] = "event_data", ["created_at"] = "2026-07-14T00:00:01Z" }
            ];
            var ct = TestContext.Current.CancellationToken;
            await publisher.PublishDirectAsync("link-block-parity", [new() { ["id"] = 1L }, new() { ["id"] = 2L }], links, ct);
            var reader = new ArchiveReader(root, manifest);
            var row = Assert.Single(await reader.ReadRowsForEventAsync("link_detail", 2, ct));
            Assert.Equal(2, row["event_id"]!.GetValue<long>());
            Assert.Equal(7, row["entity_id"]!.GetValue<int>());
            Assert.Equal(2, row["role_id"]!.GetValue<int>());
            Assert.Equal("event_data", row["extracted_from"]!.GetValue<string>());
            Assert.Equal(0.8, row["confidence"]!.GetValue<double>());
            Assert.Equal("2026-07-14T00:00:01Z", row["created_at"]!.GetValue<string>());
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    [Fact]
    public void Tail_append_changes_only_tail_and_new_blocks()
    {
        var original = Assert.Single(DirectLinkBlock.Build(Enumerable.Range(1, 512).Select(x => Row(x))));
        var changed = DirectLinkBlock.AppendTail(original, [Row(513)]);
        EqualBlocks([original], changed.Take(1).ToArray());
        Assert.Equal(1, changed[1].BlockNo);
        Assert.Equal(new long[] { 513 }, changed[1].EventIds);
    }

    [Fact]
    public void Integrity_rejects_hash_and_number_corruption()
    {
        var block = Assert.Single(DirectLinkBlock.Build([Row(1)]));
        DirectLinkBlock.Validate([block]);
        Error("SHA-256", () => DirectLinkBlock.Validate([block with { IdentitySha256 = Enumerable.Repeat((byte)'x', 32).ToArray() }]));
        Error("contiguous", () => DirectLinkBlock.Validate([block with { BlockNo = 2 }]));
    }

    [Fact]
    public void Tail_append_crosses_int32_boundary_and_preserves_legacy_hash()
    {
        var tail = Assert.Single(DirectLinkBlock.Build([Row(int.MaxValue)]));
        // Frozen Python hashlib.sha256(struct.pack('<iiH', ...)) and '<qiH' vectors.
        Assert.Equal("95c0f9077657433ab461582d154280d53fa9a597edaf8f4f736f6f3719d6a8aa", Convert.ToHexStringLower(tail.IdentitySha256));
        var changed = DirectLinkBlock.AppendTail(tail, [Row((long)int.MaxValue + 1), Row(long.MaxValue)]);
        DirectLinkBlock.Validate(changed);
        var block = Assert.Single(changed);
        Assert.Equal(new long[] { int.MaxValue, (long)int.MaxValue + 1, long.MaxValue }, block.EventIds);
        Assert.Equal("25ba443199251f5210f9bb7df0059b75d36b46aabe4090d57d8f6fd335195f80", Convert.ToHexStringLower(block.IdentitySha256));
        Assert.Equal("95c0f9077657433ab461582d154280d53fa9a597edaf8f4f736f6f3719d6a8aa", Convert.ToHexStringLower(tail.IdentitySha256));
    }

    [Theory]
    [InlineData(1, 2)]
    [InlineData(1025, 2)]
    [InlineData(1024, 1)]
    [InlineData(2049, 2)]
    [InlineData(3001, 2)]
    public void Late_suffix_equals_full_rebuild_and_preserves_prefix(long eventId, int roleId)
    {
        var rows = Enumerable.Range(1, 1800).Select(x => Row(x * 2)).ToArray();
        var original = DirectLinkBlock.Build(rows);
        var incoming = Row(eventId, role: roleId);
        int start = Enumerable.Range(0, original.Count).First(i => original[i].EventIds[^1] >= eventId);
        var prefix = original.Take(start).ToArray();
        var hashes = prefix.Select(x => x.IdentitySha256.ToArray()).ToArray();
        var changed = DirectLinkBlock.RebuildSuffix(original.Skip(start).ToArray(), [incoming]);
        var combined = prefix.Concat(changed).ToArray();
        EqualBlocks(DirectLinkBlock.Build(rows.Append(incoming)), combined);
        DirectLinkBlock.Validate(combined);
        for (int i = 0; i < start; i++) Assert.Equal(hashes[i], combined[i].IdentitySha256);
    }

    [Fact]
    public void Late_suffix_checks_stored_hash_and_entity()
    {
        var blocks = DirectLinkBlock.Build(Enumerable.Range(1, 600).Select(x => Row(x * 2)));
        Error("SHA-256", () => DirectLinkBlock.RebuildSuffix([blocks[^1] with { IdentitySha256 = Enumerable.Repeat((byte)'x', 32).ToArray() }], [Row(1101)]));
        Error("entity", () => DirectLinkBlock.RebuildSuffix([blocks[^1]], [Row(1101, entity: 8)]));
    }
}
