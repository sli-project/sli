using System.Text;
using System.Text.Json.Nodes;
using Sli.Server.Storage.Archive;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class EntityArchiveTests
{
    static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public void Entity_details_encode_unicode_and_attributes_in_identity_order()
    {
        var encoded = ArchiveCodec.Encode("entity_detail", [
            new() { ["id"] = 2L, ["display_name"] = "Bob", ["attributes_json"] = new JsonObject() },
            new() { ["id"] = 1L, ["display_name"] = "Алиса", ["attributes_json"] = new JsonObject { ["department"] = "ИБ" } }
        ]);
        Assert.Equal(1, encoded.First);
        Assert.Equal(2, encoded.Last);
        Assert.Equal("{\"kind\":\"entity_detail\",\"row\":{\"attributes_json\":{\"department\":\"ИБ\"},\"display_name\":\"Алиса\",\"id\":1}}\n" +
            "{\"kind\":\"entity_detail\",\"row\":{\"attributes_json\":{},\"display_name\":\"Bob\",\"id\":2}}\n", Encoding.UTF8.GetString(encoded.Raw));
    }

    [Fact]
    public async Task Exact_batch_hydration_uses_published_manifest_and_excludes_unrequested_entities()
    {
        using var scope = new Scope();
        await scope.Publisher.PublishEntityDetailsAsync(Guid.Parse("00000000-0000-4000-8000-000000000033"), [
            new() { ["id"] = 1L, ["display_name"] = "Алиса", ["attributes_json"] = new JsonObject { ["department"] = "ИБ" } },
            new() { ["id"] = 2L, ["display_name"] = "Bob", ["attributes_json"] = new JsonObject() }
        ], Token);
        await scope.Publisher.PublishEntityDetailsAsync(Guid.Parse("00000000-0000-4000-8000-000000000036"), [
            new() { ["id"] = 100L, ["display_name"] = "Service", ["attributes_json"] = new JsonObject { ["kind"] = "svc" } }
        ], Token);

        var result = await scope.Reader.ReadEntityDetailsManyAsync([2, 100, 2], Token);

        Assert.Equal(new long[] { 2, 100 }, result.Keys.Order());
        Assert.Equal("Bob", result[2]["display_name"]!.GetValue<string>());
        Assert.Empty(result[2]["attributes_json"]!.AsObject());
        Assert.Equal("svc", result[100]["attributes_json"]!["kind"]!.GetValue<string>());
        Assert.Equal(new[] { ("entity_detail", 2L, 100L) }, scope.Manifest.RangeCalls);
        var unicode = await scope.Reader.ReadEntityDetailsManyAsync([1], Token);
        Assert.Equal("Алиса", unicode[1]["display_name"]!.GetValue<string>());
        Assert.Equal("ИБ", unicode[1]["attributes_json"]!["department"]!.GetValue<string>());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Entity_hydration_fails_closed_for_appended_or_same_length_corruption(bool append)
    {
        using var scope = new Scope();
        var block = await scope.Publisher.PublishEntityDetailsAsync(Guid.NewGuid(), [new() { ["id"] = 1L, ["display_name"] = "A" }], Token);
        byte[] bytes = File.ReadAllBytes(block.ObjectLocation);
        if (append) bytes = [.. bytes, (byte)'x']; else bytes[^1] ^= 1;
        File.WriteAllBytes(block.ObjectLocation, bytes);

        var error = await Assert.ThrowsAsync<InvalidDataException>(() => scope.Reader.ReadEntityDetailsManyAsync([1], Token));
        Assert.Equal(append ? "archive_compressed_size_mismatch" : "archive_compressed_hash_mismatch", error.Message);
    }

    [Fact]
    public async Task Link_batch_keeps_all_rows_for_each_event_from_one_published_block()
    {
        using var scope = new Scope();
        await scope.Publisher.PublishDirectAsync("entity-archive-links", [new() { ["id"] = 10L }, new() { ["id"] = 11L }], [
            new() { ["event_id"] = 10L, ["entity_id"] = 1L, ["evidence_json"] = new JsonObject { ["field"] = "SubjectUserSid" } },
            new() { ["event_id"] = 11L, ["entity_id"] = 2L, ["attributes_json"] = new JsonObject { ["source"] = "normalized" } },
            new() { ["event_id"] = 10L, ["entity_id"] = 3L }
        ], Token);

        var result = await scope.Reader.ReadLinkDetailsManyAsync([10, 11, 10, 12], Token);

        Assert.Equal(new long[] { 10, 11 }, result.Keys.Order());
        Assert.Equal(new long[] { 1, 3 }, result[10].Select(row => row["entity_id"]!.GetValue<long>()).Order());
        Assert.Equal("SubjectUserSid", result[10].Single(row => row["entity_id"]!.GetValue<long>() == 1)["evidence_json"]!["field"]!.GetValue<string>());
        Assert.Equal("normalized", Assert.Single(result[11])["attributes_json"]!["source"]!.GetValue<string>());
        Assert.Equal(new[] { ("link_detail", 10L, 12L) }, scope.Manifest.RangeCalls);
        Assert.Single(scope.Manifest.Blocks.Values, block => block.Kind == "link_detail");
    }

    [Theory]
    [InlineData("staging")]
    [InlineData("quarantined")]
    public async Task Unpublished_blocks_do_not_supply_entity_or_link_details(string state)
    {
        using var scope = new Scope();
        var entity = await scope.Publisher.PublishEntityDetailsAsync(Guid.NewGuid(), [new() { ["id"] = 1L }], Token);
        await scope.Publisher.PublishDirectAsync("unpublished-links", [new() { ["id"] = 10L }], [new() { ["event_id"] = 10L, ["entity_id"] = 1L }], Token);
        var link = scope.Manifest.Blocks.Values.Single(block => block.Kind == "link_detail");
        scope.Manifest.Blocks[(entity.SetId, entity.Kind, entity.Index)] = entity with { State = state };
        scope.Manifest.Blocks[(link.SetId, link.Kind, link.Index)] = link with { State = state };

        await Assert.ThrowsAsync<KeyNotFoundException>(() => scope.Reader.ReadEntityDetailsManyAsync([1], Token));
        Assert.Empty(await scope.Reader.ReadLinkDetailsManyAsync([10], Token));
    }

    [Fact]
    public async Task Missing_entity_inside_verified_range_fails_instead_of_returning_partial_batch()
    {
        using var scope = new Scope();
        await scope.Publisher.PublishEntityDetailsAsync(Guid.NewGuid(), [new() { ["id"] = 1L }, new() { ["id"] = 3L }], Token);
        await Assert.ThrowsAsync<KeyNotFoundException>(() => scope.Reader.ReadEntityDetailsManyAsync([1, 2], Token));
        await Assert.ThrowsAsync<KeyNotFoundException>(() => scope.Reader.ReadEntityDetailsManyAsync([4], Token));
    }

    [Fact]
    public async Task Empty_requests_do_not_query_manifest_and_cancellation_is_observed()
    {
        using var scope = new Scope();
        Assert.Empty(await scope.Reader.ReadEntityDetailsManyAsync([], Token));
        Assert.Empty(await scope.Reader.ReadLinkDetailsManyAsync([], Token));
        Assert.Empty(scope.Manifest.RangeCalls);
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => scope.Reader.ReadEntityDetailsManyAsync([1], cancelled.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => scope.Reader.ReadLinkDetailsManyAsync([10], cancelled.Token));
        Assert.Empty(scope.Manifest.RangeCalls);
    }

    [Fact]
    public async Task Batch_hydration_has_no_arbitrary_block_limit()
    {
        using var scope = new Scope();
        for (long id = 1; id <= 65; id++)
            await scope.Publisher.PublishEntityDetailsAsync(Guid.NewGuid(), [new() { ["id"] = id }], Token);

        var result = await scope.Reader.ReadEntityDetailsManyAsync(Enumerable.Range(1, 65).Select(id => (long)id), Token);
        Assert.Equal(Enumerable.Range(1, 65).Select(id => (long)id), result.Keys.Order());
        Assert.Single(scope.Manifest.RangeCalls);
    }

    [Fact]
    public async Task Empty_or_duplicate_entity_blocks_are_rejected_before_manifest_publication()
    {
        using var scope = new Scope();
        await Assert.ThrowsAsync<InvalidDataException>(() => scope.Publisher.PublishEntityDetailsAsync(Guid.NewGuid(), [], Token));
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => scope.Publisher.PublishEntityDetailsAsync(Guid.NewGuid(), [new() { ["id"] = 1L }, new() { ["id"] = 1L }], Token));
        Assert.Equal("archive_duplicate_entity", error.Message);
        Assert.Empty(scope.Manifest.Blocks);
        Assert.Empty(Directory.GetFiles(Path.Combine(scope.Root, "published")));
    }

    sealed class Scope : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "sli-entity-archive-" + Guid.NewGuid().ToString("N"));
        internal ArchivePublisherTests.MemoryManifest Manifest { get; } = new();
        internal ArchivePublisher Publisher { get; }
        internal ArchiveReader Reader { get; }
        internal Scope() { Publisher = new(Root, Manifest); Reader = new(Root, Manifest); }
        public void Dispose() => Directory.Delete(Root, true);
    }
}
