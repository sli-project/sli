using System.Text.Json.Nodes;
using System.Text;
using Microsoft.Extensions.Configuration;
using Sli.Server.Storage.Lifecycle;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class SnapshotChangeStoreTests
{
    [Fact]
    public void Reads_always_use_postgres()
    {
        Assert.True(SnapshotChangeStore.PostgresReads(new ConfigurationBuilder().Build()));
        Assert.True(SnapshotChangeStore.PostgresReads(new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string,string?> { ["Sli:Storage:ShortEventReads"] = "false" }).Build()));
        Assert.True(SnapshotChangeStore.PostgresReads(new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string,string?> { ["Sli:Storage:ShortEventReads"] = "invalid" }).Build()));
    }

    [Fact]
    public void Values_are_bounded_by_unicode_characters_and_json_escapes_host_text()
    {
        string hostile = "<script>'\";select 1;😀";
        string value = SnapshotChangeStore.Value(JsonValue.Create(string.Concat(Enumerable.Repeat(hostile, 1000))))!;
        Assert.Equal(2048, value.EnumerateRunes().Count());
        Assert.StartsWith(hostile, value);
        string encoded = new JsonObject { ["value"] = value }.ToJsonString();
        Assert.DoesNotContain("<script>", encoded);
        Assert.Equal(value, JsonNode.Parse(encoded)!["value"]!.GetValue<string>());
        Assert.Null(SnapshotChangeStore.Value(null));
    }
}
