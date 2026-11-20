using System.Text.Json.Nodes;
using Sli.Server.Storage.Lifecycle;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class SnapshotChangesTests
{
    [Fact]
    public void Malformed_snapshot_has_only_an_allowlisted_field_reason()
    {
        var previous=JsonNode.Parse("""{"users":[{"id":"synthetic-user"}]}""")!.AsObject();
        var current=JsonNode.Parse("""{"users":[{"id":"synthetic-user","sourceState":"synthetic-private-value","synthetic-private-field":"synthetic-private-value"}]}""")!.AsObject();
        var error=Assert.Throws<LifecycleBlocked>(()=>SnapshotChanges.Extract("users_v2",previous,current));
        Assert.Equal("snapshot_history_field_invalid:sourceState",error.Message);
        Assert.DoesNotContain("synthetic-private",error.Message);
    }
    public static IEnumerable<object[]> Vectors()
    {
        using var stream=typeof(SnapshotChangesTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Storage.snapshot-changes-vectors.json")!;
        foreach(var vector in JsonNode.Parse(stream)!.AsArray()) yield return [vector!.AsObject()];
    }

    [Theory]
    [MemberData(nameof(Vectors))]
    public void Dirty_snapshots_match_python_rows_and_hashes_without_mutating_sources(JsonObject vector)
    {
        string name = vector["name"]!.GetValue<string>();
        string family = vector["family"]!.GetValue<string>();
        var previous = vector["previous"]!.AsObject(); var current = vector["current"]!.AsObject();
        string oldBytes = previous.ToJsonString(), newBytes = current.ToJsonString();
        if (vector["error"] is { } error) {
            var blocked = Assert.Throws<LifecycleBlocked>(() => SnapshotChanges.Extract(family, previous, current));
            Assert.Equal(error.GetValue<string>(), blocked.Message);
            Assert.Equal(blocked.Message, LifecycleJson.Failure(blocked));
        } else {
            // Repeated extraction catches accidental JsonNode reparenting as well as input mutation.
            for (int attempt = 0; attempt < 2; attempt++) {
                var changes = SnapshotChanges.Extract(family, previous, current);
                var rows = new JsonArray(changes.Select(c => c.DeepClone()).ToArray());
                Assert.True(JsonNode.DeepEquals(vector["rows"], rows), name);
                Assert.Equal(vector["rows_sha256"]!.GetValue<string>(), LifecycleJson.Hash(rows).ToLowerInvariant());
                Assert.Equal(vector["payloads"]!.AsArray().Select(p => p!.GetValue<string>()), changes.Select(LifecycleJson.Canonical));
                const string batch = "synthetic-batch";
                Assert.Equal(vector["record_ids"]!.AsArray().Select(p => p!.GetValue<string>()), changes.Select(c =>
                    LifecycleJson.Hash(new JsonArray(JsonValue.Create(batch), c.DeepClone())).ToLowerInvariant()));
            }
        }
        Assert.Equal(oldBytes, previous.ToJsonString()); Assert.Equal(newBytes, current.ToJsonString());
    }
}
