using System.Text.Json.Nodes;
using Sli.Server.Storage.Lifecycle;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class LifecycleContractTests
{
    [Theory] [InlineData(false)] [InlineData(true)]
    public void Bounded_read_rejects_same_size_in_place_mtime_mutation(bool changed)
    {
        // Python test_read_bytes_rejects_same_size_in_place_mutation patches
        // fstat, preserving device/inode/size and changing only mtime by 1 ns.
        using var state = new StorageLifecycleTests.State();
        string path = Path.Combine(state.Path, "payload.json"); byte[] payload = "{\"safe\":true}"u8.ToArray();
        File.WriteAllBytes(path, payload); int calls = 0;
        StorageLifecycleBoundedIo.Identity Metadata(Microsoft.Win32.SafeHandles.SafeFileHandle handle) {
            var current = StorageLifecycleBoundedIo.FileIdentity(handle);
            return changed && ++calls > 1 ? current with { ModifiedNanoseconds = current.ModifiedNanoseconds + 1 } : current;
        }
        if (changed) {
            Assert.Equal("bounded_file_changed_during_read", Assert.Throws<LifecycleBlocked>(() =>
                StorageLifecycleBoundedIo.ReadBytes(path, 1024, "too_large", Metadata)).Message);
            Assert.Equal(2, calls);
        } else Assert.Equal(payload, StorageLifecycleBoundedIo.ReadBytes(path, 1024, "too_large", Metadata));
    }

    [Fact] public void Lifecycle_json_reads_keep_size_boundary_and_missing_file_behavior()
    {
        using var state = new StorageLifecycleTests.State();
        Assert.Null(state.Files.Read("payload.json"));
        state.Files.Write("payload.json", new JsonObject { ["safe"] = true });
        string path = Path.Combine(state.Path, "runtime", "payload.json"); int size = checked((int)new FileInfo(path).Length);
        Assert.True(state.Files.Read("payload.json", size)!["safe"]!.GetValue<bool>());
        Assert.Equal("history_retention_progress_invalid", Assert.Throws<LifecycleBlocked>(() => state.Files.Read("payload.json", size - 1)).Message);
    }

    static JsonObject Snapshot(string name, bool complete = true, params string[] members) => new() {
        ["metadata"] = new JsonObject { ["collection_status"] = complete ? "complete" : "partial", ["domain"] = "example.test", ["search_base"] = "DC=example,DC=test" },
        ["users"] = new JsonArray(new JsonObject { ["objectGuid"] = "u1", ["displayName"] = name, ["arbitrary_secret"] = "must not survive",
            ["memberships"] = new JsonObject { ["status"] = "observed", ["direct"] = new JsonArray(members.Select(s => (JsonNode)JsonValue.Create(s)!).ToArray()) } })
    };
    [Fact] public void Snapshot_changes_preserve_only_allowed_fingerprints()
    {
        var changes = SnapshotChanges.Extract("users_v2", Snapshot("before"), Snapshot("after"));
        var change = Assert.Single(changes); Assert.Equal("attribute_changed", change["kind"]!.ToString()); Assert.Equal("displayName", change["field"]!.ToString());
        Assert.DoesNotContain("must not survive", change.ToJsonString()); Assert.DoesNotContain("before\"", change.ToJsonString()); Assert.Equal(64, change["before_sha256"]!.ToString().Length);
    }
    [Fact] public void Partial_snapshot_cannot_prove_object_or_membership_removal()
    {
        var previous = Snapshot("same", true, "g1"); var current = Snapshot("same", false, "g2");
        var changes = SnapshotChanges.Extract("users_v2", previous, current);
        Assert.Equal("membership_added", Assert.Single(changes)["kind"]!.ToString());
        current["users"] = new JsonArray(); Assert.Empty(SnapshotChanges.Extract("users_v2", previous, current));
    }
    [Fact] public void Complete_pair_can_prove_removal_but_cross_scope_cannot()
    {
        var previous = Snapshot("same", true, "g1"); var current = Snapshot("same", true);
        Assert.Equal("membership_removed", Assert.Single(SnapshotChanges.Extract("users_v2", previous, current))["kind"]!.ToString());
        current["metadata"]!["domain"] = "another.example.test"; Assert.Empty(SnapshotChanges.Extract("users_v2", previous, current));
    }
    [Fact] public void Unobserved_directory_state_cannot_prove_attribute_changes()
    {
        var previous = Snapshot("before"); var current = Snapshot("after"); current["users"]![0]!["sourceState"] = new JsonObject { ["status"] = "access_denied" };
        Assert.Empty(SnapshotChanges.Extract("users_v2", previous, current));
    }
    [Fact] public void Duplicate_snapshot_objects_and_unknown_families_are_invalid()
    {
        var previous = Snapshot("same"); previous["users"]!.AsArray().Add(previous["users"]![0]!.DeepClone());
        Assert.Equal("snapshot_history_object_identity_duplicate", Assert.Throws<LifecycleBlocked>(() => SnapshotChanges.Extract("users_v2", previous, Snapshot("same"))).Message);
        Assert.Equal("snapshot_history_family_invalid", Assert.Throws<LifecycleBlocked>(() => SnapshotChanges.Extract("untrusted-family", Snapshot("same"), Snapshot("same"))).Message);
    }
    [Fact] public void Policy_profiles_use_only_explicit_overrides()
    {
        var env = new Dictionary<string, string?> { ["ADLOG_STORAGE_CAPACITY_PROFILE"] = "extended", ["ADLOG_DB_RETENTION_DAYS"] = "30" };
        Assert.Equal(7, LifecyclePolicy.Read(env.GetValueOrDefault).HotDays); env["ADLOG_STORAGE_CAPACITY_PROFILE_OVERRIDES"] = "db_retention_days";
        Assert.Equal(30, LifecyclePolicy.Read(env.GetValueOrDefault).HotDays); env["ADLOG_STORAGE_CAPACITY_PROFILE"] = "surprise";
        Assert.Throws<InvalidDataException>(() => LifecyclePolicy.Read(env.GetValueOrDefault));
    }
    [Fact] public void Config_fallback_and_environment_precedence_preserve_reference_policy()
    {
        using var state = new StorageLifecycleTests.State(); Directory.CreateDirectory(Path.Combine(state.Path, "config"));
        File.WriteAllText(Path.Combine(state.Path, "config", "adlog_config.yaml"), "retention:\n  db_retention_days: 7\n  apply_by_default: true\n  archive_auto_delete_enabled: false\n");
        var env = new Dictionary<string, string?> { ["ADLOG_DB_RETENTION_DAYS"] = "14" }; var config = new LifecycleConfiguration(state.Path, env.GetValueOrDefault);
        Assert.Equal(14, LifecyclePolicy.Read(config.Get).HotDays); Assert.True(LifecyclePolicy.Read(config.Get).ApplyByDefault); Assert.False(LifecyclePolicy.Read(config.Get).ArchiveDelete);
    }
    [Fact] public void Immutable_receipt_cannot_replace_prior_evidence()
    {
        using var state = new StorageLifecycleTests.State(); state.Files.Write("immutable.json", new JsonObject { ["value"] = 1 }, replace: false);
        Assert.Throws<IOException>(() => state.Files.Write("immutable.json", new JsonObject { ["value"] = 2 }, replace: false));
        Assert.Equal("1", state.Files.Read("immutable.json")!["value"]!.ToString());
    }
}
