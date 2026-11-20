using System.Text.Json.Nodes;
using Sli.Server.Ad;
using Xunit;

namespace Sli.Server.Tests.Ad;

public sealed class AdSnapshotRetentionTests
{
    static readonly DateTimeOffset Now = new(2026, 9, 1, 12, 0, 0, TimeSpan.Zero);
    static readonly string[] Relations = [
        "ad_snapshot_manifests", "ad_snapshot_manifest_sources", "ad_snapshot_projection_receipts",
        "ad_snapshot_projection_outputs", "users_report_v2_snapshots", "computers_v6_source_snapshots", "gpo_report_v2_source_snapshots"
    ];
    static JsonObject SafeInventory(int count = 0)
    {
        var inventory = new JsonObject();
        foreach (string relation in Relations) inventory[relation] = new JsonObject {
            ["candidate_count"] = count, ["root_mapping_proven"] = true, ["anchor_proven"] = true,
            ["owner_admitted"] = true, ["shared_source"] = false, ["dependency_state"] = "safe",
            ["independent_legacy_cleaner"] = false, ["whole_unit_admitted"] = count == 0
        };
        return inventory;
    }
    static void Classification(JsonObject result, string relation, string reason, int? count)
    {
        var expected = new JsonObject { [reason] = count };
        Assert.True(JsonNode.DeepEquals(expected, result["relations"]![relation]!["classification_counts"]));
    }

    [Fact]
    public void Zero_eligible_plan_completes_without_mutating_inventory()
    {
        var inventory = SafeInventory();
        string before = inventory.ToJsonString();
        for (int attempt = 0; attempt < 2; attempt++) {
            var result = AdSnapshotRetention.Plan(Now, inventory);
            Assert.Equal("completed", result["status"]!.ToString());
            Assert.Equal(7, result["policy_horizon_days"]!.GetValue<int>());
            Assert.Equal("2026-08-25T12:00:00Z", result["horizon_before_utc"]!.ToString());
            Assert.Equal(0, result["eligible_before"]!.GetValue<int>());
            Assert.Equal(0, result["eligible_after"]!.GetValue<int>());
            Assert.Equal(Relations, result["relations"]!.AsObject().Select(p => p.Key));
            foreach (string relation in Relations) {
                Assert.Equal(0, result["relations"]![relation]!["candidate_count"]!.GetValue<int>());
                Classification(result, relation, "eligible", 0);
            }
        }
        Assert.Equal(before, inventory.ToJsonString());
    }

    [Fact]
    public void Nonzero_and_unknown_counts_never_infer_admission()
    {
        var inventory = SafeInventory();
        inventory[Relations[0]]!["candidate_count"] = 3;
        inventory[Relations[0]]!["whole_unit_admitted"] = false;
        var blocked = AdSnapshotRetention.Plan(Now, inventory);
        Assert.Equal("blocked", blocked["status"]!.ToString());
        Assert.Equal(3, blocked["eligible_before"]!.GetValue<int>());
        Assert.Equal(0, blocked["eligible_after"]!.GetValue<int>());
        Classification(blocked, Relations[0], "blocked_unapproved_whole_unit", 3);

        inventory = SafeInventory();
        inventory[Relations[6]]!["candidate_count"] = null;
        blocked = AdSnapshotRetention.Plan(Now, inventory);
        Assert.Equal("blocked", blocked["status"]!.ToString());
        Assert.Null(blocked["eligible_before"]);
        Assert.Equal(0, blocked["eligible_after"]!.GetValue<int>());
        Classification(blocked, Relations[6], "blocked_unknown_candidate_count", 1);
    }

    [Fact]
    public void Ownership_root_dependency_shared_source_and_legacy_cleaner_block_even_empty_relations()
    {
        var inventory = SafeInventory();
        inventory[Relations[3]]!["root_mapping_proven"] = false;
        inventory[Relations[4]]!["owner_admitted"] = false;
        inventory[Relations[5]]!["shared_source"] = true;
        inventory[Relations[6]]!["dependency_state"] = "unknown";
        inventory[Relations[2]]!["independent_legacy_cleaner"] = true;
        var result = AdSnapshotRetention.Plan(Now, inventory);
        Assert.Equal("blocked", result["status"]!.ToString());
        Classification(result, Relations[3], "blocked_missing_root_mapping", 0);
        Classification(result, Relations[4], "blocked_missing_owner_admission", 0);
        Classification(result, Relations[5], "blocked_shared_source", 0);
        Classification(result, Relations[6], "blocked_dependency_unknown", 0);
        Classification(result, Relations[2], "blocked_independent_legacy_cleaner", 0);
    }

    [Fact]
    public void Safe_not_due_plan_keeps_fixed_seven_day_policy()
    {
        var result = AdSnapshotRetention.Plan(Now, SafeInventory(), due: false);
        Assert.Equal("not_due", result["status"]!.ToString());
        Assert.Equal(7, result["policy_horizon_days"]!.GetValue<int>());
        Assert.Equal(0, result["eligible_before"]!.GetValue<int>());
        Assert.Equal(0, result["eligible_after"]!.GetValue<int>());
        Assert.Equal("policy_horizon_days is fixed at 7", Assert.Throws<ArgumentException>(() =>
            AdSnapshotRetention.Plan(Now, SafeInventory(), policyHorizonDays: 365)).Message);
    }

    [Fact]
    public void Missing_inventory_and_anchor_never_infer_admission_even_when_not_due()
    {
        var result = AdSnapshotRetention.Plan(Now, due: false);
        Assert.Equal("blocked", result["status"]!.ToString());
        foreach (string relation in Relations) Classification(result, relation, "blocked_missing_root_mapping", null);
        var inventory = SafeInventory();
        inventory[Relations[0]]!["anchor_proven"] = false;
        result = AdSnapshotRetention.Plan(Now, inventory, due: false);
        Assert.Equal("blocked", result["status"]!.ToString());
        Classification(result, Relations[0], "blocked_missing_anchor", 0);
    }

    [Fact]
    public void One_blocked_root_prevents_whole_unit_admission_but_preserves_relation_counts()
    {
        var inventory = SafeInventory(2);
        foreach (string relation in Relations) inventory[relation]!["whole_unit_admitted"] = true;
        var result = AdSnapshotRetention.Plan(Now.ToOffset(TimeSpan.FromHours(3)), inventory);
        Assert.Equal("completed", result["status"]!.ToString());
        Assert.Equal(14, result["eligible_before"]!.GetValue<int>());
        Assert.Equal(14, result["eligible_after"]!.GetValue<int>());
        Assert.Equal("2026-08-25T12:00:00Z", result["horizon_before_utc"]!.ToString());
        inventory[Relations[0]]!["dependency_state"] = "restrictive";
        result = AdSnapshotRetention.Plan(Now, inventory);
        Assert.Equal("blocked", result["status"]!.ToString());
        Assert.Equal(14, result["eligible_before"]!.GetValue<int>());
        Assert.Equal(0, result["eligible_after"]!.GetValue<int>());
        Classification(result, Relations[0], "blocked_dependency_restrictive", 2);
        Assert.Equal(2, result["relations"]![Relations[1]]!["eligible_after"]!.GetValue<int>());
    }

    [Theory]
    [InlineData("true")]
    [InlineData("-1")]
    [InlineData("1.5")]
    [InlineData("\"3\"")]
    public void Invalid_candidate_counts_fail_without_admitting_partial_inventory(string count)
    {
        var inventory = SafeInventory();
        inventory[Relations[6]]!["candidate_count"] = JsonNode.Parse(count);
        var result = AdSnapshotRetention.Plan(Now, inventory);
        Assert.Equal("failed", result["status"]!.ToString());
        Assert.Equal("ValueError:candidate_count must be a non-negative integer or null", result["error"]!.ToString());
        Assert.Null(result["eligible_before"]);
        Assert.Equal(0, result["eligible_after"]!.GetValue<int>());
        Assert.Empty(result["relations"]!.AsObject());
    }

    [Fact]
    public void Compatibility_roots_require_explicit_ownership_and_cannot_widen_scope()
    {
        var inventory = SafeInventory();
        var legacy = inventory[Relations[0]]!.DeepClone();
        inventory["compatibility_roots"] = new JsonObject { ["legacy_snapshot"] = legacy };
        var result = AdSnapshotRetention.Plan(Now, inventory);
        Assert.Equal("blocked", result["status"]!.ToString());
        Classification(result, "legacy_snapshot", "blocked_compatibility_ownership", 0);
        legacy["compatibility_ownership_proven"] = true;
        Assert.Equal("completed", AdSnapshotRetention.Plan(Now, inventory)["status"]!.ToString());
        foreach (string relation in new[] { "ad_context_runs", Relations[0] }) {
            inventory["compatibility_roots"] = new JsonObject { [relation] = legacy.DeepClone() };
            result = AdSnapshotRetention.Plan(Now, inventory);
            Assert.Equal("failed", result["status"]!.ToString());
            Assert.Equal(relation == "ad_context_runs" ? "ValueError:ad_context_runs is outside the AD snapshot retention scope"
                : "ValueError:compatibility root duplicates a canonical relation", result["error"]!.ToString());
            Assert.Empty(result["relations"]!.AsObject());
        }
    }
}
