using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticAdStateTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 18, 8, 0, 0, TimeSpan.Zero);
    private static SemanticAction Action(string[]? added = null, string[]? removed = null) => new(
        "directory.attribute.changed", Now, "key", new JsonObject {
            ["object_identity"] = "guid:object-1", ["attribute"] = "member",
            ["added_values"] = new JsonArray((added ?? []).Select(value => JsonValue.Create(value)).ToArray()),
            ["removed_values"] = new JsonArray((removed ?? []).Select(value => JsonValue.Create(value)).ToArray())
        }, []);
    private static DirectoryStateSnapshot Snapshot(string origin = SemanticAdState.IncrementalSync,
        string identity = "guid:object-1", string attribute = "member") =>
        new(identity, attribute, new HashSet<string> { "alice" }, Now, origin, origin == SemanticAdState.BaselineImport ? "base-1" : "state-1");

    // tests/semantic/test_semantic_ad_state1.py: exact original confirmation vectors.
    [Fact] public void State_confirmation_requires_exact_object_attribute_and_nonbaseline_evidence()
    {
        Assert.Equal(new("state_confirmed", "all_added_values_present_in_state", "state-1"), SemanticAdState.Assess(Action(added: ["alice"]), Snapshot()));
        Assert.Equal(new("contradicted", "removed_value_still_present_in_confirming_state", "state-1"), SemanticAdState.Assess(Action(removed: ["alice"]), Snapshot()));
        Assert.Equal(new("observed", "baseline_import_does_not_confirm_new_change", "base-1"),
            SemanticAdState.Assess(Action(added: ["alice"]), Snapshot(SemanticAdState.BaselineImport)));
    }

    // tests/semantic/test_semantic_ad_state1.py: exact original graph, including cycle.
    [Fact] public void Effective_privilege_paths_are_deterministic_cycle_safe_and_baseline_safe()
    {
        MembershipEdge[] edges = [
            new("alice", "group-a", "e1", Now, SemanticAdState.BaselineImport),
            new("group-a", "domain-admins", "e2", Now, SemanticAdState.BaselineImport),
            new("group-a", "alice", "cycle", Now), new("bob", "domain-admins", "e3", Now)
        ];
        var paths = SemanticAdState.DeriveEffectivePrivilegePaths(edges, ["domain-admins"]);
        Assert.Equal(3, paths.Count);
        Check(paths[0], "alice", ["alice", "group-a", "domain-admins"], ["e1", "e2"], "baseline_observed");
        Check(paths[1], "bob", ["bob", "domain-admins"], ["e3"], "state_confirmed");
        Check(paths[2], "group-a", ["group-a", "domain-admins"], ["e2"], "baseline_observed");
        var replay = SemanticAdState.DeriveEffectivePrivilegePaths(edges.Reverse(), ["domain-admins", "domain-admins", ""]);
        Assert.Equal(paths.Select(Describe), replay.Select(Describe));
    }

    [Theory]
    [InlineData("guid:other", "member", "observed", "state_identity_mismatch")]
    [InlineData("guid:object-1", "other", "observed", "state_identity_mismatch")]
    [InlineData("GUID:object-1", "member", "observed", "state_identity_mismatch")]
    [InlineData("guid:object-1", "MEMBER", "state_confirmed", "all_added_values_present_in_state")]
    public void Confirmation_matches_identity_exactly_and_folds_only_attribute(string identity, string attribute, string status, string reason)
    {
        var assessment = SemanticAdState.Assess(Action(added: ["alice"]), Snapshot(identity: identity, attribute: attribute));
        Assert.Equal(new(status, reason, status == "state_confirmed" ? "state-1" : null), assessment);
    }

    [Theory]
    [InlineData("alice", null, "state_confirmed", "all_added_values_present_in_state")]
    [InlineData(null, "bob", "state_confirmed", "all_removed_values_absent_from_state")]
    [InlineData("bob", null, "partially_confirmed", "state_has_no_observable_value_confirmation")]
    [InlineData("Alice", null, "partially_confirmed", "state_has_no_observable_value_confirmation")]
    [InlineData(null, null, "partially_confirmed", "state_has_no_observable_value_confirmation")]
    [InlineData("alice", "bob", "partially_confirmed", "state_matches_only_part_of_action")]
    [InlineData("bob", "alice", "contradicted", "removed_value_still_present_in_confirming_state")]
    public void Value_confirmation_preserves_partial_and_contradictory_states(string? added, string? removed, string status, string reason) =>
        Assert.Equal(new(status, reason, "state-1"), SemanticAdState.Assess(Action(added is null ? [] : [added], removed is null ? [] : [removed]), Snapshot(SemanticAdState.TargetedReconcile)));

    [Fact] public void Missing_identity_unsupported_action_and_baseline_do_not_confirm()
    {
        var action = Action(added: ["alice"]);
        action.Attributes.Remove("object_identity");
        Assert.Equal(new("partially_confirmed", "action_missing_material_identity"), SemanticAdState.Assess(action, Snapshot()));
        action.Attributes["object"] = "guid:object-1";
        Assert.Equal("state_confirmed", SemanticAdState.Assess(action, Snapshot()).Status);
        action.Attributes.Remove("attribute");
        Assert.Equal("action_missing_material_identity", SemanticAdState.Assess(action, Snapshot()).Reason);
        Assert.Equal(new("observed", "baseline_import_does_not_confirm_new_change", "base-1"), SemanticAdState.Assess(action, Snapshot(SemanticAdState.BaselineImport)));
        Assert.Equal(new("observed", "action_kind_has_no_directory_state_contract"), SemanticAdState.Assess(action with { Kind = "service.installed" }, Snapshot()));
        Assert.Equal("state_matches_only_part_of_action", SemanticAdState.Assess(Action(added: ["alice", "bob"]), Snapshot()).Reason);
    }

    [Fact] public void Paths_keep_distinct_evidence_and_mixed_origins_without_self_cycles()
    {
        MembershipEdge[] edges = [new("alice", "alice", "self", Now),
            new("alice", "group-a", "e2", Now, SemanticAdState.BaselineImport),
            new("alice", "group-a", "e1", Now, SemanticAdState.BaselineImport),
            new("group-a", "domain-admins", "e3", Now, SemanticAdState.TargetedReconcile)];
        var paths = SemanticAdState.DeriveEffectivePrivilegePaths(edges, ["domain-admins"]);
        Assert.Equal(3, paths.Count);
        Check(paths[0], "alice", ["alice", "group-a", "domain-admins"], ["e1", "e3"], "state_confirmed");
        Check(paths[1], "alice", ["alice", "group-a", "domain-admins"], ["e2", "e3"], "state_confirmed");
        Check(paths[2], "group-a", ["group-a", "domain-admins"], ["e3"], "state_confirmed");
        Assert.Empty(SemanticAdState.DeriveEffectivePrivilegePaths([], ["domain-admins"]));
        Assert.Empty(SemanticAdState.DeriveEffectivePrivilegePaths(edges, []));
    }

    [Fact] public void Unknown_origins_are_rejected()
    {
        Assert.Throws<ArgumentException>(() => Snapshot("unknown"));
        Assert.Throws<ArgumentException>(() => new MembershipEdge("alice", "domain-admins", "e1", Now, "unknown"));
    }

    private static string Describe(EffectivePrivilegePath path) =>
        $"{path.PrincipalIdentity}|{path.PrivilegedGroupIdentity}|{string.Join('/', path.Chain)}|{string.Join('/', path.EvidenceIds)}|{path.Status}";
    private static void Check(EffectivePrivilegePath path, string principal, string[] chain, string[] evidence, string status)
    {
        Assert.Equal(principal, path.PrincipalIdentity); Assert.Equal("domain-admins", path.PrivilegedGroupIdentity);
        Assert.Equal(chain, path.Chain); Assert.Equal(evidence, path.EvidenceIds); Assert.Equal(status, path.Status);
    }
}
