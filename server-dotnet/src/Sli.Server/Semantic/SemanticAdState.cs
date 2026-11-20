using System.Collections.Frozen;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Semantic;

internal sealed record DirectoryStateSnapshot(string ObjectIdentity, string Attribute, IReadOnlySet<string> Values,
    DateTimeOffset ObservedAtUtc, string Origin, string EvidenceId)
{
    public IReadOnlySet<string> Values { get; } = Values.ToFrozenSet(StringComparer.Ordinal);
    public string Origin { get; } = SemanticAdState.ValidateOrigin(Origin, "state");
}

internal sealed record MembershipEdge(string MemberIdentity, string GroupIdentity, string EvidenceId,
    DateTimeOffset ObservedAtUtc, string Origin = SemanticAdState.IncrementalSync)
{
    public string Origin { get; } = SemanticAdState.ValidateOrigin(Origin, "relationship");
}

internal sealed record ActionStateAssessment(string Status, string Reason, string? StateEvidenceId = null);
internal sealed record EffectivePrivilegePath(string PrincipalIdentity, string PrivilegedGroupIdentity,
    IReadOnlyList<string> Chain, IReadOnlyList<string> EvidenceIds, string Status);

// Pure parity primitives: state observations do not query AD or publish findings.
internal static class SemanticAdState
{
    internal const string BaselineImport = "baseline_import", IncrementalSync = "incremental_sync", TargetedReconcile = "targeted_reconcile";

    internal static string ValidateOrigin(string origin, string kind) =>
        origin is BaselineImport or IncrementalSync or TargetedReconcile ? origin :
            throw new ArgumentException($"unsupported {kind} origin: {origin}", nameof(origin));

    internal static ActionStateAssessment Assess(SemanticAction action, DirectoryStateSnapshot snapshot)
    {
        if (action.Kind != "directory.attribute.changed") return new("observed", "action_kind_has_no_directory_state_contract");
        if (snapshot.Origin == BaselineImport) return new("observed", "baseline_import_does_not_confirm_new_change", snapshot.EvidenceId);
        var attributes = action.Attributes;
        string identity = attributes.Text("object_identity") is { Length: > 0 } exact ? exact : attributes.Text("object") ?? "";
        string attribute = attributes.Text("attribute") ?? "";
        if (identity.Length == 0 || attribute.Length == 0) return new("partially_confirmed", "action_missing_material_identity");
        if (identity != snapshot.ObjectIdentity || UnicodeCaseFold.Fold(attribute) != UnicodeCaseFold.Fold(snapshot.Attribute))
            return new("observed", "state_identity_mismatch");

        var added = attributes["added_values"]?.AsArray().Select(value => value!.ToString()).ToHashSet(StringComparer.Ordinal) ?? [];
        var removed = attributes["removed_values"]?.AsArray().Select(value => value!.ToString()).ToHashSet(StringComparer.Ordinal) ?? [];
        bool presentAdded = added.Overlaps(snapshot.Values);
        if (removed.Overlaps(snapshot.Values)) return new("contradicted", "removed_value_still_present_in_confirming_state", snapshot.EvidenceId);
        if (added.Count > 0 && added.IsSubsetOf(snapshot.Values) && removed.Count == 0)
            return new("state_confirmed", "all_added_values_present_in_state", snapshot.EvidenceId);
        if (removed.Count > 0 && added.Count == 0) return new("state_confirmed", "all_removed_values_absent_from_state", snapshot.EvidenceId);
        if (presentAdded || removed.Count > 0) return new("partially_confirmed", "state_matches_only_part_of_action", snapshot.EvidenceId);
        return new("partially_confirmed", "state_has_no_observable_value_confirmation", snapshot.EvidenceId);
    }

    internal static IReadOnlyList<EffectivePrivilegePath> DeriveEffectivePrivilegePaths(
        IEnumerable<MembershipEdge> memberships, IEnumerable<string> privilegedGroupIdentities)
    {
        var privileged = privilegedGroupIdentities.Where(value => value.Length > 0).ToHashSet(StringComparer.Ordinal);
        var outgoing = memberships.GroupBy(edge => edge.MemberIdentity, StringComparer.Ordinal).ToDictionary(group => group.Key,
            group => group.OrderBy(edge => edge.GroupIdentity, StringComparer.Ordinal).ThenBy(edge => edge.EvidenceId, StringComparer.Ordinal).ToArray(), StringComparer.Ordinal);
        var result = new List<EffectivePrivilegePath>();
        foreach (string principal in outgoing.Keys.Order(StringComparer.Ordinal))
        {
            var queue = new Queue<(string Current, string[] Chain, string[] Evidence, bool Baseline)>();
            queue.Enqueue((principal, [principal], [], true));
            while (queue.TryDequeue(out var step))
            {
                foreach (var edge in outgoing.GetValueOrDefault(step.Current, []))
                {
                    if (step.Chain.Contains(edge.GroupIdentity, StringComparer.Ordinal)) continue;
                    string[] chain = [.. step.Chain, edge.GroupIdentity], evidence = [.. step.Evidence, edge.EvidenceId];
                    bool baseline = step.Baseline && edge.Origin == BaselineImport;
                    if (privileged.Contains(edge.GroupIdentity)) result.Add(new(principal, edge.GroupIdentity, chain, evidence,
                        baseline ? "baseline_observed" : "state_confirmed"));
                    queue.Enqueue((edge.GroupIdentity, chain, evidence, baseline));
                }
            }
        }
        result.Sort((left, right) => {
            int comparison = string.CompareOrdinal(left.PrincipalIdentity, right.PrincipalIdentity);
            if (comparison == 0) comparison = string.CompareOrdinal(left.PrivilegedGroupIdentity, right.PrivilegedGroupIdentity);
            if (comparison == 0) comparison = Compare(left.Chain, right.Chain);
            return comparison != 0 ? comparison : Compare(left.EvidenceIds, right.EvidenceIds);
        });
        return result;
    }

    private static int Compare(IReadOnlyList<string> left, IReadOnlyList<string> right)
    {
        for (int index = 0; index < Math.Min(left.Count, right.Count); index++)
        {
            int comparison = string.CompareOrdinal(left[index], right[index]);
            if (comparison != 0) return comparison;
        }
        return left.Count.CompareTo(right.Count);
    }
}
