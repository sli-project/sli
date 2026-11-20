using System.Globalization;
using System.Numerics;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sli.Server.Ad;

// Read-only admission planning, matching plugins/ad/snapshots/retention.py.
// Expiry itself belongs to the shared PostgreSQL seven-day-ring procedure.
internal static class AdSnapshotRetention
{
    internal const int PolicyHorizonDays = 7;
    internal static IReadOnlyList<string> RequiredRelations { get; } = Array.AsReadOnly(new[] {
        "ad_snapshot_manifests",
        "ad_snapshot_manifest_sources",
        "ad_snapshot_projection_receipts",
        "ad_snapshot_projection_outputs",
        "users_report_v2_snapshots",
        "computers_v6_source_snapshots",
        "gpo_report_v2_source_snapshots"
    });

    internal static JsonObject Plan(DateTimeOffset now, JsonObject? inventory = null, bool due = true, int policyHorizonDays = PolicyHorizonDays)
    {
        if (policyHorizonDays != PolicyHorizonDays) throw new ArgumentException("policy_horizon_days is fixed at 7");
        var cutoff = now.AddDays(-PolicyHorizonDays).UtcDateTime;
        string horizon = cutoff.ToString(cutoff.Ticks % TimeSpan.TicksPerSecond == 0
            ? "yyyy-MM-dd'T'HH:mm:ss'Z'" : "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
        JsonObject Result(string status, BigInteger? before, BigInteger after, JsonObject relations) => new() {
            ["status"] = status, ["policy_horizon_days"] = PolicyHorizonDays, ["horizon_before_utc"] = horizon,
            ["eligible_before"] = Count(before), ["eligible_after"] = Count(after), ["relations"] = relations
        };
        try {
            inventory ??= new JsonObject();
            var roots = new List<(string Relation, JsonObject Value, bool Compatibility)>();
            foreach (string relation in RequiredRelations) {
                var value = inventory.ContainsKey(relation) ? Mapping(inventory[relation], $"inventory for {relation}") : new JsonObject();
                roots.Add((relation, value, false));
            }
            var compatibility = inventory.ContainsKey("compatibility_roots")
                ? Mapping(inventory["compatibility_roots"], "compatibility_roots") : new JsonObject();
            foreach (var (relation, value) in compatibility.OrderBy(p => p.Key, StringComparer.Ordinal)) {
                if (relation == "ad_context_runs") throw new ArgumentException($"{relation} is outside the AD snapshot retention scope");
                if (RequiredRelations.Contains(relation)) throw new ArgumentException("compatibility root duplicates a canonical relation");
                roots.Add((relation, Mapping(value, $"inventory for {relation}"), true));
            }

            var relations = new JsonObject();
            BigInteger before = 0, after = 0;
            bool unknown = false, blocked = false;
            foreach (var (relation, value, isCompatibility) in roots) {
                var count = CandidateCount(value["candidate_count"]);
                string classification = Classify(value, count, isCompatibility);
                if (classification == "blocked_unknown_candidate_count") unknown = true;
                else if (count.HasValue) before += count.Value;
                if (classification.StartsWith("blocked_", StringComparison.Ordinal)) blocked = true;
                else if (count.HasValue) after += count.Value;
                relations[relation] = new JsonObject {
                    ["candidate_count"] = Count(count),
                    ["classification_counts"] = new JsonObject { [classification] = Count(classification == "blocked_unknown_candidate_count" ? BigInteger.One : count) },
                    ["eligible_before"] = Count(count), ["eligible_after"] = Count(classification == "eligible" ? count : BigInteger.Zero)
                };
            }
            return Result(blocked ? "blocked" : due ? "completed" : "not_due", unknown ? null : before, blocked ? BigInteger.Zero : after, relations);
        } catch (ArgumentException error) {
            var result = Result("failed", null, BigInteger.Zero, new JsonObject());
            result["error"] = "ValueError:" + error.Message;
            return result;
        }
    }

    static JsonObject Mapping(JsonNode? value, string name) => value as JsonObject ?? throw new ArgumentException($"{name} must be a mapping");
    static JsonNode? Count(BigInteger? value) => value.HasValue ? JsonNode.Parse(value.Value.ToString(CultureInfo.InvariantCulture)) : null;
    static BigInteger? CandidateCount(JsonNode? value)
    {
        if (value is null) return null;
        if (value.GetValueKind() != JsonValueKind.Number ||
            !BigInteger.TryParse(value.ToJsonString(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var count) || count < 0)
            throw new ArgumentException("candidate_count must be a non-negative integer or null");
        return count;
    }
    static bool Is(JsonObject value, string key, bool expected) => value[key] is JsonValue scalar && scalar.TryGetValue<bool>(out var flag) && flag == expected;
    static string Classify(JsonObject value, BigInteger? count, bool compatibility)
    {
        if (compatibility && !Is(value, "compatibility_ownership_proven", true)) return "blocked_compatibility_ownership";
        if (!Is(value, "root_mapping_proven", true)) return "blocked_missing_root_mapping";
        if (!Is(value, "anchor_proven", true)) return "blocked_missing_anchor";
        if (!Is(value, "owner_admitted", true)) return "blocked_missing_owner_admission";
        if (Is(value, "shared_source", true)) return "blocked_shared_source";
        if (Is(value, "independent_legacy_cleaner", true)) return "blocked_independent_legacy_cleaner";
        string? dependency = value["dependency_state"]?.ToString();
        if (dependency != "safe") return dependency == "restrictive" ? "blocked_dependency_restrictive" : "blocked_dependency_unknown";
        if (count is null) return "blocked_unknown_candidate_count";
        if (count != 0 && !Is(value, "whole_unit_admitted", true)) return "blocked_unapproved_whole_unit";
        return "eligible";
    }
}
