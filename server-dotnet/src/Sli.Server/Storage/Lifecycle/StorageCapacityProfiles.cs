using System.Globalization;
using System.Text.Json.Nodes;
using Sli.Server.Legacy;
using Sli.Server.Operations;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Storage.Lifecycle;

// Read-only capacity decisions share the same resolved policy as file cleanup.
// A recommendation never writes configuration or changes the selected profile.
internal static class StorageCapacityProfiles
{
    internal static JsonObject DefaultPolicy() => new() {
        ["raw_retention_days"] = 2, ["raw_archive_enabled"] = true, ["raw_archive_compress"] = true,
        ["db_retention_days"] = 7, ["relationship_retention_days"] = 30, ["warm_retention_days"] = 365,
        ["backup_retention_days"] = 7, ["log_retention_days"] = 14, ["artifact_retention_days"] = 30,
        ["post_collection_retention_days"] = 30, ["archive_auto_delete_enabled"] = false,
        ["min_free_disk_percent"] = 15, ["stop_collection_if_free_disk_percent_below"] = 10,
        ["stop_collection_if_free_disk_bytes_below"] = 10737418240L, ["critical_free_disk_percent"] = 5,
        ["cleanup_candidate_limit"] = 1000
    };

    internal static JsonObject Resolve(string? selected, JsonObject basis, JsonObject? overrides = null)
    {
        if (selected is not (null or "economy" or "extended")) throw new InvalidDataException("storage_capacity_profile_invalid");
        if (overrides?.Any(p => !LifecyclePolicy.Fields.Contains(p.Key)) == true) throw new InvalidDataException("storage_policy_override_fields_invalid");
        var policy = (JsonObject)basis.DeepClone();
        if (selected == "economy") { policy["raw_archive_enabled"] = false; policy["raw_archive_compress"] = false; }
        foreach (var pair in overrides ?? []) policy[pair.Key] = Copy(pair.Value);
        bool archive = B(policy["raw_archive_enabled"]);
        if (archive && N(policy["warm_retention_days"]) <= 0) throw new InvalidDataException("persistent_raw_archive_requires_positive_warm_retention_days");
        return new() {
            ["selected_profile"] = selected, ["effective_policy"] = policy, ["overrides"] = overrides?.DeepClone() ?? new JsonObject(),
            ["profile_state"] = selected is null ? "not_selected" : "confirmed_by_admin_config",
            ["persistent_raw_archive"] = new JsonObject { ["enabled"] = archive, ["retention_days"] = archive ? Copy(policy["warm_retention_days"]) : null, ["enforceable"] = true }
        };
    }

    internal static JsonObject Read(Func<string, string?> get)
    {
        var configured = DefaultPolicy();
        foreach (string key in configured.Select(p => p.Key).ToArray()) {
            // The relationship horizon is distinct from post-collection retention.
            if (key == "relationship_retention_days") continue;
            string name = key == "cleanup_candidate_limit" ? "ADLOG_STORAGE_CLEANUP_LIMIT" : "ADLOG_" + key.ToUpperInvariant();
            if (get(name) is not { Length: > 0 } raw) continue;
            if (configured[key] is JsonValue value && value.TryGetValue<bool>(out _)) configured[key] = LifecycleAdmission.Enabled(raw);
            else if (long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out long number)) configured[key] = number;
        }
        string? selected = get("ADLOG_STORAGE_CAPACITY_PROFILE");
        if (selected == "") selected = null;
        var changes = new JsonObject();
        foreach (string key in (get("ADLOG_STORAGE_CAPACITY_PROFILE_OVERRIDES") ?? "").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)) {
            if (!LifecyclePolicy.Fields.Contains(key)) throw new InvalidDataException("storage_policy_override_fields_invalid");
            changes[key] = Copy(configured[key]);
        }
        var basis = selected is null ? configured : DefaultPolicy();
        basis["cleanup_candidate_limit"] = Copy(configured["cleanup_candidate_limit"]);
        return Resolve(selected, basis, changes);
    }

    static (DateTimeOffset At, JsonObject Row)[] Snapshots(IEnumerable<JsonObject> snapshots) => snapshots
        .Select(row => (At: Time(row["captured_at"]), Row: row)).Where(p => p.At.HasValue)
        .Select(p => (At: p.At!.Value, p.Row)).OrderBy(p => p.At).ToArray();
    static long Total(JsonObject row) => OperationsStorage.ManagedFields.Sum(key => N(row[key]));

    internal static JsonObject Recommend(IEnumerable<JsonObject> snapshots, string? selected, JsonObject policy)
    {
        var valid = Snapshots(snapshots);
        long deltaSum = 0; double daysSum = 0; int positive = 0;
        for (int i = 1; i < valid.Length; i++) {
            double days = (valid[i].At - valid[i - 1].At).TotalDays;
            if (days <= 0) continue;
            long delta = Total(valid[i].Row) - Total(valid[i - 1].Row);
            if (delta <= 0) { deltaSum = 0; daysSum = 0; positive = 0; }
            else { deltaSum += delta; daysSum += days; positive++; }
        }
        var inputs = new JsonObject { ["valid_snapshots"] = valid.Length, ["positive_intervals_after_reset"] = positive };
        var result = new JsonObject {
            ["selected_profile"] = selected, ["recommended_profile"] = "economy", ["recommendation_changes_selection"] = false,
            ["reason"] = "insufficient_growth_evidence", ["inputs"] = inputs,
            ["growth_bytes_per_day"] = null, ["required_capacity_bytes"] = null, ["reserve_bytes"] = null
        };
        if (positive == 0) return result;
        long growth = (long)Math.Round(deltaSum / daysSum), free = N(valid[^1].Row["disk_free_bytes"]), total = N(valid[^1].Row["disk_total_bytes"]);
        long reserve = Math.Max(N(policy["stop_collection_if_free_disk_bytes_below"]), (long)(total * Math.Max(0, N(policy["stop_collection_if_free_disk_percent_below"])) / 100d));
        long daysBound = Math.Max(Math.Max(N(policy["db_retention_days"]), N(policy["raw_retention_days"])), B(policy["raw_archive_enabled"]) ? N(policy["warm_retention_days"]) : 0);
        long required = growth * daysBound, usable = Math.Max(0, free - reserve);
        bool extended = growth > 0 && usable >= required;
        result["recommended_profile"] = extended ? "extended" : "economy";
        result["reason"] = extended ? "extended_capacity_sufficient" : "bounded_lifecycle_exceeds_usable_capacity";
        inputs["current_disk_free_bytes"] = free; inputs["current_disk_total_bytes"] = total; inputs["bounded_lifecycle_days"] = daysBound;
        result["growth_bytes_per_day"] = growth; result["required_capacity_bytes"] = required;
        result["reserve_bytes"] = reserve; result["usable_capacity_bytes"] = usable;
        return result;
    }

    internal static JsonObject Pressure(JsonObject disk, JsonObject policy)
    {
        int warn = (int)N(policy["min_free_disk_percent"]), stop = (int)N(policy["stop_collection_if_free_disk_percent_below"]), critical = (int)N(policy["critical_free_disk_percent"]);
        bool valid = critical > 0 && critical < stop && stop < warn && warn < 100;
        double? percent = double.TryParse(S(disk["free_percent"]), CultureInfo.InvariantCulture, out double observed) ? observed : null;
        var result = LegacyEnvironment.DiskDecision(N(disk["free_bytes"]), N(disk["total_bytes"]), valid ? warn : 15, valid ? stop : 10, valid ? critical : 5,
            Math.Max(1, N(policy["stop_collection_if_free_disk_bytes_below"])), valid, percent);
        result["disk"] = disk.DeepClone(); result["policy"] = policy.DeepClone();
        return result;
    }

    internal static JsonObject RuntimeEvidence(IEnumerable<JsonObject> snapshots, DateTimeOffset now, JsonObject disk, JsonObject policy)
    {
        var pressure = Pressure(disk, policy); var threshold = pressure["blocking_threshold"]!;
        long reserve = Math.Max(N(threshold["free_bytes"]), (long)(N(disk["total_bytes"]) * N(threshold["free_percent"]) / 100d));
        var valid = Snapshots(snapshots).Where(p => p.At <= now).ToArray();
        var measured = new JsonObject { ["quality"] = "unknown", ["reason"] = "eligible_72_to_96_hour_baseline_required" };
        if (valid.Length > 1) {
            var latest = valid[^1];
            var eligible = valid.SkipLast(1).Select(p => (p.At, p.Row, Hours: (latest.At - p.At).TotalHours))
                .Where(p => p.Hours is >= 72 and <= 96).OrderBy(p => Math.Abs(p.Hours - 72)).ToArray();
            if (eligible.Length > 0) {
                var baseline = eligible[0]; double days = baseline.Hours / 24;
                long Growth(string key) => (long)Math.Round((N(latest.Row[key]) - N(baseline.Row[key])) / days);
                long operational = new[] { "database_bytes", "raw_bytes", "raw_archive_bytes", "logs_bytes", "reports_bytes" }.Sum(key => N(latest.Row[key]) - N(baseline.Row[key]));
                measured = new() { ["quality"] = "measured_72h", ["from"] = Stamp(baseline.At), ["to"] = Stamp(latest.At), ["elapsed_hours"] = Math.Round(baseline.Hours, 2),
                    ["database_bytes_per_day"] = Growth("database_bytes"), ["disk_used_bytes_per_day"] = Growth("disk_used_bytes"), ["operational_bytes_per_day"] = (long)Math.Round(operational / days) };
            }
        }
        string status; JsonObject forecast;
        if (!B(pressure["collection_allowed"])) { status = "already_at_or_below_stop"; forecast = new() { ["status"] = status, ["estimated_days_to_stop"] = 0.0 }; }
        else if (S(measured["quality"]) == "unknown") { status = "unknown"; forecast = new() { ["status"] = status, ["estimated_days_to_stop"] = null }; }
        else {
            status = "ok";
            long growth = Math.Max(0, Math.Max(N(measured["operational_bytes_per_day"]), Math.Max(N(measured["database_bytes_per_day"]), N(measured["disk_used_bytes_per_day"]))));
            forecast = growth <= 0 ? new() { ["status"] = "stable_or_nonpositive_growth", ["estimated_days_to_stop"] = null } :
                new() { ["status"] = "ok", ["estimated_days_to_stop"] = Math.Round(Math.Max(0, N(disk["free_bytes"]) - reserve) / (double)growth, 2), ["growth_bytes_per_day_used"] = growth };
        }
        return new() { ["status"] = status, ["read_only"] = true, ["disk_free_bytes"] = Copy(disk["free_bytes"]), ["disk_free_percent"] = Copy(disk["free_percent"]),
            ["stop_threshold"] = new JsonObject { ["mode"] = "free_bytes_or_percent", ["condition"] = Copy(threshold["condition"]), ["free_bytes"] = Copy(threshold["free_bytes"]), ["free_percent"] = Copy(threshold["free_percent"]), ["effective_reserve_bytes"] = reserve },
            ["measured_growth"] = measured, ["forecast"] = forecast, ["snapshot_count"] = valid.Length, ["snapshot_read_error"] = null };
    }
}
