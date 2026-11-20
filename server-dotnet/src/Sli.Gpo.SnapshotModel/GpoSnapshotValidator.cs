using System.Text.Json;
using Sli.Agent.Protocol.Compatibility;
using System.Numerics;
using System.Globalization;
using System.Text.RegularExpressions;

namespace Sli.Gpo.SnapshotModel;

// Source: server/sli/sources/gpo_v2_source.py validate_gpo_v2_snapshot.
public static partial class GpoSnapshotValidator
{
    private static readonly string[] Arrays = ["gpos", "scopes", "links", "settings", "permissions", "wmi_filters", "unresolved_links", "collection_errors"];
    private static readonly string[] Roots = ["schema_version", "collector_version", "demo", "started_at", "completed_at", "observed_at", "collection_status", "domain", "scope", "source_states"];
    private static readonly string[] SourceNames = ["gpo_list", "gpo_reports", "gpc_directory", "sysvol_gpt", "links", "permissions", "wmi_filters"];
    private static readonly HashSet<string> Statuses = new(["observed", "not_collected", "not_evaluated", "missing_in_source", "no_record", "partial", "failed", "access_denied", "parse_error", "not_applicable"], StringComparer.Ordinal);
    private static JsonElement Get(JsonElement v, string key) => v.ValueKind == JsonValueKind.Object && v.TryGetProperty(key, out var p) ? p : default;
    private static string? Str(JsonElement v) => v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    private static void Require(bool condition, string code) { if (!condition) throw new InvalidDataException(code); }

    public static void Validate(JsonElement snapshot)
    {
        Require(snapshot.ValueKind == JsonValueKind.Object, "snapshot_root_invalid");
        foreach (var name in Roots.Concat(Arrays)) Require(snapshot.TryGetProperty(name, out _), "root_fields_missing");
        Require(Str(Get(snapshot, "schema_version"))?.StartsWith("sli.ad-gpo.snapshot/", StringComparison.Ordinal) == true, "unsupported_schema_version");
        Require(Str(Get(snapshot, "collection_status")) is "complete" or "partial" or "failed", "collection_status_invalid");
        Require(Get(snapshot, "demo").ValueKind != JsonValueKind.True && !UnicodeLower.Lower(Get(snapshot, "demo_notice").ValueKind == JsonValueKind.Undefined ? "" : GpoPythonText.Str(Get(snapshot, "demo_notice"))).Contains("демо", StringComparison.Ordinal), "demo_source_snapshot_forbidden");
        foreach (string name in new[] { "started_at", "completed_at", "observed_at" })
        {
            var text = Str(Get(snapshot, name));
            Require(text is not null && GpoSnapshotTimestamp.IsAware(text), "timestamp_invalid");
        }
        foreach (var name in Arrays) Require(Get(snapshot, name).ValueKind == JsonValueKind.Array, "required_array_missing");
        Require(Get(snapshot, "gpos").GetArrayLength() <= 10000, "gpo_count_out_of_bounds");
        var rootStates = Get(snapshot, "source_states");
        Require(rootStates.ValueKind == JsonValueKind.Object, "source_states_required");
        foreach (var name in SourceNames) Require(rootStates.TryGetProperty(name, out _), "required_source_missing");
        foreach (var state in rootStates.EnumerateObject()) ValidateState(state.Value);
        var ids = Arrays.Take(6).ToDictionary(name => name, name => Ids(Get(snapshot, name)), StringComparer.Ordinal);
        foreach (var gpo in Get(snapshot, "gpos").EnumerateArray())
        {
            Require(Truth(Get(gpo, "guid")) && Truth(Get(gpo, "display_name")), "gpo_identity_required");
            var states = Get(gpo, "source_states"); Require(states.ValueKind == JsonValueKind.Object, "source_states_required");
            foreach (var state in states.EnumerateObject()) ValidateState(state.Value);
            foreach (var (field, target) in new[] { ("link_ids", "links"), ("setting_ids", "settings"), ("permission_ids", "permissions") })
            {
                var refs = Get(gpo, field);
                if (refs.ValueKind == JsonValueKind.Undefined) continue;
                Require(refs.ValueKind == JsonValueKind.Array, "invalid_reference");
                foreach (var reference in refs.EnumerateArray()) Require(Str(reference) is string id && ids[target].Contains(id), "invalid_reference");
            }
        }
        foreach (var link in Get(snapshot, "links").EnumerateArray())
        {
            Require(Str(Get(link, "gpo_id")) is string g && ids["gpos"].Contains(g) && Str(Get(link, "scope_id")) is string s && ids["scopes"].Contains(s), "invalid_link_reference");
            var raw = Get(link, "raw_options");
            bool isInteger = raw.ValueKind == JsonValueKind.True || raw.ValueKind == JsonValueKind.False || Integer(raw, out _);
            Require(isInteger, "link_raw_options_required");
            BigInteger options = raw.ValueKind == JsonValueKind.True ? 1 : raw.ValueKind == JsonValueKind.False ? 0 : ParseInteger(raw);
            Require(Truth(Get(link, "enabled")) == ((options & 1) == 0) && Truth(Get(link, "enforced")) == ((options & 2) == 2), "link_derivation_invalid");
        }
        foreach (var family in new[] { "settings", "permissions" })
            foreach (var item in Get(snapshot, family).EnumerateArray())
                Require(Str(Get(item, "gpo_id")) is string id && ids["gpos"].Contains(id), "invalid_gpo_reference");
        var acl = Get(snapshot, "acl");
        if (acl.ValueKind != JsonValueKind.Undefined) ValidateAcl(acl, ids["gpos"]);
        else foreach (var gpo in Get(snapshot, "gpos").EnumerateArray())
            Require(Str(Get(Get(Get(gpo, "source_states"), "acl"), "status")) != "observed", "gpo_acl_array_required");
    }

    private static HashSet<string> Ids(JsonElement array)
    {
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in array.EnumerateArray())
        {
            Require(item.ValueKind == JsonValueKind.Object, "record_invalid");
            var id = Str(Get(item, "id"));
            Require(!string.IsNullOrEmpty(id) && ids.Add(id), "record_id_invalid");
        }
        return ids;
    }
    private static void ValidateState(JsonElement state)
    {
        Require(state.ValueKind == JsonValueKind.Object && Statuses.Contains(Str(Get(state, "status")) ?? ""), "source_state_invalid");
        var coverage = Get(state, "coverage");
        if (coverage.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null) return;
        Require(coverage.ValueKind == JsonValueKind.Object, "source_coverage_invalid");
        var counts = new Dictionary<string, BigInteger>();
        foreach (var name in new[] { "requested", "successful", "failed" })
        {
            var value = Get(coverage, name);
            if (value.ValueKind == JsonValueKind.Undefined) continue;
            Require(Integer(value, out var n) && n >= 0, "source_coverage_counts_invalid");
            counts[name] = n;
        }
        if (counts.Count == 3) Require(counts["successful"] <= counts["requested"] && counts["failed"] <= counts["requested"] - counts["successful"], "source_coverage_total_invalid");
    }
    private static bool Integer(JsonElement value, out BigInteger result)
    {
        result = default;
        return value.ValueKind == JsonValueKind.Number && BigInteger.TryParse(value.GetRawText(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out result);
    }
    private static BigInteger ParseInteger(JsonElement value) => Integer(value, out var result) ? result : throw new InvalidDataException("integer_required");
    private static bool Truth(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.True => true, JsonValueKind.False or JsonValueKind.Null or JsonValueKind.Undefined => false,
        JsonValueKind.String => !string.IsNullOrEmpty(value.GetString()), JsonValueKind.Array => value.GetArrayLength() != 0,
        JsonValueKind.Object => value.EnumerateObject().Any(), JsonValueKind.Number => value.GetDouble() != 0,
        _ => false
    };
    private static void ValidateAcl(JsonElement acl, HashSet<string> gpos)
    {
        Require(acl.ValueKind == JsonValueKind.Array && acl.GetArrayLength() <= 100000, "gpo_acl_out_of_bounds");
        _ = Ids(acl); var indexes = new HashSet<(string, BigInteger)>();
        foreach (var ace in acl.EnumerateArray())
        {
            var g = Str(Get(ace, "gpo_id")); var index = Get(ace, "ace_index"); var mask = Get(ace, "access_mask"); var flags = Get(ace, "propagation_flags");
            Require(g is not null && gpos.Contains(g) && Integer(index, out var i) && i >= 0
                && indexes.Add((g, i)) && mask.ValueKind == JsonValueKind.Number && mask.TryGetInt64(out var m) && m >= int.MinValue && m < 4294967296L
                && flags.ValueKind == JsonValueKind.Number && flags.TryGetInt32(out var f) && f is >= 0 and <= 3
                && Str(Get(ace, "access_control_type")) is "Allow" or "Deny"
                && Get(ace, "inherited").ValueKind is JsonValueKind.True or JsonValueKind.False
                && Regex.IsMatch(Str(Get(ace, "trustee_sid")) ?? "", @"\AS-\d+(?:-\d+)+\z", RegexOptions.IgnoreCase)
                && Regex.IsMatch(Str(Get(ace, "object_type")) ?? "", @"\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z", RegexOptions.IgnoreCase), "gpo_acl_ace_invalid");
        }
    }
}


