using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol;

namespace Sli.Server.Storage;

public sealed class EvidenceRootPolicyException(string code) : Exception(code)
{
    public string Code { get; } = code;
}

// Validates normalized Windows readback only. Never contacts a source or changes ACLs.
public static class AcquisitionEvidenceRoot
{
    public const string ContractId = "sli.radius-acquisition-evidence-root.v2";
    public const string HistoricalContractId = "sli.radius-acquisition-evidence-root.v1";
    private static readonly string[] Names = [".", "staging", "published", "quarantine"];
    private static readonly string[] FixedSids = ["S-1-5-18", "S-1-5-32-544"];
    private static readonly string[] ForbiddenSids = ["S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-32-546"];
    private static readonly Regex Sid = new(@"\AS-\d(?:-\d+)+\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex Sha256 = new(@"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant);
    // Private bundled contracts are the immutable reference for caller-supplied policies.
    private static readonly JsonObject Current = ReadBundled("v2");
    private static readonly JsonObject Historical = ReadBundled("v1");

    private static JsonObject ReadBundled(string version)
    {
        using var stream = typeof(AcquisitionEvidenceRoot).Assembly.GetManifestResourceStream(
            $"Sli.Server.Storage.stage9_radius_evidence_root_{version}.json");
        if (stream is null) throw Error("evidence_root_contract_invalid");
        return JsonNode.Parse(stream) as JsonObject ?? throw Error("evidence_root_contract_invalid");
    }

    public static JsonObject LoadContract(string? path = null)
    {
        if (path is null) return ValidateContract(Current);
        try
        {
            return ValidateContract(JsonNode.Parse(File.ReadAllText(path)) as JsonObject
                ?? throw Error("evidence_root_contract_invalid"));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            throw Error("evidence_root_contract_invalid");
        }
    }

    public static JsonObject LoadHistoricalContract() => ValidateContract(Historical);

    public static JsonObject ValidateContract(JsonObject contract)
    {
        Require(Number(contract["schema_version"]) == 1, "evidence_root_schema_unsupported");
        Require(Text(contract["status"]) == "prepared_source_only", "evidence_root_source_only_required");
        Require(Text(contract["platform"]) == "windows_ntfs", "evidence_root_platform_invalid");
        Require(IsBool(contract["activation_enabled"], false), "evidence_root_activation_forbidden");
        Require(JsonNode.DeepEquals(contract["required_relative_directories"], Current["required_relative_directories"]), "evidence_root_directories_invalid");
        Require(JsonNode.DeepEquals(contract["forbidden_sids"], Current["forbidden_sids"]), "evidence_root_forbidden_sids_changed");
        Require(JsonNode.DeepEquals(contract["root_policy"], Current["root_policy"]), "evidence_root_path_policy_changed");
        Require(contract["prohibited_actions"] is JsonArray actions && actions.Select(Text).ToHashSet(StringComparer.Ordinal)
            .SetEquals(((JsonArray)Current["prohibited_actions"]!).Select(Text)), "evidence_root_prohibitions_changed");
        var reference = Text(contract["contract_id"]) switch
        {
            ContractId => Current,
            HistoricalContractId => Historical,
            _ => throw Error("evidence_root_contract_id_unexpected")
        };
        Require(JsonNode.DeepEquals(contract["manual_worker_identity"], reference["manual_worker_identity"]), "evidence_root_worker_identity_changed");
        Require(JsonNode.DeepEquals(contract["required_acl"], reference["required_acl"]), "evidence_root_acl_contract_changed");
        return (JsonObject)contract.DeepClone();
    }

    // Dependencies are explicit so supervisor failures cannot fall back to a local identity.
    public static string ConfiguredWorkerSid(Action loadSupervisorEnvironment, Func<string?> expectedSid, Func<bool> verifyCollectionIdentity)
    {
        try { loadSupervisorEnvironment(); }
        catch (InvalidOperationException) { throw Error("configured_worker_environment_unavailable"); }
        string? sid = expectedSid();
        Require(!string.IsNullOrEmpty(sid), "configured_worker_sid_required");
        Require(verifyCollectionIdentity(), "configured_collection_identity_mismatch");
        return sid!;
    }

    public static JsonObject ValidateReadback(JsonObject snapshot, JsonObject? contract = null, string? expectedWorkerSid = null)
    {
        var policy = ValidateContract(contract ?? Current);
        Require(Number(snapshot["schema_version"]) == 1, "acl_snapshot_schema_unsupported");
        Require(Text(snapshot["platform"]) == "windows", "acl_snapshot_windows_required");
        var target = snapshot["target"] as JsonObject ?? new JsonObject();
        string fingerprint = Text(target["root_fingerprint_sha256"]).ToLowerInvariant();
        Require(Sha256.IsMatch(fingerprint), "acl_snapshot_fingerprint_invalid");
        foreach (string key in new[] { "is_absolute", "outside_project_root", "exists", "is_directory", "is_reparse_point", "same_volume" })
            Require(IsBool(target[key], key != "is_reparse_point"), $"evidence_root_{key}_required");
        Require(snapshot["nodes"] is JsonArray { Count: 4 }, "evidence_root_nodes_incomplete");
        var nodes = (JsonArray)snapshot["nodes"]!;
        var byName = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
        foreach (var item in nodes)
        {
            Require(item is JsonObject, "evidence_root_node_invalid");
            var node = (JsonObject)item!;
            Require(byName.TryAdd(Text(node["relative_path"]), node), "evidence_root_node_duplicate");
        }
        Require(byName.Keys.ToHashSet(StringComparer.Ordinal).SetEquals(Names), "evidence_root_nodes_unexpected");
        var expectedSids = ExpectedSids(policy, expectedWorkerSid);
        foreach (string name in Names) ValidateNode(byName[name], name == ".", expectedSids);
        int entryCount = byName.Values.Sum(n => ((JsonArray)n["entries"]!).Count);
        var canonical = new JsonObject
        {
            ["contract_id"] = Text(policy["contract_id"]), ["root_fingerprint_sha256"] = fingerprint,
            ["nodes"] = new JsonArray(Names.Select(n => (JsonNode?)JsonValue.Create(n)).ToArray()), ["acl_entry_count"] = entryCount
        };
        return new JsonObject
        {
            ["status"] = "accepted", ["classification"] = "protected_acl_exact", ["contract_id"] = Text(policy["contract_id"]),
            ["root_fingerprint_sha256"] = fingerprint, ["node_count"] = Names.Length, ["acl_entry_count"] = entryCount,
            ["readback_sha256"] = Convert.ToHexStringLower(SHA256.HashData(CanonicalJson.ToBytes(canonical))),
            ["activation_enabled"] = false, ["source_contacted"] = false, ["raw_path_persisted"] = false
        };
    }

    private static HashSet<string> ExpectedSids(JsonObject policy, string? workerSid)
    {
        if (Text(policy["contract_id"]) == HistoricalContractId)
            return ((JsonArray)policy["required_acl"]!["full_control_sids"]!).Select(n => Text(n).ToUpperInvariant()).ToHashSet(StringComparer.Ordinal);
        Require(!string.IsNullOrEmpty(workerSid), "configured_worker_sid_required");
        Require(Sid.IsMatch(workerSid!), "configured_worker_sid_invalid");
        Require(!string.Equals(workerSid, Text(Historical["manual_worker_identity"]!["sid"]), StringComparison.OrdinalIgnoreCase), "configured_worker_sid_placeholder_forbidden");
        return FixedSids.Append(workerSid!.ToUpperInvariant()).ToHashSet(StringComparer.Ordinal);
    }

    private static void ValidateNode(JsonObject node, bool root, HashSet<string> expectedSids)
    {
        Require(IsBool(node["exists"], true) && IsBool(node["is_directory"], true), "evidence_root_node_missing");
        Require(IsBool(node["is_reparse_point"], false), "evidence_root_reparse_forbidden");
        Require(Text(node["owner_sid"]).ToUpperInvariant() == FixedSids[1], "evidence_root_owner_invalid");
        Require(Truthy(node["inheritance_protected"]) == root, root ? "evidence_root_inheritance_not_protected" : "evidence_root_child_inheritance_invalid");
        Require(node["entries"] is JsonArray, "evidence_root_acl_entries_invalid");
        var entries = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
        foreach (var item in (JsonArray)node["entries"]!)
        {
            Require(item is JsonObject, "evidence_root_acl_entry_invalid");
            var entry = (JsonObject)item!;
            string sid = Text(entry["sid"]).ToUpperInvariant();
            Require(Sid.IsMatch(sid), "evidence_root_acl_sid_invalid");
            Require(!ForbiddenSids.Contains(sid, StringComparer.Ordinal), "evidence_root_broad_principal_forbidden");
            Require(entries.TryAdd(sid, entry), "evidence_root_acl_sid_duplicate");
        }
        Require(entries.Keys.ToHashSet(StringComparer.Ordinal).SetEquals(expectedSids), "evidence_root_acl_principals_not_exact");
        foreach (var entry in entries.Values)
        {
            Require(string.Equals(Text(entry["access_type"]), "allow", StringComparison.OrdinalIgnoreCase), "evidence_root_deny_or_unknown_ace");
            Require(Number(entry["rights"]) == 2032127, "evidence_root_acl_rights_invalid");
            Require(Number(entry["inheritance_flags"]) == 3, "evidence_root_acl_inheritance_flags_invalid");
            Require(Number(entry["propagation_flags"]) == 0, "evidence_root_acl_propagation_flags_invalid");
            Require(Truthy(entry["is_inherited"]) != root, "evidence_root_acl_inherited_state_invalid");
        }
    }

    private static string Text(JsonNode? value) => value is JsonValue v && v.TryGetValue<string>(out var text) ? text : "";
    private static bool IsBool(JsonNode? value, bool expected) => value is JsonValue v && v.TryGetValue<bool>(out bool b) && b == expected;
    private static long? Number(JsonNode? value) => long.TryParse(value?.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out long n) ? n : null;
    private static bool Truthy(JsonNode? value) => value switch
    {
        null => false, JsonArray a => a.Count != 0, JsonObject o => o.Count != 0,
        JsonValue v when v.TryGetValue<bool>(out bool b) => b,
        JsonValue v when v.TryGetValue<string>(out var s) => s.Length != 0,
        _ => Number(value) != 0
    };
    private static EvidenceRootPolicyException Error(string code) => new(code);
    private static void Require(bool condition, string code) { if (!condition) throw Error(code); }
}
