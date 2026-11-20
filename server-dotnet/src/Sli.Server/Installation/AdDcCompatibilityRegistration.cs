using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Operations;

namespace Sli.Server.InstallationSetup;

// Source-only metadata: loading this contract must never activate collectors or transfer ownership.
public static class AdDcCompatibilityRegistration
{
    public const string RegistrationFile = "stage9_ad_dc_compatibility_registration_v1.json";
    public const string DatasetReportFile = "stage9_ad_dc_dataset_report_parity_v1.json";
    static readonly string[] StateKeys = ["package_lifecycle", "desired_activation", "observed_health", "component_runtime", "migration_state", "source_state", "queue_state", "dataset_state"];
    static readonly string[] RegistrationChanges = ["source_contact", "source_instance", "cursor", "database", "migration", "runtime_activation", "autostart", "access", "dataset_contract", "product_runtime_ownership"];
    static readonly string[] DatasetChanges = ["source_contact", "database", "migration", "cursor", "runtime_activation", "autostart", "access_assignment", "dataset_contract", "report_publication", "frontend", "read_path_cutover", "product_runtime_ownership"];
    static readonly string[] Steps = ["source_pack_parity", "dataset_and_report_parity", "adapter_parity", "worker_parity", "separate_read_path_cutover_decision"];
    static readonly (string Dataset, string Report, string Path, string[] Primary, string[] Enrichment)[] Contracts = [
        ("ad.audit.snapshot", "ad.state", "/ad-report", ["directory_accounts"], ["directory_group_graph", "directory_exact_logon", "domain_posture", "domain_health"]),
        ("ad.accounts.privileged", "ad.privileged", "/privileged-report", ["privileged_membership"], ["directory_accounts"]),
        ("ad.accounts.vpn", "vpn.audit", "/vpn-report", ["vpn_membership"], ["directory_accounts", "privileged_membership"]),
        ("ad.gpo.governance", "ad.gpo.review", "/gpo-report", ["gpo_governance"], [])
    ];

    static string Text(JsonNode? n) => InstallationPackages.Text(n);
    static void Check(bool valid, string code) { if (!valid) throw new InstallationException(code); }
    static JsonObject Map(JsonObject value, string key)
        => value[key] as JsonObject ?? throw new InstallationException("compatibility_" + key + "_object_required");
    static void Equal(JsonObject value, string key, JsonNode expected, string display)
        => Check(JsonNode.DeepEquals(value[key], expected), $"compatibility_{key}_must_equal_{display}");
    static void Equal(JsonObject value, string key, string expected) => Equal(value, key, JsonValue.Create(expected)!, expected);
    static string Digest(JsonNode value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalJson.Serialize(value, false))));
    static string[] Strings(JsonNode? value, string error, bool empty = false)
    {
        Check(value is JsonArray a && (empty || a.Count > 0) && a.All(n => Text(n).Length > 0), error);
        string[] result = value!.AsArray().Select(Text).ToArray();
        Check(result.Distinct(StringComparer.Ordinal).Count() == result.Length, error);
        return result;
    }
    static void NoChanges(JsonObject value, string[] keys, string prefix)
    {
        var changes = Map(value, "changes");
        Check(InstallationPackages.Keys(changes, keys), (prefix == "compatibility_registration" ? "compatibility" : prefix) + "_change_contract_incomplete");
        var enabled = changes.Where(p => p.Value is not JsonValue v || !v.TryGetValue<bool>(out bool b) || b)
            .Select(p => p.Key).Order(StringComparer.Ordinal).ToArray();
        Check(enabled.Length == 0, prefix + "_changes_execution:" + string.Join(',', enabled));
    }
    static (JsonObject Value, string Sha) Read(string file)
    {
        using var stream = typeof(InstallationPackages).Assembly.GetManifestResourceStream("Sli.Installation." + file)
            ?? throw new InvalidOperationException("installation_contract_unavailable");
        using var bytes = new MemoryStream(); stream.CopyTo(bytes);
        byte[] raw = bytes.ToArray();
        return (JsonNode.Parse(raw)!.AsObject(), Convert.ToHexStringLower(SHA256.HashData(raw)));
    }
    public static JsonObject Load()
    {
        var (value, sha) = Read(RegistrationFile);
        return Validate(value, sha);
    }
    public static JsonObject Validate(JsonObject value, string? registrationSha256 = null)
    {
        Equal(value, "schema_version", JsonValue.Create(2)!, "2");
        Equal(value, "registration_id", "sli.stage9.ad-dc.compatibility.v1");
        Equal(value, "plugin_id", "sli.windows.ad-dc");
        Equal(value, "mode", "compatibility_only");
        var package = Map(value, "package");
        Equal(package, "delivery", "bundled_reviewed");
        Equal(package, "lifecycle", "compatibility_registered");
        Equal(package, "handler_loading", "existing_allowlisted_code_only");
        Check(value["source_packs"] is JsonArray { Count: 2 }, "compatibility_source_packs_exactly_two_required");
        var packs = new OperationsCatalog().Packs();
        var ids = new List<string>();
        foreach (var node in value["source_packs"]!.AsArray())
        {
            var item = node as JsonObject ?? throw new InstallationException("compatibility_source_pack_object_required");
            string id = Text(item["pack_id"]);
            var pack = packs.OfType<JsonObject>().FirstOrDefault(p => Text(p["pack_id"]) == id)
                ?? throw new InstallationException("compatibility_source_pack_unknown:" + id);
            Check(JsonNode.DeepEquals(item["version"], pack["version"]), "compatibility_source_pack_version_drift:" + id);
            Check(JsonNode.DeepEquals(item["manifest_sha256"], pack["manifest_sha256"]), "compatibility_source_pack_hash_drift:" + id);
            ids.Add(id);
        }
        Check(ids.SequenceEqual(["sli.windows.ad-dc", "sli.windows.ad-context"]), "compatibility_source_pack_order_or_identity_invalid");
        // These describe the frozen Python host. Do not require Python executables in a native installation.
        var entrypoints = Strings(value["existing_execution_entrypoints"], "compatibility_entrypoints_required");
        foreach (string path in entrypoints)
            Check(!Path.IsPathRooted(path) && !path.Replace('\\', '/').Split('/').Any(p => p is "" or "." or ".."), "compatibility_entrypoint_invalid:" + path);
        var state = Map(value, "state");
        Check(InstallationPackages.Keys(state, StateKeys), "compatibility_state_axes_invalid");
        Equal(state, "component_runtime", "core_owned_final");
        Equal(state, "migration_state", "not_required");
        var ownership = Map(value, "ownership");
        Equal(ownership, "descriptor_and_semantic_contract", "sli.windows.ad-dc");
        Equal(ownership, "directory_context_contract", "sli.windows.ad-context");
        Equal(ownership, "canonical_evidence", "core");
        Equal(ownership, "warm_authentication_session", "core_hosted_compatibility");
        Equal(value, "acquisition_policy", "full_channel_then_core_evidence_then_subscription_routing");
        NoChanges(value, RegistrationChanges, "compatibility_registration");
        Check(Strings(value["potential_strangler_steps"], "compatibility_strangler_sequence_invalid").SequenceEqual(Steps), "compatibility_strangler_sequence_invalid");
        Equal(value, "strangler_steps_authorized", JsonValue.Create(false)!, "False");
        var decision = Map(value, "ownership_decision");
        Equal(decision, "model", "core_owned_final");
        foreach (string key in new[] { "decision_basis", "decision_date", "rationale" })
            Check(Text(decision[key]).Length > 0, "compatibility_ownership_decision_" + key + "_invalid");
        var result = new JsonObject();
        foreach (string key in new[] { "registration_id", "plugin_id", "mode", "state", "ownership", "acquisition_policy" }) result[key] = value[key]!.DeepClone();
        result["source_pack_ids"] = new JsonArray(ids.Select(id => (JsonNode?)JsonValue.Create(id)).ToArray());
        result["entrypoints"] = value["existing_execution_entrypoints"]!.DeepClone();
        result["registration_sha256"] = registrationSha256 ?? Digest(value);
        result["execution_changed"] = false;
        return result;
    }
    public static JsonObject LoadDatasetReportParity()
    {
        var (value, sha) = Read(DatasetReportFile);
        return ValidateDatasetReportParity(value, sha);
    }
    public static JsonObject ValidateDatasetReportParity(JsonObject value, string? paritySha256 = null)
    {
        Equal(value, "schema_version", JsonValue.Create(1)!, "1");
        Equal(value, "parity_id", "sli.stage9.ad-dc.dataset-report-parity.v1");
        Equal(value, "mode", "source_contract_only");
        Equal(value, "registration_id", "sli.stage9.ad-dc.compatibility.v1");
        Check(value["contracts"] is JsonArray { Count: 4 }, "dataset_report_parity_exactly_four_contracts_required");
        for (int i = 0; i < Contracts.Length; i++)
        {
            var item = value["contracts"]![i] as JsonObject ?? throw new InstallationException("dataset_report_parity_contract_shape_invalid");
            Check(InstallationPackages.Keys(item, "primary_source_sections", "enrichment_source_sections", "dataset_key", "dataset_version", "report_key", "report_version", "target_path", "scope_kinds"), "dataset_report_parity_contract_shape_invalid");
            var primary = Strings(item["primary_source_sections"], "dataset_report_parity_primary_source_sections");
            var enrichment = Strings(item["enrichment_source_sections"], "dataset_report_parity_enrichment_source_sections", true);
            Check(Strings(item["scope_kinds"], "dataset_report_parity_scope_kinds").SequenceEqual(["all", "server", "domain"]), "dataset_report_parity_scope_kinds_invalid");
            Check(JsonNode.DeepEquals(item["dataset_version"], JsonValue.Create(1)) && JsonNode.DeepEquals(item["report_version"], JsonValue.Create(1)), "dataset_report_parity_version_invalid");
            var expected = Contracts[i];
            Check(Text(item["dataset_key"]) == expected.Dataset && Text(item["report_key"]) == expected.Report && Text(item["target_path"]) == expected.Path
                && primary.SequenceEqual(expected.Primary) && enrichment.SequenceEqual(expected.Enrichment), "dataset_report_parity_contract_identity_or_order_invalid");
        }
        NoChanges(value, DatasetChanges, "dataset_report_parity");
        Equal(value, "next_gate", "adapter_and_worker_parity_without_read_path_cutover");
        return new JsonObject { ["parity_id"] = value["parity_id"]!.DeepClone(), ["registration_id"] = value["registration_id"]!.DeepClone(),
            ["contracts"] = value["contracts"]!.DeepClone(), ["parity_sha256"] = paritySha256 ?? Digest(value) };
    }
    public static JsonObject BuildEvidence() => new()
    {
        ["schema_version"] = 1, ["evidence_id"] = "stage9-ad-dc-compatibility-registration-v1", ["status"] = "accepted_source_only",
        ["scope"] = "existing_ad_dc_compatibility_registration", ["read_only"] = true, ["source_contact"] = false,
        ["database_changed"] = false, ["cursor_changed"] = false, ["runtime_changed"] = false, ["autostart_changed"] = false,
        ["access_changed"] = false, ["registration"] = Load(), ["next_gate"] = "source_pack_parity_without_runtime_ownership_transfer"
    };
}
