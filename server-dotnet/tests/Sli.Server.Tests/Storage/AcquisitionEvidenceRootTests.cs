using System.Text.Json.Nodes;
using Sli.Server.Storage;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class AcquisitionEvidenceRootTests
{
    private const string Worker = "S-1-5-21-100000001-200000002-300000003-7995";
    private const string Admins = "S-1-5-32-544";
    private static string Placeholder => AcquisitionEvidenceRoot.LoadHistoricalContract()["manual_worker_identity"]!["sid"]!.GetValue<string>();

    private static JsonObject Entry(string sid, bool inherited) => new()
    {
        ["sid"] = sid, ["access_type"] = "allow", ["rights"] = 2032127,
        ["inheritance_flags"] = 3, ["propagation_flags"] = 0, ["is_inherited"] = inherited
    };
    private static JsonObject Node(string name) => new()
    {
        ["relative_path"] = name, ["exists"] = true, ["is_directory"] = true,
        ["is_reparse_point"] = false, ["owner_sid"] = Admins, ["inheritance_protected"] = name == ".",
        ["entries"] = new JsonArray(Entry("S-1-5-18", name != "."), Entry(Admins, name != "."), Entry(Worker, name != "."))
    };
    private static JsonObject Snapshot() => new()
    {
        ["schema_version"] = 1, ["platform"] = "windows",
        ["target"] = new JsonObject
        {
            ["root_fingerprint_sha256"] = new string('a', 64), ["is_absolute"] = true,
            ["outside_project_root"] = true, ["exists"] = true, ["is_directory"] = true,
            ["is_reparse_point"] = false, ["same_volume"] = true
        },
        ["nodes"] = new JsonArray(Node("."), Node("staging"), Node("published"), Node("quarantine"))
    };
    private static JsonObject FirstEntry(JsonObject snapshot) => (JsonObject)snapshot["nodes"]![0]!["entries"]![0]!;
    private static void Rejected(string code, Action action)
    {
        var error = Assert.Throws<EvidenceRootPolicyException>(action);
        Assert.Equal(code, error.Code);
        Assert.Equal(code, error.Message);
        Assert.Null(error.InnerException);
        Assert.DoesNotContain(Worker, error.ToString());
    }

    [Fact]
    public void CurrentContractIsSourceOnlyAndConfiguredIdentityBound()
    {
        var contract = AcquisitionEvidenceRoot.LoadContract();
        Assert.Equal(AcquisitionEvidenceRoot.ContractId, contract["contract_id"]!.GetValue<string>());
        Assert.Equal("prepared_source_only", contract["status"]!.GetValue<string>());
        Assert.False(contract["activation_enabled"]!.GetValue<bool>());
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"source":"configured_collection_identity"}"""), contract["manual_worker_identity"]));
        Assert.True(contract["required_acl"]!["configured_worker_sid_required"]!.GetValue<bool>());
        Assert.Contains("acl_apply", ((JsonArray)contract["prohibited_actions"]!).Select(n => n!.GetValue<string>()));
        Assert.DoesNotContain(Placeholder, contract.ToJsonString());
        Assert.DoesNotContain("EXAMPLE", contract.ToJsonString());
    }

    [Fact]
    public void ConfiguredWorkerEnvironmentFailureIsClosedAndDoesNotReadIdentity()
    {
        bool read = false;
        Rejected("configured_worker_environment_unavailable", () => AcquisitionEvidenceRoot.ConfiguredWorkerSid(
            () => throw new InvalidOperationException("unprovisioned fixture environment"),
            () => { read = true; return Worker; }, () => { read = true; return true; }));
        Assert.False(read);
    }

    [Fact]
    public void ConfiguredWorkerRequiresSidAndVerifiedIdentity()
    {
        Rejected("configured_worker_sid_required", () => AcquisitionEvidenceRoot.ConfiguredWorkerSid(() => { }, () => null, () => throw new Exception("must not verify")));
        Rejected("configured_collection_identity_mismatch", () => AcquisitionEvidenceRoot.ConfiguredWorkerSid(() => { }, () => Worker, () => false));
        Assert.Equal(Worker, AcquisitionEvidenceRoot.ConfiguredWorkerSid(() => { }, () => Worker, () => true));
    }

    [Fact]
    public void HistoricalV1RemainsSeparatelyValidatable()
    {
        var contract = AcquisitionEvidenceRoot.LoadHistoricalContract();
        AcquisitionEvidenceRoot.ValidateContract(contract);
        var snapshot = Snapshot();
        foreach (var node in (JsonArray)snapshot["nodes"]!) node!["entries"]![2]!["sid"] = Placeholder;
        var summary = AcquisitionEvidenceRoot.ValidateReadback(snapshot, contract);
        Assert.Equal(AcquisitionEvidenceRoot.HistoricalContractId, summary["contract_id"]!.GetValue<string>());
        Assert.Equal("accepted", summary["status"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("principal", "EXAMPLE\\different")]
    [InlineData("sid", Worker)]
    public void HistoricalV1RejectsIdentityDrift(string field, string value)
    {
        var contract = AcquisitionEvidenceRoot.LoadHistoricalContract();
        contract["manual_worker_identity"]![field] = value;
        Rejected("evidence_root_worker_identity_changed", () => AcquisitionEvidenceRoot.ValidateContract(contract));
    }

    [Fact]
    public void HistoricalV1RejectsAclSidDrift()
    {
        var contract = AcquisitionEvidenceRoot.LoadHistoricalContract();
        contract["required_acl"]!["full_control_sids"]![2] = Worker;
        Rejected("evidence_root_acl_contract_changed", () => AcquisitionEvidenceRoot.ValidateContract(contract));
    }

    [Fact]
    public void ExactProtectedAclReadbackIsAcceptedWithoutIdentityOrPathLeak()
    {
        var snapshot = Snapshot();
        snapshot["root_path"] = "sensitive fixture path";
        snapshot["principal"] = "sensitive fixture identity";
        var summary = AcquisitionEvidenceRoot.ValidateReadback(snapshot, expectedWorkerSid: Worker);
        var expected = JsonNode.Parse("""
            {"status":"accepted","classification":"protected_acl_exact",
             "contract_id":"sli.radius-acquisition-evidence-root.v2",
             "root_fingerprint_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
             "node_count":4,"acl_entry_count":12,
             "readback_sha256":"d07c6ffe5cfa3f79e993744d9e53ba0147c562ff2d0bfb7998cf6b487add7126",
             "activation_enabled":false,"source_contacted":false,"raw_path_persisted":false}
            """);
        Assert.True(JsonNode.DeepEquals(expected, summary));
        Assert.False(summary.ContainsKey("root_path"));
        Assert.False(summary.ContainsKey("principal"));
        Assert.DoesNotContain(Worker, summary.ToJsonString());
        Assert.DoesNotContain("sensitive fixture", summary.ToJsonString());
    }

    [Fact]
    public void CurrentContractRequiresNonPlaceholderConfiguredSid()
    {
        Rejected("configured_worker_sid_required", () => AcquisitionEvidenceRoot.ValidateReadback(Snapshot()));
        Rejected("configured_worker_sid_placeholder_forbidden", () => AcquisitionEvidenceRoot.ValidateReadback(Snapshot(), expectedWorkerSid: Placeholder));
        Rejected("configured_worker_sid_invalid", () => AcquisitionEvidenceRoot.ValidateReadback(Snapshot(), expectedWorkerSid: "invalid"));
    }

    [Theory]
    [InlineData("S-1-1-0")]
    [InlineData("S-1-5-11")]
    [InlineData("S-1-5-32-545")]
    [InlineData("S-1-5-32-546")]
    public void BroadOrGuestPrincipalIsRejected(string sid)
    {
        var snapshot = Snapshot();
        ((JsonArray)snapshot["nodes"]![0]!["entries"]!).Add(Entry(sid, false));
        Rejected("evidence_root_broad_principal_forbidden", () => AcquisitionEvidenceRoot.ValidateReadback(snapshot, expectedWorkerSid: Worker));
    }

    [Fact]
    public void ExtraPrincipalIsRejected()
    {
        var snapshot = Snapshot();
        ((JsonArray)snapshot["nodes"]![0]!["entries"]!).Add(Entry("S-1-5-21-100000001-200000002-300000003-4", false));
        Rejected("evidence_root_acl_principals_not_exact", () => AcquisitionEvidenceRoot.ValidateReadback(snapshot, expectedWorkerSid: Worker));
    }

    [Fact]
    public void InheritedRootAclIsRejected()
    {
        var snapshot = Snapshot();
        snapshot["nodes"]![0]!["inheritance_protected"] = false;
        Rejected("evidence_root_inheritance_not_protected", () => AcquisitionEvidenceRoot.ValidateReadback(snapshot, expectedWorkerSid: Worker));
    }

    [Fact]
    public void ReparseChildIsRejected()
    {
        var snapshot = Snapshot();
        snapshot["nodes"]![2]!["is_reparse_point"] = true;
        Rejected("evidence_root_reparse_forbidden", () => AcquisitionEvidenceRoot.ValidateReadback(snapshot, expectedWorkerSid: Worker));
    }

    [Fact]
    public void NonExactRightsAreRejected()
    {
        var snapshot = Snapshot();
        snapshot["nodes"]![1]!["entries"]![2]!["rights"] = 131241;
        Rejected("evidence_root_acl_rights_invalid", () => AcquisitionEvidenceRoot.ValidateReadback(snapshot, expectedWorkerSid: Worker));
    }

    [Theory]
    [InlineData("is_absolute")][InlineData("outside_project_root")][InlineData("exists")]
    [InlineData("is_directory")][InlineData("is_reparse_point")][InlineData("same_volume")]
    public void TargetPolicyCannotBeBypassed(string field)
    {
        var snapshot = Snapshot();
        snapshot["target"]![field] = field == "is_reparse_point";
        Rejected($"evidence_root_{field}_required", () => AcquisitionEvidenceRoot.ValidateReadback(snapshot, expectedWorkerSid: Worker));
    }

    [Theory]
    [InlineData("access_type", "deny", "evidence_root_deny_or_unknown_ace")]
    [InlineData("sid", "invalid", "evidence_root_acl_sid_invalid")]
    public void MalformedOrDenyAceIsRejected(string field, string value, string code)
    {
        var snapshot = Snapshot(); FirstEntry(snapshot)[field] = value;
        Rejected(code, () => AcquisitionEvidenceRoot.ValidateReadback(snapshot, expectedWorkerSid: Worker));
    }

    [Theory]
    [InlineData("inheritance_flags", 0, "evidence_root_acl_inheritance_flags_invalid")]
    [InlineData("propagation_flags", 1, "evidence_root_acl_propagation_flags_invalid")]
    public void AceFlagsAreExact(string field, int value, string code)
    {
        var snapshot = Snapshot(); FirstEntry(snapshot)[field] = value;
        Rejected(code, () => AcquisitionEvidenceRoot.ValidateReadback(snapshot, expectedWorkerSid: Worker));
    }

    [Theory]
    [InlineData(0)][InlineData(1)]
    public void AceInheritanceStateMustMatchNode(int index)
    {
        var snapshot = Snapshot(); snapshot["nodes"]![index]!["entries"]![0]!["is_inherited"] = index == 0;
        Rejected("evidence_root_acl_inherited_state_invalid", () => AcquisitionEvidenceRoot.ValidateReadback(snapshot, expectedWorkerSid: Worker));
    }

    [Theory]
    [InlineData("manual_worker_identity", "evidence_root_worker_identity_changed")]
    [InlineData("required_acl", "evidence_root_acl_contract_changed")]
    [InlineData("root_policy", "evidence_root_path_policy_changed")]
    public void CurrentPolicyRejectsDrift(string section, string code)
    {
        var contract = AcquisitionEvidenceRoot.LoadContract(); contract[section]!["unexpected"] = true;
        Rejected(code, () => AcquisitionEvidenceRoot.ValidateContract(contract));
        // Caller mutations must not affect the private bundled reference or subsequent loads.
        AcquisitionEvidenceRoot.ValidateReadback(Snapshot(), expectedWorkerSid: Worker);
    }

    [Fact]
    public void DuplicateNodesAndSidsAreRejectedAndOrderDoesNotAffectDigest()
    {
        var snapshot = Snapshot(); snapshot["nodes"]![1]!["relative_path"] = ".";
        Rejected("evidence_root_node_duplicate", () => AcquisitionEvidenceRoot.ValidateReadback(snapshot, expectedWorkerSid: Worker));
        snapshot = Snapshot(); ((JsonArray)snapshot["nodes"]![0]!["entries"]!).Add(Entry(Worker.ToLowerInvariant(), false));
        Rejected("evidence_root_acl_sid_duplicate", () => AcquisitionEvidenceRoot.ValidateReadback(snapshot, expectedWorkerSid: Worker));
        snapshot = Snapshot();
        var nodes = (JsonArray)snapshot["nodes"]!;
        var first = nodes[0]; nodes.RemoveAt(0); nodes.Add(first);
        Assert.True(JsonNode.DeepEquals(AcquisitionEvidenceRoot.ValidateReadback(Snapshot(), expectedWorkerSid: Worker),
            AcquisitionEvidenceRoot.ValidateReadback(snapshot, expectedWorkerSid: Worker.ToLowerInvariant())));
    }
}
