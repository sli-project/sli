using System.Text.Json.Nodes;
using Sli.Server.InstallationSetup;
using Sli.Server.Operations;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.InstallationSetup;

public sealed class AdDcCompatibilityRegistrationTests
{
    static JsonObject Registration() => InstallationPackages.Contract(AdDcCompatibilityRegistration.RegistrationFile);
    static JsonObject Parity() => InstallationPackages.Contract(AdDcCompatibilityRegistration.DatasetReportFile);
    static string T(JsonNode? value) => InstallationPackages.Text(value);

    [Fact]
    public void RegistrationBindsExistingPacksAndKeepsCoreOwnership()
    {
        var result = AdDcCompatibilityRegistration.Load();
        Assert.Equal("sli.windows.ad-dc", T(result["plugin_id"]));
        Assert.Equal("compatibility_only", T(result["mode"]));
        Assert.Equal(new[] { "sli.windows.ad-dc", "sli.windows.ad-context" }, result["source_pack_ids"]!.AsArray().Select(T));
        Assert.Equal("core_owned_final", T(result["state"]!["component_runtime"]));
        Assert.Equal("core_hosted_compatibility", T(result["ownership"]!["warm_authentication_session"]));
        Assert.False(result["execution_changed"]!.GetValue<bool>());
        var raw = Registration();
        Assert.Equal("core_owned_final", T(raw["ownership_decision"]!["model"]));
        foreach (string key in new[] { "decision_basis", "decision_date", "rationale" }) Assert.NotEmpty(T(raw["ownership_decision"]![key]));
        Assert.Equal(new[] { "source_pack_parity", "dataset_and_report_parity", "adapter_parity", "worker_parity", "separate_read_path_cutover_decision" }, raw["potential_strangler_steps"]!.AsArray().Select(T));
        Assert.False(raw["strangler_steps_authorized"]!.GetValue<bool>());
        Assert.Matches("^[0-9a-f]{64}$", T(result["registration_sha256"]));
        result["state"]!["component_runtime"] = "mutated";
        Assert.Equal("core_owned_final", T(AdDcCompatibilityRegistration.Load()["state"]!["component_runtime"]));
    }

    public static TheoryData<string> RegistrationChangeKeys => new() {
        "source_contact", "source_instance", "cursor", "database", "migration", "runtime_activation", "autostart", "access", "dataset_contract", "product_runtime_ownership"
    };
    [Theory, MemberData(nameof(RegistrationChangeKeys))]
    public void RejectsEveryRegistrationExecutionChange(string key)
    {
        var raw = Registration(); raw["changes"]![key] = true;
        Assert.Equal("compatibility_registration_changes_execution:" + key,
            Assert.Throws<InstallationException>(() => AdDcCompatibilityRegistration.Validate(raw)).Message);
    }

    [Theory]
    [InlineData("ownership_decision", "model", "plugin_owned", "compatibility_model_must_equal_core_owned_final")]
    [InlineData("ownership", "warm_authentication_session", "plugin_owned", "compatibility_warm_authentication_session_must_equal_core_hosted_compatibility")]
    [InlineData("ownership_decision", "decision_basis", "", "compatibility_ownership_decision_decision_basis_invalid")]
    [InlineData("ownership_decision", "decision_date", "", "compatibility_ownership_decision_decision_date_invalid")]
    [InlineData("ownership_decision", "rationale", "", "compatibility_ownership_decision_rationale_invalid")]
    public void RejectsOwnershipTransferAndIncompleteDecision(string section, string key, string changed, string error)
    {
        var raw = Registration(); raw[section]![key] = changed;
        Assert.Equal(error, Assert.Throws<InstallationException>(() => AdDcCompatibilityRegistration.Validate(raw)).Message);
    }

    [Fact]
    public void RejectsMissingOwnershipDecisionAndUnauthorizedStranglerSteps()
    {
        var raw = Registration(); raw.Remove("ownership_decision");
        Assert.Equal("compatibility_ownership_decision_object_required", Assert.Throws<InstallationException>(() => AdDcCompatibilityRegistration.Validate(raw)).Message);
        raw = Registration(); raw["strangler_steps_authorized"] = true;
        Assert.Equal("compatibility_strangler_steps_authorized_must_equal_False", Assert.Throws<InstallationException>(() => AdDcCompatibilityRegistration.Validate(raw)).Message);
    }

    [Theory, InlineData(0), InlineData(1)]
    public void RejectsSourcePackHashDrift(int index)
    {
        var raw = Registration(); string id = T(raw["source_packs"]![index]!["pack_id"]);
        raw["source_packs"]![index]!["manifest_sha256"] = new string('0', 64);
        Assert.Equal("compatibility_source_pack_hash_drift:" + id, Assert.Throws<InstallationException>(() => AdDcCompatibilityRegistration.Validate(raw)).Message);
    }

    [Fact]
    public void EvidenceIsPayloadFreeAndStopsBeforeParity()
    {
        var result = AdDcCompatibilityRegistration.BuildEvidence();
        Assert.Equal("accepted_source_only", T(result["status"]));
        Assert.True(result["read_only"]!.GetValue<bool>());
        foreach (string key in new[] { "source_contact", "database_changed", "cursor_changed", "runtime_changed", "autostart_changed", "access_changed" })
            Assert.False(result[key]!.GetValue<bool>());
        Assert.Equal("source_pack_parity_without_runtime_ownership_transfer", T(result["next_gate"]));
        Assert.DoesNotContain("changes", result["registration"]!.AsObject().Select(p => p.Key));
    }

    static JsonObject Event(int id, string channel = "Security", string provider = "Microsoft-Windows-Security-Auditing") => new()
    {
        ["id"] = 1, ["event_id"] = id, ["channel"] = channel, ["provider_name"] = provider,
        ["server_id"] = 1, ["computer"] = "dc.example.test", ["time_created_utc"] = "2026-10-07T00:00:00Z", ["event_data_json"] = new JsonObject()
    };

    [Fact]
    public void LoadingRegistrationDoesNotChangeAdOrNpsRouting()
    {
        var ad = SemanticNormalization.Normalize(Event(4624));
        var nps = SemanticNormalization.Normalize(Event(6272));
        AdDcCompatibilityRegistration.Load();
        var afterAd = SemanticNormalization.Normalize(Event(4624));
        var afterNps = SemanticNormalization.Normalize(Event(6272));
        Assert.Equal(ad.Sha, afterAd.Sha); Assert.Equal(nps.Sha, afterNps.Sha);
        Assert.Equal("authentication.session.created", afterAd.Type);
        Assert.Equal("remote_access.authentication.allowed", afterNps.Type);
        Assert.Equal("mapped", T(afterAd.Quality["semantic_mapping_status"]));
        Assert.Equal("mapped_nps_decision", T(afterNps.Quality["semantic_mapping_status"]));
    }

    [Fact]
    public void EveryExactAdCatalogIdentityReachesTheNativeNormalizer()
    {
        using var stream = typeof(OperationsCatalog).Assembly.GetManifestResourceStream("Sli.Server.Semantic.Risk.event_catalog.json")!;
        var entries = JsonNode.Parse(stream)!["entries"]!.AsArray();
        Assert.NotEmpty(entries);
        Assert.Equal(new[] { "DNS Server", "Directory Service", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-TaskScheduler/Operational", "Security", "System" },
            entries.Select(e => T(e!["stream"])).Distinct().Order(StringComparer.Ordinal));
        foreach (var entry in entries)
        {
            var source = Event(int.Parse(T(entry!["event_key"])), T(entry["stream"]), T(entry["provider_name"]));
            var result = SemanticNormalization.Normalize(source);
            Assert.NotEqual("source_pack_or_provider_unresolved", T(result.Quality["semantic_mapping_status"]));
        }
    }

    [Fact]
    public void DatasetReportRegistrationHasTheExactFourIdentitiesAndContextSections()
    {
        var parity = AdDcCompatibilityRegistration.LoadDatasetReportParity();
        Assert.Equal("sli.stage9.ad-dc.compatibility.v1", T(parity["registration_id"]));
        var contracts = parity["contracts"]!.AsArray();
        Assert.Equal(new[] { "ad.audit.snapshot", "ad.accounts.privileged", "ad.accounts.vpn", "ad.gpo.governance" }, contracts.Select(c => T(c!["dataset_key"])));
        Assert.Equal(new[] { "ad.state", "ad.privileged", "vpn.audit", "ad.gpo.review" }, contracts.Select(c => T(c!["report_key"])));
        Assert.Equal(new[] { "/ad-report", "/privileged-report", "/vpn-report", "/gpo-report" }, contracts.Select(c => T(c!["target_path"])));
        foreach (var c in contracts) Assert.Equal(new[] { "all", "server", "domain" }, c!["scope_kinds"]!.AsArray().Select(T));
        var sections = new OperationsCatalog().Packs().Single(p => T(p!["pack_id"]) == "sli.windows.ad-context")!["sections"]!.AsArray().Select(T).ToArray();
        Assert.Equal(new[] { "privileged_membership", "directory_accounts", "directory_group_graph", "directory_exact_logon", "vpn_membership", "gpo_governance", "domain_posture", "domain_health" }, sections);
        var declared = contracts.SelectMany(c => c!["primary_source_sections"]!.AsArray().Concat(c["enrichment_source_sections"]!.AsArray())).Select(T).ToHashSet();
        Assert.True(declared.SetEquals(sections));
    }

    [Fact]
    public void CompatibilityAdaptersAreExistingAndAllowlistedForTheirPacks()
    {
        Assert.Equal(new[] { "windows-eventlog-pywin32", "windows-eventlog-powershell", "ad-context-powershell" },
            OperationsCatalog.Adapters().Select(a => T(a!["adapter_id"])));
        var packs = new OperationsCatalog().Packs();
        var ad = packs.Single(p => T(p!["pack_id"]) == "sli.windows.ad-dc")!;
        var context = packs.Single(p => T(p!["pack_id"]) == "sli.windows.ad-context")!;
        Assert.Equal(new[] { "windows-eventlog-pywin32", "windows-eventlog-powershell" }, ad["adapters"]!.AsArray().Select(T));
        Assert.Equal(new[] { "ad-context-powershell" }, context["adapters"]!.AsArray().Select(T));
    }

    public static TheoryData<string> DatasetChangeKeys => new() {
        "source_contact", "database", "migration", "cursor", "runtime_activation", "autostart", "access_assignment", "dataset_contract", "report_publication", "frontend", "read_path_cutover", "product_runtime_ownership"
    };
    [Theory, MemberData(nameof(DatasetChangeKeys))]
    public void RejectsEveryDatasetReportExecutionChange(string key)
    {
        var raw = Parity(); raw["changes"]![key] = true;
        Assert.Equal("dataset_report_parity_changes_execution:" + key, Assert.Throws<InstallationException>(() => AdDcCompatibilityRegistration.ValidateDatasetReportParity(raw)).Message);
    }

    [Theory]
    [InlineData("target_path", "/reports/vpn")]
    [InlineData("dataset_key", "ad.accounts.unknown")]
    [InlineData("report_key", "ad.unknown")]
    public void RejectsRouteAndIdentityDrift(string key, string changed)
    {
        var raw = Parity(); raw["contracts"]![2]![key] = changed;
        Assert.Equal("dataset_report_parity_contract_identity_or_order_invalid", Assert.Throws<InstallationException>(() => AdDcCompatibilityRegistration.ValidateDatasetReportParity(raw)).Message);
    }

    [Theory, InlineData(false), InlineData(true)]
    public void FalseMustBeBooleanAndChangeContractsMustBeComplete(bool dataset)
    {
        var raw = dataset ? Parity() : Registration();
        string prefix = dataset ? "dataset_report_parity" : "compatibility_registration";
        raw["changes"]!["source_contact"] = 0;
        Assert.Equal(prefix + "_changes_execution:source_contact", Assert.Throws<InstallationException>(() => Validate()).Message);
        raw["changes"]!.AsObject().Remove("source_contact");
        Assert.Equal((dataset ? "dataset_report_parity" : "compatibility") + "_change_contract_incomplete", Assert.Throws<InstallationException>(() => Validate()).Message);
        JsonObject Validate() => dataset ? AdDcCompatibilityRegistration.ValidateDatasetReportParity(raw) : AdDcCompatibilityRegistration.Validate(raw);
    }

    [Fact]
    public async Task InstallationCatalogUsesValidatedCoreOwnedState()
    {
        await using var fixture = new InstallationFixture(); await fixture.StartAsync();
        var response = await fixture.SendAsync("GET", "/api/v1/operations/plugins");
        Assert.Equal(200, response.Status);
        Assert.False(response.Body["runtime_changed"]!.GetValue<bool>());
        Assert.False(response.Body["source_contact"]!.GetValue<bool>());
        var ad = response.Body["items"]!.AsArray().Single(p => T(p!["plugin_id"]) == "sli.windows.ad-dc")!["observed"]!;
        Assert.Equal("core_owned_final", T(ad["state"]!["component_runtime"]));
        Assert.Equal("compatibility_registered_not_live_asserted", T(ad["status"]));
        Assert.Equal(0, ad["source_count"]!.GetValue<int>());
        Assert.Empty(ad["sources"]!.AsArray());
        Assert.DoesNotContain(fixture.Database.Calls, c => c.Write);
    }
}
