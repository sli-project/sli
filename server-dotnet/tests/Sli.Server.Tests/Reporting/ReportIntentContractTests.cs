using System.Text.Json.Nodes;
using Sli.Server.Reporting;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class ReportIntentContractTests
{
    static JsonObject Contract()
    {
        using var stream = typeof(ReportIntentContract).Assembly.GetManifestResourceStream("Sli.Server.Reporting.stage11a_reporting_product_v1.json")!;
        return JsonNode.Parse(stream)!.AsObject();
    }
    static JsonObject First(JsonObject contract) => contract["selected_report_set"]![0]!.AsObject();
    static void Reject(JsonNode? value, string code) =>
        Assert.Equal(code, Assert.Throws<ReportIntentContractError>(() => ReportIntentContract.ValidateReportingProductContract(value)).Message);

    [Fact]
    public void ApprovedContractHasSixUniqueCompleteSelectedIntents()
    {
        var result = ReportIntentContract.LoadReportingProductContract();
        Assert.Equal(["security.queue", "ad.state", "ad.privileged", "ad.gpo.review", "vpn.audit", "operations.readiness"],
            result["selected_report_ids"]!.AsArray().Select(id => id!.GetValue<string>()).ToArray());
        Assert.Equal(6, result["selected_count"]!.GetValue<int>());
        Assert.Equal("vpn.audit", result["primary_g11a3_vertical"]!.GetValue<string>());
        Assert.Equal("sli.stage11a.reporting-product.v1", result["contract_id"]!.GetValue<string>());
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"keep":14,"redesign":0,"merge":10,"remove":0,"defer":4}"""), result["inventory_counts"]));
        var contract = Contract();
        var before = contract.DeepClone();
        ReportIntentContract.ValidateReportingProductContract(contract);
        Assert.True(JsonNode.DeepEquals(before, contract));
    }

    [Fact]
    public void DuplicateSelectedReportIdIsRejected()
    {
        var value = Contract();
        var reports = value["selected_report_set"]!.AsArray();
        reports.Add(reports[0]!.DeepClone());
        Reject(value, "selected_report_ids_unique");
    }

    [Theory]
    [InlineData("identity")][InlineData("user_need")][InlineData("scope")][InlineData("sources")]
    [InlineData("access")][InlineData("data_quality")][InlineData("observation")][InlineData("qualification")]
    [InlineData("risk")][InlineData("confidence")][InlineData("result_limits")][InlineData("views")]
    [InlineData("acceptance_lanes")][InlineData("ai_assistance")][InlineData("fallback_and_non_goals")]
    public void MissingFullIntentSectionIsRejected(string section)
    {
        var value = Contract();
        First(value).Remove(section);
        Reject(value, "intent_section_required");
    }

    [Fact]
    public void UnknownArchetypeIsRejected()
    {
        var value = Contract();
        First(value)["identity"]!["primary_archetype"] = "unknown";
        Reject(value, "primary_archetype_invalid");
    }

    [Fact]
    public void MultiplePrimaryQuestionsAreRejected()
    {
        var value = Contract();
        First(value)["user_need"]!["question"] = new JsonArray("one", "two");
        Reject(value, "user_need_single_value_required");
    }

    [Fact]
    public void MissingCanonicalSourceIsRejectedEvenWithSupplementalSource()
    {
        var value = Contract();
        var sources = First(value)["sources"]!;
        sources["supplemental"] = sources["canonical"]!.DeepClone();
        sources["canonical"] = new JsonArray();
        Reject(value, "canonical_source_required");
    }

    [Theory]
    [InlineData("required_capability")][InlineData("dataset_or_report_grant")][InlineData("server_enforced_scope")]
    public void AccessRequiresCapabilityGrantAndServerEnforcedScope(string field)
    {
        var value = Contract();
        First(value)["access"]![field] = "";
        Reject(value, "access_contract_invalid");
    }

    [Theory]
    [InlineData("empty")][InlineData("denied")][InlineData("partial")][InlineData("stale")][InlineData("unavailable")]
    public void HonestStatesMustRemainDistinct(string state)
    {
        var value = Contract();
        var states = First(value)["result_limits"]!["honest_states"]!.AsArray();
        states.Remove(states.Single(item => item!.GetValue<string>() == state));
        Reject(value, "honest_states_incomplete");
    }

    [Fact]
    public void AiAuthorityValueIsRejected()
    {
        var value = Contract();
        First(value)["ai_assistance"]!["mode"] = "authority";
        Reject(value, "ai_assistance_invalid");
    }

    [Fact]
    public void ComplianceControlRequiresPolicyAndControlMatrix()
    {
        var value = Contract();
        var report = First(value);
        report["identity"]!["primary_archetype"] = "compliance-control";
        report["qualification"] = new JsonObject { ["status"] = "not_applicable", ["reason"] = "none" };
        Reject(value, "compliance_policy_required");
        report["qualification"] = new JsonObject { ["status"] = "measured", ["definition"] = "accepted policy" };
        Reject(value, "compliance_policy_required");
        report["qualification"]!["policy_id"] = "example-policy";
        Reject(value, "compliance_policy_required");
        report["qualification"]!["control_matrix"] = "example-matrix";
        ReportIntentContract.ValidateReportingProductContract(value);
        report["qualification"]!.AsObject().Remove("policy_id");
        Reject(value, "compliance_policy_required");
    }

    [Fact]
    public void NonComplianceReportKeepsRiskAndControlMatrixNotApplicable()
    {
        var value = Contract();
        var report = First(value);
        Assert.NotEqual("compliance-control", report["identity"]!["primary_archetype"]!.GetValue<string>());
        report["risk"] = new JsonObject { ["status"] = "not_applicable", ["reason"] = "no accepted policy" };
        report["qualification"] = new JsonObject { ["status"] = "not_applicable", ["reason"] = "no accepted policy" };
        ReportIntentContract.ValidateReportingProductContract(value);
    }

    [Fact]
    public void ReconciliationPreservesAccepted28SurfaceDistribution()
    {
        var value = Contract();
        value["inventory_reconciliation"]!["accepted_counts"]!["merge"] = 9;
        Reject(value, "inventory_counts_mismatch");
        value = Contract();
        value["inventory_reconciliation"]!["surfaces"]!.AsArray().RemoveAt(0);
        Reject(value, "inventory_counts_mismatch");
        value = Contract();
        var surface = value["inventory_reconciliation"]!["surfaces"]![0]!;
        surface["g11a0_disposition"] = surface["g11a0_disposition"]!.GetValue<string>() == "keep" ? "merge" : "keep";
        Reject(value, "inventory_counts_mismatch");
    }

    [Theory]
    [InlineData("ai-redaction-preview")][InlineData("ai-prompt-preview")][InlineData("ai-reports")][InlineData("ai-analysis")]
    public void SelectedSetCannotIncludeDeferredAiSurface(string surface)
    {
        var value = Contract();
        First(value)["identity"]!["report_id"] = surface;
        Reject(value, "selected_deferred_surface");
    }

    [Fact]
    public void PrimaryVerticalMustRemainVpnAuditAndBeSelected()
    {
        var value = Contract();
        value["primary_g11a3_vertical"] = "ad.state";
        Reject(value, "primary_vertical_invalid");
        value = Contract();
        var reports = value["selected_report_set"]!.AsArray();
        reports.Remove(reports.Single(report => report!["identity"]!["report_id"]!.GetValue<string>() == "vpn.audit"));
        Reject(value, "primary_vertical_invalid");
    }

    [Theory]
    [InlineData("new_source")][InlineData("rbac_redesign")][InlineData("universal_graph")]
    [InlineData("arbitrary_report_builder")][InlineData("mass_redesign")][InlineData("schema_migration")][InlineData("runtime_activation")]
    public void EveryForbiddenArchitectureExpansionRequiresExplicitFalse(string flag)
    {
        var value = Contract();
        var flags = value["change_flags"]!.AsObject();
        flags[flag] = true;
        Reject(value, "forbidden_change_flag");
        flags.Remove(flag);
        Reject(value, "forbidden_change_flag");
        flags[flag] = null;
        Reject(value, "forbidden_change_flag");
        flags[flag] = 0;
        Reject(value, "forbidden_change_flag");
        flags[flag] = "false";
        Reject(value, "forbidden_change_flag");
    }

    [Theory]
    [InlineData("null", "contract_object_required")]
    [InlineData("[]", "contract_object_required")]
    [InlineData("{}", "contract_identity_invalid")]
    public void InvalidContractShapeHasStableError(string json, string code) => Reject(JsonNode.Parse(json), code);

    [Theory]
    [InlineData("selected_report_set", "[]", "selected_report_set_required")]
    [InlineData("selected_report_set", "null", "selected_report_set_required")]
    [InlineData("deferred_set", "[]", "deferred_set_invalid")]
    [InlineData("merge_map", "[]", "merge_map_invalid")]
    [InlineData("collection", "\"ON\"", "collection_must_remain_off")]
    public void BoundedPackageGuardsHaveStableErrors(string field, string json, string code)
    {
        var value = Contract();
        value[field] = JsonNode.Parse(json);
        Reject(value, code);
    }

    [Fact]
    public void FileLoaderValidatesContentAndTranslatesReadErrors()
    {
        string path = Path.Combine(Path.GetTempPath(), "report-intent-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            Assert.Equal("contract_unreadable", Assert.Throws<ReportIntentContractError>(() => ReportIntentContract.LoadReportingProductContract(path)).Message);
            File.WriteAllText(path, "{");
            Assert.Equal("contract_unreadable", Assert.Throws<ReportIntentContractError>(() => ReportIntentContract.LoadReportingProductContract(path)).Message);
            File.WriteAllText(path, "null");
            Assert.Equal("contract_object_required", Assert.Throws<ReportIntentContractError>(() => ReportIntentContract.LoadReportingProductContract(path)).Message);
            File.WriteAllText(path, Contract().ToJsonString());
            Assert.True(JsonNode.DeepEquals(ReportIntentContract.LoadReportingProductContract(), ReportIntentContract.LoadReportingProductContract(path)));
        }
        finally { File.Delete(path); }
    }
}
