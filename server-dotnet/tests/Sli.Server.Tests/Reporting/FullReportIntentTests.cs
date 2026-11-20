using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Sli.Server.Access;
using Sli.Server.Reporting.V2;
using Xunit;
namespace Sli.Server.Tests.Reporting;

// tests/reporting/test_full_report_intents.py: acceptance uses declarations only, no DB.
public sealed class FullReportIntentTests
{
    private static readonly string[] Keys = [
        "ad.infrastructure", "ad.users.v2", "ad.computers.v6", "ad.computer-logons",
        "ad.new-logon-pairs", "ad.gpo.v2", "events.journal", "security.events.chains",
        "security.problems", "security.rule-quality", "vpn.accounts", "vpn.connections",
        "notifications.channels", "notifications.deliveries", "workstations.logons",
        "workstations.processes", "workstations.usb", "workstations.protection", "workstations.overview",
        "file-audit.overview", "file-audit.actions", "file-audit.mass-operations", "file-audit.permission-changes",
        "file-audit.access-denials", "file-audit.out-of-hours", "file-audit.permissions", "file-audit.audit-state"];
    // Explicit expectations, so deleting a required lane/state in production cannot weaken the test.
    private static readonly string[] Lanes = ["product_user", "authorization", "deterministic_interpretation", "api_view_model", "ui_honest_states", "evidence_audit"];
    private static readonly string[] States = ["empty", "denied", "partial", "stale", "unavailable"];
    private static readonly string[] Sections = ["identity", "user_need", "scope", "sources", "access", "data_quality", "observation",
        "qualification", "risk", "confidence", "result_limits", "views", "acceptance_lanes", "ai_assistance", "fallback_and_non_goals"];
    public static IEnumerable<object[]> Products() => Keys.Select(key => new object[] { key });
    public static IEnumerable<object[]> AcceptanceLanes() => Lanes.Select(lane => new object[] { lane });
    private static ReportDefinition Definition(string key = "ad.computers.v6") => new ReportDefinitionRegistry().Get(key)!;
    private static string Text(JsonNode? value) => value!.GetValue<string>();
    private static string[] Strings(JsonNode? value) => value!.AsArray().Select(Text).ToArray();
    private static void Nonempty(JsonNode? value) => Assert.False(string.IsNullOrWhiteSpace(Text(value)));
    private static void Error(string expected, Action action) => Assert.Equal(expected, Assert.Throws<ReportRequestException>(action).Message);
    private static QueryCollection Query(Dictionary<string, StringValues> values) => new(values);

    [Fact]
    public void AcceptanceCasesCoverEveryRegisteredProduct()
    {
        var registry = new ReportDefinitionRegistry();
        var rules = new ReportRuleCatalog(new PluginGenerationReader(null)).Capture().Rules;
        Assert.Equal(Keys.Order(), rules.Select(rule => rule.RegistryKey).Order());
        registry.ValidateIntents();
    }

    [Theory] [MemberData(nameof(Products))]
    public void ProductUserHasFullOriginalContract(string key)
    {
        var definition = Definition(key); var contract = definition.IntentContract();
        Assert.Equal(key, ReportIntent.Validate(contract));
        Assert.All(Sections, section => Assert.True(contract.ContainsKey(section), section));
        Assert.All(Lanes, lane => Nonempty(contract["acceptance_lanes"]![lane]));
        Nonempty(contract["user_need"]!["question"]); Nonempty(contract["user_need"]!["authorized_action"]);
        Assert.NotEqual("list", Text(contract["identity"]!["primary_archetype"]));
        Assert.Equal("existing", Text(contract["identity"]!["product_status"]));
        Assert.Equal(Text(definition.Declaration["title"]), Text(contract["identity"]!["name"]));
    }

    [Theory] [MemberData(nameof(Products))]
    public void AuthorizationMatchesExecutableGrantsFieldsAndCapabilities(string key)
    {
        var definition = Definition(key); var access = definition.IntentContract()["access"]!;
        Assert.Equal(definition.AccessKey, Text(access["dataset_or_report_grant"]));
        Assert.Subset(Strings(access["permitted_field_classes"]).ToHashSet(), Strings(definition.Rule["required_fields"]).ToHashSet());
        Assert.All(Strings(definition.Rule["required_capabilities"]), capability => Assert.Contains(capability, Text(access["required_capability"]).Split(", ")));
        string export = definition.Rule["export_action"]?.GetValue<string>() ?? "export";
        Assert.Equal(definition.HasExport, Strings(access["allowed_actions"]).Contains(export));
        var facts = ReportFixture.Facts(assigned: false);
        var denied = new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts));
        // ResolveScope is the counterpart of Python resolve_access_scope, including delegated readers.
        var error = Assert.Throws<ReportRequestException>(() => new ReportAccess(definition, denied).ResolveScope());
        Assert.Equal(403, error.Status); Assert.Equal("report_access_denied", error.Message);
    }

    [Theory] [MemberData(nameof(Products))]
    public void DeterministicPolicyAndOriginalInterpretationRemainRequired(string key)
    {
        var definition = Definition(key); var contract = definition.IntentContract();
        Nonempty(contract["deterministic_policy"]);
        Assert.Equal("not_applicable", Text(contract["ai_assistance"]!["mode"]));
        contract["qualification"] = new JsonObject { ["status"] = "measured", ["definition"] = "" };
        Error("qualification_invalid", () => ReportIntent.Validate(contract));
        definition.Declaration["intent"]!["deterministic_policy"] = "";
        Error("report_intent_invalid:deterministic_policy", () => ReportDefinitionRegistry.ValidateIntents([definition]));
    }

    [Theory] [MemberData(nameof(Products))]
    public void ApiBoundsComeFromExecutableDeclaration(string key)
    {
        var definition = Definition(key); var limits = definition.IntentContract()["result_limits"]!["execution"]!;
        Assert.Equal(definition.DefaultLimit, limits["default"]!.GetValue<int>());
        Assert.Equal(definition.MaxLimit, limits["max"]!.GetValue<int>());
        var periods = definition.Params.Where(param => Text(param["kind"]) == "period").ToArray();
        Assert.Equal(periods.Length, limits["period_max_days"]!.AsObject().Count);
        foreach (var param in periods) Assert.True(JsonNode.DeepEquals(param["max_days"], limits["period_max_days"]![Text(param["key"])]));
        Assert.True(JsonNode.DeepEquals(definition.Detail?["default_limit"], limits["detail_default"]));
        var query = definition.Params.Where(param => param["required"]?.GetValue<bool>() == true && Text(param["kind"]) == "domain")
            .ToDictionary(param => Text(param["key"]), param => new StringValues(param["default"]?.ToString() ?? "1"));
        var (_, paging) = ReportParameters.Parse(definition, Query(query));
        Assert.Equal(definition.DefaultLimit, paging.Limit);
        query["limit"] = (definition.MaxLimit + 1).ToString(System.Globalization.CultureInfo.InvariantCulture);
        Error("report_limit_invalid", () => ReportParameters.Parse(definition, Query(query)));
    }

    [Theory] [MemberData(nameof(Products))]
    public void MissingDataStatesRemainDistinctFromEmpty(string key)
    {
        var definition = Definition(key); var contract = definition.IntentContract();
        Assert.All(States, state => Assert.Contains(state, Strings(contract["result_limits"]!["honest_states"])));
        Nonempty(contract["fallback_and_non_goals"]!["deterministic_fallback"]);
        var states = States.ToDictionary(state => state, state => Text(ReportResult.Create(key, ReportResult.SourceState(state))["state"]));
        Assert.Equal(States.Length, states.Values.Distinct().Count());
        Assert.Equal("error", states["unavailable"]); Assert.Equal("empty", states["empty"]);
        var honest = contract["result_limits"]!["honest_states"]!.AsArray();
        honest.Remove(honest.Single(state => Text(state) == "partial"));
        Error("honest_states_incomplete", () => ReportIntent.Validate(contract));
    }

    [Theory] [MemberData(nameof(Products))]
    public void EvidenceRetainsSourceAuthorityAndRetentionBoundary(string key)
    {
        var definition = Definition(key); var contract = definition.IntentContract(); var intent = definition.Declaration["intent"]!;
        Assert.NotEmpty(contract["sources"]!["canonical"]!.AsArray());
        Assert.Equal(Text(contract["observation"]!["evidence_retention_boundary"]), Text(contract["result_limits"]!["retention_limits"]));
        Assert.Equal(Text(contract["views"]!["auditor_evidence_view"]), Text(contract["result_limits"]!["provenance"]));
        Assert.Equal(Text(intent["provenance"]), Text(contract["result_limits"]!["provenance"]));
        Assert.Equal(string.Join("; ", Strings(intent["sources"]).Where(source => source.StartsWith("Canonical:", StringComparison.Ordinal))), Text(contract["observation"]!["source_identity"]));
        Nonempty(contract["fallback_and_non_goals"]!["non_goals"]);
        contract["fallback_and_non_goals"]!["deterministic_fallback"] = "";
        Error("fallback_invalid", () => ReportIntent.Validate(contract));
    }

    [Theory] [MemberData(nameof(AcceptanceLanes))]
    public void RegistryRejectsEachMissingAcceptanceLane(string lane)
    {
        var definition = Definition(); definition.Declaration["intent"]!["acceptance_lanes"]!.AsObject().Remove(lane);
        Error("report_intent_invalid:acceptance_lanes", () => ReportDefinitionRegistry.ValidateIntents([definition]));
    }
    [Theory] [InlineData("qualification")] [InlineData("risk")] [InlineData("confidence")]
    public void RegistryUsesOriginalInterpretationValidation(string field)
    {
        var definition = Definition(); definition.Declaration["intent"]![field] = new JsonObject { ["status"] = "invented", ["reason"] = "synthetic" };
        Error(field + "_invalid", () => ReportDefinitionRegistry.ValidateIntents([definition]));
    }
    [Theory] [InlineData("Supplemental: synthetic context")] [InlineData("Canonical:")] [InlineData("untagged source")]
    public void SourceAuthorityCannotBeGuessed(string source)
    {
        var definition = Definition(); definition.Declaration["intent"]!["sources"] = new JsonArray(source);
        Error("report_intent_invalid:sources", () => ReportDefinitionRegistry.ValidateIntents([definition]));
    }
    [Fact]
    public void LimitsFollowChangedDeclarationWithoutChangingPassport()
    {
        var definition = Definition(); var original = definition.Declaration["intent"]!.DeepClone();
        definition.Declaration["limits"] = new JsonObject { ["default"] = 10, ["max"] = 20 };
        definition.Declaration["export"] = false;
        var contract = definition.IntentContract();
        Assert.Equal(10, contract["result_limits"]!["execution"]!["default"]!.GetValue<int>());
        Assert.Equal(20, contract["result_limits"]!["execution"]!["max"]!.GetValue<int>());
        Assert.Equal(new[] { "view" }, Strings(contract["access"]!["allowed_actions"]));
        Assert.True(JsonNode.DeepEquals(original, definition.Declaration["intent"]));
        contract["acceptance_lanes"]!["product_user"] = "tampered";
        Assert.True(JsonNode.DeepEquals(original, definition.Declaration["intent"]));
    }
}
