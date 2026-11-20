using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Ad;
using Sli.Server.Auth;
using Sli.Server.Domains;
using Sli.Server.Problems;
using Sli.Server.Storage.EventReports;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Reporting;

// Behavioral vectors from tests/reporting/test_ui_audit_i18n.py.
public sealed class UiAuditI18nTests
{
    [Theory]
    [InlineData(true, true, false, true, false, false, "platform_owner")]
    [InlineData(true, false, true, false, false, false, "resource_context")]
    [InlineData(true, false, false, false, false, false, "assignment_policy")]
    [InlineData(false, false, false, true, true, false, "explicit_deny")]
    [InlineData(false, false, false, false, true, true, "missing_capabilities")]
    [InlineData(false, false, false, false, false, true, "version_review")]
    [InlineData(false, false, false, false, false, false, "not_assigned")]
    public void ExplanationDescribesTheExistingDecision(bool allowed, bool owner, bool resource,
        bool denied, bool missing, bool hasSource, string expected)
    {
        JsonElement J(object value) => JsonSerializer.SerializeToElement(value);
        const string key = "synthetic-report";
        var assignments = new List<JsonElement>();
        if (denied) assignments.Add(J(new { report_key = key, effect = "deny" }));
        if (hasSource) assignments.Add(J(new { report_key = key, effect = "allow", allowed_actions = Array.Empty<string>() }));
        string[] required = missing || resource ? ["events.view"] : [];
        var definition = J(new { report_key = key, discoverable = true, version = 1, dataset_version = 1,
            definition_json = new { required_capabilities = required } });
        var facts = new AccessFacts(owner, "viewer", [], [], [], [], [], assignments, [definition]);
        var capabilities = new CapabilityDecisionSet(owner, new HashSet<string>(),
            new HashSet<string>(resource ? required : []), [], new Dictionary<string, JsonElement>());
        // The Python helper presents a decision already made, including conflicting flags.
        var decision = new AccessDecision("viewer", capabilities, [new(key, allowed, [])]);
        var result = J(AccessReadProjection.Compose(new Principal("session", 1, "viewer"), facts, capabilities, decision, false));
        var row = Assert.Single(result.GetProperty("reports").EnumerateArray());
        Assert.Equal(expected, row.GetProperty("explanation_code").GetString());
        Assert.Equal(allowed, row.GetProperty("allowed").GetBoolean());
    }

    [Fact]
    public void InfrastructureContextCarriesCodesAndPreservesSourceValues()
    {
        var context = JsonNode.Parse("""{"site_name":"Fixture","is_read_only":false}""")!.AsObject();
        var attributes = context.DeepClone().AsObject(); attributes["dns_state"] = false;
        var entity = new JsonObject { ["entity_id"] = 1, ["entity_type"] = "domain_controller",
            ["record"] = new JsonObject { ["attributes"] = attributes }.ToJsonString() };
        var row = Assert.Single(AdInfrastructure.Compose([entity], new()));
        var expected = JsonNode.Parse("""
            [
              {"code":"site_name","label":"Сайт","value":"Fixture","presentation_messages":{
                "label":{"code":"reports.v2.ad.infrastructure.context_labels.site_name","params":{},"text":"Сайт"}}},
              {"code":"is_read_only","label":"RODC","value":"Нет","presentation_messages":{
                "label":{"code":"reports.v2.ad.infrastructure.context_labels.is_read_only","params":{},"text":"RODC"},
                "value":{"code":"reports.boolean.no","params":{},"text":"Нет"}}}
            ]
            """);
        Assert.Equal("dc.dns", row["control_id"]!.GetValue<string>());
        Assert.True(JsonNode.DeepEquals(expected, row["context"]), row["context"]?.ToJsonString());
        Assert.False(row["actual_value"]!.GetValue<bool>());
        Assert.True(JsonNode.DeepEquals(context, row["object_context"]));
    }

    static ProblemAccess PresentationAccess()
    {
        var capabilities = new CapabilityDecisionSet(false, new HashSet<string>(), new HashSet<string>(), [], new Dictionary<string, JsonElement>());
        var grant = new AtomicReportGrant(JsonSerializer.SerializeToElement(new { kind = "all" }),
            new HashSet<string>(["security", "identity_basic", "technical", "raw_evidence"]), new HashSet<string>(["view"]), 1, 1);
        return new(new AccessDecision("viewer", capabilities, [new("security.queue", true, [grant])]));
    }

    [Fact]
    public void ProblemPresentationCarriesCodeWithoutChangingSourceIdentity()
    {
        const string actor = "sid:fixture:S-1-5-18";
        var finding = new JsonObject { ["id"] = 1, ["rule_code"] = "semantic.security.audit_controls_changed", ["title"] = "Stored title", ["actor"] = actor };
        var row = ProblemPresentation.Finding(finding, PresentationAccess(), "");
        Assert.Equal("audit_policy_changed", row["presentation_code"]!.GetValue<string>());
        Assert.Equal(finding["rule_code"]!.ToString(), row["rule_code"]!.ToString());
        Assert.Equal(actor, row["actor"]!.GetValue<string>());
        Assert.Equal("Изменена политика аудита Windows", row["title_text"]!.GetValue<string>());
        var home = HomePresentation.Finding(finding);
        Assert.Equal(row["presentation_code"]!.ToString(), home["presentation_code"]!.ToString());
        Assert.Equal(row["title_text"]!.ToString(), home["title"]!.ToString());
        var unknown = ProblemPresentation.Finding(new JsonObject { ["id"] = 2, ["rule_code"] = "synthetic.future", ["title"] = "Audit policy was changed" }, PresentationAccess(), "");
        Assert.Equal("synthetic.future", unknown["presentation_code"]!.ToString());
        Assert.Equal("synthetic.future", unknown["title_text"]!.ToString());
        var missing = ProblemPresentation.Finding(new JsonObject { ["id"] = 2, ["title"] = "Audit policy was changed" }, PresentationAccess(), "");
        Assert.True(missing.ContainsKey("presentation_code"));
        Assert.Null(missing["presentation_code"]);
    }

    [Theory]
    [InlineData("security.privileged_group_member_added", "privileged_group", "Учётную запись добавили в группу администраторов")]
    [InlineData("security.scheduled_task_created", "scheduled_task", "На компьютере создана задача планировщика")]
    [InlineData("qw.security-log-cleared", "eventlog_cleared", "Журнал безопасности очищен")]
    public void BuiltinL1ProblemsHavePlainWording(string rule, string code, string russian)
    {
        var finding = new JsonObject { ["id"] = 3, ["rule_code"] = "semantic." + rule, ["title"] = "Stored title" };
        var row = ProblemPresentation.Finding(finding, PresentationAccess(), "");
        Assert.Equal(code, row["presentation_code"]!.GetValue<string>());
        Assert.Equal(russian, row["title_text"]!.GetValue<string>());
        var home = HomePresentation.Finding(finding);
        Assert.Equal(code, home["presentation_code"]!.ToString());
        Assert.Equal(russian, home["title"]!.ToString());
        Assert.False(string.IsNullOrEmpty(row["what_happened"]?.ToString()));
        Assert.False(string.IsNullOrEmpty(row["next_text"]?.ToString()));
        Assert.True(row.ContainsKey("wording_limitation"));
        Assert.Null(row["wording_limitation"]);
    }

    [Fact]
    public async Task EventFactAndCheckCodesStayAlignedWithoutSourceValues()
    {
        var normalizer = new KnownBundleNormalizer(EventCardSemanticsTests.Repository(), null, null);
        var card = await normalizer.CardAsync(new JsonObject { ["event_id"] = 4719, ["channel"] = "Security",
            ["provider_name"] = "Microsoft-Windows-Security-Auditing", ["server"] = "fixture-host", ["event_data"] = new JsonObject() }, TestContext.Current.CancellationToken);
        Assert.Equal(new[] { "facts.event", "facts.server" }, card["fact_label_codes"]!.AsArray().Select(n => n!.GetValue<string>()));
        Assert.Equal(card["facts"]!.AsArray().Count, card["fact_label_codes"]!.AsArray().Count);
        Assert.Equal(new[] { "Security:Microsoft-Windows-Security-Auditing:4719.checks.0" }, card["check_codes"]!.AsArray().Select(n => n!.GetValue<string>()));
        Assert.Equal(card["checks"]!.AsArray().Count, card["check_codes"]!.AsArray().Count);
        Assert.Equal("fixture-host", card["facts"]![1]![1]!.GetValue<string>());
        Assert.DoesNotContain("fixture-host", card["fact_label_codes"]!.ToJsonString() + card["check_codes"]!.ToJsonString());
    }
}
