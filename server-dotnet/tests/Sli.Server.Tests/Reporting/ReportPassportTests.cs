using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Reporting.V2;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class ReportPassportTests
{
    private static ReportDefinition Computers() => new ReportDefinitionRegistry().Get("ad.computers.v6")!;

    [Fact]
    public void DiscoveryValidatesEveryPassportIncludingWorkstationContributionsWithoutReaders()
    {
        // No connection factory or report reader is constructed during discovery.
        var definitions = new ReportDefinitionRegistry().RegisteredReports(validateIntents: true);
        foreach (string family in new[] { "logons", "processes", "usb", "protection", "overview" })
            Assert.Contains(definitions, d => d.Key == "workstations." + family);
        foreach (var definition in definitions)
        {
            var intent = Assert.IsType<JsonObject>(definition.Declaration["intent"]);
            Assert.Equal("sli.report-intent.v1", intent["contract_id"]!.GetValue<string>());
            var fields = intent["field_classes"]!.AsArray().Select(n => n!.GetValue<string>()).ToHashSet();
            Assert.All(definition.Rule["required_fields"]!.AsArray(), n => Assert.Contains(n!.GetValue<string>(), fields));
        }
    }

    [Fact]
    public void TransitionalAllowlistCannotGrow()
    {
        Assert.Empty(ReportIntent.UnmigratedReportIntents);
    }

    [Fact]
    public void RuleQualityPassportPreservesMeasurementAndAccessBoundaries()
    {
        var definition = new ReportDefinitionRegistry().Get("security.rule-quality")!;
        ReportIntent.ValidateReports([definition]);
        var passport = definition.Declaration["intent"]!.AsObject();
        Assert.Equal("summary", passport["primary_archetype"]!.GetValue<string>());
        Assert.Equal(new[] { "security" }, passport["field_classes"]!.AsArray().Select(n => n!.GetValue<string>()));
        Assert.Contains("semantic.review", passport["rights"]!.GetValue<string>());
        Assert.Contains("not_proven", passport["completeness"]!.GetValue<string>());
        Assert.Contains("FP + confirmed", passport["denominator"]!.GetValue<string>());
        Assert.Contains("число которых неизвестно", passport["denominator"]!.GetValue<string>());
        Assert.Contains("проверяются отдельно", passport["freshness_expectation"]!.GetValue<string>());
        Assert.Contains("policy-version attribution", passport["exclusions"]!.GetValue<string>());
    }

    public static IEnumerable<object?[]> EmptyFields => Computers().Declaration["intent"]!.AsObject()
        .Where(p => p.Key is not ("version" or "contract_id"))
        .SelectMany(p => new string?[] { null, "", "  " }.Select(value => new object?[] { p.Key, value }));

    [Theory]
    [MemberData(nameof(EmptyFields))]
    public void MissingOrEmptyPassportFieldFails(string name, string? value)
    {
        var definition = Computers();
        definition.Declaration["intent"]![name] = value;
        Error("report_intent_invalid:" + name, () => ReportIntent.ValidateReports([definition]));
        definition.Declaration["intent"]!.AsObject().Remove(name);
        Error("report_intent_invalid:" + name, () => ReportIntent.ValidateReports([definition]));
    }

    public static IEnumerable<object[]> InvalidLists => new[] { "sources", "field_classes" }
        .SelectMany(name => new[] { "[]", "[\"\"]", "[\"valid\",\"  \"]", "[null]", "\"valid\"" }
            .Select(json => new object[] { name, json }));

    [Theory]
    [MemberData(nameof(InvalidLists))]
    public void SourcesAndFieldClassesRequireNonemptyStringArrays(string name, string json)
    {
        var intent = Computers().Declaration["intent"]!;
        intent[name] = JsonNode.Parse(json);
        Error("report_intent_invalid:" + name, () => ReportIntent.Validate(intent));
    }

    [Theory]
    [InlineData("0")][InlineData("-1")][InlineData("true")][InlineData("\"1\"")][InlineData("null")]
    public void InvalidVersionFails(string json)
    {
        var intent = Computers().Declaration["intent"]!;
        intent["version"] = JsonNode.Parse(json);
        Error("report_intent_invalid:version", () => ReportIntent.Validate(intent));
    }

    [Theory]
    [InlineData("question", "[\"one\",\"two\"]")]
    [InlineData("primary_archetype", "\"unknown\"")]
    public void QuestionIsSingleValueAndPrimaryArchetypeIsKnown(string name, string json)
    {
        var intent = Computers().Declaration["intent"]!;
        intent[name] = JsonNode.Parse(json);
        Error("report_intent_invalid:" + name, () => ReportIntent.Validate(intent));
    }

    [Theory]
    [InlineData("ad.computers.v6")][InlineData("ad.new-logon-pairs")]
    public void MissingPassportFailsOnlyValidationLoad(string key)
    {
        var definition = new ReportDefinitionRegistry().Get(key)!;
        definition.Declaration["intent"] = null;
        var registry = new ReportDefinitionRegistry([definition]);
        Assert.Null(registry.Get(key)!.Declaration["intent"]);
        Assert.Null(Assert.Single(registry.RegisteredReports()).Declaration["intent"]);
        Error("report_intent_missing:" + key, () => registry.RegisteredReports(validateIntents: true));
    }

    [Fact]
    public void AllowlistExemptsOnlyAbsentPassportsAndRejectsObsoleteEntries()
    {
        var definition = Computers();
        var valid = Computers();
        var allowlist = new HashSet<string> { definition.Key };
        definition.Declaration["intent"] = null;
        ReportIntent.ValidateReports([definition], allowlist);
        definition.Declaration["intent"] = valid.Declaration["intent"]!.DeepClone();
        definition.Declaration["intent"]!["question"] = " ";
        Error("report_intent_invalid:question", () => ReportIntent.ValidateReports([definition], allowlist));
        Error("report_intent_allowlist_obsolete", () => ReportIntent.ValidateReports([valid], allowlist));
    }

    [Fact]
    public void AccessFilteredDeclarationCarriesSameVersionedPassportAndSeparateProductArchetype()
    {
        var definition = Computers();
        var access = ReportFixture.Access("{\"kind\":\"domain\",\"ids\":[1]}");
        var report = access.Reports.Single();
        access = access with { Reports = [report with {
            ReportKey = definition.AccessKey,
            Grants = [report.Grants.Single() with {
                AllowedActions = new HashSet<string> { "view" },
                FieldCategories = definition.Rule["required_fields"]!.AsArray().Select(n => n!.GetValue<string>()).ToHashSet()
            }]
        }] };
        var payload = new ReportAccess(definition, access).Declaration();
        Assert.True(JsonNode.DeepEquals(definition.Declaration["intent"], payload["intent"]));
        Assert.Equal("sli.report-intent.v1", payload["intent"]!["contract_id"]!.GetValue<string>());
        Assert.Equal(1, payload["intent"]!["version"]!.GetValue<int>());
        Assert.IsType<JsonArray>(payload["intent"]!["sources"]);
        Assert.IsType<JsonArray>(payload["intent"]!["field_classes"]);
        Assert.Equal(definition.Declaration["archetype"]!.GetValue<string>(), payload["archetype"]!.GetValue<string>());
        payload["intent"]!["question"] = "changed";
        Assert.NotEqual("changed", definition.Declaration["intent"]!["question"]!.GetValue<string>());
    }

    private static void Error(string code, Action action) => Assert.Equal(code, Assert.Throws<InvalidOperationException>(action).Message);
}
