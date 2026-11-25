using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Sli.Server.Access;
using Sli.Server.Reporting.V2;
using Xunit;
namespace Sli.Server.Tests.Reporting;

public sealed class ReportV2PolicyTests
{
    static IQueryCollection Query(params (string Key,string Value)[] values) => new QueryCollection(values.GroupBy(v=>v.Key).ToDictionary(g=>g.Key,g=>new StringValues(g.Select(v=>v.Value).ToArray())));
    static ReportDefinition PeriodDefinition()
    {
        var d=ReportFixture.Definition(); d.Declaration["params"] = JsonNode.Parse("""[{"key":"period","kind":"period","default":"7d","max_days":31},{"key":"domain","kind":"domain"},{"key":"choice","kind":"choice","options":[{"value":"one","label":"One"}]},{"key":"many","kind":"multichoice","options":[{"value":"one","label":"One"}]}]""");
        return d;
    }
    [Theory]
    [InlineData("unknown","x","report_parameter_unknown:unknown")]
    [InlineData("limit","0","report_limit_invalid")][InlineData("limit","11","report_limit_invalid")][InlineData("limit","x","report_limit_invalid")]
    [InlineData("sort","unknown","report_sort_invalid")][InlineData("direction","up","report_sort_invalid")]
    [InlineData("tab","unknown","report_tab_invalid")][InlineData("tz","unknown","report_timezone_invalid")]
    [InlineData("period","yesterday","report_period_invalid")][InlineData("period","90d","report_period_too_wide")]
    [InlineData("domain","0","report_parameter_invalid:domain")][InlineData("choice","two","report_parameter_invalid:choice")]
    [InlineData("many","two","report_parameter_invalid:many")]
    public void ParametersHaveFrozenErrorCodes(string key,string value,string error)
    { Assert.Equal(error,Assert.Throws<ReportRequestException>(()=>ReportParameters.Parse(PeriodDefinition(),Query((key,value)))).Message); }
    [Fact]
    public void MultiValuesFirstScalarUnicodeIntegerAndTimezoneCalendarWindowMatchSource()
    {
        var (parameters,paging)=ReportParameters.Parse(PeriodDefinition(),Query(("limit","２"),("limit","7"),("domain","+1_2"),("many","one"),("many","one"),("period","custom"),("from","2026-01-01"),("to","2026-01-01"),("tz","Asia/Bangkok")));
        Assert.Equal(2,paging.Limit); Assert.Equal(12,parameters["domain"]!.GetValue<int>()); Assert.Equal(2,parameters["many"]!.AsArray().Count);
        Assert.Equal("2025-12-31T17:00:00Z",parameters["period"]!["from_utc"]!.GetValue<string>());
        Assert.Equal("2026-01-01T17:00:00Z",parameters["period"]!["to_utc"]!.GetValue<string>());
    }
    [Fact]
    public void ExactCustomPeriodIsExclusiveAndRequiresOffsets()
    {
        var (p,_)=ReportParameters.Parse(PeriodDefinition(),Query(("period","custom"),("from","2026-01-01T10:00:00+07:00"),("to","2026-01-01T11:00:00+07:00")));
        Assert.Equal("2026-01-01T03:00:00Z",p["period"]!["from_utc"]!.GetValue<string>()); Assert.Equal("2026-01-01T04:00:00Z",p["period"]!["to_utc"]!.GetValue<string>());
        Assert.Equal("report_period_invalid",Assert.Throws<ReportRequestException>(()=>ReportParameters.Parse(PeriodDefinition(),Query(("period","custom"),("from","2026-01-01T10:00:00"),("to","2026-01-01T11:00:00")))).Message);
    }
    [Theory]
    [InlineData("2026-01-01T10:00:00.125+07:00", "2026-01-01T10:00:00.875+07:00", "2026-01-01T03:00:00.125Z", "2026-01-01T03:00:00.875Z")]
    [InlineData("2026-01-01T10:00:00.123456Z", "2026-01-01T10:00:01.654321Z", "2026-01-01T10:00:00.123456Z", "2026-01-01T10:00:01.654321Z")]
    [InlineData("2026-01-01T10:00:00Z", "2026-01-01T10:00:01Z", "2026-01-01T10:00:00Z", "2026-01-01T10:00:01Z")]
    public void Exact_fractional_bounds_survive_workstation_to_journal_handoff(string from, string to, string expectedFrom, string expectedTo)
    {
        var registry = new ReportDefinitionRegistry();
        var (station, _) = ReportParameters.Parse(registry.Get("workstations.overview")!,
            Query(("period", "custom"), ("from", from), ("to", to)));
        Assert.Equal(expectedFrom, station["period"]!["from_utc"]!.ToString());
        Assert.Equal(expectedTo, station["period"]!["to_utc"]!.ToString());
        var (journal, _) = ReportParameters.Parse(registry.Get("events.journal")!,
            Query(("period", "custom"), ("from", station["period"]!["from_utc"]!.ToString()),
                ("to", station["period"]!["to_utc"]!.ToString())));
        Assert.True(JsonNode.DeepEquals(station["period"], journal["period"]));
    }
    [Fact]
    public void TextLimitsAndRequiredParametersAreEnforced()
    {
        var definition=ReportFixture.Definition();
        Assert.Equal("report_parameter_invalid:q",Assert.Throws<ReportRequestException>(()=>ReportParameters.Parse(definition,Query(("q",new string('x',257))))).Message);
        definition.Declaration["params"]![0]!["required"]=true;
        Assert.Equal("report_parameter_required:q",Assert.Throws<ReportRequestException>(()=>ReportParameters.Parse(definition,Query())).Message);
    }
    [Fact]
    public void RestrictedFieldsMustCoverEntireQueryAndCannotCombineDisjointCategories()
    {
        var definition=ReportFixture.Definition(); var baseAccess=ReportFixture.Access("{\"kind\":\"domain\",\"ids\":[1,2]}");
        var original=baseAccess.Reports.Single(); var grant=original.Grants.Single();
        var extra=grant with { Scope=ReportFixture.J("""{"kind":"domain","ids":[1]}"""), FieldCategories=new HashSet<string>(["technical","extra"]) };
        var access=baseAccess with { Reports=[original with { Grants=[grant,extra] }] };
        Assert.False(new ReportAccess(definition,access).FieldsAllowed(["extra"]));
        access=access with { Reports=[original with { Grants=[grant,extra,extra with {Scope=ReportFixture.J("""{"kind":"domain","ids":[2]}""")}] }] };
        Assert.True(new ReportAccess(definition,access).FieldsAllowed(["extra"]));
        var split=ReportFixture.Access(); var g=split.Reports.Single().Grants.Single();
        split=split with { Reports=[split.Reports.Single() with {Grants=[g with {FieldCategories=new HashSet<string>(["technical","a"])},g with {FieldCategories=new HashSet<string>(["technical","b"])}]}] };
        var projection=new ReportAccess(definition,split);
        Assert.True(projection.FieldsAllowed(["a"])); Assert.True(projection.FieldsAllowed(["b"])); Assert.False(projection.FieldsAllowed(["a","b"]));
    }
    [Theory][InlineData("{}")][InlineData("{\"mode\":\"none\",\"clauses\":[]}")][InlineData("{\"mode\":\"restricted\",\"clauses\":[{}]}")]
    public void MissingAndInvalidScopeNeverBecomeAll(string scope)
    { var error=Assert.Throws<ReportRequestException>(()=>new ReportAccess(ReportFixture.Definition(),ReportFixture.Access(scope))); Assert.Equal(403,error.Status); }
    [Fact]
    public void DomainReadersRefuseNonDomainDimensionsAndLegacyDelegatesRefuseGenericScopes()
    {
        var d=ReportFixture.Definition(); d.Rule["scope"]="domain";
        var a=ReportFixture.Access("{\"mode\":\"restricted\",\"clauses\":[{\"source_instance_ids\":[\"source\"],\"collection_scope_ids\":[\"ad-domain:1\"]}]}");
        Assert.Equal("report_scope_not_executable",Assert.Throws<ReportRequestException>(()=>new ReportAccess(d,a)).Message);
        d.Rule["scope"]="delegated";
        Assert.Equal("report_scope_not_executable",Assert.Throws<ReportRequestException>(()=>new ReportAccess(d,a)).Message);
    }
    [Fact]
    public void GlobalAdministrationRequiresRoleCapabilityAndAnExplicitAllScope()
    {
        var d=ReportFixture.Definition(); d.Rule["required_role"]="admin"; d.Rule["global_scope_only"]=true;
        Assert.Equal("report_access_denied",Assert.Throws<ReportRequestException>(()=>new ReportAccess(d,ReportFixture.Access())).Message);
        var scoped=ReportFixture.Access("{\"kind\":\"domain\",\"ids\":[1]}") with {CoarseRole="admin"};
        Assert.Equal("report_scope_not_executable",Assert.Throws<ReportRequestException>(()=>new ReportAccess(d,scoped)).Message);
        var all=ReportFixture.Access() with {CoarseRole="admin"};
        Assert.Equal("all",new ReportAccess(d,all).Scope.Mode);
        d.Rule["required_capabilities"]=new JsonArray("access.manage");
        Assert.Equal("report_access_denied",Assert.Throws<ReportRequestException>(()=>new ReportAccess(d,all)).Message);
    }
    [Fact]
    public void ScopedSqlAppliesDimensionsAtomicallyAndRefusesUnsupportedColumns()
    {
        var scope=new ReportAccess(ReportFixture.Definition(),ReportFixture.Access("{\"mode\":\"restricted\",\"clauses\":[{\"plugin_ids\":[\"sli.fixture\"],\"source_instance_ids\":[\"source-1\"]},{\"entity_ids\":[7]}]}")).Scope;
        var (sql,parameters)=scope.SqlFilter(new Dictionary<string,string>{{"plugin_ids","o.plugin_id"},{"source_instance_ids","o.source_instance_id"},{"entity_ids","o.entity_id"}});
        Assert.Equal("((o.plugin_id = ANY(@scope0) AND o.source_instance_id = ANY(@scope1)) OR (o.entity_id = ANY(@scope2)))",sql);
        Assert.Equal(new[]{"sli.fixture"},(string[])parameters["scope0"]); Assert.Equal(new long[]{7},(long[])parameters["scope2"]);
        Assert.Throws<ReportRequestException>(()=>scope.SqlFilter(new Dictionary<string,string>()));
        Assert.Throws<ArgumentException>(()=>scope.SqlFilter(new Dictionary<string,string>{{"plugin_ids","o.plugin_id;drop"}}));
    }
    [Theory]
    [InlineData("ok","partial","partial")][InlineData("empty","not_collected","not_collected")][InlineData("ok","processing","processing")]
    [InlineData("ok","stale","stale")][InlineData("ok","failed","error")][InlineData("error","processing","error")][InlineData("denied","stale","denied")]
    public void CoverageCannotBeReportedAsCompleteSuccess(string initial,string coverage,string expected)
    {
        var r=ReportResult.Create("fixture",initial,coverage:new(){["state"]=coverage});
        Assert.Equal(expected,r["state"]!.GetValue<string>()); Assert.Equal("sli.report-result.v2",r["contract_id"]!.GetValue<string>());
        Assert.Equal("reports.state."+expected,r["state_message"]!["code"]!.GetValue<string>());
    }
    [Fact]
    public void CoveragePreservesSourceIssuesFreshnessAndMissingDomains()
    {
        var coverage=ReportFixture.O("""{"domains":[{"domain_id":1,"domain_name":"One","section_name":"users","run_status":"failed"}],"observed_at_utc":"2026-01-01T00:00:00Z","freshness_threshold_seconds":60}""");
        var r=ReportResult.Create("fixture","ok",coverage:coverage,now:DateTimeOffset.Parse("2026-01-01T01:00:00Z"));
        Assert.Equal("stale",r["state"]!.GetValue<string>()); Assert.Equal(1,r["state_details"]!["missing_domains"]![0]!.GetValue<int>());
        Assert.Equal("source_failed",r["state_details"]!["source_issues"]![0]!["reason"]!.GetValue<string>());
        Assert.Equal("One",r["state_details"]!["source_issues"]![0]!["source_name"]!.GetValue<string>());
    }
    [Fact]
    public void UnknownAndDeniedReaderStatesDoNotExposeRowsOrSideCollections()
    {
        var projection=new ReportAccess(ReportFixture.Definition(),ReportFixture.Access());
        var unknown=projection.Project(ReportFixture.O("""{"state":"unexpected","items":[{"secret":"leak"}]}"""));
        Assert.Equal("error",unknown["state"]!.GetValue<string>()); Assert.DoesNotContain("leak",unknown.ToJsonString());
        var denied=projection.Project(ReportFixture.O("""{"state":"denied","reason":"untrusted","items":[{"secret":"leak"}],"metrics":[{"value":"leak"}],"collections":{"x":["leak"]},"has_more":true,"next_cursor":"leak","filtered_count":42}"""));
        Assert.DoesNotContain("leak",denied.ToJsonString()); Assert.Equal("report_access_denied",denied["reason"]!.GetValue<string>()); Assert.False(denied["access"]!["allowed"]!.GetValue<bool>());
    }
    [Theory][InlineData("=1+2")][InlineData("  @formula")][InlineData("\tunsafe")][InlineData("\nunsafe")][InlineData("-10")]
    public void CsvNeutralizesFormulasAndPreservesQuotedMultilineFields(string text)
    {
        var column=ReportFixture.O("""{"key":"v","label":"Value"}""");
        string csv=ReportCsv.FromColumns([column],[new(){["v"]=text}]);
        Assert.Contains("'"+text,csv);
        Assert.Equal("Value\r\n\"a,\"\"b\"\"\r\nc\"\r\n",ReportCsv.FromColumns([column],[new(){["v"]="a,\"b\"\r\nc"}]));
    }
    [Fact]
    public void AllFrozenDeclarationsAreAvailableWithoutRuntimePythonAndReturnedByCopy()
    {
        var registry=new ReportDefinitionRegistry(); var rules=new ReportRuleCatalog(new PluginGenerationReader(null)).Capture().Rules;
        Assert.Equal(27,rules.Count);
        foreach(var rule in rules)
        {
            var d=registry.Get(rule.RegistryKey); Assert.NotNull(d); Assert.Equal(rule.ReportKey,d.AccessKey);
            Assert.Equal(rule.Scope,d.ScopeKind); Assert.InRange(d.DefaultLimit,1,d.MaxLimit);
            Assert.Equal(rule.RequiredFields.Order(),d.Rule["required_fields"]!.AsArray().Select(n=>n!.GetValue<string>()).Order());
            d.Rule["report_key"]="tampered";
            Assert.Equal(rule.ReportKey,registry.Get(rule.RegistryKey)!.AccessKey);
        }
        Assert.Null(registry.Get("unknown.report"));
    }
    [Fact]
    public void NaiveObservationNeverSuppliesFreshnessAndTypedThresholdsWork()
    {
        var naive=ReportResult.Create("fixture","ok",coverage:new(){["observed_at_utc"]="2026-01-01T00:00:00",["freshness_threshold_seconds"]=60},now:DateTimeOffset.Parse("2026-11-01T00:00:00Z"));
        Assert.Equal("ok",naive["state"]!.GetValue<string>());
        var aware=ReportResult.Create("fixture","ok",coverage:new(){["observed_at_utc"]="2026-01-01T00:00:00Z",["freshness_threshold_seconds"]=60},now:DateTimeOffset.Parse("2026-11-01T00:00:00Z"));
        Assert.Equal("stale",aware["state"]!.GetValue<string>());
    }
    [Theory]
    [InlineData("2026-01-01T00:00:00+00:00","2026-01-01 00:00:00+00:00")]
    [InlineData("2026-01-01T07:00:00.1234+07:00","2026-01-01 07:00:00.123400+07:00")]
    public void PersistedNotificationTimestampsKeepPythonWireFormat(string input,string expected)
    { Assert.Equal(expected,NotificationReportReader.Timestamp(input)); }
    [Fact]
    public void CsvBooleansAndNullListElementsMatchSourceFormatting()
    {
        var column=ReportFixture.O("""{"key":"v","label":"V"}""");
        Assert.Equal("V\r\nTrue\r\n",ReportCsv.FromColumns([column],[new(){["v"]=true}]));
        Assert.Equal("V\r\n\"False, None\"\r\n",ReportCsv.FromColumns([column],[new(){["v"]=new JsonArray(false,null)}]));
    }
}
