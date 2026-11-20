using System.Net;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Reporting.V2;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class ReportV2GenericScopeTests
{
    const string SourceScope = """{"mode":"restricted","clauses":[{"source_instance_ids":["source-1"]}]}""";
    const string PluginSourceScope = """{"mode":"restricted","clauses":[{"plugin_ids":["sli.fixture"],"source_instance_ids":["source-1"]}]}""";
    static string Url(string suffix = "data") => $"/api/v2/reports/{ReportFixture.Key}/{suffix}";
    static ReportScope Point(string clause) => new("restricted", [ReportFixture.O(clause)]);

    [Fact]
    public async Task GenericQueriesFilterPluginAndSourceWithoutAnAdDirectory()
    {
        var rows = JsonNode.Parse("""
            [{"id":1,"plugin_id":"sli.fixture","source_instance_id":"source-1"},
             {"id":2,"plugin_id":"sli.fixture","source_instance_id":"source-2"},
             {"id":3,"plugin_id":"sli.other","source_instance_id":"source-1"}]
            """)!.AsArray();
        var reader = new ReportFixture.Reader
        {
            Query = ctx =>
            {
                var items = rows.OfType<JsonObject>().Where(row => ctx.Scope.Covers(new ReportScope("restricted",
                    [new() { ["plugin_ids"] = new JsonArray(row["plugin_id"]!.DeepClone()),
                        ["source_instance_ids"] = new JsonArray(row["source_instance_id"]!.DeepClone()) }])))
                    .Select(row => (JsonNode?)row.DeepClone()).ToArray();
                return new() { ["state"] = "ok", ["items"] = new JsonArray(items), ["filtered_count"] = items.Length };
            }
        };
        await using var host = await ReportFixture.Start(ReportFixture.Facts(PluginSourceScope), suppliedReader: reader);
        using var response = await host.Client.GetAsync(Url(), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var payload = await ReportFixture.Body(response);
        Assert.Equal(1, Assert.Single(payload["items"]!.AsArray())!["id"]!.GetValue<int>());
        Assert.Equal(1, payload["filtered_count"]!.GetValue<int>());
        var context = Assert.IsType<ReportQueryContext>(reader.Last);
        Assert.Null(context.DomainIds);
        Assert.Equal(7, context.Principal.Id);
        Assert.Equal("session", context.Principal.Type);
        var grant = Assert.Single(Assert.Single(context.Access.Reports).Grants);
        Assert.Equal(1, grant.DatasetVersion);
        Assert.Equal("source-1", grant.Scope.GetProperty("clauses")[0].GetProperty("source_instance_ids")[0].GetString());
        var (sql, parameters) = context.Scope.SqlFilter(new Dictionary<string, string>
            { ["plugin_ids"] = "o.plugin_id", ["source_instance_ids"] = "o.source_instance_id" });
        Assert.Equal("((o.plugin_id = ANY(@scope0) AND o.source_instance_id = ANY(@scope1)))", sql);
        Assert.Equal(new[] { "sli.fixture" }, (string[])parameters["scope0"]);
        Assert.Equal(new[] { "source-1" }, (string[])parameters["scope1"]);
    }

    [Fact]
    public async Task AClientCannotReplaceTheServerScopeWithAll()
    {
        await using var host = await ReportFixture.Start(ReportFixture.Facts(SourceScope));
        using var response = await host.Client.GetAsync(Url() + "?scope=all", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("report_parameter_unknown:scope", (await ReportFixture.Body(response))["error"]!.GetValue<string>());
        Assert.Equal(0, host.Reader.Calls);
    }

    [Fact]
    public void FieldCategoriesAreAtomicAcrossTheEntireGenericSourceScope()
    {
        var access = ReportFixture.Access("""{"mode":"restricted","clauses":[{"source_instance_ids":["source-1","source-2"]}]}""");
        var report = Assert.Single(access.Reports);
        var grant = Assert.Single(report.Grants);
        var extra = grant with { Scope = ReportFixture.J(SourceScope), FieldCategories = new HashSet<string>(["technical", "extra"]) };
        access = access with { Reports = [report with { Grants = [grant, extra] }] };
        var projection = new ReportAccess(ReportFixture.Definition(), access);
        Assert.False(projection.FieldsAllowed(["extra"]));
        Assert.True(projection.FieldsAllowed(["technical"]));
        Assert.True(projection.Scope.Covers(Point("""{"source_instance_ids":["source-2"]}""")));
    }

    [Fact]
    public void LegacyDomainAssignmentsPreserveTheirUnionAndFieldCoverage()
    {
        var definition = ReportFixture.Definition();
        definition.Rule["scope"] = "domain";
        var access = ReportFixture.Access("""{"kind":"domain","ids":[1,2]}""");
        var report = Assert.Single(access.Reports);
        var grant = Assert.Single(report.Grants);
        var extra = grant with { Scope = ReportFixture.J("""{"kind":"domain","ids":[1]}"""),
            FieldCategories = new HashSet<string>(["technical", "extra"]) };
        access = access with { Reports = [report with { Grants = [grant, extra,
            extra with { Scope = ReportFixture.J("""{"kind":"domain","ids":[2]}""") }] }] };
        var projection = new ReportAccess(definition, access);
        Assert.Equal(new long[] { 1, 2 }, projection.Scope.DomainIds());
        Assert.True(projection.FieldsAllowed(["extra"]));
        Assert.False(projection.Scope.Covers(Point("""{"source_instance_ids":["domainless-source"]}""")));
        Assert.Null(new ReportAccess(definition, ReportFixture.Access()).Scope.DomainIds());
    }

    [Fact]
    public void RequiredCapabilitiesMustBePresentEvenWithAnExplicitAllGrant()
    {
        var definition = ReportFixture.Definition();
        definition.Rule["required_capabilities"] = new JsonArray("fixture.read");
        var access = ReportFixture.Access();
        var error = Assert.Throws<ReportRequestException>(() => new ReportAccess(definition, access));
        Assert.Equal(403, error.Status);
        Assert.Equal("report_access_denied", error.Message);
        access = access with { Capabilities = access.Capabilities with
            { Capabilities = new HashSet<string>(access.Capabilities.Capabilities.Append("fixture.read")) } };
        Assert.Equal("all", new ReportAccess(definition, access).Scope.Mode);
    }

    [Theory]
    [InlineData("data")]
    [InlineData("rows/1/detail")]
    public async Task GenericCursorsBindPolicyAndDetailsInheritSourceScope(string suffix)
    {
        await using var host = await ReportFixture.Start(ReportFixture.Facts(SourceScope));
        using var first = await host.Client.GetAsync(Url(suffix), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var context = Assert.IsType<ReportQueryContext>(host.Reader.Last);
        Assert.Equal("restricted", context.Scope.Mode);
        Assert.Null(context.DomainIds);
        Assert.True(context.Scope.Covers(Point("""{"source_instance_ids":["source-1"]}""")));
        Assert.False(context.Scope.Covers(Point("""{"source_instance_ids":["source-2"]}""")));
        string cursor = (await ReportFixture.Body(first))["next_cursor"]!.GetValue<string>();
        Assert.NotEqual("position-2", cursor);
        using var second = await host.Client.GetAsync(Url(suffix) + "?cursor=" + cursor, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal("position-2", host.Reader.Last!.Paging.Cursor);
        // Change only the effective policy; source scope and dataset version stay the same.
        var facts = host.Facts.Value;
        host.Facts.Value = facts with { DirectCapabilities = [.. facts.DirectCapabilities,
            ReportFixture.J("""{"capability_key":"fixture.read","effect":"allow","scope_json":{"kind":"all"}}""")] };
        using var changed = await host.Client.GetAsync(Url(suffix) + "?cursor=" + cursor, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, changed.StatusCode);
        Assert.Equal("invalid_cursor", (await ReportFixture.Body(changed))["error"]!.GetValue<string>());
        Assert.Equal(2, host.Reader.Calls);
    }

    [Fact]
    public void OrClausesAndDimensionsIntersectWithoutWidening()
    {
        var scope = new ReportAccess(ReportFixture.Definition(), ReportFixture.Access("""
            {"mode":"restricted","clauses":[{"plugin_ids":["sli.fixture"],"source_instance_ids":["source-1"]},{"entity_ids":[7]}]}
            """)).Scope;
        Assert.True(scope.Covers(Point("""{"entity_ids":[7]}""")));
        Assert.False(scope.Covers(Point("""{"plugin_ids":["sli.other"],"source_instance_ids":["source-1"]}""")));
        var narrowed = scope.Intersect(Point("""{"source_instance_ids":["source-2"]}"""));
        Assert.False(narrowed.Covers(Point("""{"entity_ids":[7],"source_instance_ids":["source-1"]}""")));
        Assert.True(narrowed.Covers(Point("""{"entity_ids":[7],"source_instance_ids":["source-2"]}""")));
        var (sql, parameters) = narrowed.SqlFilter(new Dictionary<string, string>
            { ["entity_ids"] = "o.entity_id", ["source_instance_ids"] = "o.source_instance_id" });
        Assert.Equal("((o.source_instance_id = ANY(@scope0) AND o.entity_id = ANY(@scope1)))", sql);
        Assert.Equal(new[] { "source-2" }, (string[])parameters["scope0"]);
        Assert.Equal(new long[] { 7 }, (long[])parameters["scope1"]);
    }

    [Fact]
    public void AnUnissuedGenericContextHasNoDirectoryAndProducesFalseSql()
    {
        var context = new ReportQueryContext(ReportFixture.Definition(), new("viewer", ReportFixture.Access().Capabilities, []),
            new Principal("session", 7, "viewer"), new(), new(null, 100, "UTC", null, "asc", null),
            ReportScope.None, null, "view", _ => false, []);
        Assert.Null(context.DomainIds);
        Assert.Equal("none", context.Scope.Mode);
        var (sql, parameters) = context.Scope.SqlFilter(new Dictionary<string, string>());
        Assert.Equal("FALSE", sql);
        Assert.Empty(parameters);
    }
}
