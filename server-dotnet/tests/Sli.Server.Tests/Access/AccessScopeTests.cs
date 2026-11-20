using System.Text.Json;
using Sli.Server.Access;
using Sli.Server.Reporting.V2;
using Sli.Server.Tests.Reporting;
using Xunit;

namespace Sli.Server.Tests.Access;

// Behavioral vectors from tests/access/test_access_scope.py.
public sealed class AccessScopeTests
{
    private static JsonElement Json(string value) => JsonSerializer.Deserialize<JsonElement>(value);

    private static bool Allows(JsonElement scope, AccessResource resource)
    {
        var capabilities = new CapabilityDecisionSet(false, new HashSet<string>(), new HashSet<string>(), [],
            new Dictionary<string, JsonElement>());
        var grant = new AtomicReportGrant(scope, new HashSet<string>(), new HashSet<string> { "view" }, 1, 1);
        var access = new AccessDecision("viewer", capabilities, [new("scope.fixture", true, [grant])]);
        return ResourceAccessDecisions.ReportAction(access, "scope.fixture", "view", [[resource]]).Allowed;
    }

    [Theory]
    [InlineData("sli.fixture", "source-1", 2L, true)]
    [InlineData("sli.other", "source-1", 2L, false)]
    [InlineData("sli.fixture", "source-2", 2L, false)]
    [InlineData("sli.fixture", "source-1", null, false)]
    [InlineData("sli.other", "source-2", 3L, true)]
    [InlineData("sli.fixture", "source-2", 3L, false)]
    [InlineData("sli.other", "source-1", 3L, false)]
    public void ClausesAreOrAndDimensionsAreAnd(string plugin, string source, long? entity, bool expected)
    {
        var scope = Json("""
            {"mode":"restricted","clauses":[
              {"plugin_ids":["sli.fixture"],"source_instance_ids":["source-1"],"entity_ids":[1,2]},
              {"plugin_ids":["sli.other"],"source_instance_ids":["source-2"],"entity_ids":[3]}
            ]}
            """);
        Assert.Equal(expected, Allows(scope, new("entity")
        {
            PluginId = plugin, SourceInstanceId = source, EntityId = entity
        }));
    }

    [Theory]
    [InlineData("""{"mode":"restricted","clauses":[]}""")]
    [InlineData("""{"mode":"all","clauses":[{"entity_ids":[1]}]}""")]
    [InlineData("""{"mode":"none","clauses":[{"entity_ids":[1]}]}""")]
    [InlineData("""{"mode":"all","clauses":[],"unexpected":true}""")]
    [InlineData("""{"mode":"restricted","clauses":[{"entity_ids":[true]}]}""")]
    [InlineData("""{"mode":"restricted","clauses":[{"source_instance_ids":"source-1"}]}""")]
    public void InvalidInvariantsAndMalformedGrantsFailClosed(string payload)
    {
        var scope = Json(payload);
        // .NET validates construction at the grant boundary and represents rejection
        // as Invalid/None; the report reader exposes the corresponding 403.
        Assert.True(ReportScopeResolver.ParseScope(scope).Invalid);
        Assert.Equal("none", ReportScope.FromGrant(scope).Mode);
        Assert.False(Allows(scope, new("entity") { SourceInstanceId = "source-1", EntityId = 1 }));
        Assert.False(Allows(scope, new("domain", 1)));
        var error = Assert.Throws<ReportRequestException>(() =>
            new ReportAccess(ReportFixture.Definition(), ReportFixture.Access(payload)));
        Assert.Equal(403, error.Status);
        Assert.Equal("report_scope_not_executable", error.Message);
    }

    [Fact]
    public void DomainGrantAdapterDoesNotGrantDomainlessDevices()
    {
        var grant = Json("""{"kind":"domain","ids":[2,1]}""");
        var scope = ReportScope.FromGrant(grant);
        Assert.Equal("restricted", scope.Mode);
        Assert.Equal(new long[] { 1, 2 }, scope.DomainIds());
        // Exercise the adapted source-neutral clauses, rather than only legacy matching.
        var adapted = JsonSerializer.SerializeToElement(new { mode = scope.Mode, clauses = scope.Clauses });
        Assert.True(Allows(adapted, new("domain", 1)));
        Assert.False(Allows(adapted, new("device") { SourceInstanceId = "source-1" }));
        Assert.False(Allows(adapted, new("domain", 3)));
        Assert.Equal("all", ReportScope.FromGrant(Json("""{"kind":"all"}""")).Mode);
        Assert.Equal("none", ReportScope.FromGrant(Json("{}")).Mode);
    }

    [Fact]
    public void AtomicCoverageDoesNotBorrowOtherSources()
    {
        var full = ReportScope.FromGrant(Json("""
            {"mode":"restricted","clauses":[{"source_instance_ids":["source-1"]},{"source_instance_ids":["source-2"]}]}
            """));
        var partial = ReportScope.FromGrant(Json("""
            {"mode":"restricted","clauses":[{"source_instance_ids":["source-1"]}]}
            """));
        Assert.True(full.Covers(partial));
        Assert.False(partial.Covers(full));
    }
}
