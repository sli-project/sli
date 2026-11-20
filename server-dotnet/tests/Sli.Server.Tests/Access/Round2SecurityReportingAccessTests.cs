using System.Text.Json;
using Sli.Server.Access;
using Xunit;

namespace Sli.Server.Tests.Access;

// Behavioral vectors from tests/events/test_round2_security_reporting.py.
public sealed class Round2SecurityReportingAccessTests
{
    static JsonElement J(string text) => JsonSerializer.Deserialize<JsonElement>(text);
    static AccessFacts Facts(params JsonElement[] policies) => new(false, "viewer", [], [], policies, [], [], [], []);
    static JsonElement Policy(string scope, string effect = "deny", string key = "events.view") =>
        JsonSerializer.SerializeToElement(new { capability_key = key, effect, scope_json = J(scope) });
    static CapabilityDecisionSet Caps(params JsonElement[] policies) => new CapabilityComposer().Compose(Facts(policies));

    [Theory]
    [InlineData("null", true)]
    [InlineData("{}", true)]
    [InlineData("{\"kind\":\"all\"}", true)]
    [InlineData("{\"ids\":[7]}", false)]
    [InlineData("{\"kind\":\"\"}", false)]
    [InlineData("{\"kind\":\"server\",\"ids\":[]}", false)]
    [InlineData("{\"kind\":\"all\",\"ids\":[7]}", false)]
    [InlineData("{\"kind\":\"unknown\"}", false)]
    [InlineData("\"{broken-json\"", false)]
    public void ScopeParserFailsClosed(string scope, bool valid)
    {
        var access = Caps(Policy(scope));
        var policy = Assert.Single(access.Policies);
        Assert.Equal(valid, policy.Valid); Assert.Equal(valid, policy.Global);
        Assert.Equal(new(false, valid ? "explicit_deny" : "invalid_scope_policy"), access.Decide("events.view"));
    }

    [Fact]
    public void ScopedDenyRequiresContextAndOverridesGlobalAllowOnlyForMatchingServer()
    {
        var access = Caps(Policy("""{"kind":"all"}""", "allow"), Policy("""{"kind":"server","ids":[7]}"""));
        Assert.Equal(new(false, "resource_context_required"), access.Decide("events.view"));
        Assert.Equal(new(false, "explicit_deny"), access.DecideForResourceGroups("events.view", [[new("server", 7)]]));
        Assert.Equal(new(true, "global_allow"), access.DecideForResourceGroups("events.view", [[new("server", 8)]]));
    }

    [Fact]
    public void EveryEventNeedsCoverageAndChannelDenyWins()
    {
        const string key = "investigations.view";
        var access = Caps(Policy("""{"kind":"server","ids":[7,8]}""", "allow", key), Policy("""{"kind":"channel","values":["System"]}""", "deny", key));
        IReadOnlyList<AccessResource> first = [new("server", 7), new("channel", Value: "Security")];
        IReadOnlyList<AccessResource> second = [new("server", 8), new("channel", Value: "Directory Service")];
        Assert.Equal(new(true, "scoped_allow"), access.DecideForResourceGroups(key, [first, second]));
        Assert.Equal(new(false, "explicit_deny"), access.DecideForResourceGroups(key, [first, second, [new("server", 8), new("channel", Value: "System")]]));
        Assert.Equal(new(false, "insufficient_capability"), access.DecideForResourceGroups(key, [first, second, [new("server", 9)]]));
        Assert.Equal(new(false, "resource_context_required"), access.DecideForResourceGroups(key, []));
    }

    [Fact]
    public void OwnerBypassesEvenInvalidRecordedDeny()
    {
        var access = new CapabilityComposer().Compose(Facts(Policy("""{"kind":"unknown"}""")) with { IsOwner = true });
        Assert.Equal(new(true, "platform_owner"), access.Decide("events.view"));
        Assert.Equal(new(true, "platform_owner"), access.DecideForResourceGroups("events.view", [[new("server", 7)]]));
    }

    [Fact]
    public void ReportActionsKeepScopeAndActionAtomicForEveryEvent()
    {
        AtomicReportGrant Grant(string scope, params string[] actions) => new(J(scope), new HashSet<string>(), actions.ToHashSet(), 1, 1);
        var access = new AccessDecision("viewer", Caps(), [new("investigations.workspace", true,
            [Grant("""{"kind":"server","ids":[7]}""", "view", "start_case"), Grant("""{"kind":"channel","values":["Security"]}""", "view")])]);
        IReadOnlyList<IReadOnlyList<AccessResource>> groups = [[new("server", 7), new("channel", Value: "System")], [new("server", 9), new("channel", Value: "Security")]];
        Assert.Equal(new(true, "report_scope_match"), ResourceAccessDecisions.ReportAction(access, "investigations.workspace", "view", groups));
        Assert.Equal(new(false, "report_scope_denied"), ResourceAccessDecisions.ReportAction(access, "investigations.workspace", "start_case", groups));
        Assert.Equal(new(false, "resource_context_required"), ResourceAccessDecisions.ReportAction(access, "investigations.workspace", "view", []));
    }

    [Fact]
    public void NewReportVersionIntersectsFieldsAndActionsWithoutWidening()
    {
        var facts = Facts() with {
            ReportAssignments = [J("""{"report_key":"version.test","effect":"allow","scope_json":{"kind":"server","ids":[7]},"field_categories":["identity_basic","technical"],"allowed_actions":["view","export"]}""")],
            Definitions = [J("""{"report_key":"version.test","version":3,"dataset_version":2,"fields_json":[{"category":"identity_basic"},{"category":"security"}],"actions_json":["view","create_task"],"definition_json":{"actions":["view","create_task"]}}""")] };
        var caps = Caps() with { Capabilities = new HashSet<string> { "field.identity_basic", "field.technical", "reports.export", "tasks.create" } };
        var report = Assert.Single(new ReportEligibility().Compose(facts, caps).Reports);
        Assert.True(report.Allowed);
        var grant = Assert.Single(report.Grants);
        Assert.Equal("identity_basic", Assert.Single(grant.FieldCategories)); Assert.Equal("view", Assert.Single(grant.AllowedActions));
        Assert.Equal(3, grant.ReportVersion); Assert.Equal(2, grant.DatasetVersion);
        Assert.Equal("""{"kind":"server","ids":[7]}""", grant.Scope.GetRawText());
        facts = facts with { Definitions = [J("""{"report_key":"version.test","version":4,"dataset_version":2,"fields_json":[{"category":"identity_basic"}],"actions_json":["create_task"],"definition_json":{"actions":["create_task"]}}""")] };
        report = Assert.Single(new ReportEligibility().Compose(facts, caps).Reports);
        Assert.False(report.Allowed); Assert.Empty(report.Grants);
    }

    [Fact]
    public void ViewerRestrictionPreservesDirectAndGroupSources()
    {
        var facts = Facts(J("""{"capability_key":"evidence.exact","effect":"allow","scope_json":{"kind":"all"}}""")) with {
            Packages = [J("""{"package_key":"starter","effect":"allow","source_kind":"role"}"""), J("""{"package_key":"approved","effect":"allow","source_kind":"group"}""")],
            PackageCapabilities = [J("""{"package_key":"starter","capability_key":"workspace.view"}"""), J("""{"package_key":"starter","capability_key":"evidence.exact"}"""), J("""{"package_key":"starter","capability_key":"field.technical"}"""), J("""{"package_key":"approved","capability_key":"reports.export"}""")] };
        var access = new CapabilityComposer().Compose(facts);
        Assert.True(access.Decide("workspace.view").Allowed); Assert.True(access.Decide("evidence.exact").Allowed); Assert.True(access.Decide("reports.export").Allowed);
        Assert.False(access.Decide("field.technical").Allowed);
        Assert.False(new CapabilityComposer().Compose(facts with { DirectCapabilities = [] }).Decide("evidence.exact").Allowed);
    }
}
