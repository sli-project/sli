using System.Text.Json;
using Sli.Server.Access;
using Sli.Server.Investigations;
using Xunit;

namespace Sli.Server.Tests.Investigations;
public sealed class InvestigationAccessTests
{
    static JsonElement J(string s) => JsonDocument.Parse(s).RootElement.Clone();
    static AccessResource R(string kind, long id) => new(kind, id);
    static CapabilityDecisionSet Caps(bool global = true, params string[] policies) => new(false,
        global ? new HashSet<string>{"investigations.manage"} : new HashSet<string>(), new HashSet<string>(),
        new CapabilityComposer().Compose(new(false, "viewer", [], [], policies.Select(J).ToArray(), [], [], [], [])).Policies,
        new Dictionary<string,JsonElement>());
    static AtomicReportGrant G(string scope, string[]? actions = null, string[]? fields = null) =>
        new(J(scope), (fields ?? []).ToHashSet(), (actions ?? ["start_case"]).ToHashSet(), 1, 1);
    static AccessDecision A(CapabilityDecisionSet caps, params AtomicReportGrant[] grants) => new("viewer", caps, [new("cases.workspace", true, grants)]);

    [Fact]
    public void EveryGroupMustMatchAndScopedDenyOverridesGlobalAllow()
    {
        // Retains the prior auditor's mixed-domain/server and empty-group WIP vectors.
        var grants = new[] {G("{\"kind\":\"domain\",\"ids\":[1]}")};
        IReadOnlyList<IReadOnlyList<AccessResource>> resources = [[R("domain",1),R("server",2)], [R("domain",1)]];
        Assert.True(InvestigationAccess.Allowed(A(Caps(),grants), "cases.workspace", resources));
        var denied = Caps(true,"{\"capability_key\":\"investigations.manage\",\"effect\":\"deny\",\"scope_json\":{\"kind\":\"server\",\"ids\":[2]}}");
        Assert.False(InvestigationAccess.Allowed(A(denied,grants), "cases.workspace", resources));
        Assert.False(InvestigationAccess.Allowed(A(Caps(),grants), "cases.workspace", [resources[0],[R("domain",3)]]));
        Assert.False(InvestigationAccess.Allowed(A(Caps(),grants), "cases.workspace", [resources[0],[]]));
    }

    [Fact]
    public void MixedScopedAllowsCoverEveryGroupButAnyMatchingDenyRejects()
    {
        var caps = Caps(false,
            "{\"capability_key\":\"investigations.manage\",\"effect\":\"allow\",\"scope_json\":{\"kind\":\"server\",\"ids\":[2]}}",
            """{"capability_key":"investigations.manage","effect":"allow","scope_json":{"kind":"channel","values":[" Security "]}}""");
        IReadOnlyList<IReadOnlyList<AccessResource>> groups = [[R("domain",1),R("server",2)], [new("channel", Value:"Security")]];
        Assert.Equal(new(true,"scoped_allow"),caps.DecideForResourceGroups("investigations.manage",groups));
        Assert.False(caps.Decide("investigations.manage").Allowed); // Existing context-free semantics preserved.
        Assert.False(caps.DecideForResourceGroups("investigations.manage",[groups[0],[R("domain",9)]]).Allowed);
        Assert.False(caps.DecideForResourceGroups("investigations.manage",[]).Allowed);
        Assert.True(Caps().DecideForResourceGroups("investigations.manage",[]).Allowed);
        Assert.False(Caps().DecideForResourceGroups("investigations.manage",[[]]).Allowed);
    }

    [Fact]
    public void InvalidDenyAndGlobalDenyPrecedeGlobalAllowAndOwnerBypassesCapabilityOnly()
    {
        foreach (string scope in new[]{"{\"kind\":\"all\"}","{\"kind\":\"server\",\"ids\":[true]}"})
        {
            var caps=Caps(true,"{\"capability_key\":\"investigations.manage\",\"effect\":\"deny\",\"scope_json\":"+scope+"}");
            Assert.False(caps.DecideForResourceGroups("investigations.manage",[]).Allowed);
            Assert.True((caps with {IsOwner=true}).DecideForResourceGroups("investigations.manage",[[]]).Allowed);
        }
        var owner=Caps() with {IsOwner=true};
        Assert.False(InvestigationAccess.Allowed(A(owner,G("{\"kind\":\"all\"}")),"cases.workspace",[[]]));
    }

    [Fact]
    public void ReportActionFieldsAndScopeRemainInTheSameGrant()
    {
        var access=A(Caps(), G("{\"kind\":\"domain\",\"ids\":[1]}",["view","start_case"],["basic"]),
            G("{\"kind\":\"domain\",\"ids\":[2]}",["view","start_case"],["sensitive"]),
            G("{\"kind\":\"all\"}",["view"],["sensitive"]));
        Assert.False(ResourceAccessDecisions.ReportAction(access,"cases.workspace","start_case",[[R("domain",1)]],new HashSet<string>{"sensitive"}).Allowed);
        Assert.True(ResourceAccessDecisions.ReportAction(access,"cases.workspace","start_case",[[R("domain",2)]],new HashSet<string>{"sensitive"}).Allowed);
        Assert.False(ResourceAccessDecisions.ReportAction(access,"cases.workspace","start_case",[]).Allowed);
        Assert.True(ResourceAccessDecisions.ReportAction(A(Caps(),G("{\"mode\":\"all\"}")),"cases.workspace","start_case",[]).Allowed);
    }

    [Fact]
    public void GenericScopeDoesNotInventMissingDimensionsOrCombineAcrossAlternatives()
    {
        var access=A(Caps(),G("{\"mode\":\"restricted\",\"clauses\":[{\"collection_scope_ids\":[\"ad-domain:1\"]}]}"));
        Assert.True(ResourceAccessDecisions.ReportAction(access,"cases.workspace","start_case",[[R("domain",1)]]).Allowed);
        access=A(Caps(),G("{\"mode\":\"restricted\",\"clauses\":[{\"device_ids\":[\"server:2\"]}]}"));
        Assert.False(ResourceAccessDecisions.ReportAction(access,"cases.workspace","start_case",[[R("server",2)]]).Allowed);
        Assert.True(ResourceAccessDecisions.ReportAction(access,"cases.workspace","start_case",[[new("server",2){DeviceId="server:2"}]]).Allowed);
        access=A(Caps(),G("{\"mode\":\"restricted\",\"clauses\":[{\"device_ids\":[\"server:2\"],\"collection_scope_ids\":[\"ad-domain:1\"]}]}"));
        Assert.False(ResourceAccessDecisions.ReportAction(access,"cases.workspace","start_case",[[R("domain",1),new("server",2){DeviceId="server:2"}]]).Allowed);
    }
}
