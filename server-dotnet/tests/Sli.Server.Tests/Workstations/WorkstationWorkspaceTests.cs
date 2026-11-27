using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Sli.Server.Access;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Ingress;
using Sli.Server.Auth;
using Sli.Server.Reporting.V2;
using Sli.Server.Tests.Reporting;
using Sli.Server.Workstations;
using Xunit;

namespace Sli.Server.Tests.Workstations;

public sealed class WorkstationWorkspaceTests
{
    const string Key = "workstations.overview";
    internal static AccessFacts Facts() => new(true, "viewer", [], [], [], [], [], [],
        [JsonSerializer.SerializeToElement(new
        {
            report_key = Key, version = 1, dataset_version = 1,
            fields_json = WorkstationReportContract.Fields.Select(category => new { category }),
            actions_json = new[] { "view" },
            definition_json = new { field_categories = WorkstationReportContract.Fields, actions = new[] { "view" } }
        })]);

    internal static AccessFacts AuthorizedFacts(string stationScope = "{\"kind\":\"all\"}",
        bool journal = true, bool exact = true, string? deniedAgent = null)
    {
        JsonElement J(object value) => JsonSerializer.SerializeToElement(value);
        string[] eventFields = ["identity_basic", "technical", "security", "raw_evidence"];
        var capabilities = WorkstationReportContract.Fields.Select(field => "field." + field)
            .Concat(exact ? ["workstations.read", "field.raw_evidence", "evidence.exact"] : ["workstations.read"])
            .Select(capability => J(new { capability_key = capability, effect = "allow", scope_json = new { kind = "all" } })).ToList();
        if (deniedAgent is not null) capabilities.Add(J(new
        {
            capability_key = "workstations.read", effect = "deny", scope_json = new { kind = "agent", ids = new[] { deniedAgent } }
        }));
        JsonElement Grant(string key, string[] fields, string scope) => J(new
        {
            report_key = key, effect = "allow", field_categories = fields, allowed_actions = new[] { "view" }, scope_json = JsonNode.Parse(scope)
        });
        JsonElement Definition(string key, string[] fields) => J(new
        {
            report_key = key, version = 1, dataset_version = 1,
            fields_json = fields.Select(category => new { category }), actions_json = new[] { "view" },
            definition_json = new { field_categories = fields, actions = new[] { "view" } }
        });
        var grants = new List<JsonElement> { Grant(Key, WorkstationReportContract.Fields, stationScope) };
        if (journal) grants.Add(Grant("events.explorer", eventFields, "{\"kind\":\"all\"}"));
        return new(false, "viewer", [], [], capabilities, [], [], grants,
            [Definition(Key, WorkstationReportContract.Fields), Definition("events.explorer", eventFields)]);
    }

    static AccessDecision Access(AccessFacts facts) => new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts));
    static ReportQueryContext Context(string query = "", AccessFacts? facts = null)
    {
        var definition = new ReportDefinitionRegistry().Get(Key)!;
        var access = Access(facts ?? AuthorizedFacts());
        var (parameters, paging) = ReportParameters.Parse(definition, new QueryCollection(QueryHelpers.ParseQuery(query)),
            DateTimeOffset.Parse("2026-10-01T12:00:00Z"));
        return new(definition, access, new Principal("session", 7, "viewer"), parameters, paging,
            ReportScope.None, null, "view", _ => true, access.Reports.Single(report => report.ReportKey == Key).Grants);
    }

    static JsonObject Station() => new()
    {
        ["station_id"] = NativeWorkstationsReportFixture.Agent.ToString("D"),
        ["source_instance_id"] = NativeWorkstationsReportFixture.Source.ToString("D"), ["server_id"] = 12, ["domain_id"] = 7
    };

    [Theory]
    [InlineData("")]
    [InlineData("/data")]
    [InlineData("/rows/00000000-0000-4000-8000-000000000001/detail")]
    public async Task Native_overview_is_not_intercepted_by_frozen_family_routes(string action)
    {
        var definition = new ReportDefinitionRegistry().Get(Key)!;
        var reader = new ReportFixture.Reader { OwnerId = "sli.workstations", ReportKey = Key };
        await using var host = await ReportFixture.Start(Facts(), definition, suppliedReader: reader, workstationRoutes: true);
        using var response = await host.Client.GetAsync("/api/v2/reports/" + Key + action, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(action.Length == 0 ? 0 : 1, reader.Calls);
    }

    [Theory]
    [InlineData(25)]
    [InlineData(50)]
    [InlineData(100)]
    [InlineData(200)]
    public void Declared_workspace_admits_real_page_sizes(int limit)
    {
        var definition = new ReportDefinitionRegistry().Get(Key)!;
        var parsed = ReportParameters.Parse(definition, new QueryCollection(QueryHelpers.ParseQuery("limit=" + limit)));
        Assert.Equal(limit, parsed.Paging.Limit);
    }

    [Fact]
    public void Collection_profile_reports_only_the_effective_admitted_configuration()
    {
        var policy = AgentModuleAssignmentRules.NormalizeWorkstation(new JsonObject { ["policy_revision"] = "1" }, true);
        var profile = WorkstationWorkspaceReader.Profile(policy);
        Assert.Equal("supported", profile["state"]!.ToString());
        Assert.Equal(WorkstationJournalAdmission.EventIds, profile["event_ids"]!.AsArray().Select(id => id!.GetValue<int>()));
        Assert.Equal(new[] { "Security", "System", "Microsoft-Windows-Windows Defender/Operational" },
            profile["channels"]!.AsArray().Select(channel => channel!.ToString()));
        policy["deny_event_ids"] = new JsonArray(4624);
        policy["families"]!["local_admins"] = false;
        policy["family_filters"]!["protection"] = new JsonObject { ["deny_event_ids"] = new JsonArray(7045) };
        var limited = WorkstationWorkspaceReader.Profile(policy)["event_ids"]!.AsArray().Select(id => id!.GetValue<int>()).ToArray();
        Assert.DoesNotContain(4624, limited); Assert.DoesNotContain(4732, limited); Assert.DoesNotContain(4733, limited);
        Assert.DoesNotContain(7045, limited); Assert.Contains(5001, limited);
        var legacy = WorkstationWorkspaceReader.Profile(new JsonObject { ["allow_event_ids"] = new JsonArray(4104) });
        Assert.Equal("unsupported", legacy["state"]!.ToString()); Assert.Empty(legacy["event_ids"]!.AsArray());
        Assert.Equal("unbound", WorkstationWorkspaceReader.Profile(null)["state"]!.ToString());
    }

    [Fact]
    public void Event_admission_does_not_borrow_overview_or_separate_field_grants()
    {
        Assert.True(WorkstationWorkspaceReader.CanReadEvents(Access(AuthorizedFacts(exact: false)), Station()));
        Assert.False(WorkstationWorkspaceReader.CanReadEvents(Access(AuthorizedFacts(journal: false)), Station()));
        var facts = AuthorizedFacts();
        var eventGrant = JsonNode.Parse(facts.ReportAssignments[1].GetRawText())!.AsObject();
        JsonElement Partial(string field)
        {
            var grant = eventGrant.DeepClone().AsObject(); grant["field_categories"] = new JsonArray(field);
            return JsonSerializer.SerializeToElement(grant);
        }
        facts = facts with { ReportAssignments = [facts.ReportAssignments[0], Partial("security"), Partial("technical")] };
        Assert.False(WorkstationWorkspaceReader.CanReadEvents(Access(facts), Station()));
        var withoutBinding = Station(); withoutBinding["server_id"] = null;
        Assert.False(WorkstationWorkspaceReader.CanReadEvents(Access(AuthorizedFacts()), withoutBinding));
    }

    [Fact]
    public void Station_and_event_cursors_bind_principal_policy_window_and_selection()
    {
        var c = Context("search=WS&limit=200&event_limit=25");
        string cursor = ReportCursor.Encode(WorkstationWorkspaceReader.Binding(c, "stations"), NativeWorkstationsReportFixture.Agent.ToString("D"));
        Assert.Equal(NativeWorkstationsReportFixture.Agent.ToString("D"), ReportCursor.Decode(cursor, WorkstationWorkspaceReader.Binding(c, "stations")));
        foreach (var changed in new[]
        {
            Context("search=other&limit=200&event_limit=25"), Context("search=WS&limit=100&event_limit=25"),
            Context("search=WS&limit=200&period=24h&event_limit=25"),
            c with { Principal = new Principal("session", 8, "viewer") },
            c with { Access = Access(AuthorizedFacts(deniedAgent: NativeWorkstationsReportFixture.Agent.ToString("D"))) }
        }) Assert.Throws<ReportRequestException>(() => ReportCursor.Decode(cursor, WorkstationWorkspaceReader.Binding(changed, "stations")));

        var station = Station();
        string events = ReportCursor.Encode(WorkstationWorkspaceReader.Binding(c, "events", station), "journal-position");
        foreach (string changed in new[] { "search=WS&limit=200&event_limit=50", "search=WS&limit=200&event_limit=25&view=authentication", "search=WS&limit=200&event_limit=25&period=24h" })
            Assert.Throws<ReportRequestException>(() => ReportCursor.Decode(events, WorkstationWorkspaceReader.Binding(Context(changed), "events", station)));
        station["source_instance_id"] = Guid.NewGuid().ToString("D");
        Assert.Throws<ReportRequestException>(() => ReportCursor.Decode(events, WorkstationWorkspaceReader.Binding(c, "events", station)));
    }

    [Theory]
    [InlineData("source_instance_id=not-a-source")]
    [InlineData("domain=1&domain_id=2")]
    [InlineData("domain=999999999999999999999999")]
    [InlineData("event_limit=201")]
    public void Invalid_native_selection_is_rejected_before_querying(string query)
        => Assert.Throws<ReportRequestException>(() => WorkstationWorkspaceReader.Validate(Context(query), null));
}
