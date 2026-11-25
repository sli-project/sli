using System.Net;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Infrastructure;
using Sli.Server.Reporting;
using Sli.Server.Reporting.V2;
using Sli.Server.Semantic;
using Sli.Server.Tests.Reporting;
using Sli.Server.Workstations;
using Xunit;

namespace Sli.Server.Tests.Workstations;

public sealed class NativeWorkstationsReportPostgresTests
{
    private sealed class Connections(SqlPostgresFixture fixture) : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => fixture.Pg.OpenAsync(ct, "adlog_user");
    }

    [Fact]
    public async Task Current_bindings_pages_and_retained_events_keep_independent_permissions_and_exact_source()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var sample = await NativeWorkstationsReportFixture.SeedAsync(owner, ct);
        var connections = new Connections(fixture);
        var definitions = new ReportDefinitionRegistry();
        var facts = new ReportFixture.FactsRepo(WorkstationWorkspaceTests.AuthorizedFacts());
        var runner = new ReportRunner(new ReportDatabase(connections));
        var database = new SemanticDatabase(connections);
        var journal = new EventsJournalReader(runner, facts, database, new BuiltinReportExports(runner, facts, null!, database));
        var reader = new WorkstationWorkspaceReader(connections, facts, journal, definitions);
        await using var host = await ReportFixture.Start(facts.Value, definitions.Get("workstations.overview"),
            nativeReader: reader, workstationRoutes: true);
        string filter = "period=custom&from=" + Uri.EscapeDataString(sample["from_utc"]!.ToString())
            + "&to=" + Uri.EscapeDataString(sample["to_utc"]!.ToString())
            + "&domain=" + sample["domain_id"] + "&search=" + sample["search"];
        string detailPath = "/api/v2/reports/workstations.overview/rows/" + sample["station_id"] + "/detail?" + filter;
        async Task<JsonObject> Get(string path, HttpStatusCode status = HttpStatusCode.OK)
        {
            using var response = await host.Client.GetAsync(path, ct);
            var body = await ReportFixture.Body(response);
            Assert.True(response.StatusCode == status, body.ToJsonString());
            return body;
        }
        void Authorize(AccessFacts value) { facts.Value = value; host.Facts.Value = value; }

        JsonObject? twoHundred = null;
        foreach (int limit in new[] { 25, 50, 100, 200 })
        {
            var page = await Get("/api/v2/reports/workstations.overview/data?" + filter + "&limit=" + limit);
            Assert.Equal("ok", page["state"]!.ToString());
            Assert.Equal(limit, page["items"]!.AsArray().Count);
            Assert.Equal(NativeWorkstationsReportFixture.Count, page["filtered_count"]!.GetValue<int>());
            Assert.True(page["has_more"]!.GetValue<bool>());
            Assert.Equal(1, page["collections"]!["paging"]![0]!["start"]!.GetValue<int>());
            if (limit == 200) twoHundred = page;
        }
        var last = await Get("/api/v2/reports/workstations.overview/data?" + filter + "&limit=200&cursor="
            + Uri.EscapeDataString(twoHundred!["next_cursor"]!.ToString()));
        Assert.Equal(5, last["items"]!.AsArray().Count);
        Assert.Equal(201, last["collections"]!["paging"]![0]!["start"]!.GetValue<int>());
        Assert.True(last["collections"]!["paging"]![0]!["has_previous"]!.GetValue<bool>());
        Assert.Null(last["collections"]!["paging"]![0]!["previous_cursor"]);
        Assert.False(last["has_more"]!.GetValue<bool>());
        await Get("/api/v2/reports/workstations.overview/data?" + filter + "&limit=100&cursor="
            + Uri.EscapeDataString(twoHundred["next_cursor"]!.ToString()), HttpStatusCode.BadRequest);

        var body = await Get(detailPath + "&event_limit=200");
        var station = body["detail"]!["station"]!;
        Assert.Equal(sample["station_id"]!.ToString(), station["station_id"]!.ToString());
        Assert.Equal(sample["source_instance_id"]!.ToString(), station["source_instance_id"]!.ToString());
        Assert.Equal("Windows 11", station["operating_system"]!.ToString());
        Assert.Equal(2, station["policy_revision"]!.GetValue<int>());
        Assert.Equal(1, station["applied_policy_revision"]!.GetValue<int>());
        Assert.Equal("enabled", station["collection_state"]!.ToString());
        Assert.Equal("supported", station["profile"]!["state"]!.ToString());
        Assert.NotNull(station["last_seen"]);
        foreach (string unavailable in new[] { "online", "defender_state", "process_count", "usb_count", "ip_address" })
            Assert.Null(station[unavailable]);
        var events = body["detail"]!["events"]!;
        Assert.Equal("ok", events["state"]!.ToString());
        Assert.Equal(40L, events["journal_event_count"]!.GetValue<long>());
        var rows = events["items"]!.AsArray();
        Assert.Equal(3, rows.Count);
        Assert.Equal(40L, rows.Sum(row => row!["event_count"]!.GetValue<long>()));
        Assert.DoesNotContain("OTHER-SOURCE", events.ToJsonString());
        var exact = Assert.Single(rows, row => row!["id"]?.ToString() == sample["exact_event_id"]!.ToString())!;
        Assert.True(exact["journal_evidence_available"]!.GetValue<bool>());
        var daily = Assert.Single(rows, row => row!["summary_key"]?.ToString() == sample["group_summary_key"]!.ToString())!;
        Assert.Null(daily["id"]);
        Assert.Equal(37L, daily["event_count"]!.GetValue<long>());
        Assert.Equal(DateTimeOffset.Parse(sample["group_first_seen_utc"]!.ToString()), DateTimeOffset.Parse(daily["first_seen_utc"]!.ToString()));
        Assert.Equal(DateTimeOffset.Parse(sample["group_last_seen_utc"]!.ToString()), DateTimeOffset.Parse(daily["last_seen_utc"]!.ToString()));
        Assert.False(daily["journal_evidence_available"]!.GetValue<bool>());
        var repeated = Assert.Single(rows, row => row!["journal_expandable"]?.GetValue<bool>() == true)!;
        Assert.Equal(2L, repeated["event_count"]!.GetValue<long>());
        Assert.False(repeated["journal_evidence_available"]!.GetValue<bool>());
        Assert.All(rows, row => Assert.Null(row!["journal_finding_id"])); // No security.queue grant is borrowed.

        // The public journal link uses the same source/window selection. The
        // trusted native server ID is an additional constraint inside detail.
        var parameters = body["detail"]!["related"]!["journal"]!["params"]!.AsObject();
        Assert.Equal(sample["source_instance_id"]!.ToString(), parameters["source_instance_id"]!.ToString());
        Assert.Equal("sli.workstations", parameters["source_plugin"]!.ToString());
        string linkQuery = string.Join('&', parameters.Select(pair => Uri.EscapeDataString(pair.Key) + "=" + Uri.EscapeDataString(pair.Value!.ToString())));
        await using (var journalHost = await ReportFixture.Start(facts.Value, definitions.Get("events.journal"), nativeReader: journal))
        {
            using var response = await journalHost.Client.GetAsync("/api/v2/reports/events.journal/data?" + linkQuery, ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var linked = await ReportFixture.Body(response);
            Assert.Equal(40L, linked["journal_event_count"]!.GetValue<long>());
            Assert.DoesNotContain("OTHER-SOURCE", linked.ToJsonString());
        }
        var authentication = await Get(detailPath + "&view=authentication");
        Assert.Equal(39L, authentication["detail"]!["events"]!["journal_event_count"]!.GetValue<long>());
        Assert.All(authentication["detail"]!["events"]!["items"]!.AsArray(), row => Assert.Contains(row!["event_id"]!.GetValue<int>(), new[] { 4624, 4625 }));
        await Get("/api/v2/reports/workstations.overview/export.csv?" + filter, HttpStatusCode.NotFound);

        Authorize(WorkstationWorkspaceTests.AuthorizedFacts(exact: false));
        var noEvidence = await Get(detailPath);
        Assert.Equal(40L, noEvidence["detail"]!["events"]!["journal_event_count"]!.GetValue<long>());
        Assert.All(noEvidence["detail"]!["events"]!["items"]!.AsArray(), row => Assert.False(row!["journal_evidence_available"]!.GetValue<bool>()));
        Authorize(WorkstationWorkspaceTests.AuthorizedFacts(journal: false));
        var stationOnly = await Get(detailPath);
        Assert.Equal("denied", stationOnly["detail"]!["events"]!["state"]!.ToString());
        Assert.Null(stationOnly["detail"]!["events"]!["filtered_count"]);
        Assert.Empty(stationOnly["detail"]!["events"]!["items"]!.AsArray());
        Assert.False(stationOnly["detail"]!["related"]!["journal"]!["allowed"]!.GetValue<bool>());

        string sourceScope = "{\"mode\":\"restricted\",\"clauses\":[{\"source_instance_ids\":[\"" + sample["source_instance_id"] + "\"]}]}";
        Authorize(WorkstationWorkspaceTests.AuthorizedFacts(stationScope: sourceScope));
        var one = await Get("/api/v2/reports/workstations.overview/data?" + filter);
        Assert.Equal(sample["station_id"]!.ToString(), Assert.Single(one["items"]!.AsArray())!["station_id"]!.ToString());
        Assert.Equal(1, one["filtered_count"]!.GetValue<int>());
        await Get(detailPath.Replace(sample["station_id"]!.ToString(), "41700000-0000-4000-8000-000000000002"), HttpStatusCode.NotFound);
        Authorize(WorkstationWorkspaceTests.AuthorizedFacts(stationScope: sourceScope, deniedAgent: sample["agent_id"]!.ToString()));
        var denied = await Get("/api/v2/reports/workstations.overview/data?" + filter);
        Assert.Empty(denied["items"]!.AsArray()); Assert.Equal(0, denied["filtered_count"]!.GetValue<int>());
        await Get(detailPath, HttpStatusCode.NotFound);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
