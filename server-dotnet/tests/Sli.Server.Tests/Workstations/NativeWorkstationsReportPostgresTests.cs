using System.Net;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Access;
using AdJobPlugin = Sli.Server.Ad.AdJobPlugin;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Infrastructure;
using Sli.Server.InstallationSetup;
using Sli.Server.Reporting;
using Sli.Server.Reporting.V2;
using SemanticDatabase = Sli.Server.Semantic.SemanticDatabase;
using Sli.Server.Tests.Ad;
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
    public async Task Published_ad_inventory_advances_once_and_enriches_the_same_row_after_registration()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        const int version = 448;
        var migrations = MigrationDirectory.Read();
        int predecessor = migrations.Last(item => item.Version < version).Version;
        await fixture.StartAsync(ct, throughVersion: predecessor);
        string migration = migrations.Single(item => item.Version == version).Path;
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        var slot = DateTimeOffset.Parse("2026-11-25T11:00:00Z");
        var observed = slot.AddMinutes(5);
        var sample = await NewLogonPairsNativeFixture.SeedAsync(fixture.Pg, observed, 4, ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await Ws.Exec(owner, """
            update plugin_installations_v1 set desired_activation='enabled_manual',component_runtime='running'
            where plugin_id='sli.workstations'
            """, ct);
        var snapshot = NewLogonPairsNativeFixture.SyntheticSnapshot(observed, 4);
        var dc = snapshot["objects"]![3]!;
        dc["userAccountControl"] = 8192;
        dc["name"] = "SYNTHETIC-DC";
        // The DC bit must win even if its OS happens to look like a client.
        await NewLogonPairsNativeFixture.StoreComputersAsync(owner, sample.DomainId, observed, snapshot, ct);
        var manifest = Sli.Server.Ad.AdSnapshotPublisher.Manifest(sample.DomainId,
            "S-1-5-21-100000001-200000002-300000003", "example.test", slot, observed, AdCoordinatorCycle.Schedule,
            [Sli.Server.Ad.AdSnapshotPublisher.Member("computers_v6", "sli.ad-computers.snapshot/2.0",
                snapshot["metadata"]!.Text("snapshot_id")!, observed, "complete", AdJobPlugin.Digest(snapshot))]);
        await using (var tx = await owner.BeginTransactionAsync(ct))
        {
            await AdSnapshotManifest.PublishAsync(owner, tx, manifest, ct);
            await tx.CommitAsync(ct);
        }

        var worker = new SnapshotCycleConsumer();
        var batch = await worker.RunOnceAsync(fixture.Dsn("sli_context_login"), ct);
        Assert.Equal(sample.DomainId, Ws.Number(batch.Cursor, "workstation_inventory_domain_id"));
        Assert.Equal(3L, await Ws.Scalar(owner, "select count(*) from sli_plugin_workstations.station_inventory", ct));
        async Task<string> InventoryVersions() => (string)(await Ws.Scalar(owner, """
            select jsonb_build_array(
                (select jsonb_agg(jsonb_build_array(i.xmin::text,to_jsonb(i)) order by station_id) from sli_plugin_workstations.station_inventory i),
                (select jsonb_agg(jsonb_build_array(c.xmin::text,to_jsonb(c)) order by domain_id) from sli_plugin_workstations.ad_inventory_checkpoints436 c),
                (select count(*) from sli_plugin_workstations.projection_work))::text
            """, ct))!;
        string first = await InventoryVersions();
        Assert.Null((await worker.RunOnceAsync(fixture.Dsn("sli_context_login"), ct)).Cursor);
        Assert.Equal(first, await InventoryVersions());

        var connections = new Connections(fixture);
        var definitions = new ReportDefinitionRegistry();
        var facts = new ReportFixture.FactsRepo(WorkstationWorkspaceTests.AuthorizedFacts(stationScope: $$"""{"kind":"domain","ids":[{{sample.DomainId}}]}"""));
        var reader = new WorkstationWorkspaceReader(connections, facts, null!, definitions);
        await using var host = await ReportFixture.Start(facts.Value, definitions.Get("workstations.overview"),
            nativeReader: reader, workstationRoutes: true);
        const string path = "/api/v2/reports/workstations.overview";
        async Task<JsonObject> Read(string suffix)
        {
            using var response = await host.Client.GetAsync(path + suffix, ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var result = await ReportFixture.Body(response);
            Assert.Equal("ok", result.Text("state"));
            return result;
        }

        var rows = (await Read("/data?period=7d"))["items"]!.AsArray();
        Assert.Equal(new[] { "PC-0", "PC-1", "PC-2" }, rows.Select(row => row.Text("display_name")).Order());
        Assert.All(rows, row =>
        {
            Assert.Equal("Windows 11 Pro", row.Text("operating_system"));
            Assert.Null(row!["last_logon_utc"]);
            Assert.Null(row!["agent_key"]);
            Assert.Null(row["agent_version"]);
        });
        var station = rows.Single(row => row.Text("display_name") == "PC-0")!;
        string stationId = station.Text("station_id")!;
        long computer = long.Parse(stationId.AsSpan("ws:ad:".Length), System.Globalization.CultureInfo.InvariantCulture);
        var (agent, _) = await WorkstationInventoryJobPostgresTests.Device(owner, computer);
        await Ws.Exec(owner, """update sli_agents set rights_probe='{"agent_version":"1.2.3"}'::jsonb where id=@p0""", ct, agent);
        rows = (await Read("/data?period=7d"))["items"]!.AsArray();
        Assert.Equal(3, rows.Count);
        var linked = Assert.Single(rows, row => row.Text("station_id") == stationId);
        Assert.Equal("1.2.3", linked.Text("agent_version"));
        Assert.Equal(agent.ToString("D"), linked.Text("agent_key"));
        var pluginSources = await new InstallationService(new InstallationDatabase(connections), null!)
            .WorkstationStatusSourcesAsync(facts.Value, ct);
        var source = Assert.Single(Assert.IsType<JsonArray>(pluginSources));
        Assert.Equal(linked.Text("transport_agent_id"), source.Text("agent_id"));
        Assert.Equal(linked.Text("display_name"), source.Text("source_name"));
        Assert.False(source!["collects"]!.GetValue<bool>());
        var detail = (await Read("/rows/" + stationId + "/detail?period=7d"))["detail"]!;
        Assert.Equal("not_collected", detail["events"].Text("state"));
        Assert.False(detail["station"]!["journal_available"]!.GetValue<bool>());
        Assert.Equal(0L, await Ws.Scalar(owner, "select count(*) from public.workstation_journal_grants412", ct));

        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
        Assert.Equal(3L, await Ws.Scalar(owner, "select count(*) from sli_plugin_workstations.station_inventory", ct));
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        Assert.NotNull((await worker.RunOnceAsync(fixture.Dsn("sli_context_login"), ct)).Cursor);
        Assert.Equal(3L, await Ws.Scalar(owner, "select count(*) from sli_plugin_workstations.station_inventory", ct));
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
            var fleet = page["items"]!.AsArray();
            var reporting = Assert.Single(fleet, row => row.Text("station_id") == sample.Text("station_id"));
            Assert.Equal("Windows 11 Pro", reporting.Text("operating_system"));
            Assert.Equal("10.0.26100", reporting.Text("operating_system_version"));
            Assert.Equal(DateTimeOffset.Parse(sample.Text("group_last_seen_utc")!), DateTimeOffset.Parse(reporting.Text("last_logon_utc")!));
            Assert.All(fleet.Where(row => row.Text("station_id") != sample.Text("station_id")), row => Assert.Null(row!["last_logon_utc"]));
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
        Assert.Equal("Windows 11 Pro", station["operating_system"]!.ToString());
        Assert.Equal(2, station["policy_revision"]!.GetValue<int>());
        Assert.Equal(1, station["applied_policy_revision"]!.GetValue<int>());
        Assert.Equal("enabled", station["collection_state"]!.ToString());
        Assert.Equal("supported", station["profile"]!["state"]!.ToString());
        Assert.NotNull(station["last_seen"]);
        foreach (string unavailable in new[] { "online", "defender_state", "process_count", "usb_count", "ip_address" })
            Assert.Null(station[unavailable]);
        var events = body["detail"]!["events"]!;
        Assert.Equal("ok", events["state"]!.ToString());
        Assert.Equal(46L, events["journal_event_count"]!.GetValue<long>());
        var rows = events["items"]!.AsArray();
        Assert.Equal(8, rows.Count);
        Assert.Equal(46L, rows.Sum(row => row!["event_count"]!.GetValue<long>()));
        Assert.DoesNotContain("OTHER-SOURCE", events.ToJsonString());
        var exact = Assert.Single(rows, row => row!["id"]?.ToString() == sample["exact_event_id"]!.ToString())!;
        Assert.True(exact["journal_evidence_available"]!.GetValue<bool>());
        var daily = Assert.Single(rows, row => row!["summary_key"]?.ToString() == sample["group_summary_key"]!.ToString())!;
        Assert.Null(daily["id"]);
        Assert.Equal(37L, daily["event_count"]!.GetValue<long>());
        Assert.Equal(DateTimeOffset.Parse(sample["group_first_seen_utc"]!.ToString()), DateTimeOffset.Parse(daily["first_seen_utc"]!.ToString()));
        Assert.Equal(DateTimeOffset.Parse(sample["group_last_seen_utc"]!.ToString()), DateTimeOffset.Parse(daily["last_seen_utc"]!.ToString()));
        Assert.False(daily["journal_evidence_available"]!.GetValue<bool>());
        var repeated = Assert.Single(rows, row => row!["event_id"]!.GetValue<int>() == 4625 && row["journal_expandable"]?.GetValue<bool>() == true)!;
        Assert.Equal(2L, repeated["event_count"]!.GetValue<long>());
        Assert.False(repeated["journal_evidence_available"]!.GetValue<bool>());
        var processes = rows.Where(row => row!["event_id"]!.GetValue<int>() == 4688).ToArray();
        Assert.Equal(4, processes.Length);
        var starts = Assert.Single(processes, row => row!["journal_expandable"]!.GetValue<bool>())!;
        Assert.Equal(2L, starts["event_count"]!.GetValue<long>());
        Assert.Equal(11, (DateTimeOffset.Parse(starts.Text("last_seen_utc")!) - DateTimeOffset.Parse(starts.Text("first_seen_utc")!)).TotalSeconds);
        var process = starts["workstation_event"]!;
        Assert.Equal(@"C:\Users\example\AppData\Local\Editor\bin\abcdef12\editor.exe", process.Text("image_path"));
        Assert.Equal(@"C:\Windows\explorer.exe", process.Text("parent_image_path"));
        Assert.Equal(@"WS-WORKSPACE-001\user", process.Text("account"));
        Assert.Equal("editor.exe draft.txt", process.Text("command_line"));
        Assert.Single(processes, row => row!["workstation_event"]!["command_line"] is null);
        var resolved = Assert.Single(processes, row => row!["id"]!.GetValue<long>() == NativeWorkstationsReportFixture.ExactEvent + 9);
        Assert.EndsWith(@"\directory-user", resolved!["workstation_event"].Text("account"), StringComparison.Ordinal);
        Assert.Equal(@"WS-WORKSPACE-001\user", resolved["workstation_event"].Text("initiator"));
        var device = Assert.Single(rows, row => row!["event_id"]!.GetValue<int>() == 6416)!["workstation_event"]!;
        Assert.Equal("DiskDrive", device.Text("device_class"));
        Assert.Equal("Example USB drive", device.Text("device_name"));
        Assert.All(rows, row => Assert.Null(row!["journal_finding_id"])); // No security.queue grant is borrowed.

        var activity = body["detail"]!["activity"]!;
        var program = Assert.Single(activity["programs"]!.AsArray())!;
        Assert.Equal(@"C:\Users\example\AppData\Local\Editor\bin\987654fa\editor.exe", program.Text("path"));
        Assert.Equal("low", program.Text("severity"));
        Assert.Equal(5L, program["count"]!.GetValue<long>());
        Assert.Contains(@"WS-WORKSPACE-001\user", program["users"]!.AsArray().Select(user => user!.ToString()));
        var logons = activity["logons"]!.AsArray();
        var remote = Assert.Single(logons, logon => logon.Text("type") == "10")!;
        var failed = Assert.Single(logons, logon => logon.Text("type") == "3")!;
        Assert.Equal(37L, remote["count"]!.GetValue<long>());
        Assert.Equal(2L, failed["failures"]!.GetValue<long>());
        Assert.Equal("Example USB drive", Assert.Single(activity["devices"]!.AsArray()).Text("name"));
        Assert.Equal(new[] { "new_usb_storage", "remote_logon", "service_installed" },
            activity["notable"]!.AsArray().Select(row => row.Text("fact")));
        Assert.Equal("low", exact.Text("station_importance"));
        Assert.Equal("medium", daily.Text("station_importance"));
        Assert.Equal("medium", Assert.Single(rows, row => row!["event_id"]!.GetValue<int>() == 6416).Text("station_importance"));
        Assert.DoesNotContain("OTHER-SOURCE", activity.ToJsonString());

        var programPage = await Get(detailPath + "&event_limit=2&program="
            + Uri.EscapeDataString(@"c:/users/example/AppData/Local/Editor/bin/abcdef12/EDITOR.exe"));
        var filteredEvents = programPage["detail"]!["events"]!;
        Assert.Equal(5L, filteredEvents["journal_event_count"]!.GetValue<long>());
        Assert.Equal(2, filteredEvents["items"]!.AsArray().Count);
        Assert.All(filteredEvents["items"]!.AsArray(), row => Assert.Equal(4688, row!["event_id"]!.GetValue<int>()));
        string nextEvents = Uri.EscapeDataString(filteredEvents["next_cursor"]!.ToString());
        await Get(detailPath + "&event_limit=2&event_cursor=" + nextEvents, HttpStatusCode.BadRequest);
        Assert.Equal(5L, Assert.Single(programPage["detail"]!["activity"]!["programs"]!.AsArray())!["count"]!.GetValue<long>());

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
            Assert.Equal(46L, linked["journal_event_count"]!.GetValue<long>());
            Assert.DoesNotContain("OTHER-SOURCE", linked.ToJsonString());
        }
        var authentication = await Get(detailPath + "&view=authentication");
        Assert.Equal(39L, authentication["detail"]!["events"]!["journal_event_count"]!.GetValue<long>());
        Assert.All(authentication["detail"]!["events"]!["items"]!.AsArray(), row => Assert.Contains(row!["event_id"]!.GetValue<int>(), new[] { 4624, 4625 }));
        await Get("/api/v2/reports/workstations.overview/export.csv?" + filter, HttpStatusCode.NotFound);

        Authorize(WorkstationWorkspaceTests.AuthorizedFacts(exact: false));
        var noEvidence = await Get(detailPath);
        Assert.Equal(46L, noEvidence["detail"]!["events"]!["journal_event_count"]!.GetValue<long>());
        Assert.All(noEvidence["detail"]!["events"]!["items"]!.AsArray(), row => Assert.False(row!["journal_evidence_available"]!.GetValue<bool>()));
        Assert.All(noEvidence["detail"]!["events"]!["items"]!.AsArray().Where(row => row!["event_id"]!.GetValue<int>() == 4688),
            row =>
            {
                Assert.EndsWith(@"\editor.exe", row!["workstation_event"].Text("image_path"), StringComparison.Ordinal);
                Assert.Null(row["workstation_event"]!["command_line"]);
            });
        Authorize(WorkstationWorkspaceTests.AuthorizedFacts(journal: false));
        var stationOnly = await Get(detailPath);
        Assert.Equal("denied", stationOnly["detail"]!["events"]!["state"]!.ToString());
        Assert.Null(stationOnly["detail"]!["activity"]);
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
