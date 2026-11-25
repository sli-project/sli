using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Reporting.V2;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class FileServersReportPostgresTests
{
    private sealed class Connections(SqlPostgresFixture fixture) : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => fixture.Pg.OpenAsync(ct, "adlog_user");
    }

    [Fact]
    public async Task Retained_groups_acl_and_two_hundred_rows_share_scope_window_and_export_contract()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var sample = await FileServersReportFixture.SeedAsync(owner, ct);
        var reader = new FileAuditReportReader(new SemanticDatabase(new Connections(fixture)));
        string Filter(string? from = null, string? to = null) =>
            "source_kind=server&share=" + Uri.EscapeDataString(sample["share_key"]!.ToString())
            + "&period=custom&from=" + Uri.EscapeDataString(from ?? sample["from_utc"]!.ToString())
            + "&to=" + Uri.EscapeDataString(to ?? sample["to_utc"]!.ToString());
        async Task<JsonObject> Read(string tab, string query, string? scope = null)
        {
            await using var host = await ReportFixture.Start(FileAuditReportTests.Facts(tab, scope: scope ?? """{"kind":"all"}"""),
                new ReportDefinitionRegistry().Get("file-audit." + tab), nativeReader: reader);
            using var response = await host.Client.GetAsync("/api/v2/reports/file-audit." + tab + "/data?" + query, ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return await ReportFixture.Body(response);
        }
        var overview = await Read("overview", Filter() + "&employee=" + FileServersReportFixture.Subject + "&operation=permissions");
        var summary = Assert.Single(overview["items"]!.AsArray())!;
        Assert.Equal(7, summary["permission_changes"]!.GetValue<int>());
        Assert.Equal(1, summary["permission_change_groups"]!.GetValue<int>());
        Assert.Equal("saved_4670_events", summary["permission_change_unit"]!.ToString());
        foreach (string tab in new[] { "permission-changes", "actions" })
        {
            var page = await Read(tab, Filter());
            var row = Assert.Single(page["items"]!.AsArray())!;
            Assert.Equal("saved_event_group", row["record_unit"]!.ToString());
            Assert.Equal(7, row["aggregate"]!["count"]!.GetValue<int>());
            Assert.Equal("inside", row["aggregate"]!["boundary"]!.ToString());
            Assert.Equal(1, page["filtered_count"]!.GetValue<int>());
        }

        var first = DateTimeOffset.Parse(sample["first_seen_utc"]!.ToString(), CultureInfo.InvariantCulture);
        var last = DateTimeOffset.Parse(sample["last_seen_utc"]!.ToString(), CultureInfo.InvariantCulture);
        string boundary = Filter(first.AddSeconds(5).ToString("O"), last.AddSeconds(5).ToString("O"));
        var boundaryOverview = Assert.Single((await Read("overview", boundary))["items"]!.AsArray())!;
        var boundaryGroup = Assert.Single((await Read("permission-changes", boundary + "&record_unit=saved_event_group"))["items"]!.AsArray())!;
        Assert.Null(boundaryOverview["permission_changes"]);
        Assert.Equal("overlap", boundaryGroup["aggregate"]!["boundary"]!.ToString());
        Assert.Equal(1, boundaryOverview["permission_change_count_min"]!.GetValue<int>());
        Assert.Equal(6, boundaryOverview["permission_change_count_max"]!.GetValue<int>());
        Assert.Equal(boundaryOverview["permission_change_count_min"]!.ToString(), boundaryGroup["aggregate"]!["count_min"]!.ToString());

        var objects = await Read("permissions", Filter() + "&view=objects&limit=200");
        Assert.Equal(2, objects["items"]!.AsArray().Count);
        Assert.All(objects["items"]!.AsArray(), row => Assert.Equal(sample["snapshot_id"]!.ToString(), row!["snapshot_id"]!.ToString()));
        await using (var host = await ReportFixture.Start(FileAuditReportTests.Facts("permissions"),
            new ReportDefinitionRegistry().Get("file-audit.permissions"), nativeReader: reader))
        {
            string detail = "/api/v2/reports/file-audit.permissions/rows/" + sample["snapshot_id"] + "/detail?"
                + Filter() + "&path=" + Uri.EscapeDataString(sample["path"]!.ToString());
            using var response = await host.Client.GetAsync(detail + "&compare_snapshot_id=" + sample["before_snapshot_id"], ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = await ReportFixture.Body(response);
            Assert.Equal(126, body["detail"]!["object"]!["dacl"]!["aces"]!.AsArray().Count);
            Assert.Equal("deny", body["detail"]!["object"]!["dacl"]!["aces"]![0]!["type"]!.ToString());
            Assert.True(body["detail"]!["object"]!["dacl"]!["aces"]![1]!["inherit_only"]!.GetValue<bool>());
            Assert.Equal("available", body["detail"]!["comparison"]!["state"]!.ToString());
            Assert.Equal("file_id", body["detail"]!["comparison"]!["identity_basis"]!.ToString());
            using var missing = await host.Client.GetAsync(detail + "&compare_snapshot_id=41600000-0000-4000-8000-999999999999", ct);
            Assert.Equal("snapshot_unavailable", (await ReportFixture.Body(missing))["detail"]!["comparison"]!["reason"]!.ToString());
            using var escape = await host.Client.GetAsync(detail.Replace(Uri.EscapeDataString(sample["path"]!.ToString()), Uri.EscapeDataString(@"C:\Shares\FinanceOld")), ct);
            Assert.Equal(HttpStatusCode.NotFound, escape.StatusCode);
        }
        const string deniedScope = """{"mode":"restricted","clauses":[{"source_instance_ids":["not-this-source"]}]}""";
        var denied = await Read("permission-changes", Filter(), deniedScope);
        Assert.Empty(denied["items"]!.AsArray());
        Assert.DoesNotContain(FileServersReportFixture.Source.ToString("D"), denied.ToJsonString());

        // A second delivery of the same durable identity contributes no new group.
        await using (var replay = new NpgsqlCommand("""
            insert into public.event_cold_facts select * from public.event_cold_facts where event_id=@event
            on conflict do nothing;
            """, owner))
        {
            replay.Parameters.AddWithValue("event", FileServersReportFixture.EventId);
            await replay.ExecuteNonQueryAsync(ct);
        }
        Assert.Equal(1, (await Read("actions", Filter()))["filtered_count"]!.GetValue<int>());
        await using (var additional = new NpgsqlCommand("""
            insert into public.event_cold_facts(event_id,time_created_utc,event_kind,domain_id,actor,computer,method,outcome,fields,source_sha256,event_record_id)
            select f.event_id+n,f.time_created_utc-n*interval '1 second',f.event_kind,f.domain_id,f.actor,f.computer,
                f.method,f.outcome,jsonb_set(f.fields,'{aggregate}',jsonb_build_object(
                    'count',1,'first_seen_utc',f.time_created_utc-n*interval '1 second','last_seen_utc',f.time_created_utc-n*interval '1 second')),
                f.source_sha256,f.event_record_id+n
            from public.event_cold_facts f cross join generate_series(1,204) n where f.event_id=@event;
            """, owner))
        {
            additional.Parameters.AddWithValue("event", FileServersReportFixture.EventId);
            await additional.ExecuteNonQueryAsync(ct);
        }
        var twoHundred = await Read("actions", Filter() + "&record_unit=saved_event_group&limit=200");
        Assert.Equal(200, twoHundred["items"]!.AsArray().Count);
        Assert.Equal(205, twoHundred["filtered_count"]!.GetValue<int>());
        Assert.True(twoHundred["has_more"]!.GetValue<bool>());
        var remainder = await Read("actions", Filter() + "&record_unit=saved_event_group&limit=200&cursor="
            + Uri.EscapeDataString(twoHundred["next_cursor"]!.ToString()));
        Assert.Equal(5, remainder["items"]!.AsArray().Count);
        Assert.False(remainder["has_more"]!.GetValue<bool>());
        await using (var host = await ReportFixture.Start(FileAuditReportTests.Facts("actions"),
            new ReportDefinitionRegistry().Get("file-audit.actions"), nativeReader: reader))
        {
            using var csv = await host.Client.GetAsync("/api/v2/reports/file-audit.actions/export.csv?" + Filter() + "&record_unit=saved_event_group", ct);
            Assert.Equal(HttpStatusCode.OK, csv.StatusCode);
            Assert.Equal("205", csv.Headers.GetValues("X-Sli-Export-Rows").Single());
            Assert.Equal("false", csv.Headers.GetValues("X-Sli-Export-Truncated").Single());
            Assert.Contains("saved_event_group", await csv.Content.ReadAsStringAsync(ct));
        }
        await using (var privileges = new NpgsqlCommand("""
            select has_table_privilege('adlog_user','sli_plugin_file_audit.access_snapshots','SELECT'),
                has_function_privilege('adlog_user','public.read_file_audit_snapshot416(jsonb,uuid,timestamptz,text)','EXECUTE')
            """, owner))
        await using (var row = await privileges.ExecuteReaderAsync(ct))
        {
            Assert.True(await row.ReadAsync(ct)); Assert.False(row.GetBoolean(0)); Assert.True(row.GetBoolean(1));
        }
        // The normal fixture executor applies rollback and reapply, then reads the ledger.
        var rolledBack = await fixture.RollbackAfterAsync(415, ct);
        foreach (var path in rolledBack.Reverse()) await fixture.Pg.ApplyFileAsync(path, null, ct);
        await using (var ledger = new NpgsqlCommand("select name from public.schema_migrations where version=416", owner))
            Assert.Equal("file_servers_report_projection", await ledger.ExecuteScalarAsync(ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
