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
    public async Task File_burst_folds_companion_operations_before_paging_search_and_export()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 464);
        var migration = MigrationDirectory.Read(465).Single(item => item.Version == 465);
        await fixture.Pg.ApplyFileAsync(migration.Path, null, ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var sample = await FileServersReportFixture.SeedAsync(owner, ct);
        var first = DateTimeOffset.Parse(sample["first_seen_utc"]!.ToString(), System.Globalization.CultureInfo.InvariantCulture);
        await using (var insert = new NpgsqlCommand("""
            with burst as (
                select n,case when n<=110 then @root||chr(92)||'file-'||n||'.txt' else @root end as path,
                    case when n<=110 then 'file' else 'directory' end as kind,
                    @at+case when n=221 then interval '1 minute' else interval '0' end as stamp,
                    case when n<=110 then 65538 else 2 end as mask
                from generate_series(1,221) n
                union all
                select 222,@root||chr(92)||'FILE-1.txt','file',@at+interval '10 seconds',2
            ), evidence as (
                insert into sli_plugin_file_audit.observations
                    (evidence_key,agent_id,source_instance_id,collection_scope_id,channel,provider,generation,record_id,event_id,
                     event_version,observed_at,policy_revision,core_evidence_ref,payload_sha256,normalized)
                select encode(sha256(convert_to('fixture-observation:'||n,'UTF8')),'hex'),@agent,@source,@scope,'Security','Microsoft-Windows-Security-Auditing',
                    'fixture-generation',n,4663,0,stamp,2,'fixture:'||n,repeat('a',64),jsonb_build_object('path',path)
                from burst returning record_id,evidence_key,core_evidence_ref
            ), actions as (
                insert into sli_plugin_file_audit.actions
                    (action_id,contract_version,agent_id,source_instance_id,collection_scope_id,observed_at,subject_sid,
                     logon_id,path,share_name,object_type,access_mask,operation,outcome,server_process_id,projection_version)
                select encode(sha256(convert_to('fixture-action:'||operation||':'||b.n,'UTF8')),'hex'),1,@agent,@source,@scope,
                    stamp,@subject,'fixture-logon',path,'Finance',kind,mask,operation,'success',42,1
                from burst b cross join lateral unnest(case when b.n<=110 then array['write','delete_right'] else array['write'] end) operation
                returning action_id
            )
            insert into sli_plugin_file_audit.action_evidence(action_id,core_evidence_ref,evidence_key,role)
            select a.action_id,e.core_evidence_ref,e.evidence_key,'primary'
            from evidence e join actions a on a.action_id in (
                encode(sha256(convert_to('fixture-action:write:'||e.record_id,'UTF8')),'hex'),
                encode(sha256(convert_to('fixture-action:delete_right:'||e.record_id,'UTF8')),'hex'))
            """, owner))
        {
            insert.Parameters.AddWithValue("agent", FileServersReportFixture.Agent);
            insert.Parameters.AddWithValue("source", FileServersReportFixture.Source.ToString("D"));
            insert.Parameters.AddWithValue("scope", FileServersReportFixture.Scope);
            insert.Parameters.AddWithValue("root", FileServersReportFixture.RootPath);
            insert.Parameters.AddWithValue("subject", FileServersReportFixture.Subject);
            insert.Parameters.AddWithValue("at", first.UtcDateTime);
            await insert.ExecuteNonQueryAsync(ct);
        }
        var reader = new FileAuditReportReader(new SemanticDatabase(new Connections(fixture)));
        const string key = "file-audit.actions";
        await using var host = await ReportFixture.Start(FileAuditReportTests.Facts("actions"),
            new ReportDefinitionRegistry().Get(key), nativeReader: reader);
        string filter = $"source_kind=server&period=custom&from={Uri.EscapeDataString(sample["from_utc"]!.ToString())}"
            + $"&to={Uri.EscapeDataString(sample["to_utc"]!.ToString())}&record_unit=normalized_action";
        async Task<JsonObject> Read(string args)
        {
            using var response = await host.Client.GetAsync("/api/v2/reports/" + key + "/data?" + filter + args, ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return await ReportFixture.Body(response);
        }

        var page = await Read("&limit=50");
        var all = new JsonArray();
        do
        {
            Assert.Equal(111, page["filtered_count"]!.GetValue<int>());
            foreach (var row in page["items"]!.AsArray()) all.Add(row!.DeepClone());
            if (page["next_cursor"] is not { } cursor) break;
            page = await Read("&limit=50&cursor=" + Uri.EscapeDataString(cursor.ToString()));
        } while (true);
        Assert.Equal(111, all.Select(row => row!["id"]!.ToString()).Distinct().Count());
        Assert.All(all, row => Assert.Equal("write", row!["operation"]!.ToString()));
        Assert.All(all, row => Assert.Equal(4663, row!["event_code"]!.GetValue<int>()));
        var standalone = Assert.Single(all, row => row!["path"]!.ToString() == FileServersReportFixture.RootPath);
        Assert.Equal(1, standalone!["count"]!.GetValue<int>());
        var repeated = Assert.Single(all, row => row!["path"]!.ToString().EndsWith(@"\file-1.txt", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(2, repeated!["count"]!.GetValue<int>());
        Assert.Equal(first, DateTimeOffset.Parse(repeated["first_seen_utc"]!.ToString(), System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal(first.AddSeconds(10), DateTimeOffset.Parse(repeated["last_seen_utc"]!.ToString(), System.Globalization.CultureInfo.InvariantCulture));
        var exact = await Read("&path_search=" + Uri.EscapeDataString(FileServersReportFixture.RootPath) + "&include_nested=false");
        Assert.Equal(1, exact["filtered_count"]!.GetValue<int>());
        using var csv = await host.Client.GetAsync("/api/v2/reports/" + key + "/export.csv?" + filter, ct);
        Assert.Equal(HttpStatusCode.OK, csv.StatusCode);
        Assert.Equal("111", csv.Headers.GetValues("X-Sli-Export-Rows").Single());
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
        async Task<JsonObject> Read(string tab, string query, string? scope = null, bool manageAudit = false)
        {
            var facts = FileAuditReportTests.Facts(tab, scope: scope ?? """{"kind":"all"}""");
            if (manageAudit)
                facts = facts with { Role = "admin", DirectCapabilities = [.. facts.DirectCapabilities,
                    ReportFixture.J("""{"capability_key":"access.manage","effect":"allow","scope_json":{"kind":"all"}}"""),
                    ReportFixture.J("""{"capability_key":"file-audit.audit.manage","effect":"allow","scope_json":{"kind":"all"}}""")] };
            await using var host = await ReportFixture.Start(facts,
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
        var receipt = Guid.NewGuid();
        await using (var check = new NpgsqlCommand("""
            insert into sli_plugin_file_audit.audit_commands
              (command_id,agent_id,source_instance_id,policy_revision,action,collection_scope_ids,requested_at,actor_kind,actor_id,command_sha256)
            values ('check-fixture',@agent,@source,2,'check',array[@scope],now()-interval '20 minutes','session',1,repeat('b',64));
            insert into sli_plugin_file_audit.audit_receipts
              (receipt_id,command_id,agent_id,source_instance_id,policy_revision,action,collection_scope_id,state,observed_at,reason_code)
            values (@receipt,'check-fixture',@agent,@source,2,'check',@scope,'failed',now()-interval '19 minutes','native_unavailable');
            update public.sli_agents
            set rights_probe='{"agent_version":"26.0.136"}',
                file_audit=jsonb_build_object('request','{"command":{"command_id":"check-fixture","action":"check"}}'::jsonb,
                    'scopes',jsonb_build_object(@scope,jsonb_build_object('receipt_id',@receipt::text)))
            where id=@agent
            """, owner))
        {
            check.Parameters.AddWithValue("agent", FileServersReportFixture.Agent);
            check.Parameters.AddWithValue("source", FileServersReportFixture.Source.ToString("D"));
            check.Parameters.AddWithValue("scope", FileServersReportFixture.Scope);
            check.Parameters.AddWithValue("receipt", receipt);
            await check.ExecuteNonQueryAsync(ct);
        }
        var resource = Assert.Single((await Read("overview", Filter()))["items"]!.AsArray())!;
        var requirement = resource["audit_receipt"]!["check_agent_requirement"]!;
        Assert.Equal("26.0.136", requirement["agent_version"]!.GetValue<string>());
        Assert.Equal("26.0.154", requirement["minimum_version"]!.GetValue<string>());
        Assert.Null(resource["check_revision"]);
        var newObservation = DateTimeOffset.Parse(sample["to_utc"]!.ToString(), CultureInfo.InvariantCulture).AddMinutes(1);
        await using (var check = new NpgsqlCommand("""
            update public.sli_agents a
            set rights_probe='{"agent_version":"26.0.227"}',
                file_audit=jsonb_build_object(
                    'request',jsonb_build_object('command',jsonb_build_object('command_id','check-fixture',
                        'action','check','collection_scope_ids',jsonb_build_array(@scope)), 'config',p.policy),
                    'state','partial','scopes',jsonb_build_object(@scope,jsonb_build_object(
                        'state','partial','reason_code','policy_missing','observed_at_utc',@observed)))
            from sli_plugin_file_audit.policy_revisions p
            where a.id=@agent and p.agent_id=a.id and p.revision=2
            """, owner))
        {
            check.Parameters.AddWithValue("agent", FileServersReportFixture.Agent);
            check.Parameters.AddWithValue("scope", FileServersReportFixture.Scope);
            check.Parameters.AddWithValue("observed", newObservation.ToString("O", CultureInfo.InvariantCulture));
            await check.ExecuteNonQueryAsync(ct);
        }
        var refreshed = Assert.Single((await Read("overview", Filter()))["items"]!.AsArray())!;
        Assert.Equal("failed", refreshed["audit_receipt"]!["state"]!.ToString());
        Assert.Equal("partial", refreshed["check_receipt"]!["state"]!.ToString());
        Assert.Equal(newObservation, DateTimeOffset.Parse(refreshed["check_receipt"]!["observed_at"]!.ToString(), CultureInfo.InvariantCulture));
        Assert.Null(refreshed["check_revision"]);
        var manageable = Assert.Single((await Read("overview", Filter(), manageAudit: true))["items"]!.AsArray())!;
        Assert.NotNull(manageable["check_revision"]);
        foreach (string tab in new[] { "permission-changes", "actions" })
        {
            var page = await Read(tab, Filter());
            var row = Assert.Single(page["items"]!.AsArray())!;
            Assert.Equal("saved_event_group", row["record_unit"]!.ToString());
            Assert.Equal(7, row["aggregate"]!["count"]!.GetValue<int>());
            Assert.Equal("inside", row["aggregate"]!["boundary"]!.ToString());
            Assert.Equal(1, page["filtered_count"]!.GetValue<int>());
        }

        Assert.Single((await Read("overview", Filter() + "&file_server_domain=" + sample["domain_id"]))["items"]!.AsArray());
        Assert.Empty((await Read("overview", Filter() + "&file_server_domain=99999999"))["items"]!.AsArray());

        var foundByPath = await Read("actions", Filter() + "&path_search=finance&account_search=1199");
        Assert.Single(foundByPath["items"]!.AsArray());
        Assert.Empty((await Read("actions", Filter() + "&path_search=missing-example"))["items"]!.AsArray());
        Assert.Empty((await Read("actions", Filter() + "&activity=changes"))["items"]!.AsArray());
        Assert.Empty((await Read("overview", Filter() + "&source_instance_id=another-source"))["items"]!.AsArray());

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
