using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Ad;
using Sli.Server.Reporting.V2;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

[Collection("Semantic producer environment")]
public sealed class SliOwnActionsTests
{
    [Fact]
    public async Task Maintenance_is_attributed_in_changes_and_does_not_publish_findings()
    {
        var ct = TestContext.Current.CancellationToken;
        using var environment = new SemanticProducerPostgresTests.Admission();
        environment.Set("SLI_PLUGIN_LOCK_DIR", Path.Combine(PostCollectionPostgres.Repository(), "config/plugin_packages/v3"));
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var at = DateTimeOffset.UtcNow.AddMinutes(-3);
        var agent = ShortEventAdmissionPostgresTests.Agent;
        Guid first = Guid.Parse("0cce9215-69ae-11d9-bed3-505054503030");
        Guid second = Guid.Parse("0cce9216-69ae-11d9-bed3-505054503030");
        await ShortEventAdmissionPostgresTests.RegisterDcAsync(owner, agent, agent, 900001, 1, "dc.example.test", "Security", ct);

        async Task Add(int record, int eventId, Dictionary<string, string> fields, int seconds = 0)
        {
            var events = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
                registered: (agent, agent, 900001, 1), packetId: Guid.NewGuid(), sequence: record,
                firstRecordId: record, eventKinds: [eventId], occurredAt: at.AddSeconds(seconds), nativeFields: fields);
            await ShortEventAdmissionPostgresTests.WriteAsync(fixture, events, ct);
        }

        await Add(1, 4697, new() { ["ServiceName"] = "SLIAgentNet", ["ServiceFileName"] = "\"C:\\Program Files\\SLI\\AgentNet\\SliAgent.exe\"" });
        await Add(2, 4697, new() { ["ServiceName"] = "ExampleService", ["ServiceFileName"] = @"C:\example.exe" });
        await Add(3, 4698, new() { ["TaskName"] = @"\Microsoft\Windows\UpdateOrchestrator\AC Power Download", ["SubjectUserSid"] = "S-1-5-18" });
        await Add(4, 4698, new() { ["TaskName"] = @"\ExampleTask", ["SubjectUserSid"] = "S-1-5-21-100000001-200000002-300000003-1001" });
        await Add(5, 4719, Audit(first), 1);
        await Add(6, 4719, Audit(second), 2);
        Guid auditGpo = Guid.NewGuid();
        await Add(7, 5136, new() { ["ObjectGUID"] = auditGpo.ToString("B"), ["AttributeLDAPDisplayName"] = "displayName" });
        await Add(8, 5136, new() { ["ObjectGUID"] = Guid.NewGuid().ToString("B"), ["AttributeLDAPDisplayName"] = "displayName", ["AttributeValue"] = "Example audit GPO" });
        await PostCollectionPostgres.Sql(owner, """
            insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled)
            select '00000000-0000-4000-8000-000000000421',id,id,'telegram',true
            from auth_users where username='platform-owner'
            """, ct);

        var request = new AdReportRequest("security", false, false, 1, new(at.AddMinutes(-1), at.AddMinutes(1)), 20,
            new JsonObject { ["changes_view"] = "audit", ["repeat_mode"] = "individual", ["event_id"] = 4719 }, null);
        await using var reporting = await fixture.Pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(reporting, "set role adlog_user", ct);
        var before = await AdSecurity.ReadAsync(reporting, request, ct, null!);
        Assert.Equal(2, before["items"]!.AsArray().Count);

        await using var report = new NpgsqlCommand("update sli_agents set windows_audit=@report::jsonb where id=@agent", owner);
        report.Parameters.AddWithValue("agent", agent);
        report.Parameters.AddWithValue("report", new JsonObject { ["families"] = new JsonObject { ["domain_controller"] = new JsonObject {
            ["required"] = new JsonArray(Observation(first), Observation(second)) } } }.ToJsonString());
        await report.ExecuteNonQueryAsync(ct);

        var changes = await AdSecurity.ReadAsync(reporting, request, ct, null!);
        var row = Assert.Single(changes["items"]!.AsArray())!.AsObject();
        Assert.Equal("SLI", row["actor"]!["name"]!.ToString());
        Assert.Equal(1, changes["filtered_count"]!.GetValue<long>());
        SecurityEventsReader.Derived(row);
        Assert.Equal("SLI configured auditing · 2 subcategories", ReportPresentation.Message(
            row["presentation_messages"]!["change_text"]!["code"]!.ToString(), true,
            row["presentation_messages"]!["change_text"]!["params"]!.AsObject())!["text"]!.ToString());
        var journal = await AdSecurity.ReadAsync(reporting, request with { Filters = new JsonObject { ["event_id"] = 4719 } }, ct, null!);
        Assert.Equal(2, journal["items"]!.AsArray().Count);
        Assert.All(journal["items"]!.AsArray(), item => Assert.NotEqual("SLI", item!["actor"]?["name"]?.ToString()));
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["Sli:OwnActions:AuditGpo:1:Guid"] = auditGpo.ToString(), ["Sli:OwnActions:AuditGpo:1:Name"] = "Example audit GPO"
        }).Build();
        var withGpo = await AdSecurity.ReadAsync(reporting, request with {
            Filters = new JsonObject { ["changes_view"] = "all", ["repeat_mode"] = "individual" }
        }, ct, null!, config);
        var ownRows = withGpo["items"]!.AsArray().Where(item => item!["actor"]?["name"]?.ToString() == "SLI").ToArray();
        Assert.Equal(new[] { 4697L, 4719L, 5136L },
            ownRows.Select(item => item!["event_id"]!.GetValue<long>()).Order().ToArray());
        Assert.Equal("Example audit GPO", ownRows.Single(item => item!["event_id"]!.ToString() == "5136")!["affected_account"]!["name"]!.ToString());

        await using var runtime = PasswordProducerRuntime.Create(name => name == "ADLOG_SEMANTIC_WORKER_DSN"
            ? fixture.Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        var production = new SemanticProduction(runtime, SemanticRuntimeSettings.Read(Environment.GetEnvironmentVariable), SemanticRuntimeSettings.FindingsMode, 16);
        await SemanticProducerBackfill.RunAsync(worker, SemanticRuntimeSettings.FindingsMode, 16, ct);
        Assert.Equal(0, (await production.ProcessOutbox(worker, ct)).Number("failed"));
        Assert.Equal(0, (await production.ProcessRisk(worker, ct)).Number("failed"));
        await using var findings = new NpgsqlCommand("""
            select finding.target,(select count(*) from notification_outbox delivery
                join semantic_finding_publications publication on publication.scenario_id=delivery.publication_scenario_id
                where publication.finding_id=finding.id)
            from findings finding order by finding.target
            """, owner);
        await using var reader = await findings.ExecuteReaderAsync(ct);
        var targets = new List<string>();
        while (await reader.ReadAsync(ct))
        {
            targets.Add(reader.GetString(0));
            Assert.Equal(1, reader.GetInt64(1));
        }
        Assert.Equal(new[] { "ExampleService", @"\ExampleTask" }.Order(StringComparer.Ordinal), targets.Order(StringComparer.Ordinal));

        Dictionary<string, string> Audit(Guid guid) => new() { ["SubcategoryGuid"] = guid.ToString("B"),
            ["AuditPolicyChanges"] = "%%8449", ["SubjectUserSid"] = "S-1-5-18", ["SubjectUserName"] = "DC$", ["SubjectLogonId"] = "0x3e7" };
        JsonObject Observation(Guid guid) => new() { ["guid"] = guid.ToString(), ["enabled_at"] = at.ToString("O"),
            ["state"] = "ok", ["actual_success"] = true };
    }

    [Fact]
    public async Task Upgrade_resolves_only_fully_matched_open_problems_and_keeps_evidence()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        string migration = Assert.Single(await fixture.RollbackAfterAsync(420, ct));
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(owner, """
            insert into findings(fingerprint,rule_code,title,severity,status,first_seen_utc,last_seen_utc,evidence_count)
            values ('synthetic:sli','semantic.security.dc_service_installed','Fixture','high','new',now()::text,now()::text,1),
                   ('synthetic:mixed','semantic.security.dc_service_installed','Fixture','high','active',now()::text,now()::text,2),
                   ('synthetic:builtin','semantic.security.dc_scheduled_task_created','Fixture','high','review',now()::text,now()::text,1),
                   ('synthetic:no-evidence','semantic.security.dc_scheduled_task_created','Fixture','high','new',now()::text,now()::text,0);
            insert into finding_event_copies337(finding_id,event_id,time_created_utc,event_kind,domain_id,computer,
                method,outcome,fields,source_sha256,evidence_role,event_record_id)
            select f.id,event_id,now(),kind,1,'dc.example.test',
                jsonb_build_object('$channel','Security','$provider','Microsoft-Windows-Security-Auditing','$principals',
                                   jsonb_build_object('SubjectUserSid','S-1-5-18')),
                '{}',fields,sha256(convert_to(event_id::text,'UTF8')),'semantic_scenario',event_id
            from (values
                ('synthetic:sli',1,4697,jsonb_build_object('ServiceName','SLIAgentNet',
                    'ServiceFileName',$path$"C:\Program Files\SLI\AgentNet\SliAgent.exe"$path$)),
                ('synthetic:mixed',2,4697,jsonb_build_object('ServiceName','SLIAgentNet',
                    'ServiceFileName',$path$"C:\Program Files\SLI\AgentNet\SliAgent.exe"$path$)),
                ('synthetic:mixed',3,4697,jsonb_build_object('ServiceName','SLIAgentNet','ServiceFileName',$path$C:\different.exe$path$)),
                ('synthetic:builtin',4,4698,jsonb_build_object('TaskName',$path$\Microsoft\Windows\UpdateOrchestrator\AC Power Download$path$))
            ) as fixture(fingerprint,event_id,kind,fields) join findings f using(fingerprint)
            """, ct);
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await using var check = new NpgsqlCommand("""
            select f.fingerprint,f.status,f.status_reason,
                (select count(*) from finding_event_copies337 c where c.finding_id=f.id),
                (select count(*) from finding_status_history h where h.finding_id=f.id and h.changed_by='migration:421')
            from findings f order by f.fingerprint
            """, owner);
        await using var rows = await check.ExecuteReaderAsync(ct);
        var actual = new List<(string Fingerprint, string Status, string? Reason, long Evidence, long Decisions)>();
        while (await rows.ReadAsync(ct))
            actual.Add((rows.GetString(0), rows.GetString(1), rows.IsDBNull(2) ? null : rows.GetString(2), rows.GetInt64(3), rows.GetInt64(4)));
        Assert.Equal(new (string, string, string?, long, long)[] {
            ("synthetic:builtin", "closed", "Встроенная задача Windows", 1, 1),
            ("synthetic:mixed", "active", null, 2, 0),
            ("synthetic:no-evidence", "new", null, 0, 0),
            ("synthetic:sli", "closed", "Действие SLI", 1, 1)
        }, actual);
    }
}
