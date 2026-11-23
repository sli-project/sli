using System.Net;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Notifications;
using Sli.Server.Problems;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Problems;
using Sli.Server.Tests.Storage;
using Xunit;
using HomePeriodSql = Sli.Server.Domains.HomePeriodSql;
using HomePresentation = Sli.Server.Domains.HomePresentation;
using HomeSummaryRepository = Sli.Server.Domains.HomeSummaryRepository;

namespace Sli.Server.Tests.Semantic;

[Collection("Semantic producer environment")]
public sealed class DcTaskServicePublicationTests
{
    [Fact]
    public async Task Scope_disabled_policy_and_history_apply_before_live_delivery()
    {
        var ct = TestContext.Current.CancellationToken;
        using var environment = new SemanticProducerPostgresTests.Admission();
        environment.Set("SLI_PLUGIN_LOCK_DIR", Path.Combine(
            PostCollectionPostgres.Repository(), "config/plugin_packages/v3"));
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(owner, """
            insert into forests(id,name) values(901,'synthetic-forest.example.test');
            insert into domains(id,forest_id,fqdn) values(901,901,'synthetic-scope.example.test');
            update semantic_policy_admission set enabled=false,updated_by='synthetic:operator'
            where policy_id='l1-dc-service-installed';
            insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled)
            select '00000000-0000-4000-8000-000000001401',id,id,'telegram',true
            from auth_users where username='platform-owner';
            """, ct);
        var nativeTask = new Dictionary<string, string> { ["TaskName"] = "EquivalentSyntheticTask" };
        var live = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: [4698, 4624],
            nativeFields: nativeTask);
        var secondHost = Guid.NewGuid();
        await ShortEventAdmissionPostgresTests.RegisterDcAsync(owner, secondHost, secondHost, 900901, 901,
            "dc-901.example.test", "Security", ct, history: true);
        var history = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: [4698],
            registered: (secondHost, secondHost, 900901, 901), packetId: Guid.NewGuid(), firstRecordId: 4,
            hostName: "dc-901.example.test", nativeFields: nativeTask, history: true);
        var disabled = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: [4697],
            registered: (secondHost, secondHost, 900901, 901), packetId: Guid.NewGuid(), firstRecordId: 5,
            hostName: "dc-901.example.test", nativeFields: new Dictionary<string, string> {
                ["ServiceName"] = "DisabledSyntheticService", ["ServiceFileName"] = "synthetic-inert-file.fixture"
            });
        var unverified = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: [4698],
            registered: (secondHost, secondHost, 900901, 901), packetId: Guid.NewGuid(), sequence: 2,
            firstRecordId: 6, hostName: "dc-901.example.test");
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, live.Concat(history).Concat(disabled).Concat(unverified).ToArray(), ct);

        await using var runtime = PasswordProducerRuntime.Create(name => name == "ADLOG_SEMANTIC_WORKER_DSN"
            ? fixture.Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        var production = new SemanticProduction(runtime, SemanticRuntimeSettings.Read(Environment.GetEnvironmentVariable),
            SemanticRuntimeSettings.FindingsMode, 16);
        var backfill = await SemanticProducerBackfill.RunAsync(worker, SemanticRuntimeSettings.FindingsMode, 16, ct);
        Assert.Equal(5, backfill.Number("scanned"));
        // 4624 remains journal context. The four task and service observations
        // have their own normalization jobs in the normal findings mode.
        Assert.Equal(4, backfill.Number("queued"));
        var processed = await production.ProcessOutbox(worker, ct);
        Assert.Equal(4, processed.Number("completed"));
        Assert.Equal(0, processed.Number("failed"));
        var risk = await production.ProcessRisk(worker, ct);
        Assert.Equal(0, risk.Number("failed"));
        Assert.Equal(2, risk.Number("published"));

        await using var verify = new NpgsqlCommand("""
            select (select count(*) from public.findings where rule_code='semantic.security.dc_scheduled_task_created')=2
              and (select count(*) from public.findings)=2
              and (select count(*) from public.finding_event_copies337)=2
              and (select count(*) from public.notification_outbox where state='pending' and delivery_reason='live')=1
              and (select count(*) from public.notification_outbox where state='cancelled' and delivery_reason='history_import')=1
              and exists(select 1 from public.semantic_event_source355 where event_id=4624)
              and not exists(
                select 1 from public.findings f
                where public.semantic_finding_in_domains_v265(f.id,array[1::bigint])
                  = public.semantic_finding_in_domains_v265(f.id,array[901::bigint]))
            """, owner);
        Assert.Equal(true, await verify.ExecuteScalarAsync(ct));
    }

    [Fact]
    public async Task Attested_task_and_service_publish_once_with_paired_service_evidence()
    {
        var ct = TestContext.Current.CancellationToken;
        using var environment = new SemanticProducerPostgresTests.Admission();
        environment.Set("SLI_PLUGIN_LOCK_DIR", Path.Combine(
            PostCollectionPostgres.Repository(), "config/plugin_packages/v3"));
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(owner, """
            insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled)
            select '00000000-0000-4000-8000-000000000401',id,id,'telegram',true
            from auth_users where username='platform-owner';
            """, ct);

        var dc = (ShortEventAdmissionPostgresTests.Agent, ShortEventAdmissionPostgresTests.Agent, 900001L, 1L);
        await ShortEventAdmissionPostgresTests.RegisterDcAsync(owner, dc.Item1, dc.Item2, dc.Item3, dc.Item4,
            "dc.example.test", "Security", ct, "System");
        var securityTask = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
            eventKinds: [4698], registered: dc, nativeFields: new Dictionary<string, string> {
                ["TaskName"] = "SyntheticObservation", ["SubjectUserName"] = "synthetic-operator"
            });
        var securityService = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
            eventKinds: [4697], registered: dc, packetId: Guid.NewGuid(), sequence: 2, firstRecordId: 2,
            nativeFields: new Dictionary<string, string> {
                ["ServiceName"] = "SyntheticService", ["ServiceFileName"] = "synthetic-inert-file.fixture",
                ["SubjectUserName"] = "synthetic-operator"
            });
        var systemService = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
            eventKinds: [7045], registered: dc, eventChannel: "System", packetId: Guid.NewGuid(), sequence: 3, firstRecordId: 3,
            nativeFields: new Dictionary<string, string> {
                ["ServiceName"] = "syntheticservice", ["ImagePath"] = "synthetic-inert-file.fixture"
            });
        var rows = securityTask.Concat(securityService).Concat(systemService).ToArray();
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, rows, ct);
        await PostCollectionPostgres.Sql(owner, """
            insert into event_cold_facts select * from event_hot where event_id=900003 on conflict do nothing;
            delete from event_hot where event_id=900003;
            """, ct);

        await using var runtime = PasswordProducerRuntime.Create(name => name == "ADLOG_SEMANTIC_WORKER_DSN"
            ? fixture.Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        var production = new SemanticProduction(runtime, SemanticRuntimeSettings.Read(Environment.GetEnvironmentVariable),
            SemanticRuntimeSettings.FindingsMode, 16);
        var backfill = await SemanticProducerBackfill.RunAsync(worker, SemanticRuntimeSettings.FindingsMode, 16, ct);
        Assert.Equal(3, backfill.Number("queued"));
        var processed = await production.ProcessOutbox(worker, ct);
        Assert.Equal(3, processed.Number("completed"));
        await InterruptPublication(owner, worker, production, ct);
        var risk = await production.ProcessRisk(worker, ct);
        await using (var failures = new NpgsqlCommand("""
            select string_agg(coalesce(last_error_code,'')||':'||coalesce(last_error_detail,''),'; ')
            from semantic_risk_evaluation_jobs where evaluation_status in('failed','quarantined')
            """, owner))
            Assert.True(risk.Number("failed") == 0, Convert.ToString(await failures.ExecuteScalarAsync(ct)));
        Assert.Equal(2, risk.Number("published"));
        Assert.Equal(0, (await production.ProcessRisk(worker, ct)).Number("published"));

        await using var check = new NpgsqlCommand("""
            select to_jsonb(f)::text,
                public.semantic_finding_in_domains_v265(f.id,array[1::bigint]),
                public.semantic_finding_in_domains_v265(f.id,array[2::bigint]),
                (select count(*) from public.notification_outbox j where j.publication_scenario_id=p.scenario_id
                    and j.channel='telegram' and j.state='pending' and j.object_severity='high')
            from public.findings f join public.semantic_finding_publications p on p.finding_id=f.id
            order by f.rule_code
            """, owner);
        await using var findings = await check.ExecuteReaderAsync(ct);
        foreach (bool task in new[] { true, false })
        {
            Assert.True(await findings.ReadAsync(ct));
            var finding = JsonNode.Parse(findings.GetString(0))!.AsObject();
            Assert.Equal(task ? "semantic.security.dc_scheduled_task_created" : "semantic.security.dc_service_installed", finding.Text("rule_code"));
            Assert.Equal("high", finding.Text("severity"));
            Assert.Equal(task ? 1 : 2, finding.Number("evidence_count"));
            Assert.Equal("synthetic-operator", finding.Text("actor"));
            Assert.Contains(task ? "scheduled task" : "service", ProblemPresentation.RuleMessage(finding, "title", "en").Text("text"));
            Assert.Contains(task ? "задача" : "служба", ProblemPresentation.RuleMessage(finding, "title", "ru").Text("text"));
            Assert.True(findings.GetBoolean(1));
            Assert.False(findings.GetBoolean(2));
            Assert.Equal(1, findings.GetInt64(3));
        }
        Assert.False(await findings.ReadAsync(ct));
        await findings.DisposeAsync();

        await CheckHomeAndProblems(fixture, ct);
        await CheckNotificationDelivery(fixture, owner, environment, ct);
        await CheckMigrationRoundTrip(fixture, owner, ct);
    }

    private static async Task InterruptPublication(NpgsqlConnection owner, NpgsqlConnection worker,
        SemanticProduction production, CancellationToken ct)
    {
        await PostCollectionPostgres.Sql(owner, """
            create function det06_test_interrupt() returns trigger language plpgsql as $$
            begin
                raise exception 'synthetic publication interruption' using errcode='40001';
            end $$;
            create trigger det06_test_interrupt before insert on notification_outbox
                for each row execute function det06_test_interrupt();
            """, ct);
        var interrupted = await production.ProcessRisk(worker, ct);
        Assert.Equal(3, interrupted.Number("failed"));
        await using var partial = new NpgsqlCommand("""
            select not exists(select 1 from public.findings)
                and not exists(select 1 from public.semantic_finding_publications)
                and not exists(select 1 from public.notification_outbox)
            """, owner);
        Assert.Equal(true, await partial.ExecuteScalarAsync(ct));
        await PostCollectionPostgres.Sql(owner, """
            drop trigger det06_test_interrupt on notification_outbox;
            drop function det06_test_interrupt();
            update semantic_risk_evaluation_jobs set available_at=now() where evaluation_status='failed';
            """, ct);
    }

    private static async Task CheckHomeAndProblems(SqlPostgresFixture fixture, CancellationToken ct)
    {
        var database = new TestReadConnection(fixture.Dsn("adlog_user"));
        var home = new HomeSummaryRepository(database);
        var queue = new ProblemRepository(database, TimeProvider.System);
        var access = ProblemLifecycleTests.Access("security.queue");
        var windowEnd = DateTimeOffset.UtcNow;
        foreach (long domain in new[] { 1L, 2L })
        {
            var homeRows = await home.ReadAsync(HomePeriodSql.Problems, new Dictionary<string, object?> {
                ["ids"] = new[] { domain }, ["from"] = windowEnd.AddHours(-1), ["to"] = windowEnd,
                ["identity"] = true, ["technical"] = true
            }, ct);
            var homeItems = (Assert.Single(homeRows)["items"] as JsonArray ?? []).OfType<JsonObject>().ToArray();
            var queueRows = await queue.FindingsAsync(new FindingQuery(null, null, null, null, null, null, null,
                [domain], 50, false) { Compact = true, PageQueue = true, GroupQueue = true }, access, ct);
            var queueItems = queueRows["items"]!.AsArray().OfType<JsonObject>().ToArray();
            Assert.Equal(domain == 1 ? 2 : 0, homeItems.Length);
            Assert.Equal(homeItems.Select(row => row.Number("id")).Order(), queueItems.Select(row => row.Number("id")).Order());
            foreach (var row in homeItems)
            {
                var queueItem = Assert.Single(queueItems, item => item.Number("id") == row.Number("id"));
                foreach (string lang in new[] { "ru", "en" })
                    Assert.Equal(HomePresentation.Finding(row, lang).Text("title"),
                        ProblemPresentation.Finding(queueItem, access, lang).Text("title_text"));
            }
        }
    }

    private static async Task CheckNotificationDelivery(SqlPostgresFixture fixture, NpgsqlConnection owner,
        SemanticProducerPostgresTests.Admission environment, CancellationToken ct)
    {
        await using var recipient = new NpgsqlCommand("select id from auth_users where username='platform-owner'", owner);
        long userId = (long)(await recipient.ExecuteScalarAsync(ct))!;
        string settings = Path.Combine(fixture.Pg.Root, "det06-telegram-config.json");
        string token = Path.Combine(fixture.Pg.Root, "det06-telegram-token");
        await File.WriteAllTextAsync(settings, new JsonObject {
            ["base_url"] = "https://sli.example.test",
            ["recipients"] = new JsonObject { [userId.ToString(System.Globalization.CultureInfo.InvariantCulture)] = "-401" }
        }.ToJsonString(), ct);
        await File.WriteAllTextAsync(token, "1:synthetic_test_only", ct);
        environment.Set("ADLOG_PG_DSN", fixture.Dsn("sli_notification_login"));
        environment.Set("ADLOG_PG_DSN_FILE", null);
        environment.Set("ADLOG_PG_PASSWORD", null);
        environment.Set("ADLOG_PG_PASSWORD_FILE", null);
        environment.Set("SLI_NOTIFICATION_TELEGRAM_CONFIG_FILE", settings);
        environment.Set("SLI_NOTIFICATION_TELEGRAM_TOKEN", null);
        environment.Set("SLI_NOTIFICATION_TELEGRAM_TOKEN_FILE", token);
        await PostCollectionPostgres.Sql(owner, "update notification_channels set enabled=true,next_delivery_at=now() where kind='telegram'", ct);
        await using var database = Assert.IsType<NotificationDatabase>(NotificationDatabase.TryCreate());
        await using (var connection = await database.OpenAsync(ct))
        await using (var tx = await connection.BeginTransactionAsync(ct))
        {
            await using var claim = new NpgsqlCommand(TelegramWorker.ClaimSql, connection, tx);
            claim.Parameters.AddWithValue("token", Guid.NewGuid());
            await using var row = await claim.ExecuteReaderAsync(ct);
            Assert.True(await row.ReadAsync(ct));
            var job = new NotificationJob(row.GetGuid(0), row.GetGuid(1), row.GetInt64(2), row.GetString(3),
                row.GetGuid(4), row.GetInt64(5), row.GetInt32(6), row.GetGuid(7), row.GetDateTime(8),
                row.GetString(9), row.GetString(10), row.GetInt32(11));
            await row.DisposeAsync();
            var denied = ProblemLifecycleTests.Access("security.queue", """{"mode":"restricted","clauses":[{"collection_scope_ids":["ad-domain:2"]}]}""");
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                NotificationAlert.FormatAsync(connection, tx, job, "https://sli.example.test", denied, null, ct));
            await tx.RollbackAsync(ct);
        }
        using var fake = new CaptureTelegram();
        var worker = new TelegramWorker(database, new TelegramSender(new FakeClientFactory(fake), new TelegramRequestState()));
        for (int i = 0; i < 2; i++)
        {
            Assert.True(await worker.ProcessAsync(ct));
            await PostCollectionPostgres.Sql(owner, "update notification_channels set next_delivery_at=now() where kind='telegram'", ct);
        }
        Assert.Equal(2, fake.Messages.Count);
        Assert.Contains(fake.Messages, message => message.Contains("новая служба", StringComparison.Ordinal));
        Assert.Contains(fake.Messages, message => message.Contains("новая задача", StringComparison.Ordinal));
        Assert.All(fake.Messages, message => Assert.StartsWith("Высокая", message));
        Assert.False(await worker.ProcessAsync(ct));
    }

    private static async Task CheckMigrationRoundTrip(SqlPostgresFixture fixture, NpgsqlConnection owner, CancellationToken ct)
    {
        string migration = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/401_dc_task_service_catalog.sql");
        await PostCollectionPostgres.Sql(owner, """
            update semantic_policy_admission set enabled=false,updated_by='synthetic:operator'
            where policy_id='l1-dc-scheduled-task-created' and policy_version=1;
            """, ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
        await using var predecessor = new NpgsqlCommand("""
            select max(version)=400 and to_regprocedure('public.read_dc_catalog_action401(text,integer,uuid)') is null
            from schema_migrations
            """, owner);
        Assert.Equal(true, await predecessor.ExecuteScalarAsync(ct));
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await using var preserved = new NpgsqlCommand("""
            select not enabled and updated_by='synthetic:operator' and
                (select count(*) from public.semantic_finding_publications)=2
            from semantic_policy_admission where policy_id='l1-dc-scheduled-task-created' and policy_version=1
            """, owner);
        Assert.Equal(true, await preserved.ExecuteScalarAsync(ct));
    }

    private sealed class TestReadConnection(string dsn) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        {
            var connection = new NpgsqlConnection(dsn);
            await connection.OpenAsync(ct);
            return connection;
        }
    }

    private sealed class FakeClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class CaptureTelegram : HttpMessageHandler
    {
        public List<string> Messages { get; } = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var message = JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct));
            Assert.Equal("-401", message!["chat_id"]!.GetValue<string>());
            Messages.Add(message["text"]!.GetValue<string>());
            return new HttpResponseMessage(HttpStatusCode.OK) {
                Content = new StringContent("{\"ok\":true,\"result\":{\"message_id\":401}}")
            };
        }
    }
}
