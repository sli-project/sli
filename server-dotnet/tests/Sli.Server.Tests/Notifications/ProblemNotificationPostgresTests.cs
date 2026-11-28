using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;
using Sli.Server.Notifications;
using Sli.Server.Problems;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic.Risk;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Problems;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Notifications;

public sealed class ProblemNotificationPostgresTests(ITestOutputHelper output)
{
    private const string Migration = "config/postgres_migrations/423_problem_notification_transitions.sql";

    [Fact]
    public async Task Database_at_migration_422_accepts_423()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 422);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        // While 422 is still on a separate PR, supply its ledger entry to exercise ordering.
        await PostCollectionPostgres.Sql(owner, """
            insert into public.schema_migrations(version,name) values(422,'file_audit_scope_inventory')
            on conflict (version) do nothing
            """, ct);
        await using var latest = new NpgsqlCommand("select max(version) from public.schema_migrations", owner);
        Assert.Equal(422, await latest.ExecuteScalarAsync(ct));

        await fixture.Pg.ApplyFileAsync(Path.Combine(PostCollectionPostgres.Repository(), Migration), null, ct);

        Assert.Equal(423, await latest.ExecuteScalarAsync(ct));
    }

    [Fact]
    public async Task Problem_transitions_queue_once_and_the_journal_names_the_problem()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 420);
        var migration = Path.Combine(PostCollectionPostgres.Repository(), Migration);
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(owner, """
            insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled)
            select gen_random_uuid(),1,1,channel,true from (values('smtp'),('telegram')) channels(channel)
            """, ct);

        var at = DateTimeOffset.UtcNow.AddMinutes(-3);
        int record = 0, sequence = 0;
        var agent = ShortEventAdmissionPostgresTests.Agent;
        async Task Ingest(params int[] events)
        {
            var rows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, eventKinds: events,
                nativeTimestamps: events.Select((_, i) => PasswordJson.Stamp(at.AddMilliseconds(200 * (record + i)))).ToArray(),
                registered: sequence == 0 ? null : (agent, agent, 900001, 1), packetId: Guid.NewGuid(),
                sequence: ++sequence, firstRecordId: record + 1);
            await ShortEventAdmissionPostgresTests.WriteAsync(fixture, rows, ct);
            record += events.Length;
        }

        await Ingest(Enumerable.Repeat(4625, 12).ToArray());
        var app = new Factory(fixture);
        bool configured = false;
        async Task Publish()
        {
            await using var runtime = PasswordProducerRuntime.Create(
                name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
                _ => throw new InvalidOperationException());
            await using var worker = await runtime.OpenAsync(ct);
            await using var source = new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'", worker);
            var scope = PasswordScope.Read(JsonNode.Parse((string)(await source.ExecuteScalarAsync(ct))!)!["scope"]);
            if (!configured)
            {
                await using var db = await app.OpenAsync(ct);
                await using var bind = new NpgsqlCommand("select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')->>'status'", db);
                bind.Parameters.AddWithValue("agent", agent);
                Assert.Equal("configured", await bind.ExecuteScalarAsync(ct));
                configured = true;
            }
            await using var plan = new NpgsqlCommand("select (public.password_plan388(@scope::jsonb,'qw.password-brute-force')#>>'{live,rule_version}')::integer", worker);
            plan.Parameters.AddWithValue("scope", scope.Document.ToJsonString());
            int revision = Assert.IsType<int>(await plan.ExecuteScalarAsync(ct));
            var result = await new PasswordProducer().RunAsync(worker, new PasswordRule(scope, revision: revision), ct);
            Assert.False(result.Failed, result.Diagnostic?.ToJsonString());
            var consumer = new PasswordRiskConsumer(runtime, new());
            while (true)
            {
                var batch = await consumer.RunOnceAsync(ct);
                if (batch.Failed > 0)
                {
                    await using var errors = new NpgsqlCommand("select string_agg(coalesce(last_error_code,'')||':'||coalesce(last_error_detail,''),'; ') from semantic_risk_evaluation_jobs", owner);
                    output.WriteLine(Convert.ToString(await errors.ExecuteScalarAsync(ct)) ?? "");
                }
                Assert.Equal(0, batch.Failed);
                if (batch.Claimed == 0) break;
            }
        }

        async Task AssertDeliveries(params string[] expected)
        {
            await using var read = new NpgsqlCommand("""
                select array_agg(j.object_severity order by j.created_at,j.id)
                from notification_outbox j join semantic_finding_publications p on p.scenario_id=j.object_id
                join findings f on f.id=p.finding_id where f.rule_code='semantic.qw.password-brute-force'
                group by j.channel order by j.channel
                """, owner);
            await using var results = await read.ExecuteReaderAsync(ct);
            foreach (string _ in new[] { "smtp", "telegram" })
            {
                Assert.True(await results.ReadAsync(ct));
                Assert.Equal(expected, results.GetFieldValue<string[]>(0));
            }
            Assert.False(await results.ReadAsync(ct));
        }

        await Publish();
        await AssertDeliveries("medium");
        await Ingest(Enumerable.Repeat(4625, 100).ToArray());
        await Publish();
        await AssertDeliveries("medium");
        await using (var confirmed = new NpgsqlCommand("select evidence_count from findings where rule_code='semantic.qw.password-brute-force'", owner))
            Assert.Equal(112L, await confirmed.ExecuteScalarAsync(ct));
        await Ingest(4624, 4625);
        await Publish();
        await using (var escalated = new NpgsqlCommand("""
            select f.severity, f.evidence_count,
                (select string_agg(s.document_json->>'effective_severity', ',' order by s.created_at)
                    from semantic_qw_signals s where s.document_json->>'rule_id'='qw.password-brute-force'),
                (select count(*) from event_hot where event_kind=4624)
            from findings f where f.rule_code='semantic.qw.password-brute-force'
            """, owner))
        await using (var found = await escalated.ExecuteReaderAsync(ct))
        {
            Assert.True(await found.ReadAsync(ct));
            Assert.True(found.GetString(0) == "critical", $"Finding severity {found.GetString(0)}, evidence {found.GetInt64(1)}, signals {found.GetString(2)}, stored successful logons {found.GetInt64(3)}");
        }
        await AssertDeliveries("medium", "critical");
        await Publish();
        await AssertDeliveries("medium", "critical");

        await using var id = new NpgsqlCommand("select id from findings where rule_code='semantic.qw.password-brute-force'", owner);
        long finding = Assert.IsType<long>(await id.ExecuteScalarAsync(ct));
        var access = ProblemLifecycleTests.Access("security.queue", fields: ["security", "identity_basic", "technical"]);
        var principal = new Principal("session", 1, "admin", "platform-owner");
        var problems = new ProblemRepository(app, TimeProvider.System);
        await problems.QueueDecisionAsync(new([finding], "closed", null, false, null, "fixed", null), access, principal, ct);
        await problems.QueueDecisionAsync(new([finding], "new", null, false, null, null, null), access, principal, ct);
        await AssertDeliveries("medium", "critical", "critical");

        var journal = new NotificationAdministrationRepository(app, new NotificationRecipientsStub());
        var workspace = new NotificationWorkspaceQuery(7, "smtp", null, finding, null, null);
        var row = (await journal.WorkspaceAsync(principal, workspace, access, true, "en", ct))["items"]![0]!;
        Assert.Equal(finding, row["finding_id"]!.GetValue<long>());
        string title = row["problem_title"]!.GetValue<string>();
        Assert.Contains("Critical", title);
        Assert.Contains("synthetic-user", title);
        Assert.Contains("192.0.2.1", title);
        var restricted = ProblemLifecycleTests.Access("security.queue", fields: ["security"]);
        var redacted = (await journal.WorkspaceAsync(principal, workspace, restricted, true, "en", ct))["items"]![0]!["problem_title"]!.GetValue<string>();
        Assert.DoesNotContain("synthetic-user", redacted);
        Assert.DoesNotContain("192.0.2.1", redacted);

        var grouped = (await journal.WorkspaceAsync(principal, workspace with { Collapse = true }, access, true, "en", ct))["items"]!;
        Assert.Equal(new long[] { 2, 1 }, grouped.AsArray().Select(item => item!["occurrence_count"]!.GetValue<long>()));
        Assert.NotEqual(grouped[0]!["created_at"]!.GetValue<string>(), grouped[0]!["first_at"]!.GetValue<string>());
        var groupId = Guid.Parse(grouped[0]!["id"]!.GetValue<string>());
        var originals = (await journal.WorkspaceAsync(principal, workspace with { GroupId = groupId }, access, true, "en", ct))["items"]!.AsArray();
        Assert.Equal(2, originals.Count);
        Assert.All(originals, item => Assert.Equal("critical", item!["object_severity"]!.GetValue<string>()));

        await PostCollectionPostgres.Sql(owner, """
            update notification_outbox set state='accepted',result_code='accepted';
            update notification_outbox set state='sending',result_code=null,attempts=1,
                lease_token=gen_random_uuid(),lease_until=clock_timestamp()-interval '1 second'
            where id in (select distinct on (channel) id from notification_outbox order by channel,created_at,id)
            """, ct);
        await using var delivery = new NotificationDatabase(fixture.Dsn("sli_notification_login"));
        var transport = new UnusedTransport();
        var smtp = new SmtpWorker(delivery, new(transport), NullLogger<SmtpWorker>.Instance);
        var telegram = new TelegramWorker(delivery, new(transport, new()));
        Assert.True(await smtp.ProcessAsync(ct));
        Assert.True(await telegram.ProcessAsync(ct));
        Assert.False(await smtp.ProcessAsync(ct));
        Assert.False(await telegram.ProcessAsync(ct));
        Assert.Equal(0, transport.Attempts);
        await using var uncertain = new NpgsqlCommand("select count(*) from notification_outbox where state='delivery_unknown'", owner);
        Assert.Equal(2L, await uncertain.ExecuteScalarAsync(ct));

        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
        await AssertDeliveries("medium", "critical", "critical");
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await AssertDeliveries("medium", "critical", "critical");
    }

    private sealed class Factory(SqlPostgresFixture fixture) : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => fixture.Pg.OpenAsync(ct, "adlog_user");
    }

    private sealed class UnusedTransport : IHttpClientFactory, ISmtpSessionFactory
    {
        internal int Attempts { get; private set; }
        public HttpClient CreateClient(string name) => throw UnexpectedSend();
        public ISmtpSession Create(Action progress) => throw UnexpectedSend();
        private InvalidOperationException UnexpectedSend()
        {
            Attempts++;
            return new InvalidOperationException("Unexpected transport call for an expired lease");
        }
    }
}
