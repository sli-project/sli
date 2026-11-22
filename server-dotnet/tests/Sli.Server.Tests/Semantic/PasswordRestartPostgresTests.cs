using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic.Risk;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordRestartPostgresTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Restarts_during_a_continuous_password_attack_preserve_progress(bool upgrade)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 392);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var clock = new TestClock(new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-1), TimeSpan.Zero));
        string migration = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/393_password_pass_recovery.sql");
        await PostCollectionPostgres.Sql(owner, """
            create table public.password_test_clock(at timestamptz not null, statement_drift boolean not null);
            insert into public.password_test_clock values (now(),false);
            grant select on public.password_test_clock to adlog_storage_owner;
            create function public.password_test_statement_clock() returns timestamptz
            language sql stable as $$
                select at + case when statement_drift and current_query() like '%complete_password_producer_batch_v2(%'
                            then interval '3 seconds' else interval '0 seconds' end
                from public.password_test_clock
            $$;
            """, ct);
        const string injectClock = """
            do $$ declare fn regprocedure; begin
                foreach fn in array array['public.password_plan388(jsonb,text)'::regprocedure,
                      'public.password_event_clock362(jsonb,jsonb)'::regprocedure] loop
                    execute replace(replace(pg_get_functiondef(fn),'statement_timestamp()',
                        'public.password_test_statement_clock()'), 'transaction_timestamp()',
                        '(select at from public.password_test_clock)');
                end loop;
            end $$;
            """;
        await using var definitions = new NpgsqlCommand("""
            select string_agg(pg_get_functiondef(fn),';') from unnest(array[
                'public.password_plan388(jsonb,text)'::regprocedure,
                'public.password_event_clock362(jsonb,jsonb)'::regprocedure]) fn
            """, owner);
        var original = (string)(await definitions.ExecuteScalarAsync(ct))!;
        if (!upgrade) {
            await fixture.Pg.ApplyFileAsync(migration, null, ct);
            await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
            await fixture.Pg.ApplyFileAsync(migration, null, ct);
        }
        await PostCollectionPostgres.Sql(owner, injectClock, ct);
        var start = clock.GetUtcNow();
        var agent = ShortEventAdmissionPostgresTests.Agent;
        int record = 0;
        int sequence = 0;
        async Task SetClock(DateTimeOffset at)
        {
            clock.At = at;
            await using var advance = new NpgsqlCommand("update public.password_test_clock set at=@at", owner);
            advance.Parameters.AddWithValue("at", at);
            await advance.ExecuteNonQueryAsync(ct);
        }
        static bool PrimaryAddress(int record) => record % 5 < 2 || record % 25 == 2;
        static string Account(int record) => record % 5 == 0 ? "synthetic-brute" :
            PrimaryAddress(record) ? $"synthetic-spray-{(record / 25 * 6 + (record % 25 == 2 ? 5 : record % 25 / 5)) % 441}" :
            $"synthetic-noise-{record % 58}";
        async Task Ingest(int minutes)
        {
            int count = minutes * 50;
            var events = Enumerable.Range(record, count).ToArray();
            var rows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
                eventKinds: events.Select(i => i % 5 == 4 ? 4776 : 4625).ToArray(),
                nativeTimestamps: events.Select(i => PasswordJson.Stamp(start.AddMilliseconds(i * 1200L))).ToArray(),
                nativeAccounts: events.Select(Account).ToArray(),
                nativeAddresses: events.Select(i => PrimaryAddress(i) ? "192.0.2.1" : $"192.0.2.{2 + i % 29}").ToArray(),
                registered: sequence == 0 ? null : (agent, agent, 900001, 1), packetId: Guid.NewGuid(),
                sequence: ++sequence, firstRecordId: record + 1);
            await ShortEventAdmissionPostgresTests.WriteAsync(fixture, rows, ct);
            record += count;
            await SetClock(start.AddMilliseconds(record * 1200L));
        }
        await Ingest(4);
        bool configured = false;
        async Task<JsonObject> RunWorker(bool expectHealthy)
        {
            await using var runtime = PasswordProducerRuntime.Create(
                name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
                _ => throw new InvalidOperationException());
            await using var worker = await runtime.OpenAsync(ct);
            await using var source = new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'", worker);
            var scope = PasswordScope.Read(JsonNode.Parse((string)(await source.ExecuteScalarAsync(ct))!)!["scope"]);
            if (!configured) {
                await using var app = new NpgsqlConnection(fixture.Dsn("adlog_user"));
                await app.OpenAsync(ct);
                await using var bind = new NpgsqlCommand("select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')->>'status'", app);
                bind.Parameters.AddWithValue("agent", agent);
                Assert.Equal("configured", await bind.ExecuteScalarAsync(ct));
                configured = true;
            }
            var poller = new PasswordProducerPoller(runtime, new(), new(new(), new())) { Clock = clock };
            var results = await poller.RunSourceAsync(scope, ct);
            foreach (var result in results.Where(r => r.Failed)) output.WriteLine(result.Diagnostic?.ToJsonString() ?? result.Status);
            if (expectHealthy) {
                Assert.NotEmpty(results);
                Assert.All(results, result => Assert.True(result.Status == "committed", result.Diagnostic?.ToJsonString() ?? result.Status));
            }
            var consumer = new PasswordRiskConsumer(runtime, new());
            PasswordRiskBatch batch;
            do {
                batch = await consumer.RunOnceAsync(ct);
                Assert.Equal(0, batch.Failed);
            } while (batch.Claimed != 0);
            await using var report = new NpgsqlCommand("""
                select jsonb_build_object('passes',(select count(*) from public.password_passes388),
                    'catchup',public.password_catchup_status388(),
                    'health',(select jsonb_agg(health_status order by health_status) from public.semantic_password_checkpoints),
                    'source_errors',(select count(*) from public.semantic_password_checkpoints where health_reason='source_error'),
                    'lag_seconds',(select jsonb_object_agg(rule_code,lag) from (
                        select rule_code,extract(epoch from (@latest-max(last_seen_utc::timestamptz))) lag
                        from public.findings where rule_code in ('semantic.qw.password-brute-force','semantic.qw.password-spray')
                        group by rule_code) f))::text
                """, owner);
            report.Parameters.AddWithValue("latest", start.AddMilliseconds((record - 1) * 1200L));
            string json = (string)(await report.ExecuteScalarAsync(ct))!;
            output.WriteLine(json);
            return JsonNode.Parse(json)!.AsObject();
        }
        static void AssertCurrent(JsonObject report, int passes, double maxLagSeconds)
        {
            Assert.Equal(passes, report["passes"]!.GetValue<int>());
            Assert.Null(report["catchup"]);
            var lag = Assert.IsType<JsonObject>(report["lag_seconds"]);
            Assert.InRange(lag["semantic.qw.password-brute-force"]!.GetValue<double>(), 0, maxLagSeconds);
            Assert.InRange(lag["semantic.qw.password-spray"]!.GetValue<double>(), 0, maxLagSeconds);
        }

        var last = await RunWorker(true);
        // A new event becomes finalizable between the reader and completion,
        // just as it can when a live batch takes longer than the event spacing.
        await PostCollectionPostgres.Sql(owner, "update public.password_test_clock set statement_drift=true", ct);
        for (int restart = 0; restart < 3; restart++) {
            await Ingest(13);
            last = await RunWorker(!upgrade);
            if (!upgrade) AssertCurrent(last, 0, 130);
        }
        if (upgrade) {
            int oldPasses = last["passes"]!.GetValue<int>();
            Assert.Equal(6, oldPasses);
            Assert.NotNull(last["catchup"]);
            Assert.Equal(6, last["source_errors"]!.GetValue<int>());
            Assert.True(last["lag_seconds"]!["semantic.qw.password-brute-force"]!.GetValue<double>() > 1800);
            await using var findings = new NpgsqlCommand("select array_agg(id order by id) from public.findings", owner);
            var existing = Assert.IsType<long[]>(await findings.ExecuteScalarAsync(ct));
            await PostCollectionPostgres.Sql(owner, original, ct);
            await fixture.Pg.ApplyFileAsync(migration, null, ct);
            await using var pending = new NpgsqlCommand("select history_to from public.password_pass_state393 where history_pin is not null", owner);
            await using (var history = await pending.ExecuteReaderAsync(ct)) {
                int count = 0;
                while (await history.ReadAsync(ct)) count++;
                Assert.InRange(count, 1, 2);
            }
            string migrations = Path.GetDirectoryName(migration)!;
            string throughput = Path.Combine(migrations, "396_password_worker_throughput.sql");
            await fixture.Pg.ApplyFileAsync(Path.Combine(migrations, "394_notification_language.sql"), null, ct);
            await using var catchup = new NpgsqlCommand("select public.password_catchup_status388()::text", owner);
            var recovered = Assert.IsType<string>(await catchup.ExecuteScalarAsync(ct));
            await using var policyStates = new NpgsqlCommand("""
                select coalesce(jsonb_object_agg(p.policy_id,p.lifecycle_status),'{}')::text
                from public.semantic_risk_policies p where p.policy_id in (
                    select 'default:'||r.rule_id||':'||substr(r.history_pin,1,32)
                    from public.password_pass_state393 r where r.history_pin is not null)
                """, owner);
            var beforeRetirement = await policyStates.ExecuteScalarAsync(ct);
            await fixture.Pg.ApplyFileAsync(throughput, null, ct);
            Assert.Equal(DBNull.Value, await catchup.ExecuteScalarAsync(ct));
            Assert.Equal(existing, Assert.IsType<long[]>(await findings.ExecuteScalarAsync(ct)));
            // Poll the upgraded planner before rollback so managed policy
            // retirement exercises the same path as a deployed worker.
            await using (var runtime = PasswordProducerRuntime.Create(
                name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
                _ => throw new InvalidOperationException()))
            await using (var worker = await runtime.OpenAsync(ct))
            await using (var plan = new NpgsqlCommand("""
                select public.password_plan388(source->'scope',@rule)::text from public.default_detection_sources()
                where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'
                """, worker)) {
                plan.Parameters.AddWithValue("rule", "qw.password-brute-force");
                foreach (var rule in new[] { "qw.password-brute-force", "qw.password-spray" }) {
                    plan.Parameters["rule"].Value = rule;
                    var result = JsonNode.Parse(Assert.IsType<string>(await plan.ExecuteScalarAsync(ct)))!;
                    Assert.Empty(result["catchup"]!.AsArray());
                }
            }
            await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(throughput, ".rollback.sql"), null, ct);
            Assert.Equal(recovered, await catchup.ExecuteScalarAsync(ct));
            Assert.Equal(beforeRetirement, await policyStates.ExecuteScalarAsync(ct));
            await PostCollectionPostgres.Sql(owner, injectClock, ct);
            while (last["catchup"] is { } previous) {
                last = await RunWorker(true);
                if (last["catchup"] is { } current)
                    Assert.True(PasswordJson.Time(current["cursor"]) > PasswordJson.Time(previous["cursor"]));
            }
            AssertCurrent(await RunWorker(true), oldPasses, 130);
            var after = Assert.IsType<long[]>(await findings.ExecuteScalarAsync(ct));
            Assert.All(existing, id => Assert.Contains(id, after));
            await using var policies = new NpgsqlCommand("""
                select count(*) from public.semantic_risk_policies
                where policy_id like 'default:qw.password-%' and lifecycle_status in ('enabled','shadow')
                """, owner);
            Assert.Equal(2L, await policies.ExecuteScalarAsync(ct));
            await using var activeHealth = new NpgsqlCommand("""
                select array_agg(c.health_status order by p.rule_id)
                from public.password_pass_state393 p join public.semantic_password_checkpoints c
                  on c.scope_digest=p.scope_digest and c.pin=p.live_pin
                where p.history_pin is null
                """, owner);
            Assert.Equal(new[] { "healthy", "healthy" }, Assert.IsType<string[]>(await activeHealth.ExecuteScalarAsync(ct)));
        } else {
            Assert.All(last["health"]!.AsArray(), health => Assert.Equal("healthy", health!.GetValue<string>()));
            // The rule deployment requests a new definition once. The following
            // restart retains its live execution while finishing the old range.
            await PostCollectionPostgres.Sql(owner, """
                create or replace function public.password_definition_revision393(r text) returns integer
                language sql immutable set search_path=pg_catalog,pg_temp as $$
                    select case when r='qw.password-brute-force' then 3 else 2 end
                $$;
                """, ct);
            await Ingest(13);
            await RunWorker(true);
            AssertCurrent(await RunWorker(true), 1, 130);
            await SetClock(clock.At.AddMinutes(2));
            var complete = await RunWorker(true);
            AssertCurrent(complete, 1, 5);
            Assert.All(complete["health"]!.AsArray(), health => Assert.Equal("healthy", health!.GetValue<string>()));
        }
    }

    private sealed class TestClock(DateTimeOffset at) : TimeProvider
    {
        internal DateTimeOffset At { get; set; } = at;
        public override DateTimeOffset GetUtcNow() => At;
    }
}
