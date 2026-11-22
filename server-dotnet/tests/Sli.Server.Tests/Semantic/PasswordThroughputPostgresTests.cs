using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordThroughputPostgresTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Both_password_rules_drain_one_hour_of_dc_events_and_keep_live_coverage_current()
    {
        const int eventsPerHour = 8000;
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var start = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-1), TimeSpan.Zero);
        var clock = new TestClock(start.AddMinutes(2));
        await PostCollectionPostgres.Sql(owner, """
            create table public.password_test_clock(at timestamptz not null);
            insert into public.password_test_clock values (now());
            grant select on public.password_test_clock to adlog_storage_owner;
            do $$ declare fn regprocedure; begin
                foreach fn in array array['public.password_plan388(jsonb,text)'::regprocedure,
                       'public.password_event_clock362(jsonb,jsonb)'::regprocedure] loop
                    execute replace(replace(pg_get_functiondef(fn),'statement_timestamp()',
                        '(select at from public.password_test_clock)'), 'transaction_timestamp()',
                        '(select at from public.password_test_clock)');
                end loop;
            end $$;
            """, ct);
        int sequence = 0;
        var agent = ShortEventAdmissionPostgresTests.Agent;
        DateTimeOffset At(int index) => start.AddMilliseconds(index * 450L);
        async Task Ingest(int from, int until)
        {
            foreach (int[] packet in Enumerable.Range(from, until - from).Chunk(100)) {
                var rows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
                    eventKinds: packet.Select(i => i % 2 == 0 ? 4625 : 4776).ToArray(),
                    nativeTimestamps: packet.Select(i => PasswordJson.Stamp(At(i))).ToArray(),
                    nativeAccounts: packet.Select(i => $"synthetic-user-{(i / 2 % 4 == 0 ? 0 : i / 2 / 3 % 30)}").ToArray(),
                    nativeAddresses: packet.Select(i => i % 2 == 1 ? "-" : $"192.0.2.{(i / 2 % 4 < 2 ? 1 : 2 + i / 2 % 39)}").ToArray(),
                    registered: sequence == 0 ? null : (agent, agent, 900001, 1), packetId: Guid.NewGuid(),
                    sequence: ++sequence, firstRecordId: packet[0] + 1);
                await ShortEventAdmissionPostgresTests.WriteAsync(fixture, rows, ct);
            }
        }
        async Task SetClock(DateTimeOffset at)
        {
            clock.At = at;
            await using var move = new NpgsqlCommand("update public.password_test_clock set at=@at", owner);
            move.Parameters.AddWithValue("at", at);
            await move.ExecuteNonQueryAsync(ct);
        }

        await Ingest(0, 2);
        await SetClock(clock.At);
        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        PasswordScope scope;
        await using (var worker = await runtime.OpenAsync(ct)) {
            await using var source = new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'", worker);
            scope = PasswordScope.Read(JsonNode.Parse((string)(await source.ExecuteScalarAsync(ct))!)!["scope"]);
        }
        await using (var app = new NpgsqlConnection(fixture.Dsn("adlog_user"))) {
            await app.OpenAsync(ct);
            await using var bind = new NpgsqlCommand("select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')->>'status'", app);
            bind.Parameters.AddWithValue("agent", agent);
            Assert.Equal("configured", await bind.ExecuteScalarAsync(ct));
        }
        var poller = new PasswordProducerPoller(runtime, new(), new(new(), new())) { Clock = clock };
        async Task<IReadOnlyList<PasswordProducerOutcome>> RunWorker()
        {
            var results = await poller.RunSourceAsync(scope, ct);
            Assert.NotEmpty(results);
            Assert.All(results, result => Assert.True(result.Status == "committed", result.Diagnostic?.ToJsonString() ?? result.Status));
            return results;
        }
        async Task<Dictionary<string, DateTimeOffset>> ReadWatermarks()
        {
            await using var checkpoint = new NpgsqlCommand("""
                select p.rule_id,c.watermark from public.password_pass_state393 p
                join public.semantic_password_checkpoints c on c.scope_digest=p.scope_digest and c.pin=p.live_pin
                """, owner);
            await using var rows = await checkpoint.ExecuteReaderAsync(ct);
            var watermarks = new Dictionary<string, DateTimeOffset>();
            while (await rows.ReadAsync(ct)) watermarks.Add(rows.GetString(0), rows.GetFieldValue<DateTimeOffset>(1));
            Assert.Equal(new[] { "qw.password-brute-force", "qw.password-spray" }, watermarks.Keys.Order());
            return watermarks;
        }

        await RunWorker();
        await Ingest(2, eventsPerHour);
        await PostCollectionPostgres.Sql(owner, "analyze event_hot", ct);
        await using (var volumes = new NpgsqlCommand("""
            select count(*) filter (where event_kind=4625),count(*) filter (where event_kind=4776),
                   count(distinct method#>>'{$principals,IpAddress}') filter (where event_kind=4625),
                   count(distinct method#>>'{$principals,TargetUserName}'),count(distinct domain_id),count(distinct computer)
            from public.event_hot where source_sha256 is not null
            """, owner)) {
            await using var rows = await volumes.ExecuteReaderAsync(ct);
            Assert.True(await rows.ReadAsync(ct));
            Assert.Equal(new long[] { 4000, 4000, 40, 30, 1, 1 }, Enumerable.Range(0, 6).Select(rows.GetInt64));
        }

        DateTimeOffset newest = At(eventsPerHour - 1);
        // All backlog events have passed the unchanged 120-second holdback.
        await SetClock(newest.AddMinutes(2));
        var watch = Stopwatch.StartNew();
        var drained = await RunWorker();
        watch.Stop();
        var caughtUp = await ReadWatermarks();
        Assert.All(caughtUp.Values, watermark => Assert.Equal(newest, watermark));
        Assert.Contains(drained, result => result.Jobs > 0);
        output.WriteLine($"Backlog {watch.Elapsed.TotalSeconds:F2}s, {eventsPerHour / watch.Elapsed.TotalMinutes:F0} events/minute for both rules");
        Assert.True(watch.Elapsed < TimeSpan.FromMinutes(6), $"Backlog took {watch.Elapsed}");

        const int liveEnd = eventsPerHour + 400;
        await Ingest(eventsPerHour, liveEnd);
        await SetClock(At(liveEnd));
        watch.Restart();
        await RunWorker();
        watch.Stop();
        foreach (var (rule, watermark) in await ReadWatermarks()) {
            var lag = At(liveEnd - 1) - watermark;
            output.WriteLine($"{rule} live watermark lag {lag.TotalSeconds:F2}s after {watch.Elapsed.TotalSeconds:F2}s");
            Assert.True(watermark > caughtUp[rule]);
            Assert.InRange(lag, TimeSpan.Zero, TimeSpan.FromMinutes(2));
        }
    }

    private sealed class TestClock(DateTimeOffset at) : TimeProvider
    {
        internal DateTimeOffset At { get; set; } = at;
        public override DateTimeOffset GetUtcNow() => At;
    }
}
