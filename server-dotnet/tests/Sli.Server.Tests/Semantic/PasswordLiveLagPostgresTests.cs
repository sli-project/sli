using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic.Risk;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class PasswordLiveLagPostgresTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Eligible_password_findings_keep_up_while_history_and_late_events_are_reported()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await using var cacheGate = await fixture.Pg.OpenAsync(ct);
        var start = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(-1).AddHours(18), TimeSpan.Zero);
        var clock = new TestClock(start);
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

            create table public.password_test_stages(stage text, identity text, at timestamptz, watermark timestamptz);
            create function public.password_test_stamp() returns trigger language plpgsql
            security definer set search_path=pg_catalog,pg_temp as $$
            begin
                insert into public.password_test_stages
                values(tg_argv[0],to_jsonb(new)->>tg_argv[1],clock_timestamp(),(to_jsonb(new)->>'watermark')::timestamptz);
                return new;
            end $$;
            create trigger password_test_watermark after update on public.semantic_password_checkpoints
                for each row when (old.watermark is distinct from new.watermark)
                execute function public.password_test_stamp('checkpoint','pin');
            create trigger password_test_signal after insert on public.semantic_qw_signals
                for each row execute function public.password_test_stamp('detection','signal_id');
            create trigger password_test_aggregation after insert on public.semantic_risk_evaluation_results
                for each row execute function public.password_test_stamp('aggregation','job_id');
            create trigger password_test_publication after insert on public.semantic_finding_publications
                for each row execute function public.password_test_stamp('publication','first_job_id');
            """, ct);

        int sequence = 0, recordId = 1;
        var agent = ShortEventAdmissionPostgresTests.Agent;
        var accountIds = new Dictionary<string, int>(StringComparer.Ordinal);
        async Task Admit(IEnumerable<(DateTimeOffset At, string Account, string Address)> events)
        {
            foreach (var packet in events.Chunk(100))
            {
                var rows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
                    eventKinds: packet.Select(_ => 4625).ToArray(),
                    nativeTimestamps: packet.Select(e => PasswordJson.Stamp(e.At)).ToArray(),
                    nativeAccounts: packet.Select(e => e.Account).ToArray(),
                    nativeAddresses: packet.Select(e => e.Address).ToArray(),
                    nativeTargetSids: packet.Select(e =>
                    {
                        accountIds.TryAdd(e.Account, 1001 + accountIds.Count);
                        return $"S-1-5-21-100000001-200000002-300000003-{accountIds[e.Account]}";
                    }).ToArray(),
                    registered: sequence == 0 ? null : (agent, agent, 900001, 1), packetId: Guid.NewGuid(),
                    sequence: ++sequence, firstRecordId: recordId);
                await ShortEventAdmissionPostgresTests.WriteAsync(fixture, rows, ct);
                recordId += packet.Length;
            }
        }
        async Task SetClock(DateTimeOffset at)
        {
            clock.At = at;
            await using var move = new NpgsqlCommand("update public.password_test_clock set at=@at", owner);
            move.Parameters.AddWithValue("at", at);
            await move.ExecuteNonQueryAsync(ct);
        }
        async Task<long> Count(string sql)
        {
            await using var command = new NpgsqlCommand(sql, owner);
            return (long)(await command.ExecuteScalarAsync(ct))!;
        }
        await SetClock(start);
        await Admit(Enumerable.Range(0, 18)
            .Select(i => (start.AddHours(-14).AddMinutes(40 * i), $"historical-{i}", "192.0.2.1")));
        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        PasswordScope scope;
        await using (var worker = await runtime.OpenAsync(ct))
        {
            await using var source = new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'", worker);
            scope = PasswordScope.Read(JsonNode.Parse((string)(await source.ExecuteScalarAsync(ct))!)!["scope"]);
        }
        await using (var app = new NpgsqlConnection(fixture.Dsn("adlog_user")))
        {
            await app.OpenAsync(ct);
            await using var bind = new NpgsqlCommand("select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')->>'status'", app);
            bind.Parameters.AddWithValue("agent", agent);
            Assert.Equal("configured", await bind.ExecuteScalarAsync(ct));
        }
        var poller = new PasswordProducerPoller(runtime, new(), new(new(), new())) { Clock = clock };
        async Task<IReadOnlyList<PasswordProducerOutcome>> Detect()
        {
            var outcomes = await poller.RunSourceAsync(scope, ct);
            Assert.NotEmpty(outcomes);
            Assert.All(outcomes, r => Assert.True(r.Status == "committed", r.Diagnostic?.ToJsonString() ?? r.Status));
            return outcomes;
        }
        await Detect();

        const string historyAdvanced = """
            select count(*) from public.password_test_stages t
            join public.password_pass_state393 p on p.history_pin=t.identity
            where t.stage='checkpoint'
            """;
        const int holdbackPolls = 4, measuredPolls = 4;
        var scheduled = new List<(DateTimeOffset At, string Account, string Address)[]>();
        var arriving = Enumerable.Range(0, holdbackPolls + measuredPolls).Select(cycle =>
        {
            var baseTime = start.AddSeconds(30 * cycle);
            var packet = Enumerable.Range(0, 25).Select(i => (
                At: baseTime.AddMilliseconds(i * 1185),
                Account: i < 10 ? $"brute-{cycle}" : $"test-{cycle}-{i}",
                Address: i < 10 ? $"192.0.2.{20 + cycle}" : i < 15 ? $"192.0.2.{30 + cycle}" : $"198.51.100.{20 * cycle + i}")).ToArray();
            if (cycle == 1)
            {
                packet[9] = (packet[9].At, $"test-{cycle}-9", "192.0.2.41");
                packet[14] = (packet[14].At, packet[14].Account, "192.0.2.42");
            }
            return packet;
        });
        foreach (var packet in arriving)
        {
            int cycle = scheduled.Count;
            scheduled.Add(packet);
            var source = Stopwatch.StartNew();
            await Admit(packet);
            var pollAt = packet[^1].At.AddSeconds(2);
            output.WriteLine($"cycle={cycle} newest_arrival_delay=2s admitted={packet.Length} admission_wall={source.Elapsed.TotalSeconds:F3}s");
            await SetClock(pollAt);
            var before = await Count(historyAdvanced);
            var run = Stopwatch.StartNew();
            await using var stamp = new NpgsqlCommand("select clock_timestamp()", owner);
            var pollStarted = (DateTime)(await stamp.ExecuteScalarAsync(ct))!;
            var outcomes = await Detect();
            Assert.True(await Count(historyAdvanced) > before);
            int ready = cycle - holdbackPolls;
            bool qualifies = ready >= 0 && ready != 1;
            Assert.Equal(qualifies ? 2 : 0, outcomes.Sum(r => r.Jobs));
            if (ready < 0) continue;
            var events = scheduled[ready];
            // A one-job production batch crosses a poll boundary between the two rules.
            // Recreate the consumer as the production coordinator does.
            int published = 0, failures = 0, polls = 0;
            bool drained = false;
            var pollDelay = TimeSpan.Zero;
            await using var cacheLock = cycle == holdbackPolls ? await cacheGate.BeginTransactionAsync(ct) : null;
            using var publishDeadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            if (cacheLock is not null)
            {
                await PostCollectionPostgres.Sql(cacheGate, "lock table public.password_queue_projection399 in access exclusive mode", ct);
                publishDeadline.CancelAfter(TimeSpan.FromSeconds(30));
            }
            Assert.Equal(0, await SemanticProduction.RunCyclesAsync(new(Limit: 1), async token =>
            {
                polls++;
                var risk = await new PasswordRiskConsumer(runtime, new(MaxJobs: 1)).RunOnceAsync(token);
                failures += risk.Failed;
                published += risk.Published;
                drained = risk.Claimed == 0;
                return new JsonObject
                {
                    ["status"] = "ok",
                    ["password_risk"] = new JsonObject { ["claimed"] = risk.Claimed, ["published"] = risk.Published }
                };
            }, (_, _) => Task.CompletedTask, () => drained || polls >= 4, (delay, _) =>
            {
                pollDelay += delay;
                return Task.CompletedTask;
            }, publishDeadline.Token));
            Assert.True(drained);
            Assert.Equal(0, failures);
            Assert.Equal(qualifies ? 2 : 0, published);
            if (cacheLock is not null)
            {
                Assert.Equal(2L, await Count("select count(*) from public.semantic_finding_publications"));
                await cacheLock.RollbackAsync(ct);
            }
            output.WriteLine($"cycle={cycle} password publication poll delay={pollDelay.TotalSeconds:F0}s");
            Assert.Equal(TimeSpan.Zero, pollDelay);
            await using var stages = new NpgsqlCommand("""
                select p.rule_id,c.watermark,t.at,d.at,a.at,f.at
                from public.password_pass_state393 p
                join public.semantic_password_checkpoints c on c.pin=p.live_pin and c.scope_digest=p.scope_digest
                left join public.semantic_qw_signals s on s.document_json->>'rule_id'=p.rule_id
                  and (s.document_json->>'occurred_at_utc')::timestamptz between @first and @last
                left join lateral(select min(at) at from public.password_test_stages t
                    where stage='checkpoint' and identity=p.live_pin
                    and t.watermark >= (s.document_json->>'occurred_at_utc')::timestamptz) t on true
                left join public.semantic_risk_evaluation_jobs j on j.qw_signal_id=s.signal_id
                left join public.password_test_stages d on d.stage='detection' and d.identity=s.signal_id
                left join public.password_test_stages a on a.stage='aggregation' and a.identity=j.job_id::text
                left join public.password_test_stages f on f.stage='publication' and f.identity=j.job_id::text
                order by p.rule_id
                """, owner);
            stages.Parameters.AddWithValue("first", events[0].At);
            stages.Parameters.AddWithValue("last", events[^1].At);
            await using var rows = await stages.ExecuteReaderAsync(ct);
            int seen = 0;
            while (await rows.ReadAsync(ct))
            {
                seen++;
                var rule = rows.GetString(0);
                Assert.Equal(pollAt.AddSeconds(-120), rows.GetFieldValue<DateTimeOffset>(1));
                if (!qualifies)
                {
                    Assert.True(rows.IsDBNull(3));
                    output.WriteLine($"cycle={cycle} {rule}: eligible window processed without a qualifying event");
                    continue;
                }
                int crossing = rule == PasswordRule.RuleId ? 9 : 14;
                var eligibilityWait = pollAt - events[crossing].At.AddSeconds(120);
                var checkpoint = rows.GetFieldValue<DateTimeOffset>(2);
                var detection = rows.GetFieldValue<DateTimeOffset>(3);
                var aggregation = rows.GetFieldValue<DateTimeOffset>(4);
                var publication = rows.GetFieldValue<DateTimeOffset>(5);
                Assert.True(detection <= aggregation && aggregation <= publication);
                var eligibleToPublication = eligibilityWait + (publication - pollStarted) + pollDelay;
                Assert.InRange(eligibleToPublication, TimeSpan.Zero, TimeSpan.FromSeconds(120));
                output.WriteLine($"cycle={cycle} {rule}: eligible_to_poll={eligibilityWait.TotalSeconds:F3}s " +
                    $"poll_to_checkpoint={(checkpoint - pollStarted).TotalSeconds:F3}s poll_to_signal={(detection - pollStarted).TotalSeconds:F3}s " +
                    $"signal_to_aggregation={(aggregation - detection).TotalSeconds:F3}s aggregation_to_publication={(publication - aggregation).TotalSeconds:F3}s " +
                    $"eligible_to_publication={eligibleToPublication.TotalSeconds:F3}s cycle_wall={run.Elapsed.TotalSeconds:F3}s");
            }
            Assert.Equal(2, seen);
        }

        var lateAt = clock.At.AddSeconds(-150);
        await Admit([(lateAt, "late-synthetic", "192.0.2.99")]);
        Assert.Equal(0, (await Detect()).Sum(r => r.Jobs));
        Assert.Equal(2L, await Count("""
            select count(*) from public.password_pass_state393 p
            join public.semantic_password_checkpoints c on c.pin=p.live_pin and c.scope_digest=p.scope_digest
            join public.semantic_password_window_members m on m.pin=c.pin and m.scope_digest=c.scope_digest
            where m.member_document->>'reason'='too_late'
            """));
        Assert.Equal(2L, await Count("""
            select count(*) from public.password_pass_state393 p
            join public.semantic_password_checkpoints c on c.pin=p.live_pin and c.scope_digest=p.scope_digest
            cross join lateral public.password_v2_health(c,clock_timestamp()) health
            where health->>'status'='partial' and health->>'reason'='recent_loss'
            """));
        Assert.Equal(0, (await Detect()).Sum(r => r.Jobs));
        Assert.Equal(0, (await new PasswordRiskConsumer(runtime, new()).RunOnceAsync(ct)).Claimed);
        Assert.Equal(6L, await Count("select count(*) from public.semantic_finding_publications"));
        await fixture.AssertNoSqlErrorsAsync(ct, allowLockTimeout: true);
    }

    private sealed class TestClock(DateTimeOffset at) : TimeProvider
    {
        internal DateTimeOffset At { get; set; } = at;
        public override DateTimeOffset GetUtcNow() => At;
    }
}
