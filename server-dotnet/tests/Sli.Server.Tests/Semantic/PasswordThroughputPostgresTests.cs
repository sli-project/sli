using System.Diagnostics;
using System.Reflection;
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
        bool measurePhases = Environment.GetEnvironmentVariable("SLI_TEST_P1_PHASES_411") == "1";
        await using var fixture = new SqlPostgresFixture();
        if (measurePhases)
            await fixture.StartAsync(ct, throughVersion: 411);
        else
            await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        if (measurePhases)
            await InstallPhaseMeasurementAsync(owner, ct);
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
        if (measurePhases)
            await WritePhaseMeasurementsAsync(fixture.Pg, ct);
        if (measurePhases && Environment.GetEnvironmentVariable("SLI_TEST_P1_SPRAY_HISTORY_411") == "1")
            await MeasureSprayContinuationAsync(owner, runtime, scope, SetClock, At(liveEnd).AddMinutes(12),
                sequence, liveEnd + 1, ct, fixture, output);
    }

    private static Task InstallPhaseMeasurementAsync(NpgsqlConnection owner, CancellationToken ct) =>
        PostCollectionPostgres.Sql(owner, """
            do $probe$
            declare body text; modified text;
            begin
                body:=pg_get_functiondef('public.read_password_episode_portions_v2(jsonb,jsonb,text)'::regprocedure);
                modified:=replace(body,'declare identity jsonb;',
                    'declare p1_started timestamptz:=clock_timestamp(); p1_rows integer:=0; p1_refs integer:=0; identity jsonb;');
                modified:=replace(modified,'        return query select encode(sha256',
                    $history_rows$        p1_rows:=p1_rows+1;
                    p1_refs:=p1_refs+coalesce(jsonb_array_length(d->'evidence_refs'),0);
                    return query select encode(sha256$history_rows$);
                modified:=replace(modified,E'    end loop;\nend ',
                    $history_end$    end loop;
                raise log 'p1_411_phase %',jsonb_build_object(
                    'rule',execution->>'rule_id','phase','history_read','rows',p1_rows,'refs',p1_refs,
                    'elapsed_ms',round(1000*extract(epoch from clock_timestamp()-p1_started),3))::text;
            end $history_end$);
                if modified=body or strpos(modified,'''history_read''')=0 or strpos(modified,'p1_rows:=p1_rows+1')=0
                    or strpos(modified,'p1_started timestamptz')=0
                    then raise exception 'p1_history_measurement_shape'; end if;
                execute modified;

                body:=pg_get_functiondef('public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)'::regprocedure);
                modified:=replace(body,'declare c public.semantic_password_checkpoints%rowtype;',
                    'declare p1_started timestamptz:=clock_timestamp(); c public.semantic_password_checkpoints%rowtype;');
                modified:=replace(modified,$finish$    return jsonb_build_object('status','staged','revision',$finish$,
                    $finalizer$    raise log 'p1_411_phase %',jsonb_build_object(
                        'rule',execution->>'rule_id','phase','finalizer','revision',c.state_revision,
                        'window_rows',jsonb_array_length(next_st->'window'),
                        'active_episodes',jsonb_array_length(next_st->'episodes'),
                        'closed_admissions',coalesce(jsonb_array_length(next_st->'closed_admissions'),0),
                        'elapsed_ms',round(1000*extract(epoch from clock_timestamp()-p1_started),3),
                        'after_checkpoint_stamp_ms',round(1000*extract(epoch from clock_timestamp()-stamp),3))::text;
                return jsonb_build_object('status','staged','revision',$finalizer$);
                if modified=body or strpos(modified,'''finalizer''')=0 or strpos(modified,'p1_started timestamptz')=0
                    then raise exception 'p1_finalizer_measurement_shape'; end if;
                execute modified;
            end $probe$;
            """, ct);

    private async Task WritePhaseMeasurementsAsync(PostCollectionPostgres postgres, CancellationToken ct)
    {
        const string marker = "LOG:  p1_411_phase ";
        var measurements = (await postgres.DiagnosticsAsync(ct)).Split('\n')
            .Where(line => line.Contains(marker, StringComparison.Ordinal))
            .Select(line => JsonNode.Parse(line[(line.IndexOf(marker, StringComparison.Ordinal) + marker.Length)..].Trim())!)
            .ToArray();
        foreach (string rule in new[] { "qw.password-brute-force", "qw.password-spray" })
        {
            var byRule = measurements.Where(row => row["rule"]!.GetValue<string>() == rule).ToArray();
            Assert.Contains(byRule, row => row["phase"]!.GetValue<string>() == "finalizer");
            output.WriteLine($"p1_411_history_calls {rule} {byRule.Count(row => row["phase"]!.GetValue<string>() == "history_read")}");
            foreach (var row in byRule)
                output.WriteLine($"p1_411_phase {row.ToJsonString()}");
        }
    }

    private static async Task MeasureSprayContinuationAsync(
        NpgsqlConnection owner, PasswordProducerRuntime runtime, PasswordScope scope,
        Func<DateTimeOffset, Task> setClock, DateTimeOffset start, int sequence,
        int firstRecord, CancellationToken ct, SqlPostgresFixture fixture, ITestOutputHelper output)
    {
        const int slices = 47;
        const int hotClientRows = 178;
        const int qualifyingClients = 10;
        const int otherQualifyingClientRows = 9;
        const int nonQualifyingClients = 21;
        const int qualifyingRows = hotClientRows + (qualifyingClients - 1) * otherQualifyingClientRows;
        const int sliceRows = qualifyingRows + nonQualifyingClients;
        const int spacingMs = 176;

        await using var worker = await runtime.OpenAsync(ct);
        var spray = new PasswordRule(scope, "spray");
        await using (var plan = new NpgsqlCommand("""
            select (public.password_plan388(@scope::jsonb,@rule)#>>'{live,rule_version}')::int
            """, worker))
        {
            plan.Parameters.AddWithValue("scope", scope.Document.ToJsonString());
            plan.Parameters.AddWithValue("rule", spray.Id);
            spray = new PasswordRule(scope, "spray", Assert.IsType<int>(await plan.ExecuteScalarAsync(ct)));
        }

        var producer = new PasswordProducer();
        var agent = ShortEventAdmissionPostgresTests.Agent;
        var invoke = typeof(PasswordProducer).GetMethod("RunCore", BindingFlags.Static | BindingFlags.NonPublic)!;
        for (int slice = 0; slice < slices; slice++)
        {
            int[] clients = Enumerable.Range(0, sliceRows).Select(i => i < hotClientRows ? 0 :
                i < qualifyingRows ? 1 + (i - hotClientRows) / otherQualifyingClientRows :
                qualifyingClients + i - qualifyingRows).ToArray();
            int[] accounts = Enumerable.Range(0, sliceRows).Select(i => i < hotClientRows ? i % 30 :
                i < qualifyingRows ? 100 + clients[i] * 10 + (i - hotClientRows) % otherQualifyingClientRows :
                300 + clients[i]).ToArray();
            DateTimeOffset sliceStart = start.AddMilliseconds((long)slice * sliceRows * spacingMs);
            for (int offset = 0; offset < sliceRows; offset += 100)
            {
                int[] packet = Enumerable.Range(offset, Math.Min(100, sliceRows - offset)).ToArray();
                var rows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
                    eventKinds: packet.Select(_ => 4625).ToArray(),
                    nativeTimestamps: packet.Select(i => PasswordJson.Stamp(sliceStart.AddMilliseconds(i * spacingMs))).ToArray(),
                    nativeAccounts: packet.Select(i => $"continuation-user-{accounts[i]}").ToArray(),
                    nativeTargetSids: packet.Select(i => $"S-1-5-21-100000001-200000002-300000003-{20000 + accounts[i]}").ToArray(),
                    nativeAddresses: packet.Select(i => $"198.51.100.{10 + clients[i]}").ToArray(),
                    registered: (agent, agent, 900001, 1), packetId: Guid.NewGuid(),
                    sequence: ++sequence, firstRecordId: firstRecord + slice * sliceRows + offset);
                await ShortEventAdmissionPostgresTests.WriteAsync(fixture, rows, ct);
            }

            var target = sliceStart.AddMilliseconds((sliceRows - 1) * spacingMs);
            await setClock(target.AddSeconds(120));
            bool measured = slice == slices - 1;
            if (measured)
                output.WriteLine("p1_411_spray_shape_before " + await ReadSprayShapeAsync(owner, spray.Pin, ct));

            var memo = new Dictionary<long, PasswordNative>();
            var watch = Stopwatch.StartNew();
            var profiled = new List<PasswordProofObservation>();
            var outcomes = await PasswordProducerPoller.RunBatchesAsync(scope, async (rule, token) =>
            {
                if (!measured)
                    return await producer.RunAsync(worker, rule, token, memo);

                // Reuse the exact producer core and its existing phase timers.
                // The normal reporting threshold hides successful unsplit passes.
                var observation = new PasswordProofObservation();
                profiled.Add(observation);
                var core = (Task<PasswordProducerOutcome>)invoke.Invoke(null, [worker, rule, token, memo, observation])!;
                return await core;
            }, ct, rules: [spray], targetWatermark: target);
            watch.Stop();
            Assert.NotEmpty(outcomes);
            Assert.All(outcomes, outcome => Assert.True(outcome.Status == "committed", outcome.Diagnostic?.ToJsonString() ?? outcome.Status));
            Assert.Equal(target, PasswordJson.Time(outcomes[^1].Work!["watermark"]));

            if ((slice + 1) % 8 == 0)
                output.WriteLine($"p1_411_spray_warmup slice={slice + 1} elapsed_ms={watch.Elapsed.TotalMilliseconds:F0}");
            if (!measured)
                continue;

            int historyReads = profiled.Sum(observation => Counter<int>(observation, "historyReads"));
            Assert.True(historyReads > 0);
            var phaseMilliseconds = new JsonObject();
            foreach (var phase in new[] { PasswordProofTiming.HistoryRead, PasswordProofTiming.HistoryCheck,
                PasswordProofTiming.NativeRead, PasswordProofTiming.NativeCheck, PasswordProofTiming.Checkpoint,
                PasswordProofTiming.Finalizer, PasswordProofTiming.Commit })
            {
                phaseMilliseconds[phase.ToString()] = Math.Round(profiled.Sum(observation =>
                    Counter<TimeSpan[]>(observation, "phaseElapsed")[(int)phase].TotalMilliseconds), 3);
            }
            var result = new JsonObject
            {
                ["warmup_rows"] = (slices - 1) * sliceRows,
                ["last_slice_rows"] = sliceRows,
                ["producer_passes"] = profiled.Count,
                ["history_calls"] = historyReads,
                ["history_portions_read"] = profiled.Sum(observation => Counter<int>(observation, "historyRows")),
                ["native_read_calls"] = profiled.Sum(observation => Counter<int>(observation, "nativeReads")),
                ["native_refs_verified"] = profiled.Sum(observation => Counter<long>(observation, "verifiedRefs")),
                ["producer_elapsed_ms"] = Math.Round(watch.Elapsed.TotalMilliseconds, 3),
                ["phase_ms"] = phaseMilliseconds
            };
            output.WriteLine("p1_411_spray_continuation " + result.ToJsonString());
            output.WriteLine("p1_411_spray_shape_after " + await ReadSprayShapeAsync(owner, spray.Pin, ct));
        }

        static T Counter<T>(PasswordProofObservation observation, string name) =>
            (T)typeof(PasswordProofObservation).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(observation)!;
    }

    private static async Task<string> ReadSprayShapeAsync(NpgsqlConnection owner, string pin, CancellationToken ct)
    {
        await using var shape = new NpgsqlCommand("""
            select jsonb_build_object(
                'state_revision',c.state_revision,
                'window_rows',jsonb_array_length(c.state_document->'window'),
                'active_episodes',jsonb_array_length(c.state_document->'episodes'),
                'closed_admissions',coalesce(jsonb_array_length(c.state_document->'closed_admissions'),0),
                'episodes_with_ledger',ledger.episodes,
                'portions',ledger.portions,
                'reference_occurrences',ledger.refs,
                'max_episode_portions',ledger.max_portions,
                'max_episode_refs',ledger.max_refs)::text
            from public.semantic_password_checkpoints c
            cross join lateral (
                select count(*) as episodes,coalesce(sum(b.reserved_portions),0) as portions,
                    coalesce(sum(b.reserved_ref_occurrences),0) as refs,max(b.reserved_portions) as max_portions,
                    max(b.reserved_ref_occurrences) as max_refs
                from jsonb_array_elements(c.state_document->'episodes') e(value)
                join public.semantic_password_episode_budgets b
                  on b.scope_digest=c.scope_digest and b.pin=c.pin and b.episode_key=e.value->>'key'
            ) ledger
            where c.pin=@pin
            """, owner);
        shape.Parameters.AddWithValue("pin", pin);
        return Assert.IsType<string>(await shape.ExecuteScalarAsync(ct));
    }

    private sealed class TestClock(DateTimeOffset at) : TimeProvider
    {
        internal DateTimeOffset At { get; set; } = at;
        public override DateTimeOffset GetUtcNow() => At;
    }
}
