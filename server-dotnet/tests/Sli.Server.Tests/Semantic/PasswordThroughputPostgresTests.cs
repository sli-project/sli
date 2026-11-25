using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;
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
        bool compareCanonical = Environment.GetEnvironmentVariable("SLI_TEST_P1_COMPARE_CANONICAL") == "1";
        await using var fixture = new SqlPostgresFixture();
        if (measurePhases)
            await fixture.StartAsync(ct, throughVersion: 414);
        else
            await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        if (compareCanonical)
            await InstallDecoderProbeAsync(owner, ct);
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
        await using var traced = await fixture.Pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(traced, """
            load 'auto_explain';
            set auto_explain.log_min_duration='50ms';
            set auto_explain.log_analyze=on;
            set auto_explain.log_buffers=on;
            set auto_explain.log_timing=off;
            set auto_explain.log_nested_statements=on;
            set track_functions='all';
            set session authorization sli_semantic_login;
            set role adlog_semantic_worker;
            """, ct);
        await using (var login = new NpgsqlCommand("""
            select session_user='sli_semantic_login' and current_user='adlog_semantic_worker'
            """, traced))
            Assert.Equal(true, await login.ExecuteScalarAsync(ct));
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
            if (measured && Environment.GetEnvironmentVariable("SLI_TEST_P1_COMPARE_CANONICAL") == "1")
            {
                await traced.CloseAsync();
                await CompareRetainedReadOnClonesAsync(owner, worker, fixture, spray, target, output, ct);
                return;
            }

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
                var core = (Task<PasswordProducerOutcome>)invoke.Invoke(null, [traced, rule, token, memo, observation])!;
                return await core;
            }, ct, rules: [spray], targetWatermark: target);
            watch.Stop();
            Assert.NotEmpty(outcomes);
            Assert.All(outcomes, outcome => Assert.True(outcome.Status == "committed", outcome.Diagnostic?.ToJsonString() ?? outcome.Status));
            Assert.Equal(target, PasswordJson.Time(outcomes[^1].Work!["watermark"]));

            if (slice == 0 && Environment.GetEnvironmentVariable("SLI_TEST_P1_COMPARE_CANONICAL") == "1")
                await VerifyDecoderMigrationAsync(owner, traced, spray, output, ct);

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
            await PostCollectionPostgres.Sql(traced, "select pg_stat_force_next_flush()", ct);
            await ReportReadProfileAsync(owner, fixture.Pg, ct, output);
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

    private static async Task CompareRetainedReadOnClonesAsync(
        NpgsqlConnection owner, NpgsqlConnection worker, SqlPostgresFixture fixture,
        PasswordRule rule, DateTimeOffset target, ITestOutputHelper output, CancellationToken ct)
    {
        var source = new NpgsqlConnectionStringBuilder(owner.ConnectionString);
        Assert.Equal("postgres", source.Database);
        await owner.CloseAsync();
        await worker.CloseAsync();

        source.Database = "template1";
        await using (var maintenance = new NpgsqlConnection(source.ConnectionString))
        {
            await maintenance.OpenAsync(ct);
            await PostCollectionPostgres.Sql(maintenance, "create database p1_read_before template postgres", ct);
            await PostCollectionPostgres.Sql(maintenance, "create database p1_read_after template postgres", ct);
        }

        var before = await MeasureClone("p1_read_before", false);
        var after = await MeasureClone("p1_read_after", true);
        output.WriteLine("p1_read_ab_reference_digest " + before);
        output.WriteLine("p1_read_ab_candidate_digest " + after);
        Assert.Equal(before, after);

        async Task<string> MeasureClone(string database, bool candidate)
        {
            string Connection(string role) => new NpgsqlConnectionStringBuilder(fixture.Dsn(role)) { Database = database }.ConnectionString;
            await using var admin = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.Pg.ConnectionString) { Database = database }.ConnectionString);
            await admin.OpenAsync(ct);
            if (candidate)
            {
                string migrationPath = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations", "415_password_portion_canonical.sql");
                await PostCollectionPostgres.Sql(admin, await File.ReadAllTextAsync(migrationPath, ct), ct);
            }

            await using var runtime = PasswordProducerRuntime.Create(
                name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? Connection("sli_semantic_login") : null,
                _ => throw new InvalidOperationException());
            await using var producerConnection = new NpgsqlConnection(admin.ConnectionString);
            await producerConnection.OpenAsync(ct);
            await PostCollectionPostgres.Sql(producerConnection, """
                load 'auto_explain';
                set auto_explain.log_min_duration='50ms';
                set auto_explain.log_analyze=on;
                set auto_explain.log_buffers=on;
                set auto_explain.log_timing=off;
                set auto_explain.log_nested_statements=on;
                set track_functions='all';
                set session authorization sli_semantic_login;
                set role adlog_semantic_worker;
                """, ct);
            Guid[] olderJobs = await JobIds(admin, ct);
            var profile = new PasswordProofObservation();
            var invoke = typeof(PasswordProducer).GetMethod("RunCore", BindingFlags.Static | BindingFlags.NonPublic)!;
            var watch = Stopwatch.StartNew();
            var run = (Task<PasswordProducerOutcome>)invoke.Invoke(null,
                [producerConnection, rule, ct, new Dictionary<long, PasswordNative>(), profile])!;
            var outcome = await run;
            watch.Stop();
            Assert.True(outcome.Status == "committed", outcome.Diagnostic?.ToJsonString() ?? outcome.Status);
            Assert.Equal(target, PasswordJson.Time(outcome.Work!["watermark"]));
            Assert.True(outcome.Jobs > 0);
            await PostCollectionPostgres.Sql(producerConnection, "select pg_stat_force_next_flush()", ct);
            await using (var calls = new NpgsqlCommand("""
                select coalesce(sum(calls),0)::bigint
                from pg_stat_user_functions where schemaname='public' and funcname='password_v2_json_compact'
                """, admin))
            {
                var durations = (TimeSpan[])typeof(PasswordProofObservation)
                    .GetField("phaseElapsed", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(profile)!;
                var metrics = new JsonObject
                {
                    ["variant"] = candidate ? "candidate" : "reference",
                    ["producer_ms"] = Math.Round(watch.Elapsed.TotalMilliseconds, 3),
                    ["history_read_ms"] = Math.Round(durations[(int)PasswordProofTiming.HistoryRead].TotalMilliseconds, 3),
                    ["history_check_ms"] = Math.Round(durations[(int)PasswordProofTiming.HistoryCheck].TotalMilliseconds, 3),
                    ["native_read_ms"] = Math.Round(durations[(int)PasswordProofTiming.NativeRead].TotalMilliseconds, 3),
                    ["finalizer_ms"] = Math.Round(durations[(int)PasswordProofTiming.Finalizer].TotalMilliseconds, 3),
                    ["compact_calls"] = Assert.IsType<long>(await calls.ExecuteScalarAsync(ct))
                };
                output.WriteLine("p1_read_ab " + metrics.ToJsonString());
            }

            await using var snapshot = new NpgsqlCommand("""
                select jsonb_build_object(
                  'checkpoint_sha',(select encode(sha256(convert_to(coalesce(string_agg(
                    (to_jsonb(c)-array['last_attempt_at','last_completed_at'])::text, '|' order by c.pin),''),'UTF8')),'hex')
                    from public.semantic_password_checkpoints c),
                  'checkpoint_marks',(select jsonb_agg(jsonb_build_array(c.execution_json->>'rule_id',
                    c.state_revision,c.watermark,c.coverage_epoch) order by c.pin)
                    from public.semantic_password_checkpoints c),
                  'episode_sha',(select encode(sha256(convert_to(coalesce(string_agg(
                      (to_jsonb(b)-array['admission_xid','frozen_at','last_admitted_as_of'])::text, '|' order by b.pin,b.episode_key),''),'UTF8')),'hex')
                    from public.semantic_password_episode_budgets b),
                  'signal_sha',(select encode(sha256(convert_to(coalesce(string_agg(
                      (q.document_json-'received_at_utc')::text, '|' order by q.signal_id),''),'UTF8')),'hex')
                    from public.semantic_qw_signals q),
                  'job_sha',(select encode(sha256(convert_to(coalesce(string_agg(
                      (to_jsonb(j)-array['created_at','updated_at','available_at','lease_until','lease_token','heartbeat_at','completed_at'])::text,
                      '|' order by j.job_id),''),'UTF8')),'hex') from public.semantic_risk_evaluation_jobs j),
                  'new_jobs',(select count(*) from public.semantic_risk_evaluation_jobs j where j.job_id<>all(@older)),
                  'evidence_sha',(select encode(sha256(convert_to(coalesce(string_agg(
                      normalized, '|' order by normalized),''),'UTF8')),'hex')
                    from (select (to_jsonb(r)-array['created_at','updated_at'])::text as normalized
                          from public.finding_evidence_refs r) q))::text
                """, admin);
            snapshot.Parameters.AddWithValue("older", olderJobs);
            var stable = JsonNode.Parse(Assert.IsType<string>(await snapshot.ExecuteScalarAsync(ct)))!.AsObject();
            Assert.Equal(outcome.Jobs, stable["new_jobs"]!.GetValue<int>());
            return stable.ToJsonString();
        }

        static async Task<Guid[]> JobIds(NpgsqlConnection db, CancellationToken ct)
        {
            await using var query = new NpgsqlCommand("select job_id from public.semantic_risk_evaluation_jobs order by job_id", db);
            await using var rows = await query.ExecuteReaderAsync(ct);
            var ids = new List<Guid>();
            while (await rows.ReadAsync(ct))
                ids.Add(rows.GetGuid(0));
            return ids.ToArray();
        }
    }

    private static Task InstallDecoderProbeAsync(NpgsqlConnection owner, CancellationToken ct) =>
        PostCollectionPostgres.Sql(owner, """
            set role adlog_storage_owner;
            create function public.p1_test_decode415(scope jsonb,execution jsonb,documents jsonb)
            returns jsonb language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $probe$
            begin
                if session_user<>'sli_semantic_login' then
                    raise exception 'p1_test_semantic_login_required' using errcode='42501';
                end if;
                return public.password_v2_decode(scope,execution,documents);
            end
            $probe$;
            revoke all on function public.p1_test_decode415(jsonb,jsonb,jsonb) from public;
            grant execute on function public.p1_test_decode415(jsonb,jsonb,jsonb) to adlog_semantic_worker;
            reset role;
            """, ct);

    private static async Task VerifyDecoderMigrationAsync(
        NpgsqlConnection owner, NpgsqlConnection worker, PasswordRule rule, ITestOutputHelper output,
        CancellationToken ct)
    {
        async Task<JsonNode> Definition()
        {
            await using var definition = new NpgsqlCommand("""
                select jsonb_build_array(pg_get_functiondef(oid),proowner,proacl)::text
                from pg_proc where oid='public.password_v2_decode(jsonb,jsonb,jsonb)'::regprocedure
                """, owner);
            return JsonNode.Parse(Assert.IsType<string>(await definition.ExecuteScalarAsync(ct)))!;
        }

        async Task<JsonObject> GuardResults()
        {
            await using var valid = new NpgsqlCommand("""
                select public.p1_test_decode415(@scope::jsonb,@rule::jsonb,jsonb_build_array(document_json))
                    #>>'{signal_ids,0}'=signal_id
                from public.semantic_qw_signals
                where document_json#>>'{password_context,pin}'=@pin
                  and document_json#>>'{password_context,portion_total}'='1'
                order by signal_id limit 1
                """, worker);
            valid.Parameters.AddWithValue("scope", rule.Scope.Document.ToJsonString());
            valid.Parameters.AddWithValue("rule", rule.Execution.ToJsonString());
            valid.Parameters.AddWithValue("pin", rule.Pin);
            Assert.Equal(true, await valid.ExecuteScalarAsync(ct));

            var guards = new JsonArray(
                await RejectionAsync(worker, rule, "received_at_utc", JsonValue.Create(new string('x',513))!, ct),
                await RejectionAsync(worker, rule, "evidence_total", JsonValue.Create(1.25)!, ct),
                await RejectionAsync(worker, rule, "evidence_total",
                    JsonNode.Parse(new string('[',18)+"1"+new string(']',18))!, ct),
                await RejectionAsync(worker, rule, "password_context.emission_id", JsonValue.Create(new string('0',64))!, ct));
            Assert.Equal("22023:password_v2_state_invalid", guards[0]!.GetValue<string>());
            Assert.Equal("22023:password_v2_state_invalid", guards[1]!.GetValue<string>());
            Assert.Equal("54000:password_v2_state_bound", guards[2]!.GetValue<string>());
            Assert.Equal("22023:password_v2_emission_hash_conflict", guards[3]!.GetValue<string>());
            return new JsonObject
            {
                ["valid_signed_id"] = true,
                ["guards"] = guards,
                ["byte_limits"] = await ByteLimitCasesAsync(owner, worker, rule, ct)
            };
        }

        var original = await Definition();
        var before = await GuardResults();
        var migrations = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations");
        await PostCollectionPostgres.Sql(owner, await File.ReadAllTextAsync(
            Path.Combine(migrations, "415_password_portion_canonical.sql"), ct), ct);
        var installed = await Definition();
        Assert.NotEqual(original[0]!.GetValue<string>(), installed[0]!.GetValue<string>());
        Assert.True(JsonNode.DeepEquals(original[1], installed[1]));
        Assert.True(JsonNode.DeepEquals(original[2], installed[2]));
        var after = await GuardResults();
        Assert.True(JsonNode.DeepEquals(before, after), $"{before}\n{after}");
        await PostCollectionPostgres.Sql(owner, await File.ReadAllTextAsync(
            Path.Combine(migrations, "415_password_portion_canonical.rollback.sql"), ct), ct);
        Assert.True(JsonNode.DeepEquals(original, await Definition()));
        output.WriteLine("p1_decoder_guard_preflight " + before.ToJsonString());
    }

    private static async Task<string> RejectionAsync(
        NpgsqlConnection db, PasswordRule rule, string key, JsonNode value, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            select public.p1_test_decode415(@scope::jsonb,@rule::jsonb,
                jsonb_build_array(case when @tamper_emission then
                    jsonb_set(jsonb_set(document_json,@path,@value::jsonb,true),
                        '{password_context,root_id}',@value::jsonb,true)
                    else jsonb_set(document_json,@path,@value::jsonb,true) end))
            from public.semantic_qw_signals
            where document_json#>>'{password_context,pin}'=@pin
              and document_json#>>'{password_context,portion_total}'='1'
            order by signal_id limit 1
            """, db);
        cmd.Parameters.AddWithValue("scope", rule.Scope.Document.ToJsonString());
        cmd.Parameters.AddWithValue("rule", rule.Execution.ToJsonString());
        cmd.Parameters.AddWithValue("path", key.Split('.'));
        cmd.Parameters.AddWithValue("tamper_emission", key == "password_context.emission_id");
        cmd.Parameters.AddWithValue("value", value.ToJsonString());
        cmd.Parameters.AddWithValue("pin", rule.Pin);
        var rejected = await Assert.ThrowsAsync<PostgresException>(() => cmd.ExecuteScalarAsync(ct));
        return $"{rejected.SqlState}:{rejected.MessageText}";
    }

    private static async Task<JsonArray> ByteLimitCasesAsync(
        NpgsqlConnection db, NpgsqlConnection worker, PasswordRule rule, CancellationToken ct)
    {
        var results = new JsonArray();
        foreach (int bytes in new[] { 524287, 524288, 524289 })
        {
            string document;
            await using (var build = new NpgsqlCommand("""
                with seed as (
                    select jsonb_set(jsonb_set(document_json,'{received_at_utc}',
                        to_jsonb('bad'||chr(34)||chr(92)||chr(10)||chr(233)),true),'{evidence_refs}','[]',true) as doc
                    from public.semantic_qw_signals
                    where document_json#>>'{password_context,pin}'=@pin
                      and document_json#>>'{password_context,portion_total}'='1'
                    order by signal_id limit 1
                ), sizes as (
                    select doc,octet_length(public.password_v2_json_compact(doc)) as base_bytes from seed
                ), pieces as (
                    -- 85 Unicode characters compact to 510 escaped bytes.
                    -- Quotes and the array separator add three more bytes.
                    select doc,base_bytes,(@bytes-base_bytes-2)/513 as chunks from sizes
                ), inputs as (
                    select jsonb_set(doc,'{evidence_refs}',
                        to_jsonb(array_fill(repeat(chr(233),85),array[chunks]))
                        ||jsonb_build_array(repeat('x',@bytes-base_bytes-2-513*chunks)),true) as doc
                    from pieces
                )
                select doc::text,octet_length(doc::text),octet_length(public.password_v2_json_compact(doc)),
                    octet_length(public.password_v2_json_compact(doc-'received_at_utc'))
                      +octet_length(',"received_at_utc":')
                      +octet_length(public.password_v2_json_compact(doc->'received_at_utc',1))
                from inputs
                """, db))
            {
                build.Parameters.AddWithValue("pin", rule.Pin);
                build.Parameters.AddWithValue("bytes", bytes);
                await using var row = await build.ExecuteReaderAsync(ct);
                Assert.True(await row.ReadAsync(ct));
                document = row.GetString(0);
                Assert.True(row.GetInt32(1) < 524288);
                Assert.Equal(bytes, row.GetInt32(2));
                Assert.Equal(bytes, row.GetInt32(3));
            }

            await using var decode = new NpgsqlCommand("""
                select public.p1_test_decode415(@scope::jsonb,@rule::jsonb,jsonb_build_array(@document::jsonb))
                """, worker);
            decode.Parameters.AddWithValue("scope", rule.Scope.Document.ToJsonString());
            decode.Parameters.AddWithValue("rule", rule.Execution.ToJsonString());
            decode.Parameters.AddWithValue("document", document);
            var rejected = await Assert.ThrowsAsync<PostgresException>(() => decode.ExecuteScalarAsync(ct));
            Assert.Equal("22023", rejected.SqlState);
            var expected = bytes > 524288 ? "password_v2_portion_invalid" : "password_v2_state_invalid";
            Assert.Equal(expected, rejected.MessageText);
            results.Add(new JsonObject { ["bytes"] = bytes, ["error"] = rejected.MessageText });
        }
        return results;
    }

    private static async Task ReportReadProfileAsync(
        NpgsqlConnection owner, PostCollectionPostgres postgres, CancellationToken ct, ITestOutputHelper output)
    {
        await using (var counters = new NpgsqlCommand("""
            select jsonb_build_object(
                'work_mem',current_setting('work_mem'),
                'shared_buffers',current_setting('shared_buffers'),
                'postgres_version',current_setting('server_version'),
                'function_counters',
                (select jsonb_agg(jsonb_build_object(
                    'function',funcname,'calls',calls,'total_ms',round(total_time::numeric,3),
                    'self_ms',round(self_time::numeric,3)) order by total_time desc)
                 from pg_stat_user_functions
                 where schemaname='public' and calls>0 and funcname in (
                    'read_password_episode_portions_v2','password_v2_episode_documents','password_v2_assert_episode',
                    'password_v2_json_compact','password_v2_decode','read_password_retained_proof_v2',
                    'read_password_retained_proof_v2_short337','short_ref_allowed337','short_native_source337',
                    'complete_password_producer_batch_v2')))
            """, owner))
        {
            output.WriteLine("p1_read_postgres " + Assert.IsType<string>(await counters.ExecuteScalarAsync(ct)));
        }

        var logs = await postgres.DiagnosticsAsync(ct);
        var blocks = Regex.Split(logs, @"(?m)(?=^[^\r\n]*\bLOG:\s+duration:\s+[\d.]+\s+ms\s+plan:)");
        var groups = new Dictionary<string, List<(decimal Milliseconds, int IndexNodes, int SeqNodes, long Reads, long Hits)>>();
        foreach (string block in blocks)
        {
            var duration = Regex.Match(block, @"\bLOG:\s+duration:\s+([\d.]+)\s+ms\s+plan:");
            int start = block.IndexOf("Query Text:", StringComparison.Ordinal);
            if (!duration.Success || start < 0)
                continue;
            var root = Regex.Match(block[start..], @"(?m)^.*\(cost=\d");
            if (!root.Success)
                continue;
            var query = block.Substring(start, root.Index).ToLowerInvariant();
            var label = query switch
            {
                _ when query.Contains("from public.read_password_episode_portions_v2(") => "read_history",
                _ when query.Contains("from public.read_password_retained_proof_v2(") => "read_native",
                _ when query.Contains("from public.read_password_retained_proof_v2_short337(") => "read_native_short",
                _ when query.Contains("from public.semantic_qw_signals v") &&
                    query.Contains("password_scope_digest") => "episode_documents",
                _ when query.Contains("public.password_v2_assert_episode(") => "assert_episode",
                _ when query.Contains("public.password_v2_decode(") => "decode_portions",
                _ when query.Contains("from public.detection_events337 e") => "native_row_lookup",
                _ when query.Contains("public.short_native_source337(") => "native_representation",
                _ when query.Contains("public.short_ref_allowed337(") => "native_authorization",
                _ when query.Contains("public.complete_password_producer_batch_v2(") => "finalizer",
                _ => null
            };
            if (label is null)
                continue;

            var plan = block[(start + root.Index)..];
            var buffers = Regex.Match(plan, @"Buffers: shared([^\r\n]*)");
            var hits = Regex.Match(buffers.Groups[1].Value, @"\bhit=(\d+)");
            var reads = Regex.Match(buffers.Groups[1].Value, @"\bread=(\d+)");
            if (!groups.TryGetValue(label, out var group))
                groups.Add(label, group = []);
            group.Add((decimal.Parse(duration.Groups[1].Value, CultureInfo.InvariantCulture),
                Regex.Matches(plan, @"\b(?:Index(?: Only)? Scan|Bitmap Index Scan)\b").Count,
                Regex.Matches(plan, @"\bSeq Scan\b").Count,
                reads.Success ? long.Parse(reads.Groups[1].Value, CultureInfo.InvariantCulture) : 0,
                hits.Success ? long.Parse(hits.Groups[1].Value, CultureInfo.InvariantCulture) : 0));
        }

        Assert.Contains("read_history", groups.Keys);
        Assert.Contains("read_native", groups.Keys);
        foreach (var (label, plans) in groups.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            var sample = new JsonObject
            {
                ["query"] = label,
                ["plans_at_least_50ms"] = plans.Count,
                ["elapsed_ms"] = plans.Sum(plan => plan.Milliseconds),
                ["index_nodes"] = plans.Sum(plan => plan.IndexNodes),
                ["sequential_nodes"] = plans.Sum(plan => plan.SeqNodes),
                ["shared_reads"] = plans.Sum(plan => plan.Reads),
                ["shared_hits"] = plans.Sum(plan => plan.Hits)
            };
            output.WriteLine("p1_read_plan " + sample.ToJsonString());
        }
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
