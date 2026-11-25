using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic.Password;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed partial class PasswordConcurrentImportWindowPostgresTests(ITestOutputHelper output)
{
    // Test-only lock in a disposable database. The reader, prepare body and
    // finalizer still execute the definitions installed by migrations 1–410.
    private const long Gate = 1939800420;

    [Theory]
    [InlineData("brute", 10)]
    [InlineData("spray", 5)]
    public async Task Import_between_read_and_finalization_rolls_back_and_is_processed_once(
        string kind, int threshold)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 410);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await InstallPrepareGateAsync(owner, ct);

        // Keep every input live, within one decision window, and beyond the
        // 120-second finalization holdback from the start of the experiment.
        var start = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 300);
        var agent = ShortEventAdmissionPostgresTests.Agent;
        Task<ShortEventRow[]> Stage(int first, int count, int sequence)
        {
            var records = Enumerable.Range(first, count).ToArray();
            return ShortEventAdmissionPostgresTests.SeedAsync(owner, ct,
                eventKinds: records.Select(_ => 4625).ToArray(),
                nativeTimestamps: records.Select(i => PasswordJson.Stamp(start.AddSeconds(i - 1))).ToArray(),
                nativeAccounts: records.Select(i => kind == "spray" ? $"synthetic-{i}" : "synthetic-user").ToArray(),
                nativeTargetSids: records.Select(i =>
                    $"S-1-5-21-100000001-200000002-300000003-{1000 + (kind == "spray" ? i : 1)}").ToArray(),
                registered: sequence == 1 ? null : (agent, agent, 900001L, 1L),
                packetId: Guid.NewGuid(), sequence: sequence, firstRecordId: first);
        }

        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, await Stage(1, threshold - 1, 1), ct);
        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null,
            _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        await using var importer = new NpgsqlConnection(fixture.Dsn("sli_storage_login"));
        await importer.OpenAsync(ct);
        await using var source = new NpgsqlCommand("""
            select source::text from public.default_detection_sources()
            where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'
            """, worker);
        var scope = PasswordScope.Read(JsonNode.Parse(Assert.IsType<string>(await source.ExecuteScalarAsync(ct)))!["scope"]);

        await using (var app = new NpgsqlConnection(fixture.Dsn("adlog_user")))
        {
            await app.OpenAsync(ct);
            await using var bind = new NpgsqlCommand("""
                select public.provision_password_detection_domain_v2(@agent,1,null,'example.test','session:1')->>'status'
                """, app);
            bind.Parameters.AddWithValue("agent", agent);
            Assert.Equal("configured", await bind.ExecuteScalarAsync(ct));
        }
        await using var plan = new NpgsqlCommand("""
            select (public.password_plan388(@scope::jsonb,@rule)#>>'{live,rule_version}')::int
            """, worker);
        plan.Parameters.AddWithValue("scope", scope.Document.ToJsonString());
        plan.Parameters.AddWithValue("rule", new PasswordRule(scope, kind).Id);
        var rule = new PasswordRule(scope, kind, Assert.IsType<int>(await plan.ExecuteScalarAsync(ct)));

        var producer = new PasswordProducer();
        var cache = new Dictionary<long, PasswordNative>();
        var control = await RunGatedAsync(producer, worker, importer, rule, cache, [], ct);
        AssertCommitted(control);
        Assert.Equal(0, control.Jobs);
        var before = await ReadCheckpointAsync(owner, rule.Pin, ct);
        Assert.Equal(start.AddSeconds(threshold - 2), before.Watermark);
        Assert.Equal(0L, before.Signals);
        Assert.Equal(0L, before.Jobs);

        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, await Stage(threshold, 1, 2), ct);
        var lateRows = await Stage(threshold + 1, 1, 3);
        long lateId = 900000L + threshold + 1; // identity assigned by the existing synthetic fixture
        Assert.Equal(0L, await CountHotEventAsync(owner, lateId, ct));

        var conflicted = await RunGatedAsync(producer, worker, importer, rule, cache, lateRows, ct);
        Assert.False(conflicted.Failed, conflicted.Diagnostic?.ToJsonString());
        Assert.False(conflicted.FailureObserved);
        Assert.Equal("busy", conflicted.Status);
        Assert.Equal(0, conflicted.Jobs);
        Assert.Equal("password_v2_window_changed393", conflicted.Diagnostic?["reason"]?.GetValue<string>());
        Assert.Equal("40001", conflicted.Diagnostic?["sql_state"]?.GetValue<string>());
        Assert.Equal("complete_password_producer_batch_v2", conflicted.Diagnostic?["step"]?.GetValue<string>());
        Assert.Equal(1L, await CountHotEventAsync(owner, lateId, ct));
        Assert.Equal(before, await ReadCheckpointAsync(owner, rule.Pin, ct));

        using var retryTime = CancellationTokenSource.CreateLinkedTokenSource(ct);
        retryTime.CancelAfter(TimeSpan.FromSeconds(45));
        var retry = await producer.RunAsync(worker, rule, retryTime.Token, cache);
        AssertCommitted(retry);
        Assert.True(retry.Jobs > 0);
        var after = await ReadCheckpointAsync(owner, rule.Pin, ct);
        Assert.Equal(before.Revision + 1, after.Revision);
        Assert.Equal(start.AddSeconds(threshold), after.Watermark);
        Assert.Equal(after.Watermark, after.LastSuccessfulCutoff);
        Assert.True(after.Signals > before.Signals);
        Assert.Equal((long)retry.Jobs, after.Jobs - before.Jobs);
        Assert.Equal(1L, await CountNewOccurrencesAsync(owner, rule.Pin, lateId, ct));

        var replay = await producer.RunAsync(worker, rule, retryTime.Token, cache);
        AssertCommitted(replay);
        Assert.Equal(0, replay.Jobs);
        var replayed = await ReadCheckpointAsync(owner, rule.Pin, ct);
        Assert.Equal(after.Signals, replayed.Signals);
        Assert.Equal(after.Jobs, replayed.Jobs);
        Assert.Equal(1L, await CountNewOccurrencesAsync(owner, rule.Pin, lateId, ct));
        Assert.Equal(1L, await CountHotEventAsync(owner, lateId, ct));
    }

    private static void AssertCommitted(PasswordProducerOutcome result)
    {
        Assert.False(result.Failed, result.Diagnostic?.ToJsonString());
        Assert.Equal("committed", result.Status);
    }

    private static Task InstallPrepareGateAsync(NpgsqlConnection owner, CancellationToken ct) =>
        PostCollectionPostgres.Sql(owner, $"""
            alter function public.prepare_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text[])
                rename to p1_test_prepare_native;
            create function public.prepare_password_producer_batch_v2(
                jsonb,jsonb,bigint,bigint,text[]
            ) returns jsonb language plpgsql volatile set search_path=pg_catalog,pg_temp as $gate$
            begin
                perform pg_advisory_xact_lock({Gate}::bigint);
                return public.p1_test_prepare_native($1,$2,$3,$4,$5);
            end;
            $gate$;
            revoke all on function public.prepare_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text[]) from public;
            grant execute on function public.prepare_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text[])
                to adlog_semantic_worker;
            """, ct);

    private static async Task<PasswordProducerOutcome> RunGatedAsync(PasswordProducer producer,
        NpgsqlConnection worker, NpgsqlConnection importer, PasswordRule rule,
        Dictionary<long, PasswordNative> cache, IReadOnlyList<ShortEventRow> arriving, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(45));
        var token = deadline.Token;
        await PostCollectionPostgres.Sql(importer, $"select pg_advisory_lock({Gate}::bigint)", token);
        var running = producer.RunAsync(worker, rule, token, cache);
        bool ready = false;
        try
        {
            await using var waiting = new NpgsqlCommand("""
                select pg_backend_pid() = any(pg_blocking_pids(@worker))
                  and exists(select 1 from pg_locks
                             where pid=@worker and locktype='advisory' and not granted)
                """, importer);
            waiting.Parameters.AddWithValue("worker", worker.ProcessID);
            while (await waiting.ExecuteScalarAsync(token) is not true)
            {
                Assert.False(running.IsCompleted, "Producer exited before reaching its post-read gate");
                await Task.Delay(25, token);
            }

            if (arriving.Count != 0)
            {
                await using var tx = await importer.BeginTransactionAsync(token);
                await PostCollectionPostgres.Sql(importer, "set local role adlog_storage_worker", token);
                await ShortEventWriter.WriteAsync(importer, tx, arriving, token);
                await tx.CommitAsync(token);
            }
            ready = true;
        }
        finally
        {
            await using var release = new NpgsqlCommand($"select pg_advisory_unlock({Gate}::bigint)", importer)
                { CommandTimeout = 5 };
            try
            {
                Assert.True(await release.ExecuteScalarAsync(CancellationToken.None) is true);
            }
            finally
            {
                if (!ready)
                {
                    deadline.Cancel();
                    try { await running; }
                    catch (OperationCanceledException) when (deadline.IsCancellationRequested) { }
                }
            }
        }
        return await running;
    }

    private sealed record Checkpoint(long Revision, DateTimeOffset Watermark,
        DateTimeOffset LastSuccessfulCutoff, string DurableState, long Signals, long Jobs);

    private static async Task<Checkpoint> ReadCheckpointAsync(NpgsqlConnection db, string pin, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            with signals as (
                select q.signal_id from public.semantic_qw_signals q
                where q.document_json#>>'{password_context,pin}'=@pin
            )
            select c.state_revision,c.watermark,c.last_successful_cutoff,
                (to_jsonb(c)-'active_token'-'last_attempt_at')::text,
                (select count(*) from signals),
                (select count(*) from public.semantic_risk_evaluation_jobs j join signals s on s.signal_id=j.qw_signal_id)
            from public.semantic_password_checkpoints c where c.pin=@pin
            """, db);
        command.Parameters.AddWithValue("pin", pin);
        await using var reader = await command.ExecuteReaderAsync(ct);
        Assert.True(await reader.ReadAsync(ct));
        return new(reader.GetInt64(0), reader.GetFieldValue<DateTimeOffset>(1),
            reader.GetFieldValue<DateTimeOffset>(2), reader.GetString(3), reader.GetInt64(4), reader.GetInt64(5));
    }

    private static async Task<long> CountHotEventAsync(NpgsqlConnection db, long eventId, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("select count(*) from public.event_hot where event_id=@event", db);
        command.Parameters.AddWithValue("event", eventId);
        return Assert.IsType<long>(await command.ExecuteScalarAsync(ct));
    }

    private static async Task<long> CountNewOccurrencesAsync(NpgsqlConnection db, string pin, long eventId, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("""
            select count(*) from public.semantic_qw_signals q
            cross join lateral (select q.document_json->'password_context' as doc) c
            cross join lateral jsonb_array_elements(c.doc->'occurrences') with ordinality o(witness,ordinal)
            where c.doc->>'pin'=@pin and (o.witness->>0)::bigint=@event
              and ((c.doc->>'occurrence_from')::int + o.ordinal - 1) - (c.doc->>'new_from')::int
                  between 0 and (c.doc->>'new_count')::int - 1
            """, db);
        command.Parameters.AddWithValue("pin", pin);
        command.Parameters.AddWithValue("event", eventId);
        return Assert.IsType<long>(await command.ExecuteScalarAsync(ct));
    }
}
