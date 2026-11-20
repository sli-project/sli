using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Semantic;

[Collection("Semantic producer environment")]
public sealed class SemanticWorkerShutdownTests
{
    private const string LockSql = "select pg_advisory_lock(hashtextextended('ad_log_reports_runtime_semantic_production_worker',0))";
    private static string? Facts(string key) => key switch {
        "ADLOG_SEMANTIC_RUNTIME_MODE" => "facts-v1",
        "ADLOG_SEMANTIC_PRODUCTION_ENABLED" or "ADLOG_SEMANTIC_NORMALIZATION_ENABLED" or "ADLOG_SEMANTIC_ASSEMBLY_ENABLED" => "1",
        _ => null
    };
    private static PasswordProducerRuntime Runtime(SqlPostgresFixture fixture) => PasswordProducerRuntime.Create(
        key => key == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException());
    private static async Task<object?> Scalar(NpgsqlConnection db, string sql, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(sql, db);
        return await command.ExecuteScalarAsync(ct);
    }
    private static async Task WaitFor(NpgsqlConnection db, string sql, CancellationToken ct)
    {
        while (await Scalar(db, sql, ct) is not true) await Task.Delay(20, ct);
    }
    private static Task WaitForBackfill(NpgsqlConnection owner, int blockerPid, CancellationToken ct) => WaitFor(owner, $"""
        select exists(select 1 from pg_stat_activity where usename='sli_semantic_login'
          and state='active' and wait_event_type='Lock' and {blockerPid}=any(pg_blocking_pids(pid))
          and query like '%public.semantic_producer_coverage%' and query like '%public.semantic_event_source355%')
        """, ct);
    private static Task WaitForClosed(NpgsqlConnection owner, CancellationToken ct) => WaitFor(owner,
        "select not exists(select 1 from pg_stat_activity where usename='sli_semantic_login')", ct);

    [Theory]
    [InlineData(true, null)] [InlineData(false, null)]
    [InlineData(false, "TERM")] [InlineData(false, "INT")]
    public async Task Stop_cancels_backfill_closes_sessions_and_next_worker_acquires_lock(bool once, string? signal)
    {
        Assert.SkipWhen(signal is not null && !OperatingSystem.IsLinux(), "POSIX signals require Linux; stop-token cases run on Windows too");
        using var environment=new SemanticProducerPostgresTests.Admission(SemanticRuntimeSettings.FactsMode);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(90)); var ct = timeout.Token;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await using var blocker = await fixture.Pg.OpenAsync(ct);
        await using var blockingTransaction = await blocker.BeginTransactionAsync(ct);
        // Block the actual short-event backfill while leaving the worker's lease acquisition available.
        await using (var command = new NpgsqlCommand(
            "lock table public.semantic_producer_coverage in access exclusive mode", blocker, blockingTransaction))
            await command.ExecuteNonQueryAsync(ct);
        if (signal is null) await RunAndCancel();
        else {
            var info = SemanticRuntimePostgresTests.NativeProcess(fixture, findings: false, bundle: false);
            using var process = Process.Start(info)!;
            var stdout = process.StandardOutput.ReadToEndAsync(ct); var stderr = process.StandardError.ReadToEndAsync(ct);
            try {
                await WaitForLeasedBackfill();
                var kill = new ProcessStartInfo("/bin/kill") { UseShellExecute = false, CreateNoWindow = true };
                kill.ArgumentList.Add("-" + signal); kill.ArgumentList.Add(process.Id.ToString(System.Globalization.CultureInfo.InvariantCulture));
                using var sender = Process.Start(kill)!; await sender.WaitForExitAsync(ct); Assert.Equal(0, sender.ExitCode);
                await process.WaitForExitAsync(ct).WaitAsync(TimeSpan.FromSeconds(10), ct);
                Assert.True(process.ExitCode == 0, await stderr); await stdout;
            }
            finally { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); } }
        }
        await WaitForClosed(owner, ct);
        Assert.True(await SemanticProduction.AcquireWorkerLockAsync(owner, ct, TimeSpan.Zero));
        await Scalar(owner, "select pg_advisory_unlock_all()", ct);
        // A second real worker must enter the backfill, rather than wait on the old session lock.
        await RunAndCancel();
        await WaitForClosed(owner, ct);
        Assert.True(await SemanticProduction.AcquireWorkerLockAsync(owner, ct, TimeSpan.Zero));
        await Scalar(owner, "select pg_advisory_unlock_all()", ct);

        async Task WaitForLeasedBackfill()
        {
            await WaitForBackfill(owner, blocker.ProcessID, ct);
            Assert.False(await SemanticProduction.AcquireWorkerLockAsync(owner, ct, TimeSpan.Zero));
        }

        async Task RunAndCancel() {
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var worker = SemanticProduction.RunWorker(new(Once: once), stop.Token, Facts, () => Runtime(fixture));
            try {
                await WaitForLeasedBackfill();
                stop.Cancel();
                Assert.Equal(0, await worker.WaitAsync(TimeSpan.FromSeconds(10), ct));
            }
            finally { stop.Cancel(); await worker.WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None); }
        }
    }

    [Fact]
    public async Task Shutdown_cancels_independent_stage_before_drain_and_releases_its_lock()
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(60)); var ct = timeout.Token;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await using var runtime = Runtime(fixture);
        var production = new SemanticProduction(runtime, new(true,true,false,false,false,false), "facts-v1", 1, independent: true);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        await production.Stage("slow_source", owner, async db => {
            await PostCollectionPostgres.Sql(db, LockSql, stop.Token);
            await PostCollectionPostgres.Sql(db, "select pg_sleep(3600)", stop.Token);
            return new JsonObject();
        }, stop.Token);
        try {
            await WaitFor(owner, "select exists(select 1 from pg_stat_activity where usename='sli_semantic_login' and wait_event='PgSleep')", ct);
            await production.StopAsync(Task.Delay(Timeout.Infinite, stop.Token), stop).WaitAsync(TimeSpan.FromSeconds(10), ct);
            await WaitForClosed(owner, ct);
            Assert.True(await SemanticProduction.AcquireWorkerLockAsync(owner, ct, TimeSpan.Zero));
        }
        finally { stop.Cancel(); await production.StopAsync(Task.CompletedTask, stop); }
    }

    [Fact]
    public async Task Busy_lock_retries_without_terminating_owner_and_wait_is_bounded_and_cancelable()
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30)); var ct = timeout.Token;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(ct);
        await using var owner = await pg.OpenAsync(ct); await using var next = await pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(owner, LockSql, ct);
        var acquire = SemanticProduction.AcquireWorkerLockAsync(next, ct);
        await WaitFor(owner, $"select exists(select 1 from pg_stat_activity where pid={next.ProcessID} and state='idle' and query like '%pg_try_advisory_lock%')", ct);
        Assert.False(acquire.IsCompleted);
        await Scalar(owner, "select pg_advisory_unlock_all()", ct);
        Assert.True(await acquire);
        await Scalar(next, "select pg_advisory_unlock_all()", ct);
        await PostCollectionPostgres.Sql(owner, LockSql, ct);
        Assert.False(await SemanticProduction.AcquireWorkerLockAsync(next, ct, TimeSpan.FromMilliseconds(100)));
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var waiting = SemanticProduction.AcquireWorkerLockAsync(next, stop.Token);
        stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
        Assert.Equal(1, await Scalar(owner, "select 1", ct));
    }

}
