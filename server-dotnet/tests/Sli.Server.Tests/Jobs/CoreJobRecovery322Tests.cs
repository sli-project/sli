using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Jobs;
using Sli.Server.Tests.Agents;
using Ws = Sli.Server.Workstations.Ws;
using WorkstationJobPlugin = Sli.Server.Workstations.WorkstationJobPlugin;
using WorkstationEvaluators = Sli.Server.Workstations.WorkstationEvaluators;
using Xunit;

namespace Sli.Server.Tests.Jobs;

public sealed class CoreJobRecovery322Tests(ITestOutputHelper output)
{
    static async Task<object?> Scalar(NpgsqlConnection db, string sql, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand(sql, db) { CommandTimeout = 0 };
        return await command.ExecuteScalarAsync(ct);
    }
    [Fact]
    public async Task Daemon_reconnects_after_its_dispatcher_backend_is_terminated()
    {
        var fixtureToken = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(nativeJobAddress: true, nativeJobHost: "127.0.0.3");
        // The current daemon uses activation and drain functions introduced after migration 322.
        await fixture.StartAsync(fixtureToken);
        await using var owner = await fixture.Pg.OpenAsync(fixtureToken);
        await Scalar(owner, """
            alter role sli_job_dispatcher_light login;
            alter role sli_job_executor_light login;
            alter role sli_job_publisher_light login;
            update plugin_installations_v1 set desired_activation='enabled_manual',component_runtime='running' where plugin_id='sli.workstations';
            """, fixtureToken);
        await using (var dispatcher = new NpgsqlConnection(fixture.Dsn("sli_job_dispatcher_light")))
        {
            await dispatcher.OpenAsync(fixtureToken);
            var session = new PostgresCoreJobSession(dispatcher);
            var ordinary = new InvalidOperationException("synthetic contract failure");
            Assert.False(CoreJobWorker.Recoverable(ordinary));
            Assert.False(CoreJobWorker.DispatcherConnectionLost(ordinary, session));
            var denied = await Assert.ThrowsAsync<PostgresException>(() =>
                Scalar(dispatcher, "select 1 from public.plugin_installations_v1 limit 1", fixtureToken));
            Assert.Equal("42501", denied.SqlState);
            Assert.Equal("job_database_error", CoreJobCommand.FailureCode(denied));
            Assert.True(CoreJobWorker.Recoverable(denied));
            Assert.False(CoreJobWorker.DispatcherConnectionLost(denied, session));
            await dispatcher.CloseAsync();
            Assert.True(session.IsDisconnected);
            Assert.False(CoreJobWorker.DispatcherConnectionLost(ordinary, session));
        }

        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        { UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true };
        start.ArgumentList.Add(typeof(CoreJobCommand).Assembly.Location);
        start.ArgumentList.Add("core-job-executor");start.ArgumentList.Add("--profile");start.ArgumentList.Add("light");
        var inherited = new[]{"PATH","SystemRoot","WINDIR","DOTNET_ROOT","DOTNET_HOST_PATH","DOTNET_CLI_HOME","TEMP","TMP","APPDATA","LOCALAPPDATA"}
            .Select(k=>(Key:k,Value:Environment.GetEnvironmentVariable(k))).ToArray();
        start.Environment.Clear();foreach(var (key,value) in inherited)if(value is not null)start.Environment[key]=value;
        start.Environment["SLI_JOB_PG_HOST"]="127.0.0.3";
        start.Environment["SLI_CORE_JOB_WORKSTATIONS_PROJECTION"]="1";
        start.Environment["SLI_EXECUTOR_STATUS_DIR"]=fixture.Pg.Root;
        start.Environment["ADLOG_DATA_DIR"]=fixture.Pg.Root;
        foreach(string purpose in new[]{"dispatcher","executor","publisher"})
        {
            string path=Path.Combine(fixture.Pg.Root,"synthetic-"+purpose+".txt");
            await File.WriteAllTextAsync(path,"synthetic-disposable-password",fixtureToken);
            start.Environment[CoreJobIdentity.PasswordName("light",purpose)+"_FILE"]=path;
        }
        // Allow several real dispatcher scheduling cycles (30 seconds each).
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(fixtureToken);
        deadline.CancelAfter(TimeSpan.FromMinutes(2));
        var ct = deadline.Token;
        using var poll = new PeriodicTimer(TimeSpan.FromMilliseconds(100));
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync(fixtureToken);
        var stderr = process.StandardError.ReadToEndAsync(fixtureToken);
        string phase = "initial dispatcher";
        long killed = 0, reconnected = 0;
        Guid? completed = null;
        async Task RequireRunning()
        {
            if (!process.HasExited) return;
            var diagnostic = (await stderr).Split('\n')
                .Where(line => line.StartsWith("core_executor_", StringComparison.Ordinal));
            Assert.Fail($"Disposable executor exited during {phase} with code {process.ExitCode}: {string.Join(" ", diagnostic)}");
        }

        try
        {
            async Task<long> Backend(long previous)
            {
                // A short-lived failure recorder can share the process application name.
                // Only an idle session that has actually polled the queue is the dispatcher.
                await using var command = new NpgsqlCommand("""
                    select pid::bigint from pg_stat_activity where application_name=@name and pid<>@previous
                        and state='idle' and query like 'select public.claim_core_job_v1(%'
                    """, owner);
                command.Parameters.AddWithValue("name", "sli-core-job-dispatcher-light-" + process.Id);
                command.Parameters.AddWithValue("previous", previous);
                while (true)
                {
                    await RequireRunning();
                    if (await command.ExecuteScalarAsync(ct) is long pid) return pid;
                    await poll.WaitForNextTickAsync(ct);
                }
            }

            killed = await Backend(0);
            Assert.Equal(true, await Scalar(owner, "select pg_terminate_backend(" + killed + ")", ct));
            phase = "reconnected dispatcher";
            reconnected = await Backend(killed);
            Assert.NotEqual(killed, reconnected);

            // The real station trigger creates pending work only after this daemon has reconnected.
            phase = "post-reconnect publication";
            await Scalar(owner, """
                insert into sli_plugin_workstations.station_inventory(station_id,agent_key,station_type,metadata)
                    values('synthetic-recovery-station','synthetic-recovery-agent','workstation','{}');
                """, ct);
            await using var publication = new NpgsqlCommand("""
                select array(select j.job_id from sli_jobs.jobs j
                join sli_jobs.audit a on a.job_id=j.job_id and a.transition='completed' and a.lease_generation=j.lease_generation
                join sli_plugin_workstations.projection_work w on w.kind='station_inventory'
                    and w.station_id='synthetic-recovery-station' and a.at_utc>=w.created_at
                where j.source_instance_id='workstations:projection' and j.executor_id=@executor
                    and j.state='completed' and j.lease_generation=1 and j.result_sha256 is not null
                    and (select bool_and(r.applied_at is not null)
                         from sli_plugin_workstations.projection_receipts r where r.work_id=w.work_id))
                """, owner);
            publication.Parameters.AddWithValue("executor", "executor-light-" + process.Id);
            while (completed is null)
            {
                await RequireRunning();
                var jobs = (Guid[])(await publication.ExecuteScalarAsync(ct))!;
                if (jobs.Length > 0) { completed = Assert.Single(jobs); break; }
                var failure = await Scalar(owner, """
                    select error_code from sli_jobs.jobs where source_instance_id='workstations:projection'
                        and error_code not in ('job_connection_lost','lease_expired') limit 1
                    """, ct);
                Assert.True(failure is null, "disposable projection job failure: " + failure);
                await poll.WaitForNextTickAsync(ct);
            }
            await RequireRunning();
        }
        catch (OperationCanceledException) when (!fixtureToken.IsCancellationRequested && deadline.IsCancellationRequested)
        {
            Assert.Fail("Disposable executor did not reach " + phase + " within two minutes");
        }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None);
        }
        string errors = await stderr;
        await stdout;
        Assert.True(errors.Contains("57P01", StringComparison.Ordinal) || errors.Contains("job_connection_lost", StringComparison.Ordinal), errors);
        Assert.NotNull(completed);
        output.WriteLine($"real daemon pid={process.Id}: terminated backend={killed}; reconnected backend={reconnected}; completed projection job={completed}; failure reason observed");
    }
    [Fact]
    public async Task Real_321_upgrade_unlimited_query_batched_projection_and_connection_death()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 320);
        string migrations = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations");
        string forward = Path.Combine(migrations, "322_core_job_recovery.sql");
        // The curator merges 321 first. An unmerged worktree may supply that
        // real migration as an explicit test dependency, never a forged marker.
        string predecessor = Directory.GetFiles(migrations, "321_*.sql").SingleOrDefault(p => !p.EndsWith(".rollback.sql"))
            ?? Environment.GetEnvironmentVariable("SLI_TEST_PREDECESSOR_321")
            ?? throw new InvalidOperationException("real_migration_321_required");
        await using var owner = new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        Assert.Equal(320, await Scalar(owner, "select max(version) from schema_migrations", ct));
        var denied = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Pg.ApplyFileAsync(forward, null, ct));
        Assert.Contains("core_job_322_preflight", denied.Message);
        await fixture.Pg.ApplyFileAsync(predecessor, null, ct);
        Assert.Equal(321, await Scalar(owner, "select max(version) from schema_migrations", ct));
        await fixture.Pg.ApplyFileAsync(forward, null, ct);
        Assert.Equal(322, await Scalar(owner, "select max(version) from schema_migrations", ct));
        Assert.Equal(0L, await Scalar(owner, "select count(*) from pg_roles r cross join lateral unnest(r.rolconfig) c where r.rolname in (select role_name from core_job_role_limits322) and (c like 'statement_timeout=%' or c like 'idle_in_transaction_session_timeout=%')", ct));
        Assert.Equal(9L, await Scalar(owner, "select count(*) from pg_roles r where r.rolname in (select role_name from core_job_role_limits322) and 'lock_timeout=1s'=any(rolconfig)", ct));
        await fixture.Pg.ApplyFileAsync(Path.Combine(migrations, "322_core_job_recovery.rollback.sql"), null, ct);
        Assert.Equal(9L, await Scalar(owner, "select count(*) from pg_roles where rolname ~ '^sli_job_(dispatcher|executor|publisher)_(light|heavy|long)$' and 'statement_timeout=10s'=any(rolconfig) and 'idle_in_transaction_session_timeout=15s'=any(rolconfig)", ct));
        await fixture.Pg.ApplyFileAsync(forward, null, ct);
        await Scalar(owner, "alter role sli_job_dispatcher_light login; alter role sli_job_executor_light login; alter role sli_job_publisher_light login", ct);
        await using var dispatcher = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.Dsn("sli_job_dispatcher_light")) { CommandTimeout = 0 }.ConnectionString);
        await dispatcher.OpenAsync(ct);
        var watch = Stopwatch.StartNew();
        await Scalar(dispatcher, "select pg_sleep(11)", ct);
        Assert.True(watch.Elapsed.TotalSeconds > 10);
        output.WriteLine($"real PostgreSQL: query completed after {watch.Elapsed.TotalSeconds:F2}s; role timeout reset; rollback/reapply verified");

        // Immutable synthetic station revisions. Seven consumers are already
        // applied, C02 remains pending: the actual publisher evaluates it as a
        // no-op for station inputs and still verifies every payload hash.
        await Scalar(owner, """
            update plugin_installations_v1 set desired_activation='enabled_manual',component_runtime='running' where plugin_id='sli.workstations';
            insert into sli_plugin_workstations.station_inventory(station_id,agent_key,station_type,metadata)
                values('synthetic-station','synthetic-agent','workstation','{}');
            insert into sli_plugin_workstations.projection_consumers(projector_key,projection_version,backfill_complete)
                select key,1,true from unnest(array['workstations.C02','workstations.C05','workstations.C06','workstations.protection','workstations.last-interactive-login','workstations.C07','workstations.C03','workstations.C04']) key;
            insert into sli_plugin_workstations.projection_checkpoints(projector_key,partition_key,projection_version,committed_position)
                select 'workstations.backfill',key,1,'{"complete":true}' from unnest(array['observations','protection_state','station_inventory']) key;
            insert into sli_plugin_workstations.station_summary(station_id,protection,as_of_utc)
                values('synthetic-station','{"next_refresh_at":"2999-01-01T00:00:00Z"}',now());
            insert into sli_plugin_workstations.projection_work(kind,source_id,agent_key,station_id,payload,payload_sha256)
                select 'station_inventory','synthetic-revision:'||n,'synthetic-agent','synthetic-station',
                    jsonb_build_object('station_id','synthetic-station','revision',n),
                    encode(sha256(convert_to(jsonb_build_object('station_id','synthetic-station','revision',n)::text,'UTF8')),'hex')
                from generate_series(1,100000) n;
            insert into sli_plugin_workstations.projection_receipts(work_id,projector_key,projection_version,payload_sha256,applied_at)
                select w.work_id,c.projector_key,1,w.payload_sha256,case when c.projector_key='workstations.C02' and w.source_id like 'synthetic-revision:%' then null else now() end
                from sli_plugin_workstations.projection_work w cross join sli_plugin_workstations.projection_consumers c;
            analyze sli_plugin_workstations.projection_work;
            analyze sli_plugin_workstations.projection_receipts;
            """, ct);
        var catalog = CoreJobPluginCatalog.Compiled(); var registry = catalog.Registry(null);
        var implementation = catalog.Resolve(new JsonObject { ["plugin_id"] = "sli.workstations", ["handler_id"] = "workstations.overview-project" });
        var queue = new CoreJobQueue(new PostgresCoreJobSession(dispatcher));
        var source = JsonNode.Parse((string)(await Scalar(dispatcher, "select read_workstation_projection_job_source_v1()::text", ct))!)!.AsObject();
        var keys = WorkstationEvaluators.Identities(null);
        await using (var explain = Ws.Command(owner, "explain (analyze,buffers,format json) " + WorkstationJobPlugin.PendingSql, keys.Keys.ToArray(), keys.Values.ToArray(), 100))
        {
            string plan = (string)(await explain.ExecuteScalarAsync(ct))!;
            Assert.Contains("workstation_projection_pending", plan);
            var tree = JsonNode.Parse(plan)!;
            var bad = new List<string>();
            void Inspect(JsonNode? node)
            {
                if (node is JsonObject o)
                {
                    if (o["Node Type"]?.ToString() == "Seq Scan" && o["Relation Name"]?.ToString() is "projection_work" or "projection_receipts") bad.Add(o.ToJsonString());
                    foreach (var item in o) Inspect(item.Value);
                }
                else if (node is JsonArray a) foreach (var item in a) Inspect(item);
            }
            Inspect(tree); Assert.Empty(bad);
            output.WriteLine("pending page EXPLAIN ANALYZE: " + plan);
        }
        await using var publisher = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.Dsn("sli_job_publisher_light")) { CommandTimeout = 0 }.ConnectionString);
        await publisher.OpenAsync(ct); var publishing = new CoreJobQueue(new PostgresCoreJobSession(publisher));
                async Task<JsonObject> Claim()
        {
            source["projection_progress"] = (string)(await Scalar(dispatcher,"select read_workstation_projection_progress_v322()",ct))!;
            var spec = CoreJobScheduler.Create(registry, "light", source, DateTimeOffset.UtcNow, WorkstationJobPlugin.Pin).Single(s => s.Text("handler_id") == "workstations.overview-project");
            spec["schedule_key"] = CoreJobJson.Digest(new JsonArray(spec["schedule_key"]!.DeepClone(),source["projection_progress"]!.DeepClone()));
            registry.Resolve(spec); await queue.EnqueueAsync(spec, ct);
            return await queue.ClaimAsync("light", "synthetic-322", registry.Identities("light"), ct) ?? throw new InvalidOperationException("real_job_not_claimed");
        }
        int processed = 0, batches = 0; watch.Restart();
        while (processed < 100000)
        {
            var job = await Claim();
            var result = await implementation.Stage(publisher, job, ct);
            int count = result["work_ids"]!.AsArray().Count; Assert.InRange(count, 1, 100);
            Assert.Equal("committed", await publishing.PublishAsync(job, result, token => implementation.Publish(publisher, job, result, token), ct));
            processed += count; batches++;
            if (batches is 1 or 500 || processed == 100000)
            {
                long pending = (long)(await Scalar(owner, "select count(*) from sli_plugin_workstations.projection_receipts where applied_at is null", ct))!;
                Assert.Equal(100000 - processed, pending);
                output.WriteLine($"batch={batches} processed={processed} pending={pending} elapsed={watch.Elapsed.TotalSeconds:F2}s");
            }
        }
        Assert.Equal(1000, batches);
        Assert.Equal(100001L, await Scalar(owner, "select count(*) from sli_plugin_workstations.projection_work", ct)); // reference history is retained

        var failed = await Claim(); bool killed = false;
        await Scalar(owner, "update sli_jobs.jobs set attempts=max_attempts where job_id='" + failed.Text("job_id") + "'", ct);
        var executor = new CoreJobExecutor(queue, registry, async (request, purpose, timeout, beat, token) =>
        {
            if (!killed)
            {
                killed = true;
                await using var victim = new NpgsqlConnection(fixture.Dsn("sli_job_executor_light")); await victim.OpenAsync(token);
                int pid = (int)(await Scalar(victim, "select pg_backend_pid()", token))!;
                await Scalar(owner, "select pg_terminate_backend(" + pid + ")", token);
                await Scalar(victim, "select 1", token);
            }
            if (purpose == "handler") return await implementation.Stage(publisher, request, token);
            var result = request["staged_result"]!.AsObject();
            return new JsonObject { ["status"] = await publishing.PublishAsync(request, result, t => implementation.Publish(publisher, request, result, t), token) };
        });
        await executor.ExecuteAsync(failed, ct);
        Assert.Equal("job_connection_lost", await Scalar(owner, "select error_code from sli_jobs.jobs where job_id='" + failed.Text("job_id") + "'", ct));
        Assert.Equal(false, await Scalar(dispatcher, "select retry_core_job_v322('" + failed.Text("job_id") + "','job_statement_cancelled')", ct));
        Assert.Equal(true, await Scalar(dispatcher, "select retry_core_job_v322('" + failed.Text("job_id") + "','job_connection_lost')", ct));
        var recovered = await queue.ClaimAsync("light", "synthetic-recovered", registry.Identities("light"), ct);
        Assert.NotNull(recovered);
        Assert.True(recovered["lease_generation"]!.GetValue<long>() > failed["lease_generation"]!.GetValue<long>());
        await executor.ExecuteAsync(recovered, ct);
        Assert.Equal("completed", await Scalar(owner, "select state from sli_jobs.jobs where job_id='" + failed.Text("job_id") + "'", ct));
        Assert.Equal(1L, await Scalar(owner, "select count(*) from sli_jobs.audit where transition='recovery_requested'", ct));
        output.WriteLine("pg_terminate_backend: recorded job_connection_lost; executor accepted the next invocation");
    }
}
