using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Jobs;
using Sli.Server.Workstations;
using Xunit;

namespace Sli.Server.Tests.Workstations;

public sealed class WorkstationDrainTests(ITestOutputHelper output)
{
    static async Task<object?> Sql(NpgsqlConnection db,string sql,CancellationToken ct)
    {
        await using var command=new NpgsqlCommand(sql,db){CommandTimeout=0};
        return await command.ExecuteScalarAsync(ct);
    }
    static NpgsqlConnection Connection(SqlPostgresFixture fixture,string? role=null)=>new(new NpgsqlConnectionStringBuilder(
        role is null?fixture.Pg.ConnectionString:fixture.Dsn(role)){CommandTimeout=0}.ConnectionString);

    [Fact]
    public async Task Real_process_drains_200000_inputs_eight_consumers_without_starvation_or_extra_connections()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(nativeJobAddress:true,nativeJobHost:"127.0.0.4");
        await fixture.StartAsync(ct,throughVersion:320);
        string migrations=Path.Combine(Agents.PostCollectionPostgres.Repository(),"config/postgres_migrations");
        string predecessor=Directory.GetFiles(migrations,"321_*.sql").SingleOrDefault(p=>!p.EndsWith(".rollback.sql"))
            ?? Environment.GetEnvironmentVariable("SLI_TEST_PREDECESSOR_321") ?? throw new InvalidOperationException("real_migration_321_required");
        string forward=Path.Combine(migrations,"323_workstation_projection_drain.sql");
        var denied=await Assert.ThrowsAsync<InvalidOperationException>(()=>fixture.Pg.ApplyFileAsync(forward,null,ct));
        Assert.Contains("workstation_projection_323_preflight",denied.Message);
        await fixture.Pg.ApplyFileAsync(predecessor,null,ct);
        await fixture.Pg.ApplyFileAsync(Path.Combine(migrations,"322_core_job_recovery.sql"),null,ct);
        await using var owner=Connection(fixture);await owner.OpenAsync(ct);
        Assert.Equal(322,await Sql(owner,"select max(version) from schema_migrations",ct));
        string acl=(string)(await Sql(owner,"select proowner::text||':'||proacl::text from pg_proc where oid='heartbeat_core_job_v1(uuid,uuid,bigint)'::regprocedure",ct))!;
        await fixture.Pg.ApplyFileAsync(forward,null,ct);
        Assert.Equal(323,await Sql(owner,"select max(version) from schema_migrations",ct));
        await fixture.Pg.ApplyFileAsync(Path.Combine(migrations,"323_workstation_projection_drain.rollback.sql"),null,ct);
        Assert.Equal(322,await Sql(owner,"select max(version) from schema_migrations",ct));
        Assert.DoesNotContain("greatest",(string)(await Sql(owner,"select pg_get_functiondef('heartbeat_core_job_v1(uuid,uuid,bigint)'::regprocedure)",ct))!);
        await fixture.Pg.ApplyFileAsync(forward,null,ct);
        Assert.Equal(acl,await Sql(owner,"select proowner::text||':'||proacl::text from pg_proc where oid='heartbeat_core_job_v1(uuid,uuid,bigint)'::regprocedure",ct));
        // Native children run the current binary, including its narrow
        // activation reader. Upgrade after the historical 323 round-trip.
        foreach(var successor in MigrationDirectory.Read(324))await fixture.Pg.ApplyFileAsync(successor.Path,null,ct);
        await Sql(owner,"""
            alter role sli_job_dispatcher_light login;alter role sli_job_executor_light login;alter role sli_job_publisher_light login;
            update plugin_installations_v1 set desired_activation='enabled_manual',component_runtime='running' where plugin_id='sli.workstations';
            insert into sli_plugin_workstations.station_inventory(station_id,agent_key,station_type,metadata)
                values('synthetic-station','synthetic-agent','workstation','{}');
            insert into sli_plugin_workstations.station_summary(station_id,protection,as_of_utc)
                values('synthetic-station','{"next_refresh_at":"2999-01-01T00:00:00Z"}',now());
            insert into sli_plugin_workstations.projection_checkpoints(projector_key,partition_key,projection_version,committed_position)
                select 'workstations.backfill',key,1,'{"complete":true}' from unnest(array['observations','protection_state','station_inventory']) key;
            insert into sli_plugin_workstations.projection_work(kind,source_id,agent_key,payload,payload_sha256)
                select 'observations','synthetic:'||n,'synthetic-agent',payload,encode(sha256(convert_to(payload::text,'UTF8')),'hex')
                from generate_series(1,200000) n cross join lateral (select jsonb_build_object('id',lpad(to_hex(n),64,'0'),
                    'agent_key','synthetic-agent','family','logons','event_id',4624,'observed_at','2026-10-19T12:00:00Z',
                    'observation',jsonb_build_object('channel','Security','provider_name','Microsoft-Windows-Security-Auditing',
                    'facts',jsonb_build_object('logon_type','3'))) payload) p;
            analyze sli_plugin_workstations.projection_work;
            """,ct);
        await using var dispatcher=Connection(fixture,"sli_job_dispatcher_light");await dispatcher.OpenAsync(ct);
        var catalog=CoreJobPluginCatalog.Compiled();var registry=catalog.Registry(null);var queue=new CoreJobQueue(new PostgresCoreJobSession(dispatcher));
        var source=JsonNode.Parse((string)(await Sql(dispatcher,"select read_workstation_projection_job_source_v1()::text",ct))!)!.AsObject();
        var sameSlot=DateTimeOffset.UtcNow;
        async Task<JsonObject> Claim()
        {
            source["projection_progress"]=(string)(await Sql(dispatcher,"select read_workstation_projection_progress_v322()",ct))!;
            var spec=CoreJobScheduler.Create(registry,"light",source,sameSlot,WorkstationJobPlugin.Pin).Single(s=>s["handler_id"]!.ToString()=="workstations.overview-project");
            spec["schedule_key"]=CoreJobJson.Digest(new JsonArray(spec["schedule_key"]!.DeepClone(),source["projection_progress"]!.DeepClone()));
            await queue.EnqueueAsync(spec,ct);
            return await queue.ClaimAsync("light","synthetic-drain",registry.Identities("light"),ct)??throw new InvalidOperationException("real_job_not_claimed");
        }
        var job=await Claim();string jobId=job["job_id"]!.ToString();
        await Sql(owner,$"update sli_jobs.jobs set deadline_at=clock_timestamp()+interval '2 seconds' where job_id='{jobId}'",ct);
        await queue.HeartbeatAsync(job,ct);
        Assert.Equal(true,await Sql(owner,$"select deadline_at>clock_timestamp()+interval '290 seconds' from sli_jobs.jobs where job_id='{jobId}'",ct));
        var forged=(JsonObject)job.DeepClone();forged["lease_token"]=Guid.NewGuid().ToString();
        await Assert.ThrowsAsync<CoreJobLeaseLost>(()=>queue.HeartbeatAsync(forged,ct));
        forged=(JsonObject)job.DeepClone();forged["lease_generation"]=job["lease_generation"]!.GetValue<long>()+1;
        await Assert.ThrowsAsync<CoreJobLeaseLost>(()=>queue.HeartbeatAsync(forged,ct));
        var environment=new Dictionary<string,string>{["SLI_JOB_PG_HOST"]="127.0.0.4",["SLI_CORE_JOB_WORKSTATIONS_PROJECTION"]="1"};
        foreach(string key in new[]{"PATH","SystemRoot","WINDIR"})if(Environment.GetEnvironmentVariable(key) is {} value)environment[key]=value;
        foreach(string purpose in new[]{"executor","publisher"})
        {
            string path=Path.Combine(fixture.Pg.Root,"synthetic-"+purpose+".txt");
            await File.WriteAllTextAsync(path,"synthetic-disposable-password",ct);
            environment[CoreJobIdentity.PasswordName("light",purpose)+"_FILE"]=path;
        }
        JsonObject? publication=null;
        CoreJobExecutor Executor()=>new(queue,registry,async (request,purpose,timeout,beat,token)=>
        {
            var start=CoreJobProcess.StartInfo(request,purpose,key=>environment.GetValueOrDefault(key),Environment.GetEnvironmentVariable("DOTNET_HOST_PATH")??"dotnet",false);
            var result=await CoreJobProcess.RunAsync(start,request["budget"]!.AsObject(),timeout,beat,token,request);
            if(purpose=="publisher")publication=result;
            return result;
        });
        async Task<long> CheckFairness()
        {
            var rows=await Ws.Rows(owner,"""
                select c.projector_key,c.backfill_position,c.backfill_complete,
                    coalesce((p.committed_position->>'processed_count')::bigint,0) as processed
                from sli_plugin_workstations.projection_consumers c left join sli_plugin_workstations.projection_checkpoints p
                    on p.projector_key=c.projector_key and p.partition_key='synthetic-station'
                """,ct);
            if(rows.Count==0)return 0;
            Assert.Equal(8,rows.Count);
            Assert.InRange(rows.Max(r=>r.Number("processed"))-rows.Min(r=>r.Number("processed")),0,100);
            Assert.InRange(rows.Max(r=>r.Number("backfill_position"))-rows.Min(r=>r.Number("backfill_position")),0,100);
            return rows.Min(r=>r.Number("processed"));
        }
        bool imported=false;double importMs=0;int maxConnections=0;long reported=0;
        var watch = Stopwatch.StartNew();
        var attempt = job;
        while (true)
        {
            publication = null;
            var execution = Executor().ExecuteAsync(attempt, ct);
            while (!execution.IsCompleted)
            {
                await Task.WhenAny(execution, Task.Delay(250, ct));
                ct.ThrowIfCancellationRequested();
                long position = await CheckFairness();
                maxConnections = Math.Max(maxConnections, Convert.ToInt32(await Sql(owner, "select count(*) from pg_stat_activity where usename like 'sli_job_%'", ct)));
                Assert.InRange(maxConnections, 0, 2);
                if (!imported && position >= 1000)
                {
                    var import = Stopwatch.StartNew();
                    await Sql(owner, "select sli_plugin_workstations.enqueue_projection_input('observations',jsonb_build_object('id',repeat('f',64),'agent_key','synthetic-agent','family','logons','event_id',4624,'observed_at','2026-10-19T12:00:00Z','observation',jsonb_build_object('channel','Security','provider_name','Microsoft-Windows-Security-Auditing','facts',jsonb_build_object('logon_type','3'))))", ct);
                    importMs = import.Elapsed.TotalMilliseconds;
                    imported = true;
                }
                if (position - reported >= 10000)
                {
                    reported = position;
                    output.WriteLine($"all eight >= {position}; seconds={watch.Elapsed.TotalSeconds:F2}");
                }
            }
            await execution;
            var status = Assert.Single(await Ws.Rows(owner, """
                select state,error_code,greatest(0,ceil(extract(epoch from available_at-clock_timestamp())*1000))::integer as retry_ms
                from sli_jobs.jobs where job_id=@p0
                """, ct, Guid.Parse(jobId)));
            output.WriteLine($"drain state={Ws.Text(status, "state")}; error_code={Ws.Text(status, "error_code")}");
            if (Ws.Text(status, "state") != "retry_wait" || Ws.Text(status, "error_code") != "job_lock_unavailable")
                break;

            // The executor records a transient lock failure for the production
            // dispatcher to reclaim. Keep the backoff in the measured time.
            await Task.Delay(TimeSpan.FromMilliseconds(status.Number("retry_ms")), ct);
            var nextAttempt = await queue.ClaimAsync("light", "synthetic-drain", registry.Identities("light"), ct);
            Assert.NotNull(nextAttempt);
            Assert.Equal(jobId, CoreJobJson.Text(nextAttempt, "job_id"));
            Assert.True(nextAttempt.Number("lease_generation") > attempt.Number("lease_generation"));
            attempt = nextAttempt;
        }
        watch.Stop();
        Assert.True(imported);Assert.Equal("committed",publication?["status"]?.ToString());
        Assert.Equal(200002L,await CheckFairness());
        Assert.Equal(0L,await Sql(owner,"select count(*) from sli_plugin_workstations.projection_receipts where applied_at is null",ct));
        Assert.Equal(8L,await Sql(owner,"select count(*) from sli_plugin_workstations.projection_consumers where backfill_complete",ct));
        Assert.Equal("completed",await Sql(owner,$"select state from sli_jobs.jobs where job_id='{jobId}'",ct));
        Assert.Equal(200002L,await Sql(owner,"select count(*) from sli_plugin_workstations.projection_work",ct));
        double rate=200002/watch.Elapsed.TotalSeconds;
        Assert.True(rate>=6.6*5,$"projection rate {rate:F2} inputs/s below 33 inputs/s");
        output.WriteLine($"200002 inputs / eight projectors: {watch.Elapsed.TotalSeconds:F3}s; {rate:F2} inputs/s; {rate*8:F2} receipts/s; pages={publication!["pages"]}; peak executor connections={maxConnections}; concurrent import={importMs:F2}ms");

        // Separated pending ranges must all receive a share in one page.
        sameSlot=DateTimeOffset.UtcNow;
        await Sql(owner,"""
            with consumers as (select projector_key,row_number() over(order by projector_key)-1 as n from sli_plugin_workstations.projection_consumers)
            update sli_plugin_workstations.projection_receipts r set applied_at=null from consumers c
            where r.projector_key=c.projector_key and r.work_id>c.n*100 and r.work_id<=c.n*100+100;
            analyze sli_plugin_workstations.projection_receipts;
            """,ct);
        var next=await Claim();Assert.NotEqual(jobId,next["job_id"]!.ToString());
        await using(var publisher=Connection(fixture,"sli_job_publisher_light"))
        {
            await publisher.OpenAsync(ct);var implementation=catalog.Resolve(next);var batch=await implementation.Stage(publisher,next,ct);
            long[] ids=batch["work_ids"]!.AsArray().Select(n=>n!.GetValue<long>()).ToArray();
            var shares=await Ws.Rows(owner,"select projector_key,count(*) as n from sli_plugin_workstations.projection_receipts where applied_at is null and work_id=any(@p0) group by projector_key",ct,ids);
            Assert.Equal(8,shares.Count);foreach(var share in shares)Assert.InRange(share.Number("n"),12,13);
            var identities=WorkstationEvaluators.Identities(null);
            await using(var explain=Ws.Command(owner,"explain (analyze,buffers,format json) "+WorkstationJobPlugin.PendingSql,identities.Keys.ToArray(),identities.Values.ToArray(),100))
            {
                string plan=(string)(await explain.ExecuteScalarAsync(ct))!;Assert.Contains("workstation_projection_pending",plan);
                output.WriteLine("fair pending EXPLAIN ANALYZE: "+plan);
            }
            var publishing=new CoreJobQueue(new PostgresCoreJobSession(publisher));long id=ids[0];
            await Sql(owner,$"update sli_plugin_workstations.projection_work set payload=payload||'{{\"synthetic_corruption\":true}}'::jsonb where work_id={id}",ct);
            Assert.Equal("workstation_projection_input_conflict",(await Assert.ThrowsAsync<WorkstationException>(()=>publishing.ApplyBatchAsync(next,batch,t=>implementation.Publish(publisher,next,batch,t),ct))).Message);
            await Sql(owner,$"update sli_plugin_workstations.projection_work set payload=payload-'synthetic_corruption' where work_id={id}",ct);
            Assert.Equal(800L,await Sql(owner,"select count(*) from sli_plugin_workstations.projection_receipts where applied_at is null",ct));
            using var stop=CancellationTokenSource.CreateLinkedTokenSource(ct);int committed=0;
            await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>WorkstationJobPlugin.DrainAsync(publisher,publishing,next,batch,stop.Token,n=>{committed+=n;stop.Cancel();return Task.CompletedTask;}));
            Assert.InRange(committed,1,800);
            Assert.Equal(800L-committed,await Sql(owner,"select count(*) from sli_plugin_workstations.projection_receipts where applied_at is null",ct));
            await Sql(owner,$"update sli_jobs.jobs set lease_until=clock_timestamp()-interval '1 second' where job_id='{next["job_id"]}'",ct);
            await Assert.ThrowsAsync<CoreJobLeaseLost>(()=>queue.HeartbeatAsync(next,ct));
            bool applied=false;
            await Assert.ThrowsAsync<CoreJobLeaseLost>(()=>publishing.ApplyBatchAsync(next,batch,_=>{applied=true;return Task.CompletedTask;},ct));Assert.False(applied);
        }
        Assert.Null(await queue.ClaimAsync("light","synthetic-reaper",registry.Identities("light"),ct));
        await Sql(owner,$"update sli_jobs.jobs set available_at=clock_timestamp() where job_id='{next["job_id"]}' and state='retry_wait'",ct);
        var recovered=(await queue.ClaimAsync("light","synthetic-recovered",registry.Identities("light"),ct))!;
        Assert.True(recovered["lease_generation"]!.GetValue<long>()>next["lease_generation"]!.GetValue<long>());
        await Executor().ExecuteAsync(recovered,ct);
        Assert.Equal("committed",publication?["status"]?.ToString());
        await Sql(owner,"update sli_plugin_workstations.projection_receipts set applied_at=null where work_id=1 and projector_key='workstations.C02'",ct);
        var immediate=await Claim(); // same frozen 15-second schedule slot as next
        Assert.NotEqual(next["job_id"]!.ToString(),immediate["job_id"]!.ToString());
        await Executor().ExecuteAsync(immediate,ct);
        Assert.Equal("committed",publication?["status"]?.ToString());
        Assert.Equal(0L,await Sql(owner,"select count(*) from sli_plugin_workstations.projection_receipts where applied_at is null",ct));
        output.WriteLine("same-slot follow-up, fair disjoint pages, payload hash rollback, committed-page cancellation and expired-fence recovery passed");
    }
}
