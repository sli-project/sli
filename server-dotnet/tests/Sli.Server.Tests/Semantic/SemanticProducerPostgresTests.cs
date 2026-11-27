using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Semantic;

[Collection("Semantic producer environment")]
public sealed class SemanticProducerPostgresTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Backfill_332_migrates_previous_maximum_rolls_back_and_preserves_failed_jobs()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct,throughVersion:331);
        string migration=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/332_semantic_backfill_window");
        await fixture.Pg.ApplyFileAsync(migration+".sql",null,ct);
        await fixture.Pg.ApplyFileAsync(migration+".rollback.sql",null,ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        Assert.Equal(331,await Scalar(admin,"select max(version) from schema_migrations",ct));
        Assert.Equal(0,await Scalar(admin,"select count(*) from pg_attribute where attrelid='semantic_producer_coverage'::regclass and attname='source_unavailable_ids' and not attisdropped",ct));
        await fixture.Pg.ApplyFileAsync(migration+".sql",null,ct);
        Assert.Equal(332,await Scalar(admin,"select max(version) from schema_migrations",ct));
        await SemanticRuntimePostgresTests.SeedNative(admin,ct);
        await PostCollectionPostgres.Sql(admin,"delete from semantic_processing_outbox where source_event_id<>900003",ct);
        await PostCollectionPostgres.Sql(admin,"""
            update semantic_processing_outbox set status='failed',attempt_count=3,last_error_code='semantic_processing_failed';
            update sli_agent_packet_inbox set imported_at=null;
            """,ct);
        await using var worker=new NpgsqlConnection(fixture.Dsn("sli_semantic_login")); await worker.OpenAsync(ct);
        await PostCollectionPostgres.Sql(worker,"set role adlog_semantic_worker",ct);
        await SemanticProduction.Heartbeat(worker,Guid.NewGuid(),SemanticRuntimeSettings.FindingsMode,"running",10,ct);
        Assert.Equal(1,await Scalar(admin,"select count(*) from semantic_processing_outbox where status='failed' and attempt_count=3 and last_error_code='semantic_processing_failed'",ct));
        Assert.Equal(0,await Scalar(admin,"select has_table_privilege('adlog_semantic_worker','sli_agent_packet_inbox','SELECT')::int",ct));
        Assert.Equal(0,await Scalar(admin,"select count(*) from pg_proc p cross join lateral aclexplode(p.proacl) a where p.oid='public.semantic_backfill_window_v332(bigint,integer,text,text)'::regprocedure and a.grantee=0 and a.privilege_type='EXECUTE'",ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Coverage_331_applies_to_330_rolls_back_and_serializes_decision_writers()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct,throughVersion:330);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        await SemanticProduction.Heartbeat(admin,Guid.NewGuid(),SemanticRuntimeSettings.FindingsMode,"running",10,ct);
        await PostCollectionPostgres.Sql(admin,"update runtime_worker_heartbeats set details_json=details_json || '{\"producer_cursors\":{\"findings-v1:1.4+identity-1.0\":900003}}'::jsonb where worker_name='semantic'",ct);
        string migration=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/331_semantic_producer_coverage");
        await fixture.Pg.ApplyFileAsync(migration+".sql",null,ct);
        Assert.Equal(331,await Scalar(admin,"select max(version) from schema_migrations",ct));
        Assert.Equal(0,await Scalar(admin,"select count(*) from runtime_worker_heartbeats where details_json ? 'producer_cursors'",ct));
        await fixture.Pg.ApplyFileAsync(migration+".rollback.sql",null,ct);
        Assert.Equal(330,await Scalar(admin,"select max(version) from schema_migrations",ct));
        Assert.Equal(0,await Scalar(admin,"select has_table_privilege('adlog_storage_lifecycle_guard','semantic_processing_outbox','UPDATE')::int",ct));
        Assert.Equal(1,await Scalar(admin,"select has_column_privilege('adlog_storage_lifecycle_guard','semantic_processing_outbox','source_event_id','UPDATE')::int",ct));
        Assert.Equal(1,await Scalar(admin,"select (to_regclass('semantic_producer_coverage') is null)::int",ct));
        await fixture.Pg.ApplyFileAsync(migration+".sql",null,ct);
        await using var deletion=new NpgsqlConnection(fixture.Dsn("sli_storage_lifecycle_delete_login")); await deletion.OpenAsync(ct);
        await PostCollectionPostgres.Sql(deletion,"set role adlog_storage_lifecycle_delete",ct);
        await using var writer=new NpgsqlConnection(fixture.Dsn("sli_semantic_login")); await writer.OpenAsync(ct);
        await PostCollectionPostgres.Sql(writer,"set role adlog_semantic_worker",ct);
        foreach(string relation in new[]{"semantic_processing_outbox","semantic_producer_coverage"}) {
            await using var tx=await deletion.BeginTransactionAsync(ct);
            await PostCollectionPostgres.Sql(deletion,"select public.lock_semantic_decisions_v331()",ct);
            await using var command=new NpgsqlCommand($"update {relation} set {(relation=="semantic_processing_outbox"?"status=status":"decided_ids=decided_ids")} where false",writer) { CommandTimeout=0 };
            var blocked=command.ExecuteNonQueryAsync(ct);
            while(await Scalar(admin,$"select count(*) from pg_locks where pid={writer.ProcessID} and relation='public.{relation}'::regclass and not granted",ct)==0) {
                if(blocked.IsCompleted) { await blocked; Assert.Fail("Decision writer escaped deletion lock"); }
                ct.ThrowIfCancellationRequested(); await Task.Yield();
            }
            Assert.False(blocked.IsCompleted);
            await tx.CommitAsync(ct); await blocked;
        }
        Assert.Equal(0,await Scalar(deletion,"select has_table_privilege(current_user,'semantic_producer_coverage','UPDATE')::int",ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    internal sealed class Admission : IDisposable
    {
        private readonly Dictionary<string,string?> previous=new();
        internal Admission(string? mode=SemanticRuntimeSettings.FindingsMode) {
            Set("ADLOG_SEMANTIC_PRODUCTION_ENABLED",mode is null?"0":"1"); Set("ADLOG_SEMANTIC_RUNTIME_MODE",mode ?? "");
            foreach(string stage in new[]{"NORMALIZATION","ASSEMBLY","CORRELATION","RISK_ENGINE","FINDING_CREATION"})
                Set("ADLOG_SEMANTIC_"+stage+"_ENABLED",stage is "NORMALIZATION" or "ASSEMBLY" || mode==SemanticRuntimeSettings.FindingsMode || stage=="CORRELATION" && mode==SemanticRuntimeSettings.InvestigationMode?"1":"0");
            Set("ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED","0");
        }
        internal void Set(string name,string? value) { if(!previous.ContainsKey(name)) previous[name]=Environment.GetEnvironmentVariable(name); Environment.SetEnvironmentVariable(name,value); }
        public void Dispose() { foreach(var pair in previous) Environment.SetEnvironmentVariable(pair.Key,pair.Value); }
    }
    [Fact]
    public async Task Outbox_throughput_and_stage_costs_as_native_semantic_login()
    {
        const int batchSize = 128;
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        Assert.Equal(1,await Scalar(admin,"select (to_regclass('public.raw_log_files') is null and to_regclass('public.events_v2_core') is null)::int",ct));
        using var admission=new Admission(); admission.Set("SLI_PLUGIN_LOCK_DIR",Path.Combine(SemanticProduction.SourceBundleRoot(null,AppContext.BaseDirectory),"config/plugin_packages/v3"));
        await using var runtime=Sli.Server.Semantic.Password.PasswordProducerRuntime.Create(n=>n=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
        await using var worker=await runtime.OpenAsync(ct);
        Assert.Equal(1,await Scalar(worker,"select (session_user='sli_semantic_login' and current_user='adlog_semantic_worker')::int",ct));
        await PublishBatch(0);
        var production=new SemanticProduction(runtime,SemanticRuntimeSettings.Read(Environment.GetEnvironmentVariable),SemanticRuntimeSettings.FindingsMode,batchSize);
        var stages=new Dictionary<SemanticProcessingStep,double>();
        var watch=Stopwatch.StartNew();
        var result=await production.ProcessOutbox(worker,ct,(step,time)=>stages[step]=stages.GetValueOrDefault(step)+time.TotalMilliseconds);
        watch.Stop(); output.WriteLine(result.ToJsonString());
        output.WriteLine(FormattableString.Invariant($"CONSUMER: {result.Number("completed")/watch.Elapsed.TotalSeconds:F2} jobs/s; {watch.Elapsed.TotalMilliseconds/batchSize:F2} ms/job; {batchSize} jobs in one lease"));
        foreach(var pair in stages.OrderByDescending(p=>p.Value)) output.WriteLine(FormattableString.Invariant($"{pair.Key}: {pair.Value/batchSize:F3} ms/job"));
        Assert.Contains(SemanticProcessingStep.SourceRead, stages.Keys);
        Assert.Contains(SemanticProcessingStep.PersistNormalized, stages.Keys);
        Assert.Contains(SemanticProcessingStep.Commit, stages.Keys);
        Assert.Equal(batchSize,result.Number("completed")); Assert.Equal(0,result.Number("failed"));
        Assert.Equal(batchSize,await Scalar(admin,"select count(*) from normalized_events",ct));
        Assert.Equal(batchSize,await Scalar(admin,"select count(*) from canonical_actions",ct));
        // Fresh native events: same workload as the baseline, now while a
        // detector connection is stalled. More than --limit must complete.
        await PublishBatch(batchSize);
        var rate=new SemanticQueueRate(); watch.Restart();
        await using var pump=new SemanticOutboxPump(runtime,SemanticRuntimeSettings.Read(Environment.GetEnvironmentVariable),SemanticRuntimeSettings.FindingsMode,16,null,rate,ct);
        await pump.Ready;
        async Task DetectorsAndRisk() {
            // This is a real query on a separate worker connection, like a timed
            // out detector. Subsequent detector/risk steps must still execute.
            await PostCollectionPostgres.Sql(worker,"select pg_sleep(15)",ct);
            for(int step=0;step<4;step++) await PostCollectionPostgres.Sql(worker,"select 1",ct);
        }
        var detectors=DetectorsAndRisk();
        using var bounded=CancellationTokenSource.CreateLinkedTokenSource(ct); bounded.CancelAfter(TimeSpan.FromSeconds(20));
        while(await Scalar(admin,"select count(*) from normalized_events",bounded.Token)<2*batchSize) await Task.Delay(20,bounded.Token);
        watch.Stop();
        output.WriteLine(FormattableString.Invariant($"INDEPENDENT: {batchSize/watch.Elapsed.TotalSeconds:F2} jobs/s, {watch.Elapsed.TotalMilliseconds/batchSize:F2} ms/job, detector still blocked={!detectors.IsCompleted}"));
        Assert.False(detectors.IsCompleted); Assert.True(batchSize/watch.Elapsed.TotalSeconds>=10);
        await detectors;
        var pumped=await pump.StopAsync(); output.WriteLine(pumped.ToJsonString());
        Assert.Equal(batchSize,pumped.Number("completed")); Assert.Equal(0,pumped.Number("failed"));
        Assert.Equal(2*batchSize,await Scalar(admin,"select count(*) from canonical_actions",ct));
        // Replay integrity remains checked in the consumer; no duplicate rows.
        await PostCollectionPostgres.Sql(admin,"update semantic_processing_outbox set status='queued',attempt_count=0,completed_at=null",ct);
        var replay=await production.ProcessOutbox(worker,ct); Assert.Equal(batchSize,replay.Number("completed")); Assert.Equal(0,replay.Number("failed"));
        Assert.Equal(2*batchSize,await Scalar(admin,"select count(*) from normalized_events",ct));
        Assert.Equal(2*batchSize,await Scalar(admin,"select count(*) from canonical_actions",ct));
        Assert.Equal(2*batchSize,await Scalar(admin,"""
            select count(*) from canonical_action_evidence evidence
            join normalized_events normalized using (normalized_event_id)
            join public.semantic_event_source355 source on source.id=normalized.source_event_id
                and source.normalized_hash=normalized.source_event_sha256
            where source.event_id=4625
            """,ct));
        await fixture.AssertNoSqlErrorsAsync(ct);

        async Task PublishBatch(int first)
        {
            var selections = new List<long>(batchSize);
            for (int source = first; source < first + batchSize; source++)
            {
                var (_, rows) = await SemanticRuntimePostgresTests.SeedShortAsync(fixture, admin, source, ct);
                Assert.Equal(3, rows.Length);
                selections.Add(Assert.Single(rows, row => row.Kind == 4625).EventId);
            }
            Assert.Equal(3 * (first + batchSize), await Scalar(admin,"select count(*) from public.semantic_event_source355",ct));
            await using var tx = await worker.BeginTransactionAsync(ct);
            await SemanticProducer.PublishAsync(worker, tx, selections, ct);
            await tx.CommitAsync(ct);
            Assert.Equal(batchSize, await Scalar(admin,"select count(*) from semantic_processing_outbox where status='queued'",ct));
        }
    }
    private static async Task<long> Scalar(NpgsqlConnection db,string sql,CancellationToken ct)
    { await using var c=new NpgsqlCommand(sql,db); return Convert.ToInt64(await c.ExecuteScalarAsync(ct)); }

    [Fact]
    public async Task Investigation_admits_only_exact_reset_context_and_durable_late_expansion()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct); await SemanticProducerParityTests.Prepare(admin,ct);
        await using var worker=new NpgsqlConnection(fixture.Dsn("sli_storage_login")); await worker.OpenAsync(ct);
        await PostCollectionPostgres.Sql(worker,"set role adlog_storage_worker",ct);
        using var admission=new Admission(SemanticRuntimeSettings.InvestigationMode);
        await PostCollectionPostgres.Sql(admin,"insert into storage_v2_keywords(value) values('0x8020000000000001') on conflict do nothing",ct);
        await SemanticProducerParityTests.Event(admin,1000000,4724,ct);
        await SemanticProducerParityTests.Event(admin,1000001,4624,ct,seconds:1800);
        await SemanticProducerParityTests.Event(admin,1000002,4624,ct,sid:"S-1-5-21-100000001-200000002-300000003-1002",seconds:1800);
        await using(var tx=await worker.BeginTransactionAsync(ct)) {
            await SemanticProducer.PublishAsync(worker,tx,[1000000,1000001,1000002],ct); await tx.CommitAsync(ct);
        }
        Assert.Equal(3,await Scalar(admin,"select count(*) from semantic_processing_outbox",ct));
        Assert.Equal(1,await Scalar(admin,"select count(*) from semantic_processing_outbox where source_event_id=1000000 and job_kind='investigation_context'",ct));
        Assert.Equal(1,await Scalar(admin,"select count(*) from semantic_processing_outbox where source_event_id=1000001 and payload_json->>'selection_reason'='related_context'",ct));
        Assert.Equal(0,await Scalar(admin,"select count(*) from semantic_processing_outbox where source_event_id=1000002",ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

}
