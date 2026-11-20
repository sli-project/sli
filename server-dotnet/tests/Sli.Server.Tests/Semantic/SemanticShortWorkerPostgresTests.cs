using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Password;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

[Collection("Semantic producer environment")]
public sealed class SemanticShortWorkerPostgresTests
{
    [Fact]
    public async Task Previous_maximum_accepts_cursor_migration_and_rollback_preserves_decisions()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct,throughVersion:351);
        string migration=Path.Combine(SemanticProduction.SourceBundleRoot(null,AppContext.BaseDirectory),"config/postgres_migrations/355_semantic_short_cursor.sql");
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(owner,"insert into semantic_producer_coverage(runtime_mode,processor_version,decided_ids) values('findings-v1','synthetic','{[41,42)}')",ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration,".rollback.sql"),null,ct);
        await using(var read=new NpgsqlCommand("select decided_ids @> 41::bigint and to_regclass('public.semantic_event_source355') is null from semantic_producer_coverage where processor_version='synthetic'",owner))
            Assert.Equal(true,await read.ExecuteScalarAsync(ct));
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        await using(var read=new NpgsqlCommand("select has_table_privilege('adlog_semantic_worker','semantic_event_source355','SELECT') and not has_table_privilege('adlog_semantic_worker','sli_agent_packet_inbox','SELECT') and not has_table_privilege('adlog_semantic_worker','event_hot','INSERT')",owner))
            Assert.Equal(true,await read.ExecuteScalarAsync(ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Late_lower_id_commit_is_discovered_and_repeated_pass_does_not_duplicate_jobs()
    {
        var ct=TestContext.Current.CancellationToken;
        using var environment=new SemanticProducerPostgresTests.Admission();
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,[rows[1] with { PacketId=null }],ct);
        await using var first=new NpgsqlConnection(fixture.Dsn("sli_storage_login")); await first.OpenAsync(ct);
        await using var tx=await first.BeginTransactionAsync(ct);
        await PostCollectionPostgres.Sql(first,"set local role adlog_storage_worker",ct);
        await ShortEventWriter.WriteAsync(first,tx,[rows[0]],ct);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,[rows[2]],ct);
        await using var worker=new NpgsqlConnection(fixture.Dsn("sli_semantic_login")); await worker.OpenAsync(ct);
        await PostCollectionPostgres.Sql(worker,"set role adlog_semantic_worker",ct);
        var earlier=await SemanticProducerBackfill.RunAsync(worker,SemanticRuntimeSettings.FindingsMode,10,ct);
        Assert.Equal(1,earlier.Number("scanned")); Assert.Equal(1,earlier.Number("queued"));
        await tx.CommitAsync(ct);
        var later=await SemanticProducerBackfill.RunAsync(worker,SemanticRuntimeSettings.FindingsMode,10,ct);
        Assert.Equal(1,later.Number("scanned")); Assert.Equal(1,later.Number("queued"));
        var replay=await SemanticProducerBackfill.RunAsync(worker,SemanticRuntimeSettings.FindingsMode,10,ct);
        Assert.Equal(0,replay.Number("scanned")); Assert.Equal(0,replay.Number("queued"));
        Assert.Equal(rows[2].EventId,earlier.Number("cursor"));
        Assert.Equal(earlier.Number("cursor"),later.Number("cursor")); Assert.Equal(later.Number("cursor"),replay.Number("cursor"));
        await using var read=new NpgsqlCommand("select source_event_id from semantic_processing_outbox order by source_event_id",owner);
        await using(var reader=await read.ExecuteReaderAsync(ct)) {
            Assert.True(await reader.ReadAsync(ct)); Assert.Equal(rows[0].EventId,reader.GetInt64(0));
            Assert.True(await reader.ReadAsync(ct)); Assert.Equal(rows[2].EventId,reader.GetInt64(0));
            Assert.False(await reader.ReadAsync(ct));
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Admitted_short_event_normalizes_assembles_and_builds_scenario_without_old_tables(bool cold)
    {
        var ct=TestContext.Current.CancellationToken;
        using var environment=new SemanticProducerPostgresTests.Admission();
        environment.Set("SLI_PLUGIN_LOCK_DIR",Path.Combine(SemanticProduction.SourceBundleRoot(null,AppContext.BaseDirectory),"config/plugin_packages/v3"));
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,[rows[0]],ct);
        if(cold) await PostCollectionPostgres.Sql(owner,"delete from event_hot",ct);
        await using var runtime=PasswordProducerRuntime.Create(n=>n=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
        await using var worker=await runtime.OpenAsync(ct);
        var backfill=await SemanticProducerBackfill.RunAsync(worker,SemanticRuntimeSettings.FindingsMode,10,ct);
        Assert.Equal(1,backfill.Number("queued"));
        var production=new SemanticProduction(runtime,SemanticRuntimeSettings.Read(Environment.GetEnvironmentVariable),SemanticRuntimeSettings.FindingsMode,10);
        var processed=await production.ProcessOutbox(worker,ct);
        await using(var errors=new NpgsqlCommand("select coalesce(last_error_code,'')||':'||coalesce(last_error_detail,'') from semantic_processing_outbox where status='failed'",owner))
            Assert.True(processed.Number("failed")==0,Convert.ToString(await errors.ExecuteScalarAsync(ct)));
        Assert.Equal(1,processed.Number("completed")); Assert.Equal(0,processed.Number("failed"));
        await using(var tx=await worker.BeginTransactionAsync(ct)) {
            var session=new SemanticSession(worker,tx);
            var normalized=Assert.Single(await session.QueryAsync("select *,encode(semantic_sha256,'hex') as semantic_sha256 from normalized_events",ct))!;
            Assert.Equal("eventlog.cleared.fragment",normalized.Text("semantic_type"));
            Assert.Equal("900001",normalized["roles_json"].Text("source_host"));
            var action=Assert.Single(await session.QueryAsync("select * from canonical_actions",ct))!;
            var policy=new SemanticPolicy("synthetic.short-worker",1,"canonical_action",new(),new string('3',64),
                action.Text("action_kind")!,"synthetic.authentication.failure","security_incident",["source_host"],300,
                "Synthetic failure","Synthetic failure","high",30,30,false,"Synthetic failure",1,[],null);
            var proposal=new SemanticProposal(policy,action.Text("canonical_action_id")!,SigmaProjection.At(normalized,"occurred_at_utc"),"900001",
                new() { ["source_host"]="900001" },new() { ["identity_resolution"]="exact",["state_confirmed"]=false,
                    ["multi_source_confirmed"]=false,["sequence_completeness"]=100,["time_quality"]="good",["parser_quality"]="good" },
                [Guid.Parse(normalized.Text("normalized_event_id")!)],[],[]);
            var scenario=await SemanticProduction.PersistProposal(session,proposal,ct);
            var repeat=await SemanticProduction.PersistProposal(session,proposal,ct);
            Assert.Equal(scenario.Text("scenario_id"),repeat.Text("scenario_id"));
            Assert.Equal(1,repeat.Number("evidence_count")); Assert.Equal(1,repeat.Number("contribution_count"));
            var completeness=await SemanticProduction.Completeness(session,proposal,ct);
            Assert.NotNull(completeness["channel_availability"]);
            await tx.CommitAsync(ct);
        }
        Guid staleToken=Guid.NewGuid();
        // A crashed last attempt must be reclaimable; terminal jobs and a live
        // lease stay untouched. Exercise the real selector under the worker role.
        foreach(string status in new[] { "queued", "failed", "quarantined", "leased" }) {
            await using(var update=new NpgsqlCommand("update semantic_processing_outbox set status=@status,attempt_count=5,completed_at=null,last_error_code=case when @status in ('failed','quarantined') then 'semantic_processing_failed' end,lease_token=case when @status='leased' then @token end,lease_until=case when @status='leased' then now()+interval '1 day' end",owner)) {
                update.Parameters.AddWithValue("status",status); update.Parameters.AddWithValue("token",staleToken); await update.ExecuteNonQueryAsync(ct);
            }
            await using var session=new SemanticSession(worker,await worker.BeginTransactionAsync(ct));
            Assert.Empty(await SemanticProduction.Claim(session,ct)); await session.CommitAsync(ct);
        }
        await PostCollectionPostgres.Sql(owner,"update semantic_processing_outbox set lease_until=now()-interval '8 days'",ct);
        await using(var session=new SemanticSession(worker,await worker.BeginTransactionAsync(ct))) {
            var claimed=Assert.Single(await SemanticProduction.Claim(session,ct))!;
            Assert.Equal(5,claimed.Number("attempt_count")); Assert.NotEqual(staleToken.ToString(),claimed.Text("lease_token"));
            var stale=claimed.DeepClone(); stale["lease_token"]=staleToken.ToString();
            Assert.False(await SemanticProduction.HeartbeatJob(session,stale,ct));
            await Assert.ThrowsAsync<InvalidOperationException>(()=>SemanticProduction.Complete(session,"semantic_processing_outbox","status",stale,ct));
            await Assert.ThrowsAsync<InvalidOperationException>(()=>SemanticProduction.Fail(session,"semantic_processing_outbox","status",stale,ct,new IOException(),SemanticProcessingStep.SourceRead));
            await session.CommitAsync(ct);
        }
        // A second interrupted owner can also resume the same attempt.
        await PostCollectionPostgres.Sql(owner,"update semantic_processing_outbox set lease_until=now()-interval '8 days'",ct);
        var replay=await production.ProcessOutbox(worker,ct);
        Assert.Equal(1,replay.Number("completed")); Assert.Equal(0,replay.Number("failed"));
        await using(var session=new SemanticSession(worker,await worker.BeginTransactionAsync(ct))) {
            var job=Assert.Single(await session.QueryAsync("select job_id,attempt_count,lease_token from semantic_processing_outbox",ct))!;
            Assert.Equal(5,job.Number("attempt_count")); Assert.Null(job["lease_token"]);
            job["lease_token"]=staleToken.ToString();
            await Assert.ThrowsAsync<InvalidOperationException>(()=>SemanticProduction.Complete(session,"semantic_processing_outbox","status",job,ct));
            await session.CommitAsync(ct);
        }
        await using(var count=new NpgsqlCommand("select (select count(*) from normalized_events),(select count(*) from canonical_actions),(select count(*) from semantic_security_scenarios)",owner))
        await using(var r=await count.ExecuteReaderAsync(ct)) { Assert.True(await r.ReadAsync(ct)); Assert.Equal(1,r.GetInt64(0)); Assert.Equal(1,r.GetInt64(1)); Assert.Equal(1,r.GetInt64(2)); }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}

