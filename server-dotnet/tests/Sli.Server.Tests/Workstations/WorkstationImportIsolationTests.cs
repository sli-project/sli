using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Jobs;
using Sli.Server.Workstations;
using Xunit;

namespace Sli.Server.Tests.Workstations;

public sealed class WorkstationImportIsolationTests
{
    [Fact]
    public async Task Publisher_releases_registration_lock_before_projection_reads_and_import_trigger_can_enqueue()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct,throughVersion:375);
        string migration=Path.Combine(Agents.PostCollectionPostgres.Repository(),"config/postgres_migrations/376_workstation_import_isolation.sql");
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString);await admin.OpenAsync(ct);
        await Agents.PostCollectionPostgres.Sql(admin,"""
            alter role sli_job_dispatcher_light login;alter role sli_job_publisher_light login;alter role sli_job_executor_light login;
            update plugin_installations_v1 set desired_activation='enabled_manual',component_runtime='running' where plugin_id='sli.workstations';
            """,ct);
        await using var dispatcher=new NpgsqlConnection(fixture.Dsn("sli_job_dispatcher_light"));await dispatcher.OpenAsync(ct);
        await using var publisher=new NpgsqlConnection(fixture.Dsn("sli_job_publisher_light"));await publisher.OpenAsync(ct);
        foreach(string role in new[]{"adlog_user","sli_job_dispatcher_light","sli_job_executor_light","sli_job_publisher_light"}) {
            await using var session=new NpgsqlConnection(fixture.Dsn(role));await session.OpenAsync(ct);
            Assert.True(await Ws.Scalar(session,"select public.workstation_runtime_enabled_v376()",ct) is true);
            Assert.False(await Ws.Scalar(admin,"select has_table_privilege(@p0,'public.plugin_installations_v1','SELECT')",ct,role) is true);
        }
        Assert.False(await Ws.Scalar(admin,"select has_function_privilege('sli_job_publisher_heavy','public.workstation_runtime_enabled_v376()','EXECUTE')",ct) is true);
        var catalog=CoreJobPluginCatalog.Compiled();var registry=catalog.Registry(null);
        var queue=new CoreJobQueue(new PostgresCoreJobSession(dispatcher));
        var source=JsonNode.Parse((string)(await Ws.Scalar(dispatcher,"select read_workstation_projection_job_source_v1()::text",ct))!)!.AsObject();
        var spec=CoreJobScheduler.Create(registry,"light",source,DateTimeOffset.UtcNow,WorkstationJobPlugin.Pin)
            .Single(s=>s["handler_id"]!.ToString()=="workstations.overview-project");
        await queue.EnqueueAsync(spec,ct);
        var job=await queue.ClaimAsync("light","synthetic-isolation",registry.Identities("light"),ct);Assert.NotNull(job);
        var first=await catalog.Resolve(job).Stage(publisher,job,ct);
        bool imported=false;
        var result=await WorkstationJobPlugin.DrainAsync(publisher,new(new PostgresCoreJobSession(publisher)),job,first,ct,publishing:async()=> {
            if(imported)return;
            Assert.True(await Ws.Scalar(admin,"select xact_start is not null from pg_stat_activity where pid=@p0",ct,publisher.ProcessID) is true);
            await using var tx=await admin.BeginTransactionAsync(ct);
            // This is the lock requested by the real observation INSERT trigger.
            // Test it without waiting so a regression reports a failure directly.
            Assert.True(await Ws.Scalar(admin,"select pg_try_advisory_xact_lock_shared(hashtext('workstations.projection-consumers'))",ct) is true);
            await Ws.Exec(admin,"""
                select sli_plugin_workstations.enqueue_projection_input('observations',jsonb_build_object(
                    'id',repeat('f',64),'agent_key','synthetic-unbound-agent','family','logons','event_id',4624,
                    'observed_at','2026-11-01T00:00:00Z','observation','{}'::jsonb))
                """,ct);
            await tx.CommitAsync(ct);imported=true;
        });
        Assert.True(imported);Assert.Equal("committed",result["status"]!.ToString());
        Assert.Equal(1L,await Ws.Scalar(admin,"select count(*) from sli_plugin_workstations.projection_work where source_id=repeat('f',64)",ct));
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration,".rollback.sql"),null,ct);
        Assert.True(await Ws.Scalar(admin,"select to_regprocedure('public.workstation_runtime_enabled_v376()') is null",ct) is true);
        Assert.Equal(1L,await Ws.Scalar(admin,"select count(*) from sli_plugin_workstations.projection_work where source_id=repeat('f',64)",ct));
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        Assert.True(await Ws.Scalar(publisher,"select public.workstation_runtime_enabled_v376()",ct) is true);
    }
}
