using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Agents.Consumer;
using Sli.Server.Infrastructure;
using Sli.Server.Jobs;
using Sli.Server.Storage.Direct;
using Sli.Server.Workstations;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed partial class AdDcImportPerformanceTests
{
    [Fact]
    public async Task Disabled_workstations_do_not_touch_their_schema_or_block_dc_import_under_a_projection_reader()
    {
        var ct=TestContext.Current.CancellationToken;
        using var environment=new Semantic.SemanticProducerPostgresTests.Admission(mode:null);
        environment.Set("SLI_PLUGIN_RUNTIME_DIR",null);environment.Set("SLI_PLUGIN_LOCK_DIR",null);
        await using var fixture=new SqlPostgresFixture();await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString);await admin.OpenAsync(ct);
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert=new CertificateRequest("CN=synthetic",key,HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(1));
        await SeedAsync(admin,fixture.Pg.Root,cert,ct);
        // The DC agent can also have old workstation packets in the shared inbox.
        var workstation=Guid.NewGuid();
        await using(var insert=new NpgsqlCommand("""
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            values(@agent,'sli.workstations',1,@packet,repeat('a',64),
                jsonb_build_object('agent_id',@agent::text,'module_id','sli.workstations'),'{"status":"committed"}');
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at)
            values(@packet,jsonb_build_object('agent_id',@agent::text,'module_id','sli.workstations'),'{}','[]','2026-01-01');
            revoke all on schema sli_plugin_workstations from adlog_user;
            update plugin_installations_v1 set desired_activation='disabled',component_runtime='stopped' where plugin_id='sli.workstations';
            """,admin)) {
            insert.Parameters.AddWithValue("packet",workstation);insert.Parameters.AddWithValue("agent",Agent);await insert.ExecuteNonQueryAsync(ct);
        }
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["ConnectionStrings:Sli"]=new NpgsqlConnectionStringBuilder(fixture.Dsn("adlog_user")) { NoResetOnClose=true }.ConnectionString
        }).Build();
        Assert.True(AgentImportCommand.TryCreateFactory(config,out var factory));
        await using var worker=new NpgsqlDataSourceBuilder(fixture.Dsn("sli_storage_login")).Build();
        var runtime=new DirectAdDcRuntime(worker,Path.Combine(PostCollectionPostgres.Repository(),"config/event_catalog.json"));
        var consumer=new AgentWorkstationInboxConsumer(factory!,runtime);
        await using var reader=new NpgsqlConnection(fixture.Pg.ConnectionString);await reader.OpenAsync(ct);
        await using var held=await reader.BeginTransactionAsync(ct);
        // Keep a projection read and the same registration lock as the publisher
        // open until import completes. No timeout releases the test's blocker.
        await PostCollectionPostgres.Sql(reader,"""
            select count(*) from sli_plugin_workstations.projection_receipts;
            select pg_advisory_xact_lock(hashtext('workstations.projection-consumers'));
            lock sli_plugin_workstations.observations in access exclusive mode;
            """,ct);
        int total=0;
        foreach(string? flag in new string?[]{null,"0","1"}) {
            environment.Set("SLI_CORE_JOB_WORKSTATIONS_PROJECTION",flag);
            // Default/off must win even over an old enabled registry entry;
            // explicit opt-in must still respect a disabled registry entry.
            await using(var activation=new NpgsqlCommand("update plugin_installations_v1 set desired_activation=@state where plugin_id='sli.workstations'",admin)) {
                activation.Parameters.AddWithValue("state",flag=="1"?"disabled":"enabled_manual");await activation.ExecuteNonQueryAsync(ct);
            }
            await using(var connection=await factory!.OpenAsync(ct)) {
                var catalog=new CoreJobPluginCatalog();new WorkstationJobPlugin().Register(catalog);
                await catalog.ScheduleAsync("sli.workstations",connection,new(new PostgresCoreJobSession(connection)),catalog.Registry(null),"light",ct);
                var job=new JsonObject { ["plugin_id"]="sli.workstations",["source_instance_id"]="workstations:projection",["handler_id"]="workstations.overview-project" };
                if(flag=="1")Assert.Equal("agent_plugin_disabled",(await Assert.ThrowsAsync<WorkstationException>(()=>
                    WorkstationJobPlugin.DrainAsync(connection,new(new PostgresCoreJobSession(connection)),job,new(),ct))).Message);
                else Assert.False(CoreJobWorker.Enabled(job,Environment.GetEnvironmentVariable));
            }
            for(int n=0;n<3;n++)await ReceiptAsync(admin,Sample(++total),ct);
            var result=await consumer.RunOnceAsync(3,ct);
            Assert.Equal(3,result.Imported);Assert.Equal(3,result.Scanned);Assert.Empty(result.PendingReasons);
        }
        await using(var check=new NpgsqlCommand("""
            select (select count(*) from event_hot),
                imported_at is null and module_disabled_at is not null,
                exists(select 1 from sli_agent_receipts where packet_id=@packet and receipt->>'status'='committed'),
                exists(select 1 from pg_locks where pid=@reader and granted and mode='AccessExclusiveLock')
            from sli_agent_packet_inbox where packet_id=@packet
            """,admin)) {
            check.Parameters.AddWithValue("reader",reader.ProcessID);check.Parameters.AddWithValue("packet",workstation);
            await using var rows=await check.ExecuteReaderAsync(ct);Assert.True(await rows.ReadAsync(ct));
            Assert.Equal(total,rows.GetInt64(0));Assert.True(rows.GetBoolean(1));Assert.True(rows.GetBoolean(2));Assert.True(rows.GetBoolean(3));
        }
        await held.RollbackAsync(ct);
        // The factory enforces pooling even if the incoming DSN disabled it.
        int pid;
        await using(var connection=await factory!.OpenAsync(ct)) {
            pid=connection.ProcessID;
            await PostCollectionPostgres.Sql(connection,"set application_name='synthetic-dirty';create temporary table synthetic_import_pool(id int)",ct);
        }
        await using(var connection=await factory!.OpenAsync(ct)) {
            Assert.Equal(pid,connection.ProcessID);
            await using var check=new NpgsqlCommand("select to_regclass('pg_temp.synthetic_import_pool') is null,current_setting('application_name')<>'synthetic-dirty'",connection);
            await using var rows=await check.ExecuteReaderAsync(ct);Assert.True(await rows.ReadAsync(ct));
            Assert.True(rows.GetBoolean(0));Assert.True(rows.GetBoolean(1));
        }
    }
}
