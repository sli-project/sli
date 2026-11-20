using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Entities.State;
using Sli.Server.Tests.Integration;
using Xunit;
namespace Sli.Server.Tests.Entities;
public class EntityStateWorkerDatabaseTests
{
    [Fact] public async Task Existing_owned_jobs_apply_once_under_source_claim() {
        var ct=TestContext.Current.CancellationToken;
        var ids=new[]{Guid.Parse("d458d8e9-dacd-5305-87e5-9c5c9456ee3e"),Guid.Parse("2f657235-4348-593f-a8d4-e0ef45c1e539"),Guid.Parse("5983b487-6daa-52bc-9bb0-c0d61eaf44a2")};
        await using var fixture=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        await using var app=await fixture.OpenConnectionAsync(ct);
        var secret=JsonNode.Parse(await File.ReadAllBytesAsync(Environment.GetEnvironmentVariable("SLI_STATE_WORKER_SECRET")!,ct))!.AsObject();
        var connection=new NpgsqlConnectionStringBuilder(app.ConnectionString) { Username=secret["username"]!.GetValue<string>(),Password=secret["password"]!.GetValue<string>() };
        var env=new Dictionary<string,string?> { ["ADLOG_STORAGE_V2_WORKER_DSN"]=connection.ConnectionString };
        await using var runtime=EntityStateWorkerRuntime.TryCreate(k=>env.GetValueOrDefault(k),_=>[]) ?? throw new InvalidOperationException("worker configuration missing");
        await using(var worker=await runtime.DataSource.OpenConnectionAsync(ct)) {
            await using(var role=new NpgsqlCommand("set role adlog_storage_worker",worker))await role.ExecuteNonQueryAsync(ct);
            await using(var role=new NpgsqlCommand("select current_user",worker))Assert.Equal("adlog_storage_worker",await role.ExecuteScalarAsync(ct));
            await using var check=new NpgsqlCommand("""
                select job.job_id from entity_state_projection_jobs job
                where job.job_schema_version=1 and job.attempt_count<job.max_attempts and job.available_at<=now()
                  and (job.status in ('queued','failed') or (job.status='running' and job.lease_until<now()))
                  and exists(select 1 from event_hot event where event.event_id=job.source_event_db_id and event.source_sha256 is not null)
                  and not exists(select 1 from jsonb_array_elements(job.candidate_states) candidate
                    left join entities_v2_active entity on entity.id=resolve_entity_identity_v2((candidate->>'entity_id')::integer)
                    where entity.id is null)
                order by job.source_event_db_id
                """,worker);
            var eligible=new List<Guid>();await using var r=await check.ExecuteReaderAsync(ct);while(await r.ReadAsync(ct))eligible.Add(r.GetGuid(0));
            Assert.Equal(ids,eligible);
        }
        await using(var check=new NpgsqlCommand("select count(*) from runtime_worker_heartbeats where worker_name='entity_state'",app))Assert.Equal(0L,(long)(await check.ExecuteScalarAsync(ct))!);
        await using(var check=new NpgsqlCommand("select count(*) from entity_state_current where entity_id=56",app))Assert.Equal(0L,(long)(await check.ExecuteScalarAsync(ct))!);
        JsonObject? output=null;
        var exit=await new EntityStateWorker(runtime).RunAsync(true,30,3,ct,r=>output=r);
        Assert.Equal(0,exit);Assert.NotNull(output);Assert.Equal(3,(int)output!["completed"]!);Assert.Equal(0,(int)output["failed"]!);
        await using(var check=new NpgsqlCommand("select count(*) from entity_state_projection_jobs where job_id=any(@ids) and status='completed'",app)) {check.Parameters.AddWithValue("ids",ids);Assert.Equal(3L,(long)(await check.ExecuteScalarAsync(ct))!);}
        await using(var check=new NpgsqlCommand("select count(*) from entity_states where entity_id=56 and evidence_event_id in (select source_event_db_id from entity_state_projection_jobs where job_id=any(@ids))",app)) {check.Parameters.AddWithValue("ids",ids);Assert.Equal(3L,(long)(await check.ExecuteScalarAsync(ct))!);}
        await using(var check=new NpgsqlCommand("select state_type,status from entity_state_current where entity_id=56 order by state_type",app)) {await using var r=await check.ExecuteReaderAsync(ct);var rows=new List<(string,string)>();while(await r.ReadAsync(ct))rows.Add((r.GetString(0),r.GetString(1)));Assert.Equal(new[]{("account.access","locked"),("account.lifecycle","created")},rows);}
        await using var replayConnection=await runtime.DataSource.OpenConnectionAsync(ct);
        var replay=await new EntityStateProjector().RunOnceAsync(replayConnection,3,ct);Assert.Equal(0,replay.Claimed);
    }
}
