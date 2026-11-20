using System.Text.Json.Nodes;
using System.Runtime.CompilerServices;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Sli.Server.Storage.Direct;
using Sli.Server.Entities.State;
using Sli.Server.Agents.Consumer;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Entities;

public class EntityStateWorker132DatabaseTests
{
    private static readonly Guid Agent = Guid.Parse("85eea031-26b1-47a6-97b7-05c14593796c");
    private static readonly Guid Host = Guid.Parse("925a2af5-6c59-4169-a53e-c9c7d965c686");
    private static readonly Guid Packet = Guid.Parse("ba9b4f67-6a9c-400c-9e21-c3036e5b47d7");
    private const string Name = "dc-sv2-603d08a32d69";
    private static string Vector([CallerFilePath] string path="")
    {
        for(var dir=new FileInfo(path).Directory;dir is not null;dir=dir.Parent) {
            var file=Path.Combine(dir.FullName,"agent-dotnet","tests","vectors","ad-dc-scenarios.json");
            if(File.Exists(file)) return file;
        }
        throw new FileNotFoundException();
    }
    private static (JsonObject Envelope,JsonObject Packet,JsonArray Rows) Sample()
    {
        var scenario=JsonNode.Parse(File.ReadAllBytes(Vector()))!.AsArray().OfType<JsonObject>().Single(x=>x["name"]!.GetValue<string>()=="security-initial-window-all");
        var step=scenario["steps"]![0]!; var expected=step["expected"]!; string old=scenario["host_id"]!.GetValue<string>();
        var payload=JsonNode.Parse(expected["payload_canonical"]!.GetValue<string>().Replace(old,Host.ToString("D"),StringComparison.Ordinal).Replace("fixture-dc",Name,StringComparison.Ordinal))!.AsObject();
        string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>1</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00.1234575Z'/><Channel>Security</Channel><Computer>{Name}</Computer></System><EventData><Data Name='LogonType'>3</Data></EventData></Event>";
        payload["records"]![0]!["payload"]=EventXml.Parse(xml,Name,"fixture-endpoint","Security");
        var before=JsonNode.Parse(expected["cursor_before"]!.ToJsonString().Replace(old,Host.ToString("D"),StringComparison.Ordinal));
        var after=JsonNode.Parse(expected["cursor_after"]!.ToJsonString().Replace(old,Host.ToString("D"),StringComparison.Ordinal));
        var env=new Envelope(Packet.ToString("D"),Agent.ToString("D"),Host.ToString("D"),"sli.windows.ad-dc","1.0.0","1","ad-dc",Host.ToString("D"),1,
            Cursor.FromJson(before),Cursor.FromJson(after),CollectionPacket.Contract,Packets.Digest(payload),1,CanonicalJson.Length(payload),
            step["now"]!.GetValue<string>(),"not_proven",0,0);
        var rows=AgentAdDcValidator.Validate(env,payload,null,Name);
        return (env.ToJson(),payload,rows);
    }

    private static (JsonObject Envelope,JsonObject Packet,JsonArray Rows) BuildBatch() {
        string sid=TargetSid;var packetId=Guid.Parse("b063e314-2bec-41cf-ac96-ed3a174c77d3");
        var sample=Sample();var payload=(JsonObject)sample.Packet.DeepClone();payload["records"]!.AsArray().Clear();
        int record=13;foreach(int kind in new[]{4624,4722,4740,4720,4722}) {
            string data=kind==4624?"<Data Name='LogonType'>3</Data>":$"<Data Name='TargetSid'>{sid}</Data><Data Name='TargetUserName'>statecase</Data><Data Name='TargetDomainName'>EXAMPLE</Data>";
            string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>{kind}</EventID><EventRecordID>{record}</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00.1234575Z'/><Channel>Security</Channel><Computer>{Name}</Computer></System><EventData>{data}</EventData></Event>";
            payload["records"]!.AsArray().Add(new JsonObject{["format"]="event_xml",["record_id"]=record,["payload"]=EventXml.Parse(xml,Name,"fixture-endpoint","Security")});record++;
        }
        payload["header"]!["cursor"]!["last_record_id"]=17;payload["header"]!["record_id_range"]!["first"]=13;payload["header"]!["record_id_range"]!["last"]=17;
        var envelope=(JsonObject)sample.Envelope.DeepClone();envelope["packet_id"]=packetId.ToString("D");envelope["sequence"]=18;envelope["record_count"]=5;
        envelope["payload_sha256"]=Packets.Digest(payload);envelope["payload_bytes"]=CanonicalJson.Length(payload);
        var state=JsonNode.Parse(envelope["cursor_after"]!["token"]!.GetValue<string>())!.AsObject();state["channels"]!["Security"]!["record_id"]=17;
        state["channels"]!["Security"]!["bookmark"]=state["channels"]!["Security"]!["bookmark"]!.GetValue<string>().Replace("RecordId='1'","RecordId='17'",StringComparison.Ordinal);
        envelope["cursor_after"]!["token"]=CanonicalJson.Serialize(state);
        var rows=AgentAdDcValidator.Validate(Envelope.Parse(envelope),payload,null,Name);return (envelope,payload,rows);
    }
    private const string TargetSid="S-1-5-21-100000001-200000001-300000001-1199";
    [Fact] public void Generated_batch_passes_public_source_admission() => Assert.Equal(5,BuildBatch().Rows.Count);
    [Fact]
    public async Task Real_jobs_serialize_current_and_session_loss_stops_worker()
    {
        var ct=TestContext.Current.CancellationToken;
        var packetId=Guid.Parse("b063e314-2bec-41cf-ac96-ed3a174c77d3");
        string sid=TargetSid;
        var proof=Environment.GetEnvironmentVariable("SLI_STATE_132_PROOF")!;
        await using var fixture=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        await using var app=await fixture.OpenConnectionAsync(ct);
        var secret=JsonNode.Parse(await File.ReadAllBytesAsync(Environment.GetEnvironmentVariable("SLI_STATE_WORKER_SECRET")!,ct))!.AsObject();
        var builder=new NpgsqlConnectionStringBuilder(app.ConnectionString){Username=secret["username"]!.GetValue<string>(),Password=secret["password"]!.GetValue<string>()};
        var env=new Dictionary<string,string?>{["ADLOG_STORAGE_V2_WORKER_DSN"]=builder.ConnectionString,["ADLOG_PG_LOCK_TIMEOUT_MS"]="30000"};
        string catalog=Environment.GetEnvironmentVariable("SLI_SV2_CATALOG")!;
        await using var publisher=DirectAdDcRuntime.TryCreate(k=>env.GetValueOrDefault(k),_=>[],catalog) ?? throw new InvalidOperationException("publisher unavailable");
        await using var worker=EntityStateWorkerRuntime.TryCreate(k=>env.GetValueOrDefault(k),_=>[]) ?? throw new InvalidOperationException("worker unavailable");
        var (envelope,payload,rows)=BuildBatch();
        await using(var tx=await app.BeginTransactionAsync(ct)) {
            await using var receipt=new NpgsqlCommand("""
                insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                values(@agent,'sli.windows.ad-dc',18,@packet,@hash,@envelope,'{"status":"committed"}'::jsonb);
                insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows) values(@packet,@envelope,@payload,@rows)
                """,app,tx);
            receipt.Parameters.AddWithValue("agent",Agent);receipt.Parameters.AddWithValue("packet",packetId);receipt.Parameters.AddWithValue("hash",Packets.Digest(envelope));
            receipt.Parameters.AddWithValue("envelope",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(envelope));receipt.Parameters.AddWithValue("payload",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(payload));receipt.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(rows));
            await receipt.ExecuteNonQueryAsync(ct);await tx.CommitAsync(ct);
        }
        await using(var tx=await app.BeginTransactionAsync(ct)) { await DirectAdDcPacket.ImportAsync(app,tx,publisher.Worker,packetId,envelope,payload,rows,catalog,ct);await tx.CommitAsync(ct); }
        var jobs=new List<Guid>();
        await using(var query=new NpgsqlCommand("select distinct j.job_id,e.event_record_id from entity_state_projection_jobs j join event_hot e on e.event_id=j.source_event_db_id join sli_agent_packet_inbox i on i.packet_id=@packet cross join lateral jsonb_array_elements(i.event_rows) native where (native->>'record_id')::bigint=e.event_record_id and (native->>'time_created')::timestamptz=e.time_created_utc and (native->>'event_id')::integer=e.event_kind and e.method#>>'{$origin,source_instance_id}'=i.envelope->>'source_instance_id' and e.method#>>'{$origin,source_generation}'=i.envelope->>'generation' and e.method->>'$channel'=i.collection_channel order by e.event_record_id",app)) {
            query.Parameters.AddWithValue("packet",packetId);await using var r=await query.ExecuteReaderAsync(ct);while(await r.ReadAsync(ct))jobs.Add(r.GetGuid(0));
        }
        Assert.Equal(4,jobs.Count);
        await using(var eligible=new NpgsqlCommand("""
            select job_id from entity_state_projection_jobs j where job_schema_version=1 and attempt_count<max_attempts and available_at<=now()
              and (status in ('queued','failed') or (status='running' and lease_until<now()))
              and exists(select 1 from event_hot e where e.event_id=j.source_event_db_id and e.source_sha256 is not null)
              and not exists(select 1 from jsonb_array_elements(j.candidate_states) candidate left join entities_v2_active entity on entity.id=resolve_entity_identity_v2((candidate->>'entity_id')::integer) where entity.id is null)
            order by source_event_db_id
            """,app)) {var found=new List<Guid>();await using var r=await eligible.ExecuteReaderAsync(ct);while(await r.ReadAsync(ct))found.Add(r.GetGuid(0));Assert.Equal(jobs,found);}
        var projector=new EntityStateProjector();
        await using var db1=await worker.DataSource.OpenConnectionAsync(ct);await using var db2=await worker.DataSource.OpenConnectionAsync(ct);
        var first=await projector.ClaimAsync(db1,ct);var second=await projector.ClaimAsync(db2,ct);Assert.NotNull(first);Assert.NotNull(second);
        Assert.Equal(jobs[0],first!.Id);Assert.Equal(jobs[1],second!.Id);
        await using var gate=await worker.DataSource.OpenConnectionAsync(ct);
        await using(var tx=await gate.BeginTransactionAsync(ct)) {
            await using(var role=new NpgsqlCommand("set local role adlog_storage_worker",gate,tx))await role.ExecuteNonQueryAsync(ct);
            await using(var hold=new NpgsqlCommand("lock table entity_state_current in share mode",gate,tx))await hold.ExecuteNonQueryAsync(ct);
            await using(var reset=new NpgsqlCommand("reset role",gate,tx))await reset.ExecuteNonQueryAsync(ct);
            int gatePid;await using(var gatePidCommand=new NpgsqlCommand("select pg_backend_pid()",gate,tx))gatePid=(int)(await gatePidCommand.ExecuteScalarAsync(ct))!;
            var one=projector.CompleteAsync(db1,first,ct);var two=projector.CompleteAsync(db2,second,ct);long waiting=0;
            try {
                for(int i=0;i<100;i++) {
                    if(one.IsFaulted)await one;
                    if(two.IsFaulted)await two;
                    await using(var clear=new NpgsqlCommand("select pg_stat_clear_snapshot()",gate,tx))await clear.ExecuteNonQueryAsync(ct);
                    await using var probe=new NpgsqlCommand("select count(*) from pg_stat_activity where usename=@name and wait_event_type='Lock' and datname=current_database() and query like '%entity_state_current%' and @gate=any(pg_blocking_pids(pid))",gate,tx);
                    probe.Parameters.AddWithValue("name",builder.Username!);probe.Parameters.AddWithValue("gate",gatePid);waiting=(long)(await probe.ExecuteScalarAsync(ct))!;if(waiting>=2)break;await Task.Delay(100,ct);
                }
                Assert.Equal(2L,waiting);await tx.CommitAsync(ct);await Task.WhenAll(one,two);
            } finally {
                if(tx.Connection is not null)await tx.RollbackAsync(CancellationToken.None);
                try { await Task.WhenAll(one,two); } catch(Exception error) {
                    var code=error is PostgresException pg?pg.SqlState:"none";
                    await File.WriteAllTextAsync(Path.Combine(proof,"apply-task-error.txt"),$"type={error.GetType().Name}; sqlstate={code}",CancellationToken.None);
                }
            }
        }
        await using(var query=new NpgsqlCommand("select c.status from entity_state_current c join entities_v2 e on e.id=c.entity_id where e.natural_key=@sid and c.state_type='account.access'",app)) {query.Parameters.AddWithValue("sid","sid:"+sid);Assert.Equal("locked",await query.ExecuteScalarAsync(ct));}
        var third=await projector.ClaimAsync(db1,ct);Assert.NotNull(third);Assert.Equal(jobs[2],third!.Id);await projector.CompleteAsync(db1,third,ct);
        int entity;
        await using(var query=new NpgsqlCommand("select id from entities_v2 where natural_key=@sid",app)) {query.Parameters.AddWithValue("sid","sid:"+sid);entity=(int)(await query.ExecuteScalarAsync(ct))!;}
        await using var block=await db2.BeginTransactionAsync(ct);
        await using(var role=new NpgsqlCommand("set local role adlog_storage_worker",db2,block))await role.ExecuteNonQueryAsync(ct);
        await using(var hold=new NpgsqlCommand("select entity_id from entity_state_current where entity_id=@id and state_type='account.access' for update",db2,block)) {hold.Parameters.AddWithValue("id",entity);Assert.Equal(entity,await hold.ExecuteScalarAsync(ct));}
        var actual=new EntityStateWorker(worker);var running=actual.RunAsync(true,30,1,ct);
        int pid=0;
        for(int i=0;i<100;i++) {
            await using var probe=new NpgsqlCommand("select pid from pg_stat_activity where usename=@name and wait_event_type='Lock' and datname=current_database() and query like '%entity_state_current%'",db1);
            probe.Parameters.AddWithValue("name",builder.Username!);var found=await probe.ExecuteScalarAsync(ct);if(found is int value){pid=value;break;}await Task.Delay(100,ct);
        }
        Assert.True(pid>0);
        await using(var contender=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_entity_state_worker'))",db1))Assert.Equal(false,await contender.ExecuteScalarAsync(ct));
        await File.WriteAllTextAsync(Path.Combine(proof,"owned-worker-pid.txt"),pid.ToString(),ct);
        var outcome=await Record.ExceptionAsync(async()=>await running);Assert.NotNull(outcome);await block.RollbackAsync(ct);
        await using(var check=new NpgsqlCommand("select status from entity_state_projection_jobs where job_id=@job",app)){check.Parameters.AddWithValue("job",jobs[3]);Assert.Equal("running",await check.ExecuteScalarAsync(ct));}
        await using(var check=new NpgsqlCommand("select count(*) from entity_states s join entity_state_projection_jobs j on j.source_event_db_id=s.evidence_event_id where j.job_id=@job",app)){check.Parameters.AddWithValue("job",jobs[3]);Assert.Equal(0L,(long)(await check.ExecuteScalarAsync(ct))!);}
        await using(var check=new NpgsqlCommand("select status from entity_state_current where entity_id=@id and state_type='account.access'",app)){check.Parameters.AddWithValue("id",entity);Assert.Equal("locked",await check.ExecuteScalarAsync(ct));}
        await using(var check=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_entity_state_worker'))",db1))Assert.Equal(true,await check.ExecuteScalarAsync(ct));
        await using(var unlock=new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_entity_state_worker'))",db1))Assert.Equal(true,await unlock.ExecuteScalarAsync(ct));
    }
    [Fact]
    public async Task Continue_owned_jobs_and_stop_on_owned_session_loss()
    {
        var ct=TestContext.Current.CancellationToken;
        var expected=new[]{Guid.Parse("636bc66e-3f06-548d-8a7f-c1b8d00b2aa0"),Guid.Parse("a254b092-3209-5929-899d-81901fb7dc63")};
        var proof=Environment.GetEnvironmentVariable("SLI_STATE_132_PROOF")!;
        await using var fixture=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        await using var app=await fixture.OpenConnectionAsync(ct);
        var secret=JsonNode.Parse(await File.ReadAllBytesAsync(Environment.GetEnvironmentVariable("SLI_STATE_WORKER_SECRET")!,ct))!.AsObject();
        var builder=new NpgsqlConnectionStringBuilder(app.ConnectionString){Username=secret["username"]!.GetValue<string>(),Password=secret["password"]!.GetValue<string>()};
        var env=new Dictionary<string,string?>{["ADLOG_STORAGE_V2_WORKER_DSN"]=builder.ConnectionString,["ADLOG_PG_LOCK_TIMEOUT_MS"]="30000"};
        await using var runtime=EntityStateWorkerRuntime.TryCreate(k=>env.GetValueOrDefault(k),_=>[]) ?? throw new InvalidOperationException("worker unavailable");
        await using(var eligible=new NpgsqlCommand("""
            select job_id from entity_state_projection_jobs j where job_schema_version=1 and attempt_count<max_attempts and available_at<=now()
              and (status in ('queued','failed') or (status='running' and lease_until<now()))
              and exists(select 1 from event_hot e where e.event_id=j.source_event_db_id and e.source_sha256 is not null)
              and not exists(select 1 from jsonb_array_elements(j.candidate_states) candidate left join entities_v2_active entity on entity.id=resolve_entity_identity_v2((candidate->>'entity_id')::integer) where entity.id is null)
            order by source_event_db_id
            """,app)) {var found=new List<Guid>();await using var r=await eligible.ExecuteReaderAsync(ct);while(await r.ReadAsync(ct))found.Add(r.GetGuid(0));Assert.Equal(expected,found);}
        JsonObject? firstResult=null;
        Assert.Equal(0,await new EntityStateWorker(runtime).RunAsync(true,30,1,ct,r=>firstResult=r));
        Assert.NotNull(firstResult);Assert.Equal(1,(int)firstResult!["claimed"]!);Assert.Equal(1,(int)firstResult["completed"]!);
        await using(var check=new NpgsqlCommand("select status from entity_state_projection_jobs where job_id=@id",app)){check.Parameters.AddWithValue("id",expected[0]);Assert.Equal("completed",await check.ExecuteScalarAsync(ct));}
        int entity;
        await using(var query=new NpgsqlCommand("select id from entities_v2 where natural_key=@sid",app)){query.Parameters.AddWithValue("sid","sid:"+TargetSid);entity=(int)(await query.ExecuteScalarAsync(ct))!;}
        await using var observer=await runtime.DataSource.OpenConnectionAsync(ct);
        await using var blocking=await runtime.DataSource.OpenConnectionAsync(ct);
        await using var tx=await blocking.BeginTransactionAsync(ct);
        await using(var role=new NpgsqlCommand("set local role adlog_storage_worker",blocking,tx))await role.ExecuteNonQueryAsync(ct);
        await using(var row=new NpgsqlCommand("select entity_id from entity_state_current where entity_id=@id and state_type='account.access' for update",blocking,tx)){row.Parameters.AddWithValue("id",entity);Assert.Equal(entity,await row.ExecuteScalarAsync(ct));}
        var running=new EntityStateWorker(runtime).RunAsync(true,30,1,ct);int pid=0;
        for(int i=0;i<100;i++) {
            await using(var clear=new NpgsqlCommand("select pg_stat_clear_snapshot()",observer))await clear.ExecuteNonQueryAsync(ct);
            await using var probe=new NpgsqlCommand("select pid from pg_stat_activity where usename=@name and wait_event_type='Lock' and datname=current_database() and query like '%entity_state_current%'",observer);
            probe.Parameters.AddWithValue("name",builder.Username!);if(await probe.ExecuteScalarAsync(ct) is int found){pid=found;break;}await Task.Delay(100,ct);
        }
        Assert.True(pid>0);
        await using(var contender=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_entity_state_worker'))",observer))Assert.Equal(false,await contender.ExecuteScalarAsync(ct));
        await File.WriteAllTextAsync(Path.Combine(proof,"owned-worker-pid.txt"),pid.ToString(),ct);
        var outcome=await Record.ExceptionAsync(async()=>await running);Assert.NotNull(outcome);await tx.RollbackAsync(ct);
        await using(var check=new NpgsqlCommand("select status from entity_state_projection_jobs where job_id=@id",app)){check.Parameters.AddWithValue("id",expected[1]);Assert.Equal("running",await check.ExecuteScalarAsync(ct));}
        await using(var check=new NpgsqlCommand("select count(*) from entity_states s join entity_state_projection_jobs j on j.source_event_db_id=s.evidence_event_id where j.job_id=@id",app)){check.Parameters.AddWithValue("id",expected[1]);Assert.Equal(0L,(long)(await check.ExecuteScalarAsync(ct))!);}
        await using(var check=new NpgsqlCommand("select status from entity_state_current where entity_id=@id and state_type='account.access'",app)){check.Parameters.AddWithValue("id",entity);Assert.Equal("locked",await check.ExecuteScalarAsync(ct));}
        await using(var contender=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_entity_state_worker'))",observer))Assert.Equal(true,await contender.ExecuteScalarAsync(ct));
        await using(var release=new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_entity_state_worker'))",observer))Assert.Equal(true,await release.ExecuteScalarAsync(ct));
    }
}
