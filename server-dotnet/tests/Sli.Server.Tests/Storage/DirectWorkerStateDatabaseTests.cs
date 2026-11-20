using System.Text.Json.Nodes;
using System.Runtime.CompilerServices;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Sli.Server.Storage.Direct;
using Sli.Server.Agents.Consumer;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Storage;

[Collection("Semantic producer environment")]
public class DirectWorkerStateDatabaseTests
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
    [Fact]
    public void Source_state_events_pass_native_agent_admission()
    {
        var sample=Sample();var payload=(JsonObject)sample.Packet.DeepClone();payload["records"]!.AsArray().Clear();
        int record=9;foreach(int kind in new[]{4624,4720,4722,4740}) {
            string data=kind==4624 ? "<Data Name='LogonType'>3</Data>" : "<Data Name='TargetSid'>S-1-5-21-100000001-200000001-300000001-1102</Data><Data Name='TargetUserName'>alice</Data><Data Name='TargetDomainName'>EXAMPLE</Data>";
            string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>{kind}</EventID><EventRecordID>{record}</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00.1234575Z'/><Channel>Security</Channel><Computer>{Name}</Computer></System><EventData>{data}</EventData></Event>";
            payload["records"]!.AsArray().Add(new JsonObject{["format"]="event_xml",["record_id"]=record,["payload"]=EventXml.Parse(xml,Name,"fixture-endpoint","Security")});record++;
        }
        payload["header"]!["cursor"]!["last_record_id"]=12;payload["header"]!["record_id_range"]!["first"]=9;payload["header"]!["record_id_range"]!["last"]=12;
        var env=(JsonObject)sample.Envelope.DeepClone();env["record_count"]=4;env["payload_sha256"]=Packets.Digest(payload);env["payload_bytes"]=CanonicalJson.Length(payload);
        var state=JsonNode.Parse(env["cursor_after"]!["token"]!.GetValue<string>())!.AsObject();state["channels"]!["Security"]!["record_id"]=12;
        state["channels"]!["Security"]!["bookmark"]=state["channels"]!["Security"]!["bookmark"]!.GetValue<string>().Replace("RecordId='1'","RecordId='12'",StringComparison.Ordinal);env["cursor_after"]!["token"]=CanonicalJson.Serialize(state);
        var rows=AgentAdDcValidator.Validate(Envelope.Parse(env),payload,null,Name);Assert.Equal(4,rows.Count);Assert.Equal(4,DirectAdDcPacket.PrepareBatch(rows).Count);
    }
    [Fact]
    public async Task Mixed_state_jobs_rollback_replay_and_unknown_pending()
    {
        using var environment=new Sli.Server.Tests.Semantic.SemanticProducerPostgresTests.Admission(mode:null);
        environment.Set("Sli__Storage__ShortEventReads","false");
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        await using var db=await fixture.OpenConnectionAsync(ct);
        var secret=JsonNode.Parse(await File.ReadAllBytesAsync(Environment.GetEnvironmentVariable("SLI_SV2_WORKER_SECRET")!,ct))!.AsObject();
        Assert.Equal("sli_sv2_state_a57ae169",secret["username"]!.GetValue<string>());
        Guid supported=Guid.Parse("a57ae169-ec5a-4f55-ae79-7b15358d07e1"), unsupported=Guid.Parse("4f340616-6d66-46c8-9807-f9f9a7ad6156");
        (DateTime Received,Guid Packet) after;
        await using(var previous=new NpgsqlCommand("select received_at,packet_id from sli_agent_packet_inbox where packet_id='2b719fee-903b-4cb3-9ef4-2a4a4edee662'",db)) {
            await using var r=await previous.ExecuteReaderAsync(ct);Assert.True(await r.ReadAsync(ct));after=(r.GetDateTime(0),r.GetGuid(1));
        }
        var sample=Sample();
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            for(int i=0;i<2;i++) {
                var payload=(JsonObject)sample.Packet.DeepClone();
                string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>9</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00.1234575Z'/><Channel>Security</Channel><Computer>{Name}</Computer></System><EventData><Data Name='LogonType'>3</Data></EventData></Event>";
                payload["records"]![0]!["payload"]=EventXml.Parse(xml,Name,"fixture-endpoint","Security");payload["records"]![0]!["record_id"]=9;
                int record=10;
                foreach(int kind in new[]{4720,4722,4740}) {
                    string extra=i==1 && kind==4740 ? "<Data Name='UnsupportedField'>x</Data>" : "";
                    string x=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>{kind}</EventID><EventRecordID>{record}</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00.1234575Z'/><Channel>Security</Channel><Computer>{Name}</Computer></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-100000001-200000001-300000001-1101</Data><Data Name='SubjectUserName'>operator</Data><Data Name='SubjectDomainName'>EXAMPLE</Data><Data Name='TargetSid'>S-1-5-21-100000001-200000001-300000001-1102</Data><Data Name='TargetUserName'>alice</Data><Data Name='TargetDomainName'>EXAMPLE</Data>{extra}</EventData></Event>";
                    payload["records"]!.AsArray().Add(new JsonObject { ["format"]="event_xml",["record_id"]=record,["payload"]=EventXml.Parse(x,Name,"fixture-endpoint","Security") });record++;
                }
                payload["header"]!["cursor"]!["last_record_id"]=12;payload["header"]!["record_id_range"]!["first"]=9;payload["header"]!["record_id_range"]!["last"]=12;
                var envelope=(JsonObject)sample.Envelope.DeepClone();Guid id=i==0?supported:unsupported;
                envelope["packet_id"]=id.ToString("D");envelope["sequence"]=i+16;
                var state=JsonNode.Parse(envelope["cursor_after"]!["token"]!.GetValue<string>())!.AsObject();
                state["channels"]!["Security"]!["record_id"]=12;
                state["channels"]!["Security"]!["bookmark"]=state["channels"]!["Security"]!["bookmark"]!.GetValue<string>().Replace("RecordId='1'","RecordId='12'",StringComparison.Ordinal);
                envelope["cursor_after"]!["token"]=CanonicalJson.Serialize(state);
                envelope["record_count"]=4;envelope["payload_sha256"]=Packets.Digest(payload);envelope["payload_bytes"]=CanonicalJson.Length(payload);
                var rows=AgentAdDcValidator.Validate(Envelope.Parse(envelope),payload,null,Name);
                await using var insert=new NpgsqlCommand("""
                    insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                    values(@agent,'sli.windows.ad-dc',@sequence,@packet,@hash,@envelope,'{"status":"committed"}'::jsonb);
                    insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows) values(@packet,@envelope,@payload,@rows)
                    """,db,tx);
                insert.Parameters.AddWithValue("agent",Agent);insert.Parameters.AddWithValue("sequence",(long)i+16);insert.Parameters.AddWithValue("packet",id);
                insert.Parameters.AddWithValue("hash",Packets.Digest(envelope));insert.Parameters.AddWithValue("envelope",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(envelope));
                insert.Parameters.AddWithValue("payload",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(payload));insert.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(rows));
                await insert.ExecuteNonQueryAsync(ct);
            }
            await tx.CommitAsync(ct);
        }
        string catalog=Environment.GetEnvironmentVariable("SLI_SV2_CATALOG")!;
        var env=new Dictionary<string,string?> { ["ADLOG_STORAGE_V2_WORKER_DSN"]="host=127.0.0.1 port=60872 dbname=sli_oracle user=sli_sv2_state_a57ae169 sslmode=disable", ["ADLOG_STORAGE_V2_WORKER_PASSWORD"]=secret["password"]!.GetValue<string>() };
        await using var runtime=DirectAdDcRuntime.TryCreate(k=>env.GetValueOrDefault(k),_=>[],catalog);Assert.NotNull(runtime);
        await using var contender=await fixture.OpenConnectionAsync(ct);
        await using(var hold=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))",db))Assert.Equal(true,await hold.ExecuteScalarAsync(ct));
        await using(var blocked=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))",contender))Assert.Equal(false,await blocked.ExecuteScalarAsync(ct));
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            var first=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,after,ct,runtime);
            Assert.True(first.Imported,first.PendingReason);Assert.Equal(supported,first.PacketId);await tx.RollbackAsync(ct);
            await using(var absent=new NpgsqlCommand("select count(*) from entity_state_projection_jobs j join events_v2_core e on e.id=j.source_event_db_id where e.event_record_id between 10 and 12 and e.server_id=(select id from servers where hostname=@name)",db)) { absent.Parameters.AddWithValue("name",Name);Assert.Equal(0L,(long)(await absent.ExecuteScalarAsync(ct))!); }
            await using var stillHeld=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))",contender);Assert.Equal(false,await stillHeld.ExecuteScalarAsync(ct));
        }
        (DateTime Received,Guid Packet) next;
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            var replay=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,after,ct,runtime);
            Assert.True(replay.Imported,replay.PendingReason);Assert.Equal(supported,replay.PacketId);next=(replay.Received,replay.PacketId);await tx.CommitAsync(ct);
        }
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            JsonObject savedEnvelope,savedPacket;JsonArray savedRows;
            await using(var get=new NpgsqlCommand("select envelope::text,packet::text,event_rows::text from sli_agent_packet_inbox where packet_id=@id",db,tx)) {
                get.Parameters.AddWithValue("id",supported);await using var reader=await get.ExecuteReaderAsync(ct);Assert.True(await reader.ReadAsync(ct));
                savedEnvelope=JsonNode.Parse(reader.GetString(0))!.AsObject();savedPacket=JsonNode.Parse(reader.GetString(1))!.AsObject();savedRows=JsonNode.Parse(reader.GetString(2))!.AsArray();
            }
            await DirectAdDcPacket.ImportAsync(db,tx,runtime!.Worker,supported,savedEnvelope,savedPacket,savedRows,catalog,ct);
            await tx.CommitAsync(ct);
        }
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            long existing;JsonArray changed;
            await using(var get=new NpgsqlCommand("select j.source_event_db_id,j.candidate_states::text from entity_state_projection_jobs j join events_v2_core e on e.id=j.source_event_db_id where e.event_record_id=10 and e.server_id=(select id from servers where hostname=@name)",db,tx)) {
                get.Parameters.AddWithValue("name",Name);await using var reader=await get.ExecuteReaderAsync(ct);Assert.True(await reader.ReadAsync(ct));
                existing=reader.GetInt64(0);changed=JsonNode.Parse(reader.GetString(1))!.AsArray();
            }
            changed[0]!["status"]="synthetic-conflict";
            var error=await Assert.ThrowsAsync<InvalidOperationException>(()=>DirectStateProjection.EnqueueCandidatesAsync(db,tx,existing,changed,ct));
            Assert.Equal("entity_state_job_replay_conflict",error.Message);await tx.RollbackAsync(ct);
        }
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            var pending=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,next,ct,runtime);
            Assert.True(pending.Scanned);Assert.False(pending.Imported);Assert.Equal(unsupported,pending.PacketId);await tx.CommitAsync(ct);
        }
        var golden=JsonNode.Parse(File.ReadAllBytes(DirectStateProjectionTests.FixturePath()))!.AsArray();
        await using var verify=new NpgsqlCommand("""
            select e.id,e.event_record_id,e.event_id,i.imported_at is not null,
                   (select count(*) from event_entity_links_v2 l where l.event_id=e.id),
                   j.job_id,j.candidate_states::text,(select count(*) from event_facts_v2 f where f.event_id=e.id),
                   (select id from entities_v2 where natural_key='sid:S-1-5-21-100000001-200000001-300000001-1102')
            from sli_agent_packet_inbox i join raw_log_files raw on raw.file_path='agent-packet:'||i.packet_id::text
            join events_v2_core e on e.raw_log_file_id=raw.id left join entity_state_projection_jobs j on j.source_event_db_id=e.id
            where i.packet_id=@packet order by e.event_record_id
            """,db);
        verify.Parameters.AddWithValue("packet",supported);
        await using(var r=await verify.ExecuteReaderAsync(ct)) {
            Assert.True(await r.ReadAsync(ct));Assert.Equal(9,r.GetInt64(1));Assert.Equal(4624,r.GetInt32(2));Assert.True(r.GetBoolean(3));Assert.True(r.IsDBNull(5));
            foreach(var kind in new[]{4720,4722,4740}) {
                Assert.True(await r.ReadAsync(ct));long id=r.GetInt64(0);Assert.Equal(kind,r.GetInt32(2));Assert.True(r.GetBoolean(3));Assert.Equal(5L,r.GetInt64(4));Assert.Equal(DirectStateProjection.JobId(id),r.GetGuid(5));Assert.Equal(0L,r.GetInt64(7));
                var actual=JsonNode.Parse(r.GetString(6))!.AsArray();var expected=(JsonObject)golden.Single(x=>(int)x!["event_id"]! == kind)!["candidate"]!.DeepClone();expected["source_event_db_id"]=id;expected["entity_id"]=r.GetInt32(8);
                Assert.True(JsonNode.DeepEquals(expected,Assert.Single(actual))); 
            }
            Assert.False(await r.ReadAsync(ct));
        }
        await using(var pendingCheck=new NpgsqlCommand("select imported_at is null, not exists(select 1 from raw_log_files where file_path='agent-packet:'||packet_id::text) from sli_agent_packet_inbox where packet_id=@id",db)) {
            pendingCheck.Parameters.AddWithValue("id",unsupported);await using var rr=await pendingCheck.ExecuteReaderAsync(ct);Assert.True(await rr.ReadAsync(ct));Assert.True(rr.GetBoolean(0));Assert.True(rr.GetBoolean(1));
        }
        await using(var release=new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_post_collection_process'))",db))Assert.Equal(true,await release.ExecuteScalarAsync(ct));
        await using(var available=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))",contender))Assert.Equal(true,await available.ExecuteScalarAsync(ct));
        await using(var release=new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_post_collection_process'))",contender))Assert.Equal(true,await release.ExecuteScalarAsync(ct));
    }}
