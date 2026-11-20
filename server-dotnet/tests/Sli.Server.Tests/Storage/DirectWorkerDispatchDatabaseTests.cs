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
public class DirectWorkerDispatchDatabaseTests
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
        string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>1</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00Z'/><Channel>Security</Channel><Computer>{Name}</Computer></System><EventData><Data Name='LogonType'>3</Data></EventData></Event>";
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
    public async Task Shared_claim_ad_dispatch_rollback_replay_and_pending()
    {
        using var environment=new Sli.Server.Tests.Semantic.SemanticProducerPostgresTests.Admission(mode:null);
        environment.Set("Sli__Storage__ShortEventReads","false");
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        await using var db=await fixture.OpenConnectionAsync(ct);
        var secret=JsonNode.Parse(await File.ReadAllBytesAsync(Environment.GetEnvironmentVariable("SLI_SV2_WORKER_SECRET")!,ct))!.AsObject();
        Assert.Equal("sli_sv2_dispatch_2168ae88",secret["username"]!.GetValue<string>());
        Guid supported=Guid.Parse("2168ae88-170e-4ca3-ba50-8e51740e5fa5"), unsupported=Guid.Parse("de90c58a-576d-421c-93e5-c79c705281e7");
        (DateTime Received,Guid Packet) after;
        await using(var previous=new NpgsqlCommand("select received_at,packet_id from sli_agent_packet_inbox where packet_id='695d7477-e710-4c54-9893-c7948fd16d35'",db)) {
            await using var r=await previous.ExecuteReaderAsync(ct);Assert.True(await r.ReadAsync(ct));after=(r.GetDateTime(0),r.GetGuid(1));
        }
        var sample=Sample();
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            for(int i=0;i<2;i++) {
                var payload=(JsonObject)sample.Packet.DeepClone();
                string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}'/><EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><EventRecordID>4</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00Z'/><Execution ProcessID='4' ThreadID='8'/><Channel>Security</Channel><Computer>{Name}</Computer></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-100000001-200000001-300000001-1101</Data><Data Name='SubjectUserName'>operator</Data><Data Name='SubjectDomainName'>EXAMPLE</Data><Data Name='SubjectLogonId'>0x123</Data><Data Name='TargetUserSid'>S-1-5-21-100000001-200000001-300000001-1102</Data><Data Name='TargetUserName'>alice</Data><Data Name='TargetDomainName'>EXAMPLE</Data><Data Name='TargetLogonId'>0x456</Data><Data Name='LogonType'>3</Data><Data Name='IpAddress'>192.0.2.55</Data><Data Name='WorkstationName'>ws01</Data>{(i==1?"<Data Name='UnsupportedField'>x</Data>":"")}</EventData></Event>";
                payload["records"]![0]!["payload"]=EventXml.Parse(xml,Name,"fixture-endpoint","Security");
                payload["records"]![0]!["record_id"]=4;payload["header"]!["cursor"]!["last_record_id"]=4;
                payload["header"]!["record_id_range"]!["first"]=4;payload["header"]!["record_id_range"]!["last"]=4;
                var envelope=(JsonObject)sample.Envelope.DeepClone();Guid id=i==0?supported:unsupported;
                envelope["packet_id"]=id.ToString("D");envelope["sequence"]=i+8;
                var state=JsonNode.Parse(envelope["cursor_after"]!["token"]!.GetValue<string>())!.AsObject();
                state["channels"]!["Security"]!["record_id"]=4;
                state["channels"]!["Security"]!["bookmark"]=state["channels"]!["Security"]!["bookmark"]!.GetValue<string>().Replace("RecordId='1'","RecordId='4'",StringComparison.Ordinal);
                envelope["cursor_after"]!["token"]=CanonicalJson.Serialize(state);
                envelope["payload_sha256"]=Packets.Digest(payload);envelope["payload_bytes"]=CanonicalJson.Length(payload);
                var rows=AgentAdDcValidator.Validate(Envelope.Parse(envelope),payload,null,Name);
                await using var insert=new NpgsqlCommand("""
                    insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                    values(@agent,'sli.windows.ad-dc',@sequence,@packet,@hash,@envelope,'{"status":"committed"}'::jsonb);
                    insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows) values(@packet,@envelope,@payload,@rows)
                    """,db,tx);
                insert.Parameters.AddWithValue("agent",Agent);insert.Parameters.AddWithValue("sequence",(long)i+8);insert.Parameters.AddWithValue("packet",id);
                insert.Parameters.AddWithValue("hash",Packets.Digest(envelope));insert.Parameters.AddWithValue("envelope",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(envelope));
                insert.Parameters.AddWithValue("payload",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(payload));insert.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(rows));
                await insert.ExecuteNonQueryAsync(ct);
            }
            await tx.CommitAsync(ct);
        }
        string catalog=Environment.GetEnvironmentVariable("SLI_SV2_CATALOG")!;
        var env=new Dictionary<string,string?> { ["ADLOG_STORAGE_V2_WORKER_DSN"]="host=127.0.0.1 port=60872 dbname=sli_oracle user=sli_sv2_dispatch_2168ae88 sslmode=disable", ["ADLOG_STORAGE_V2_WORKER_PASSWORD"]=secret["password"]!.GetValue<string>() };
        await using var runtime=DirectAdDcRuntime.TryCreate(k=>env.GetValueOrDefault(k),_=>[],catalog);Assert.NotNull(runtime);
        await using var contender=await fixture.OpenConnectionAsync(ct);
        await using(var hold=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))",db))Assert.Equal(true,await hold.ExecuteScalarAsync(ct));
        await using(var blocked=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))",contender))Assert.Equal(false,await blocked.ExecuteScalarAsync(ct));
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            var first=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,after,ct,runtime);
            Assert.True(first.Imported,first.PendingReason);Assert.Equal(supported,first.PacketId);await tx.RollbackAsync(ct);
            await using var stillHeld=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))",contender);Assert.Equal(false,await stillHeld.ExecuteScalarAsync(ct));
        }
        (DateTime Received,Guid Packet) next;
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            var replay=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,after,ct,runtime);
            Assert.True(replay.Imported,replay.PendingReason);Assert.Equal(supported,replay.PacketId);next=(replay.Received,replay.PacketId);await tx.CommitAsync(ct);
        }
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            var pending=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,next,ct,runtime);
            Assert.True(pending.Scanned);Assert.False(pending.Imported);Assert.Equal(unsupported,pending.PacketId);await tx.CommitAsync(ct);
        }
        await using var verify=new NpgsqlCommand("""
            select i.imported_at is not null, e.version,e.level,e.task,e.opcode,k.value,e.subject_user_sid,e.subject_user_name,
                   sd.value,e.target_user_sid,e.target_user_name,td.value,e.ip_address,e.workstation_name,e.logon_id,f.logon_type,
                   (select count(*) from event_entity_links_v2 l where l.event_id=e.id),
                   (select count(*) from entity_state_projection_jobs j where j.source_event_db_id=e.id),
                   (select imported_at is null from sli_agent_packet_inbox where packet_id=@unsupported)
            from sli_agent_packet_inbox i join raw_log_files raw on raw.file_path='agent-packet:'||i.packet_id::text
            join events_v2_core e on e.raw_log_file_id=raw.id join event_facts_v2 f on f.event_id=e.id
            left join storage_v2_keywords k on k.id=e.keywords_id
            left join storage_v2_domain_name sd on sd.id=e.subject_domain_id left join storage_v2_domain_name td on td.id=e.target_domain_id
            where i.packet_id=@supported
            """,db);
        verify.Parameters.AddWithValue("supported",supported);verify.Parameters.AddWithValue("unsupported",unsupported);
        await using var result=await verify.ExecuteReaderAsync(ct);Assert.True(await result.ReadAsync(ct));
        Assert.True(result.GetBoolean(0)); Assert.Equal((short)2,result.GetInt16(1)); Assert.Equal((short)0,result.GetInt16(2));
        Assert.Equal(12544,result.GetInt32(3));Assert.Equal(0,result.GetInt32(4));Assert.Equal("0x8020000000000000",result.GetString(5));
        Assert.Equal("S-1-5-21-100000001-200000001-300000001-1101",result.GetString(6));Assert.Equal("operator",result.GetString(7));Assert.Equal("EXAMPLE",result.GetString(8));
        Assert.Equal("S-1-5-21-100000001-200000001-300000001-1102",result.GetString(9));Assert.Equal("alice",result.GetString(10));Assert.Equal("EXAMPLE",result.GetString(11));
        Assert.Equal("192.0.2.55",result.GetString(12));Assert.Equal("ws01",result.GetString(13));Assert.Equal("0x456",result.GetString(14));Assert.Equal("3",result.GetString(15));
        Assert.Equal(8,result.GetInt64(16));Assert.Equal(0,result.GetInt64(17));Assert.True(result.GetBoolean(18));Assert.False(await result.ReadAsync(ct));await result.CloseAsync();
        await using(var release=new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_post_collection_process'))",db))Assert.Equal(true,await release.ExecuteScalarAsync(ct));
        await using(var available=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))",contender))Assert.Equal(true,await available.ExecuteScalarAsync(ct));
        await using(var release=new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_post_collection_process'))",contender))Assert.Equal(true,await release.ExecuteScalarAsync(ct));
    }}
