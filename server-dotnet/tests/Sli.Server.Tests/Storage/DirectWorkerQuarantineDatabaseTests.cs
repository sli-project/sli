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

public class DirectWorkerQuarantineDatabaseTests
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
    public async Task Conflict_quarantine_is_atomic_and_unknown_superset_stays_pending()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        await using var db=await fixture.OpenConnectionAsync(ct);
        var secret=JsonNode.Parse(await File.ReadAllBytesAsync(Environment.GetEnvironmentVariable("SLI_SV2_WORKER_SECRET")!,ct))!.AsObject();
        Assert.Equal("sli_sv2_quarantine_7dc831c5",secret["username"]!.GetValue<string>());
        Guid supported=Guid.Parse("7dc831c5-e288-46eb-ab10-20265235130a"), unsupported=Guid.Parse("1cab7c3a-dd65-4c86-b000-0388e03d9091");
        (DateTime Received,Guid Packet) after;
        await using(var previous=new NpgsqlCommand("select received_at,packet_id from sli_agent_packet_inbox where packet_id='de90c58a-576d-421c-93e5-c79c705281e7'",db)) {
            await using var r=await previous.ExecuteReaderAsync(ct);Assert.True(await r.ReadAsync(ct));after=(r.GetDateTime(0),r.GetGuid(1));
        }
        var sample=Sample();
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            for(int i=0;i<2;i++) {
                var payload=(JsonObject)sample.Packet.DeepClone();
                string xml=$"<Event xmlns='{EventXml.Namespace}'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-A5BA-3E3B0328C30D}}'/><EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><EventRecordID>4</EventRecordID><TimeCreated SystemTime='2026-10-07T00:00:00Z'/><Execution ProcessID='4' ThreadID='8'/><Channel>Security</Channel><Computer>{Name}</Computer></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-100000001-200000001-300000001-1101</Data><Data Name='SubjectUserName'>operator</Data><Data Name='SubjectDomainName'>EXAMPLE</Data><Data Name='SubjectLogonId'>0x123</Data><Data Name='TargetUserSid'>S-1-5-21-100000001-200000001-300000001-1102</Data><Data Name='TargetUserName'>alice</Data><Data Name='TargetDomainName'>EXAMPLE</Data><Data Name='TargetLogonId'>0x456</Data><Data Name='LogonType'>{(i==0?"10":"3")}</Data><Data Name='IpAddress'>192.0.2.55</Data><Data Name='WorkstationName'>ws01</Data>{(i==1?"<Data Name='UnsupportedField'>x</Data>":"")}</EventData></Event>";
                payload["records"]![0]!["payload"]=EventXml.Parse(xml,Name,"fixture-endpoint","Security");
                payload["records"]![0]!["record_id"]=4;payload["header"]!["cursor"]!["last_record_id"]=4;
                payload["header"]!["record_id_range"]!["first"]=4;payload["header"]!["record_id_range"]!["last"]=4;
                var envelope=(JsonObject)sample.Envelope.DeepClone();Guid id=i==0?supported:unsupported;
                envelope["packet_id"]=id.ToString("D");envelope["sequence"]=i+10;
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
                insert.Parameters.AddWithValue("agent",Agent);insert.Parameters.AddWithValue("sequence",(long)i+10);insert.Parameters.AddWithValue("packet",id);
                insert.Parameters.AddWithValue("hash",Packets.Digest(envelope));insert.Parameters.AddWithValue("envelope",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(envelope));
                insert.Parameters.AddWithValue("payload",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(payload));insert.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(rows));
                await insert.ExecuteNonQueryAsync(ct);
            }
            await tx.CommitAsync(ct);
        }
        string catalog=Environment.GetEnvironmentVariable("SLI_SV2_CATALOG")!;
        var env=new Dictionary<string,string?> { ["ADLOG_STORAGE_V2_WORKER_DSN"]="host=127.0.0.1 port=60872 dbname=sli_oracle user=sli_sv2_quarantine_7dc831c5 sslmode=disable", ["ADLOG_STORAGE_V2_WORKER_PASSWORD"]=secret["password"]!.GetValue<string>() };
        await using var runtime=DirectAdDcRuntime.TryCreate(k=>env.GetValueOrDefault(k),_=>[],catalog);Assert.NotNull(runtime);
        await using var contender=await fixture.OpenConnectionAsync(ct);
        await using(var hold=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))",db))Assert.Equal(true,await hold.ExecuteScalarAsync(ct));
        await using(var blocked=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))",contender))Assert.Equal(false,await blocked.ExecuteScalarAsync(ct));
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            var first=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,after,ct,runtime);
            Assert.True(first.Quarantined);Assert.False(first.Imported);Assert.Equal("published_source_event_hash_mismatch",first.PendingReason);Assert.Equal(supported,first.PacketId);await tx.RollbackAsync(ct);
        }
        await using(var check=new NpgsqlCommand("select count(*) from sli_agent_packet_quarantine where packet_id=@id",db)){check.Parameters.AddWithValue("id",supported);Assert.Equal(0L,await check.ExecuteScalarAsync(ct));}
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            var replay=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,after,ct,runtime);
            Assert.True(replay.Quarantined);Assert.False(replay.Imported);Assert.Equal("published_source_event_hash_mismatch",replay.PendingReason);Assert.Equal(supported,replay.PacketId);await tx.CommitAsync(ct);
        }
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            var pending=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,after,ct,runtime);
            Assert.True(pending.Scanned);Assert.False(pending.Imported);Assert.False(pending.Quarantined);Assert.Equal(unsupported,pending.PacketId);await tx.CommitAsync(ct);
        }
        await using var verify=new NpgsqlCommand("""
            select i.imported_at is null,q.reason_code,q.event_ordinal,
                (select count(*) from sli_agent_packet_quarantine where packet_id=@unsupported),
                (select imported_at is null from sli_agent_packet_inbox where packet_id=@unsupported),
                (select count(*) from raw_log_files where file_path='agent-packet:'||@unsupported::text)
            from sli_agent_packet_inbox i join sli_agent_packet_quarantine q on q.packet_id=i.packet_id where i.packet_id=@supported
            """,db);
        verify.Parameters.AddWithValue("supported",supported);verify.Parameters.AddWithValue("unsupported",unsupported);
        await using var result=await verify.ExecuteReaderAsync(ct);Assert.True(await result.ReadAsync(ct));Assert.True(result.GetBoolean(0));
        Assert.Equal("published_source_event_hash_mismatch",result.GetString(1));Assert.Equal(0,result.GetInt32(2));Assert.Equal(0L,result.GetInt64(3));Assert.True(result.GetBoolean(4));Assert.Equal(0L,result.GetInt64(5));Assert.False(await result.ReadAsync(ct));
    }
}