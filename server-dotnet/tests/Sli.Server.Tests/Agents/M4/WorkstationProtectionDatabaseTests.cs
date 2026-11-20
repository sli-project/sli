using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Consumer;
using Sli.Server.Tests.Integration;
using Xunit;
namespace Sli.Server.Tests.Agents.M4;
public sealed class WorkstationProtectionDatabaseTests
{
    [Fact]
    public async Task StateOnlyMixedReplayAndConflictsAreAtomic()
    {
        var ct=TestContext.Current.CancellationToken;await using var fixture=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        var baseline=await fixture.ReadBaselineAsync(ct);Assert.Equal(18,baseline.MajorVersion);Assert.Equal(300,baseline.SchemaVersion);await using var db=await fixture.OpenConnectionAsync(ct);
        await using(var profile=new NpgsqlCommand("select current_user,installed,enabled from read_plugin_states_v1() where plugin_id='sli.workstations'",db)){await using var r=await profile.ExecuteReaderAsync(ct);Assert.True(await r.ReadAsync(ct));Assert.Equal("adlog_user",r.GetString(0));Assert.True(r.GetBoolean(1));Assert.True(r.GetBoolean(2));}
        var agent=Guid.NewGuid();var host=Guid.NewGuid();var packets=Enumerable.Range(0,6).Select(_=>Guid.NewGuid()).ToArray();var stamp=new DateTime(2100,1,1,0,0,0,DateTimeKind.Utc);
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            await using(var preflight=new NpgsqlCommand("select count(*) from sli_agent_packet_inbox where received_at>=@stamp",db,tx)){preflight.Parameters.AddWithValue("stamp",stamp);Assert.Equal(0L,(long)(await preflight.ExecuteScalarAsync(ct))!);}
            await using(var seed=new NpgsqlCommand("insert into sli_agents(id,host_id,key_fingerprint,assigned_modules) values(@id,@host,repeat('a',64),'[{\"module_id\":\"sli.workstations\",\"enabled\":true}]'::jsonb)",db,tx)){seed.Parameters.AddWithValue("id",agent);seed.Parameters.AddWithValue("host",host);await seed.ExecuteNonQueryAsync(ct);}
            var f=Fixture();
            for(int i=0;i<packets.Length;i++) {
                var packet=(JsonObject)f["positive"]![i>=4?1:0]!["packet"]!.DeepClone();packet["header"]!["source"]=host.ToString("D");
                packet["header"]!["observed_at_utc"]=i switch {2=>"2026-10-07T12:34:59Z",4=>"2026-10-07T12:35:01Z",5=>"2026-10-07T12:35:02Z",_=>"2026-10-07T12:35:00Z"};
                if(i is 2 or 3)packet["context"]!["workstations"]!["protection_state"]!["components"]!["antivirus_enabled"]=false;
                foreach(var item in packet["records"]!.AsArray())item!["payload"]!["computer_name"]=host.ToString("D");
                if(i==5){var record=packet["records"]![0]!.AsObject();string xml=record["payload"]!["xml"]!.GetValue<string>().Replace("<EventID>5001</EventID>","<EventID>9999</EventID>");record["payload"]=EventXml.Parse(xml,host.ToString("D"),"","Microsoft-Windows-Windows Defender/Operational");}
                var rows=new JsonArray(packet["records"]!.AsArray().Select(x=>x!["payload"]!.DeepClone()).ToArray());
                var env=new JsonObject{["agent_id"]=agent.ToString("D"),["packet_id"]=packets[i].ToString("D"),["module_id"]="sli.workstations",["source_instance_id"]=host.ToString("D"),["payload_sha256"]=Packets.Digest(packet)};
                await using var insert=new NpgsqlCommand("""
                    insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt) values(@agent,'sli.workstations',@sequence,@packet,@hash,@envelope,'{"status":"committed"}'::jsonb);
                    insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at) values(@packet,@envelope,@payload,@rows,@stamp)
                    """,db,tx);
                insert.Parameters.AddWithValue("agent",agent);insert.Parameters.AddWithValue("sequence",(long)i+1);insert.Parameters.AddWithValue("packet",packets[i]);insert.Parameters.AddWithValue("hash",Packets.Digest(env));insert.Parameters.AddWithValue("envelope",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(env));insert.Parameters.AddWithValue("payload",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(packet));insert.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(rows));insert.Parameters.AddWithValue("stamp",stamp.AddSeconds(i));await insert.ExecuteNonQueryAsync(ct);
            }
            (DateTime,Guid)? cursor=(stamp.AddDays(-1),Guid.Empty);
            for(int i=0;i<packets.Length;i++){
                var step=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,cursor,ct);Assert.True(step.Scanned);Assert.Equal(packets[i],step.PacketId);
                if(i==3){Assert.False(step.Imported);Assert.Equal("agent_projection_failed",step.PendingReason);}else Assert.True(step.Imported,$"step {i}: {step.PendingReason}");
                await using var state=new NpgsqlCommand("select observed_at,state::text,state_sha256 from sli_plugin_workstations.protection_state where agent_key=@key",db,tx);state.Parameters.AddWithValue("key",agent.ToString("D"));await using(var r=await state.ExecuteReaderAsync(ct)){Assert.True(await r.ReadAsync(ct));Assert.Equal(DateTimeOffset.Parse(i>=4?"2026-10-07T12:35:01+00:00":"2026-10-07T12:35:00+00:00"),r.GetFieldValue<DateTimeOffset>(0));var json=JsonNode.Parse(r.GetString(1))!;Assert.Equal(r.GetString(2),Packets.Digest(json));Assert.Equal(i>=4?"unavailable":"available",json["state"]!.GetValue<string>());}cursor=(step.Received,step.PacketId);
            }
            await using(var verify=new NpgsqlCommand("select (select count(*) from sli_agent_packet_inbox where packet_id=any(@ids) and imported_at is not null),(select count(*) from sli_plugin_workstations.observations where agent_key=@key)",db,tx)){verify.Parameters.AddWithValue("ids",packets);verify.Parameters.AddWithValue("key",agent.ToString("D"));await using var r=await verify.ExecuteReaderAsync(ct);Assert.True(await r.ReadAsync(ct));Assert.Equal(5L,r.GetInt64(0));Assert.Equal(1L,r.GetInt64(1));}
            await tx.RollbackAsync(ct);
        }
        await using(var absent=new NpgsqlCommand("select (select count(*) from sli_agents where id=@agent),(select count(*) from sli_agent_packet_inbox where packet_id=any(@ids)),(select count(*) from sli_plugin_workstations.observations where agent_key=@key),(select count(*) from sli_plugin_workstations.protection_state where agent_key=@key)",db)){absent.Parameters.AddWithValue("agent",agent);absent.Parameters.AddWithValue("key",agent.ToString("D"));absent.Parameters.AddWithValue("ids",packets);await using var r=await absent.ExecuteReaderAsync(ct);Assert.True(await r.ReadAsync(ct));for(int i=0;i<4;i++)Assert.Equal(0L,r.GetInt64(i));}
    }
    private static JsonObject Fixture([CallerFilePath]string path="")=>JsonNode.Parse(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(path)!,"workstation-protection.json")))!.AsObject();
}
