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
public sealed class WorkstationServiceDefenderDatabaseTests
{
    [Fact]
    public async Task MixedServicePacketImportsAtomicallyWithReplayAndUnsupportedPending()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        var baseline=await fixture.ReadBaselineAsync(ct);Assert.Equal(18,baseline.MajorVersion);Assert.Equal(300,baseline.SchemaVersion);
        await using var db=await fixture.OpenConnectionAsync(ct);
        await using(var profile=new NpgsqlCommand("select current_user,installed,enabled from read_plugin_states_v1() where plugin_id='sli.workstations'",db)) { await using var r=await profile.ExecuteReaderAsync(ct);Assert.True(await r.ReadAsync(ct));Assert.Equal("adlog_user",r.GetString(0));Assert.True(r.GetBoolean(1));Assert.True(r.GetBoolean(2)); }
        var agent=Guid.NewGuid();var host=Guid.NewGuid();var packets=new[]{Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid()};var stamp=new DateTime(2100,1,1,0,0,0,DateTimeKind.Utc);
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            await using(var preflight=new NpgsqlCommand("select count(*) from sli_agent_packet_inbox where received_at>=@stamp",db,tx)) {preflight.Parameters.AddWithValue("stamp",stamp);Assert.Equal(0L,(long)(await preflight.ExecuteScalarAsync(ct))!);}
            await using(var seed=new NpgsqlCommand("insert into sli_agents(id,host_id,key_fingerprint,assigned_modules) values(@id,@host,repeat('a',64),'[{\"module_id\":\"sli.workstations\",\"enabled\":true}]'::jsonb)",db,tx)) {seed.Parameters.AddWithValue("id",agent);seed.Parameters.AddWithValue("host",host);await seed.ExecuteNonQueryAsync(ct);}
            var original=Fixture()[0]!["packet"]!.AsObject();
            for(int i=0;i<packets.Length;i++) {
                var packet=(JsonObject)original.DeepClone();packet["header"]!["source"]=host.ToString("D");
                foreach(var item in packet["records"]!.AsArray()) item!["payload"]!["computer_name"]=host.ToString("D");
                if(i==2) {var record=packet["records"]![1]!.AsObject();string xml=record["payload"]!["xml"]!.GetValue<string>().Replace("<EventID>7040</EventID>","<EventID>7045</EventID>");record["payload"]=EventXml.Parse(xml,host.ToString("D"),"","System");}
                var rows=new JsonArray(packet["records"]!.AsArray().Select(x=>x!["payload"]!.DeepClone()).ToArray());
                var env=new JsonObject{["agent_id"]=agent.ToString("D"),["packet_id"]=packets[i].ToString("D"),["module_id"]="sli.workstations",["source_instance_id"]=host.ToString("D"),["payload_sha256"]=Packets.Digest(packet)};
                await using var insert=new NpgsqlCommand("""
                    insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt) values(@agent,'sli.workstations',@sequence,@packet,@hash,@envelope,'{"status":"committed"}'::jsonb);
                    insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at) values(@packet,@envelope,@payload,@rows,@stamp)
                    """,db,tx);
                insert.Parameters.AddWithValue("agent",agent);insert.Parameters.AddWithValue("sequence",(long)i+1);insert.Parameters.AddWithValue("packet",packets[i]);insert.Parameters.AddWithValue("hash",Packets.Digest(env));insert.Parameters.AddWithValue("envelope",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(env));insert.Parameters.AddWithValue("payload",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(packet));insert.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(rows));insert.Parameters.AddWithValue("stamp",stamp.AddSeconds(i));await insert.ExecuteNonQueryAsync(ct);
            }
            (DateTime,Guid)? cursor=(stamp.AddDays(-1),Guid.Empty);
            for(int i=0;i<packets.Length;i++) {var step=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,cursor,ct);Assert.True(step.Scanned);Assert.Equal(packets[i],step.PacketId);Assert.True(step.Imported,$"step {i}: {step.PendingReason}");cursor=(step.Received,step.PacketId);}
            await using(var verify=new NpgsqlCommand("select event_id,observation_sha256,observation::text,encode(sha256(convert_to(source_xml,'UTF8')),'hex') from sli_plugin_workstations.observations where agent_key=@agent order by event_id",db,tx)) {
                verify.Parameters.AddWithValue("agent",agent.ToString("D"));await using var r=await verify.ExecuteReaderAsync(ct);
                foreach(int eventId in new[]{7036,7040}) {Assert.True(await r.ReadAsync(ct));Assert.Equal(eventId,r.GetInt32(0));var observation=JsonNode.Parse(r.GetString(2))!;Assert.Equal(r.GetString(1),Packets.Digest(observation));Assert.Equal(observation["source_sha256"]!.GetValue<string>(),r.GetString(3));}Assert.False(await r.ReadAsync(ct));
            }
            await using(var verify=new NpgsqlCommand("select count(*) filter(where imported_at is not null),count(*) filter(where imported_at is null) from sli_agent_packet_inbox where packet_id=any(@ids)",db,tx)) {verify.Parameters.AddWithValue("ids",packets);await using var r=await verify.ExecuteReaderAsync(ct);Assert.True(await r.ReadAsync(ct));Assert.Equal(3L,r.GetInt64(0));Assert.Equal(0L,r.GetInt64(1));}
            await tx.RollbackAsync(ct);
        }
        await using(var absent=new NpgsqlCommand("select (select count(*) from sli_agents where id=@agent),(select count(*) from sli_agent_packet_inbox where packet_id=any(@ids)),(select count(*) from sli_plugin_workstations.observations where agent_key=@key)",db)) {absent.Parameters.AddWithValue("agent",agent);absent.Parameters.AddWithValue("key",agent.ToString("D"));absent.Parameters.AddWithValue("ids",packets);await using var r=await absent.ExecuteReaderAsync(ct);Assert.True(await r.ReadAsync(ct));Assert.Equal(0L,r.GetInt64(0));Assert.Equal(0L,r.GetInt64(1));Assert.Equal(0L,r.GetInt64(2));}
    }
    private static JsonArray Fixture([CallerFilePath] string path="")=>JsonNode.Parse(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(path)!,"workstation-service-defender.json")))!.AsArray();
}
