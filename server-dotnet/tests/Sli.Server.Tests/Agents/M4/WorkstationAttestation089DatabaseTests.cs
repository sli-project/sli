using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Consumer;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Agents.M4;
public sealed class WorkstationAttestation089DatabaseTests
{
    [Fact]
    public async Task EqualJsonButDifferentInboxDigestIsRejectedBeforeIdentityAndSink()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        var baseline=await fixture.ReadBaselineAsync(ct);Assert.Equal(18,baseline.MajorVersion);Assert.Equal(300,baseline.SchemaVersion);
        await using var db=await fixture.OpenConnectionAsync(ct);
        await using(var profile=new NpgsqlCommand("select current_user,installed,enabled from read_plugin_states_v1() where plugin_id='sli.workstations'",db)) {await using var r=await profile.ExecuteReaderAsync(ct);Assert.True(await r.ReadAsync(ct));Assert.Equal("adlog_user",r.GetString(0));Assert.True(r.GetBoolean(1));Assert.True(r.GetBoolean(2));}
        var agent=Guid.NewGuid();var host=Guid.NewGuid();var packetId=Guid.NewGuid();var stamp=new DateTime(2100,1,1,0,0,0,DateTimeKind.Utc);
        var source=Fixture();var packet=source["packet"]!.AsObject();packet["header"]!["source"]=host.ToString("D");packet["records"]![0]!["payload"]!["computer_name"]=host.ToString("D");
        var rows=new JsonArray(packet["records"]![0]!["payload"]!.DeepClone());
        var received=new JsonObject{["agent_id"]=agent.ToString("D"),["packet_id"]=packetId.ToString("D"),["module_id"]="sli.workstations",["source_instance_id"]=host.ToString("D"),["sequence"]=1,["payload_sha256"]=Packets.Digest(packet)};
        var inbox=(JsonObject)received.DeepClone();inbox["sequence"]=JsonNode.Parse("1.0");Assert.NotEqual(Packets.Digest(received),Packets.Digest(inbox));
        string naturalKey="core:"+Packets.Digest(new JsonArray("device","sli.agent.key","agent-registry",agent.ToString("D")));
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            await using(var pre=new NpgsqlCommand("select count(*) from sli_agent_packet_inbox where received_at>=@stamp",db,tx)){pre.Parameters.AddWithValue("stamp",stamp);Assert.Equal(0L,(long)(await pre.ExecuteScalarAsync(ct))!);}
            await using(var seed=new NpgsqlCommand("""
                insert into sli_agents(id,host_id,key_fingerprint,assigned_modules) values(@agent,@host,repeat('a',64),'[{"module_id":"sli.workstations","enabled":true}]'::jsonb);
                insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt) values(@agent,'sli.workstations',1,@packet,@hash,@received,'{"status":"committed"}'::jsonb);
                insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at) values(@packet,@inbox,@payload,@rows,@stamp)
                """,db,tx)) {
                seed.Parameters.AddWithValue("agent",agent);seed.Parameters.AddWithValue("host",host);seed.Parameters.AddWithValue("packet",packetId);seed.Parameters.AddWithValue("hash",Packets.Digest(received));
                seed.Parameters.AddWithValue("received",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(received));seed.Parameters.AddWithValue("inbox",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(inbox));seed.Parameters.AddWithValue("payload",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(packet));seed.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(rows));seed.Parameters.AddWithValue("stamp",stamp);await seed.ExecuteNonQueryAsync(ct);
            }
            var step=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,(stamp.AddDays(-1),Guid.Empty),ct);
            Assert.True(step.Scanned);Assert.False(step.Imported);Assert.Equal("agent_packet_attestation_invalid",step.PendingReason);
            await using(var verify=new NpgsqlCommand("""
                select imported_at is null,(select count(*) from sli_plugin_workstations.observations where agent_key=@key),
                       (select count(*) from entities_v2_active where natural_key=@natural)
                from sli_agent_packet_inbox where packet_id=@packet
                """,db,tx)) {
                verify.Parameters.AddWithValue("packet",packetId);verify.Parameters.AddWithValue("key",agent.ToString("D"));verify.Parameters.AddWithValue("natural",naturalKey);
                await using var r=await verify.ExecuteReaderAsync(ct);Assert.True(await r.ReadAsync(ct));Assert.True(r.GetBoolean(0));Assert.Equal(0L,r.GetInt64(1));Assert.Equal(0L,r.GetInt64(2));
            }
            await tx.RollbackAsync(ct);
        }
        await using(var absent=new NpgsqlCommand("select (select count(*) from sli_agents where id=@agent),(select count(*) from sli_agent_packet_inbox where packet_id=@packet),(select count(*) from entities_v2_active where natural_key=@natural)",db)) {
            absent.Parameters.AddWithValue("agent",agent);absent.Parameters.AddWithValue("packet",packetId);absent.Parameters.AddWithValue("natural",naturalKey);
            await using var r=await absent.ExecuteReaderAsync(ct);Assert.True(await r.ReadAsync(ct));Assert.Equal(0L,r.GetInt64(0));Assert.Equal(0L,r.GetInt64(1));Assert.Equal(0L,r.GetInt64(2));
        }
    }
    private static JsonObject Fixture([CallerFilePath] string path="")=>JsonNode.Parse(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(path)!,"workstation-1102.json")))!.AsObject();
}
