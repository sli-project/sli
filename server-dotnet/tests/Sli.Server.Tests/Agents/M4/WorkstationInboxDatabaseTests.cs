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
public sealed class WorkstationInboxDatabaseTests
{
    [Fact]
    public async Task AtomicImportDuplicatePendingAndRollback()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        var baseline=await fixture.ReadBaselineAsync(ct); Assert.Equal(18,baseline.MajorVersion); Assert.Equal(300,baseline.SchemaVersion);
        await using var db=await fixture.OpenConnectionAsync(ct);
        await using(var profile=new NpgsqlCommand("select current_user,installed,enabled from read_plugin_states_v1() where plugin_id='sli.workstations'",db)) {
            await using var r=await profile.ExecuteReaderAsync(ct);Assert.True(await r.ReadAsync(ct));Assert.Equal("adlog_user",r.GetString(0));Assert.True(r.GetBoolean(1));Assert.True(r.GetBoolean(2));
        }
        var agent=Guid.NewGuid();var host=Guid.NewGuid();var packets=new[]{Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid(),Guid.NewGuid()};
        var stamp=new DateTime(2100,1,1,0,0,0,DateTimeKind.Utc); string? observationId=null;
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            await using(var preflight=new NpgsqlCommand("select count(*) from sli_agent_packet_inbox where received_at>=@stamp",db,tx)) { preflight.Parameters.AddWithValue("stamp",stamp);Assert.Equal(0L,(long)(await preflight.ExecuteScalarAsync(ct))!); }
            await using(var seed=new NpgsqlCommand("insert into sli_agents(id,host_id,key_fingerprint,assigned_modules) values(@id,@host,repeat('a',64),'[{\"module_id\":\"sli.workstations\",\"enabled\":true}]'::jsonb)",db,tx)) {
                seed.Parameters.AddWithValue("id",agent);seed.Parameters.AddWithValue("host",host);await seed.ExecuteNonQueryAsync(ct);
            }
            var source=Fixture(); var original=source["packet"]!.AsObject();
            for(int i=0;i<packets.Length;i++) {
                var packet=(JsonObject)original.DeepClone();packet["header"]!["source"]=host.ToString("D");
                var payload=packet["records"]![0]!["payload"]!.AsObject();payload["computer_name"]=host.ToString("D");
                if(i==0) { string xml=payload["xml"]!.GetValue<string>().Replace("<EventID>1102</EventID>","<EventID>4624</EventID>"); packet["records"]![0]!["payload"]=EventXml.Parse(xml,host.ToString("D"),"","Security"); }
                if(i==4) {
                    string firstXml=payload["xml"]!.GetValue<string>().Replace("<EventRecordID>7</EventRecordID>","<EventRecordID>6</EventRecordID>");
                    string secondXml=payload["xml"]!.GetValue<string>().Replace("synthetic.example","changed.example");
                    packet["records"]=new JsonArray(
                        new JsonObject { ["format"]="event_xml",["record_id"]=6,["payload"]=EventXml.Parse(firstXml,host.ToString("D"),"","Security") },
                        new JsonObject { ["format"]="event_xml",["record_id"]=7,["payload"]=EventXml.Parse(secondXml,host.ToString("D"),"","Security") });
                    packet["header"]!["record_id_range"]=new JsonObject { ["first"]=6,["last"]=7 };
                }
                var rows=new JsonArray(packet["records"]!.AsArray().Select(x=>x!["payload"]!.DeepClone()).ToArray());
                string module=i==5?"sli.windows-eventlog":"sli.workstations";
                var env=new JsonObject { ["agent_id"]=agent.ToString("D"),["packet_id"]=packets[i].ToString("D"),["module_id"]=module,["source_instance_id"]=host.ToString("D"),["payload_sha256"]=i==3?new string('f',64):Packets.Digest(packet) };
                await using var insert=new NpgsqlCommand("""
                    insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                    values(@agent,@module,@sequence,@packet,@hash,@envelope,'{"status":"committed"}'::jsonb);
                    insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at)
                    values(@packet,@envelope,@payload,@rows,@stamp)
                    """,db,tx);
                insert.Parameters.AddWithValue("agent",agent);insert.Parameters.AddWithValue("module",module);insert.Parameters.AddWithValue("sequence",(long)i+1);insert.Parameters.AddWithValue("packet",packets[i]);insert.Parameters.AddWithValue("hash",Packets.Digest(env));
                insert.Parameters.AddWithValue("envelope",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(env));insert.Parameters.AddWithValue("payload",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(packet));insert.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,CanonicalJson.Serialize(rows));insert.Parameters.AddWithValue("stamp",stamp.AddSeconds(i));await insert.ExecuteNonQueryAsync(ct);
            }
            (DateTime,Guid)? cursor=(stamp.AddDays(-1),Guid.Empty);
            for(int i=0;i<packets.Length;i++) {
                var step=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,cursor,ct);Assert.True(step.Scanned);Assert.Equal(packets[i],step.PacketId);
                if(i==0) Assert.True(step.Imported,step.PendingReason);
                if(i is 1 or 2) Assert.True(step.Imported,$"step {i}: {step.PendingReason}");
                if(i==3) { Assert.False(step.Imported);Assert.Equal("agent_packet_attestation_invalid",step.PendingReason); }
                if(i==4) { Assert.False(step.Imported);Assert.Equal("agent_projection_failed",step.PendingReason); }
                if(i==5) { Assert.False(step.Imported);Assert.Equal("agent_storage_unavailable",step.PendingReason); }
                cursor=(step.Received,step.PacketId);
            }
            await using(var verify=new NpgsqlCommand("select id,observation_sha256,observation::text from sli_plugin_workstations.observations where agent_key=@agent",db,tx)) {
                verify.Parameters.AddWithValue("agent",agent.ToString("D"));await using var r=await verify.ExecuteReaderAsync(ct);Assert.True(await r.ReadAsync(ct));observationId=r.GetString(0);
                var observation=JsonNode.Parse(r.GetString(2))!;Assert.Equal(r.GetString(1),Packets.Digest(observation)); Assert.Equal("security.audit.cleared",observation["semantic_type"]!.GetValue<string>());Assert.False(await r.ReadAsync(ct));
            }
            await using(var verify=new NpgsqlCommand("select count(*) filter(where imported_at is not null),count(*) filter(where imported_at is null) from sli_agent_packet_inbox where packet_id=any(@ids)",db,tx)) {
                verify.Parameters.AddWithValue("ids",packets);await using var r=await verify.ExecuteReaderAsync(ct);Assert.True(await r.ReadAsync(ct));Assert.Equal(3L,r.GetInt64(0));Assert.Equal(3L,r.GetInt64(1));
            }
            await tx.RollbackAsync(ct);
        }
        await using(var absent=new NpgsqlCommand("select (select count(*) from sli_agents where id=@agent),(select count(*) from sli_agent_packet_inbox where packet_id=any(@ids)),(select count(*) from sli_plugin_workstations.observations where id=@observation)",db)) {
            absent.Parameters.AddWithValue("agent",agent);absent.Parameters.AddWithValue("ids",packets);absent.Parameters.AddWithValue("observation",observationId!);
            await using var r=await absent.ExecuteReaderAsync(ct);Assert.True(await r.ReadAsync(ct));Assert.Equal(0L,r.GetInt64(0));Assert.Equal(0L,r.GetInt64(1));Assert.Equal(0L,r.GetInt64(2));
        }
    }
    private static JsonObject Fixture([CallerFilePath] string path="")=>JsonNode.Parse(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(path)!,"workstation-1102.json")))!.AsObject();
}


