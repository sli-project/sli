using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.FileAudit;
using Sli.Server.Agents.Consumer;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Agents;

// Explicit owned fixture only; entire data setup, calls and assertions roll back.
public class FileAuditWorkerMixedDatabaseTests
{
    [Fact]
    public async Task MixedWorkerPassesShareSessionAndRollbackFixture()
    {
        var ct=TestContext.Current.CancellationToken;
        var ids=JsonNode.Parse(await File.ReadAllTextAsync(Environment.GetEnvironmentVariable("SLI_FILE_AUDIT_OWN_IDS")!,ct))!.AsObject();
        Guid Id(string key)=>Guid.Parse(ids[key]!.GetValue<string>());
        string commandId=ids["command"]!.GetValue<string>();
        await using var fixture=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        await using var db=await fixture.OpenConnectionAsync(ct);
        await using(var check=new NpgsqlCommand("select current_user,(select count(*) from read_plugin_states_v1() where plugin_id in ('sli.file-audit','sli.workstations') and installed and enabled)",db)) {
            await using var reader=await check.ExecuteReaderAsync(ct);Assert.True(await reader.ReadAsync(ct));Assert.Equal("adlog_user",reader.GetString(0));Assert.Equal(2L,reader.GetInt64(1));
        }
        var retained=JsonNode.Parse(await File.ReadAllTextAsync(Environment.GetEnvironmentVariable("SLI_RETAINED_OWN_IDS")!,ct))!.AsObject();
        async Task<string> RetainedState() {
            await using var cmd=new NpgsqlCommand("select jsonb_build_object('imported',(select to_jsonb(i) from sli_agent_packet_inbox i where packet_id=@imported),'pending',(select to_jsonb(i) from sli_agent_packet_inbox i where packet_id=@pending),'observations',(select coalesce(jsonb_agg(to_jsonb(o) order by o.id),'[]'::jsonb) from sli_plugin_workstations.observations o where agent_key=@agent))::text",db);
            cmd.Parameters.AddWithValue("imported",Guid.Parse(retained["packetId"]!.GetValue<string>()));cmd.Parameters.AddWithValue("pending",Guid.Parse(retained["pendingId"]!.GetValue<string>()));cmd.Parameters.AddWithValue("agent",retained["agent"]!.GetValue<string>());
            return (string)(await cmd.ExecuteScalarAsync(ct))!;
        }
        string before=await RetainedState(); var snapshotBefore=JsonNode.Parse(before)!;
        Assert.NotNull(snapshotBefore["imported"]!["imported_at"]);Assert.Null(snapshotBefore["pending"]!["imported_at"]);Assert.Single(snapshotBefore["observations"]!.AsArray());
        await using(var lockCommand=new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))",db)) Assert.Equal(true,await lockCommand.ExecuteScalarAsync(ct));
        await using var tx=await db.BeginTransactionAsync(ct);
        try {
            async Task<object?> Sql(string sql,params (string Key,object Value,NpgsqlDbType? Type)[] values) {
                await using var cmd=new NpgsqlCommand(sql,db,tx);foreach(var (key,value,type) in values) { if(type is null) cmd.Parameters.AddWithValue(key,value);else cmd.Parameters.AddWithValue(key,type.Value,value); }return await cmd.ExecuteScalarAsync(ct);
            }
            var raw=await File.ReadAllBytesAsync(Environment.GetEnvironmentVariable("SLI_FILE_AUDIT_VECTORS")!,ct);
            Assert.Equal("84474f140f4a8668eb1a7c0907e3c64716ab78e63fbca954cd008285a57b200e",Convert.ToHexStringLower(SHA256.HashData(raw)));
            var original=JsonNode.Parse(raw)!.AsArray().OfType<JsonObject>().Single(x=>x["name"]!.GetValue<string>()=="events-restart-filter");
            string oldHost=original["host_id"]!.GetValue<string>();
            async Task<(JsonObject Config,Envelope Envelope)> Seed(string prefix,bool workstation,DateTime received) {
                var agent=Id(prefix+"_agent");var host=Id(prefix+"_host");var packet=Id(prefix+"_packet");
                var step=JsonNode.Parse(original["steps"]![0]!.ToJsonString().Replace(oldHost,host.ToString("D")))!.AsObject();
                var body=JsonNode.Parse(step["payload_canonical"]!.GetValue<string>().Replace("0x10000","0x2"))!.AsObject();body["context"]!["policy_revision"]="2";
                var config=(JsonObject)original["config"]!.DeepClone(); config["policy_revision"]="2";config["source_kind"]=workstation?"workstation":"server";config["mass_operation_files"]=1;if(workstation) config["roots"]![0]!["share_name"]="";
                var assigned=new JsonArray(new JsonObject { ["module_id"]="sli.file-audit",["enabled"]=true,["config"]=config.DeepClone() },new JsonObject { ["module_id"]="sli.workstations",["enabled"]=true });
                await Sql("insert into sli_agents(id,host_id,key_fingerprint,status,assigned_modules) values(@agent,@host,@fp,'active',@assigned)",("agent",agent,null),("host",host,null),("fp",new string('a',64),null),("assigned",CanonicalJson.Serialize(assigned),NpgsqlDbType.Jsonb));
                var env=new Envelope(packet.ToString("D"),agent.ToString("D"),host.ToString("D"),"sli.file-audit","1.0.0","2","Security",body["header"]!["generation"]!.GetValue<string>(),1,Cursor.FromJson(step["cursor_before"]),Cursor.FromJson(step["cursor_after"]),CollectionPacket.Contract,Packets.Digest(body),body["records"]!.AsArray().Count,CanonicalJson.Length(body),step["now"]!.GetValue<string>(),step["continuity_state"]!.GetValue<string>(),step["filtered_count"]!.GetValue<long>(),step["lost_count"]?.GetValue<long>());
                var envelope=env.ToJson();var eventRows=new JsonArray(body["records"]!.AsArray().Select(x=>x!["payload"]!.DeepClone()).ToArray());
                await Sql("insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt,received_at) values(@agent,'sli.file-audit',1,@packet,@hash,@env,'{\"status\":\"committed\"}'::jsonb,@at)",("agent",agent,null),("packet",packet,null),("hash",Packets.Digest(envelope),null),("env",CanonicalJson.Serialize(envelope),NpgsqlDbType.Jsonb),("at",received,null));
                await Sql("insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at) values(@packet,@env,@body,@rows,@at)",("packet",packet,null),("env",CanonicalJson.Serialize(envelope),NpgsqlDbType.Jsonb),("body",CanonicalJson.Serialize(body),NpgsqlDbType.Jsonb),("rows",CanonicalJson.Serialize(eventRows),NpgsqlDbType.Jsonb),("at",received,null));return (config,env);
            }
            DateTime first=new(2001,1,1,0,0,0,DateTimeKind.Utc);DateTime second=first.AddSeconds(1);
            Assert.Equal(0L,(long)(await Sql("select count(*) from sli_agent_packet_inbox where imported_at is null and envelope->>'module_id'='sli.file-audit' and received_at<=@end",("end",second,null)))!);
            var (config,env)=await Seed("workstation",true,first);await Seed("server",false,second);
            var command=new JsonObject { ["contract_id"]="sli.file-audit.audit-command.v1",["command_id"]=commandId,["action"]="check",["policy_revision"]="2",["collection_scope_ids"]=new JsonArray("scope:one") };
            await Sql("select sli_plugin_file_audit.enqueue_audit(@agent,@source,@policy,@command,'session',1)",("agent",Id("workstation_agent"),null),("source",Id("workstation_host").ToString("D"),null),("policy",CanonicalJson.Serialize(config),NpgsqlDbType.Jsonb),("command",CanonicalJson.Serialize(command),NpgsqlDbType.Jsonb));
            var snap=new JsonObject { ["snapshot_id"]=Id("snapshot").ToString("D"),["collection_scope_id"]="scope:one",["observed_at_utc"]="2026-10-07T00:00:00+00:00",["completeness"]="complete",["snapshot_sha256"]=new string('b',64),["unread_objects"]=0,["objects"]=new JsonArray(new JsonObject { ["path"]="C:\\synthetic\\item",["object_type"]="file" }) };
            var result=new JsonObject { ["command_id"]=commandId,["policy_revision"]="2",["action"]="check",["snapshots"]=new JsonArray(snap),["scopes"]=new JsonArray() };
            await Sql("select sli_plugin_file_audit.store_audit_result(@agent,@result)",("agent",Id("workstation_agent"),null),("result",CanonicalJson.Serialize(result),NpgsqlDbType.Jsonb));
            Assert.Equal(0L,(long)(await Sql("select count(*) from sli_agent_packet_inbox where imported_at is null and received_at<@first",("first",first,null)))!);
            string wsPath=Environment.GetEnvironmentVariable("SLI_WORKER_WS_VECTOR")!;
            var wsFixture=JsonNode.Parse(await File.ReadAllTextAsync(wsPath,ct))!.AsObject();var wsBody=wsFixture["packet"]!.DeepClone().AsObject();
            Guid wsAgent=Id("ws_agent"),wsHost=Id("ws_host"),wsPacket=Id("ws_packet");wsBody["header"]!["source"]=wsHost.ToString("D");wsBody["records"]![0]!["payload"]!["computer_name"]=wsHost.ToString("D");
            var wsRows=new JsonArray(wsBody["records"]!.AsArray().Select(x=>x!["payload"]!.DeepClone()).ToArray());
            var wsEnv=new JsonObject { ["agent_id"]=wsAgent.ToString("D"),["packet_id"]=wsPacket.ToString("D"),["module_id"]="sli.workstations",["source_instance_id"]=wsHost.ToString("D"),["payload_sha256"]=Packets.Digest(wsBody) };
            await Sql("insert into sli_agents(id,host_id,key_fingerprint,assigned_modules) values(@agent,@host,repeat('a',64),'[{\"module_id\":\"sli.workstations\",\"enabled\":true}]'::jsonb)",("agent",wsAgent,null),("host",wsHost,null));
            await Sql("insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt,received_at) values(@agent,'sli.workstations',1,@packet,@hash,@env,'{\"status\":\"committed\"}'::jsonb,@at)",("agent",wsAgent,null),("packet",wsPacket,null),("hash",Packets.Digest(wsEnv),null),("env",CanonicalJson.Serialize(wsEnv),NpgsqlDbType.Jsonb),("at",first.AddSeconds(-1),null));
            await Sql("insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at) values(@packet,@env,@body,@rows,@at)",("packet",wsPacket,null),("env",CanonicalJson.Serialize(wsEnv),NpgsqlDbType.Jsonb),("body",CanonicalJson.Serialize(wsBody),NpgsqlDbType.Jsonb),("rows",CanonicalJson.Serialize(wsRows),NpgsqlDbType.Jsonb),("at",first.AddSeconds(-1),null));
            AgentInboxStep? wsStep=null;AgentInboxStep? one=null;
            int exit=await AgentImportLoop.RunAsync(new(true,10),async (limit,token)=> {
                Assert.Equal(16,limit);
                wsStep=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,null,token);
                one=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,(wsStep.Received,wsStep.PacketId),token);
                return new AgentInboxBatchResult(2,(wsStep.Imported?1:0)+(one.Imported?1:0),new Dictionary<string,int>());
            },(_,_)=>throw new InvalidOperationException(),ct);
            Assert.Equal(0,exit);Assert.NotNull(wsStep);Assert.Equal(wsPacket,wsStep.PacketId);Assert.True(wsStep.Imported,wsStep.PendingReason);
            Assert.NotNull(one);Assert.Equal(Id("workstation_packet"),one.PacketId);Assert.True(one.Imported,one.PendingReason);
            Assert.Equal(1L,(long)(await Sql("select count(*) from sli_plugin_workstations.observations where agent_key=@agent",("agent",wsAgent.ToString("D"),null)))!);
            Assert.Equal(1L,(long)(await Sql("select count(*) from sli_agent_packet_inbox where packet_id=@packet and imported_at is not null",("packet",wsPacket,null)))!);
            var roots=new JsonArray(new JsonObject { ["agent_id"]=env.AgentId,["source_instance_id"]=env.SourceInstanceId,["collection_scope_id"]="scope:one" });
            var report=(string)(await Sql("select sli_plugin_file_audit.report_rows(@roots,'mass-operations','2026-10-06T00:00:00Z','2026-10-08T00:00:00Z',null,false,null,null,null,100)::text",("roots",CanonicalJson.Serialize(roots),NpgsqlDbType.Jsonb)))!;
            Assert.Contains("file-audit.mass-write",report);
            var two=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,(one.Received,one.PacketId),ct);Assert.Equal(Id("server_packet"),two.PacketId);Assert.False(two.Imported);Assert.Equal("file_audit_source_not_configured",two.PendingReason);
            Assert.Equal(1L,(long)(await Sql("select count(*) from sli_agent_packet_inbox where packet_id=@packet and imported_at is not null",("packet",one.PacketId,null)))!);
            Assert.Equal(0L,(long)(await Sql("select count(*) from sli_agent_packet_inbox where packet_id=@packet and imported_at is not null",("packet",two.PacketId,null)))!);
            await Sql("update sli_agent_packet_inbox set imported_at=null where packet_id=@packet",("packet",one.PacketId,null));
            var replay=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,null,ct);Assert.True(replay.Imported,replay.PendingReason);Assert.Equal(one.PacketId,replay.PacketId);
        } finally { await tx.RollbackAsync(ct); }
        await using var checkGone=new NpgsqlCommand("select count(*) from sli_agents where id in (@one,@two,@three)",db);checkGone.Parameters.AddWithValue("one",Id("workstation_agent"));checkGone.Parameters.AddWithValue("two",Id("server_agent"));checkGone.Parameters.AddWithValue("three",Id("ws_agent"));Assert.Equal(0L,(long)(await checkGone.ExecuteScalarAsync(ct))!);
        Assert.Equal(before,await RetainedState());
        await using var unlock=new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_post_collection_process'))",db);Assert.Equal(true,await unlock.ExecuteScalarAsync(ct));
    }
}
