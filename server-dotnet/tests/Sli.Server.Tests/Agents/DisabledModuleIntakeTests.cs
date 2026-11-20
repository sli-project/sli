using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Server.Agents;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Ingress;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class DisabledModuleIntakeTests
{
    [Fact]
    public async Task Upgrade_disables_collection_refuses_packets_and_releases_queue_share_without_deleting_bodies()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct,throughVersion:376);
        await using var owner=new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        Guid agent=Guid.NewGuid(),host=Guid.NewGuid();
        var now=DateTimeOffset.UtcNow;
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert=new CertificateRequest("CN=example.test",key,HashAlgorithmName.SHA256).CreateSelfSigned(now.AddDays(-1),now.AddDays(1));
        var signed=Packets.Make(new EcdsaPacketSigner(key),agent.ToString("D"),1,
            new Sample("sli.workstations",host.ToString("D"),"workstations","g",new Cursor("record_id",""),new Cursor("record_id","1"),
                new JsonObject { ["contract"]="sli.collection-packet.v1" }),now);
        var modules=JsonNode.Parse("""
            [{"module_id":"sli.workstations","enabled":true,"config":{}},
             {"module_id":"sli.file-audit","enabled":true,"config":{}},
             {"module_id":"sli.windows.ad-dc","enabled":true,"config":{}},
             {"module_id":"sli.windows-eventlog","enabled":false,"config":{}}]
            """)!.AsArray();
        modules[2]!["config"]=AgentAdDcValidator.NormalizePolicy(new JsonObject {
            ["source_name"]="dc.example.test",["connect_address"]="dc.example.test",["policy_revision"]="4",
            ["channels"]=new JsonObject { ["Security"]=true,["System"]=true,["Directory Service"]=true }
        },false);
        await using(var seed=new NpgsqlCommand("""
            insert into sli_agents(id,host_id,key_fingerprint,assigned_modules,policy_revision)
              values(@agent,@host,repeat('a',64),@modules::jsonb,4);
            insert into sli_agent_module_bindings(agent_id,module_id,source_instance_id,source_name,channel,module_version,policy_revision)
              values(@agent,'sli.windows.ad-dc',@source,'dc.example.test','ad-dc','1.0.0','4');
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt,received_at)
              values(@agent,'sli.workstations',1,@packet,@hash,@envelope::jsonb,@receipt::jsonb,now()-interval '10 days');
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at)
              values(@packet,@envelope::jsonb,@payload::jsonb,'[]',now()-interval '10 days');
            """,owner)) {
            seed.Parameters.AddWithValue("agent",agent); seed.Parameters.AddWithValue("host",host);
            seed.Parameters.AddWithValue("source",host.ToString("D"));
            seed.Parameters.AddWithValue("modules",modules.ToJsonString()); seed.Parameters.AddWithValue("packet",Guid.Parse(signed.Envelope.PacketId));
            seed.Parameters.AddWithValue("hash",Packets.Digest(signed.Envelope.ToJson())); seed.Parameters.AddWithValue("envelope",signed.Envelope.ToJson().ToJsonString());
            seed.Parameters.AddWithValue("receipt",AgentReceipt.Make(signed.Envelope,"committed",null,now).ToJsonString());
            seed.Parameters.AddWithValue("payload",signed.Payload.ToJsonString()); await seed.ExecuteNonQueryAsync(ct);
        }
        string migration=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/380_disabled_module_intake.sql");
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        async Task AssertMarker(bool marked) {
            await using var query=new NpgsqlCommand("select module_disabled_at is not null,imported_at is null,packet=@payload::jsonb from sli_agent_packet_inbox where envelope->>'module_id'='sli.workstations'",owner);
            query.Parameters.AddWithValue("payload",signed.Payload.ToJsonString());
            await using var row=await query.ExecuteReaderAsync(ct); Assert.True(await row.ReadAsync(ct));
            Assert.Equal(marked,row.GetBoolean(0)); Assert.True(row.GetBoolean(1)); Assert.True(row.GetBoolean(2));
        }
        await AssertMarker(true);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration,".rollback.sql"),null,ct);
        await AssertMarker(false);
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        await AssertMarker(true);

        await using var db=new NpgsqlConnection(fixture.Dsn("adlog_user")); await db.OpenAsync(ct);
        var identity=new AgentIdentity(agent,host,new string('a',64),"active");
        using var state=new StorageLifecycleTests.State();
        var limits=new AgentInboxLimits(1,long.MaxValue,32768,long.MaxValue,65536,long.MaxValue,long.MaxValue) { FreeDiskBytes=()=>20L*1024*1024*1024 };
        var diagnostics=new AgentIngressDiagnostics(state.Path,NullLogger<AgentIngressDiagnostics>.Instance,TimeProvider.System);
        var ingress=new AgentPacketService(TimeProvider.System,limits,diagnostics);
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            // The endpoint authenticates and locks the agent before check-in.
            await using(var locked=new NpgsqlCommand("select id from sli_agents where id=@id for update",db,tx)) {
                locked.Parameters.AddWithValue("id",agent); await locked.ExecuteScalarAsync(ct);
            }
            var service=new AgentClientControlService(new AgentControlAudit(),TimeProvider.System);
            var policy=await service.CheckInAsync(db,tx,identity,ct);
            Assert.Equal(5,policy["policy_revision"]!.GetValue<long>());
            foreach(var module in new[] { "sli.workstations","sli.file-audit" })
                Assert.False(policy["assigned_modules"]!.AsArray().OfType<JsonObject>().Single(m=>m["module_id"]!.GetValue<string>()==module)["enabled"]!.GetValue<bool>());
            Assert.NotNull(AgentPolicyAssignments.FindCurrent(policy["assigned_modules"]!.AsArray(),"sli.windows.ad-dc"));
            Assert.Equal(5,(await service.CheckInAsync(db,tx,identity,ct))["policy_revision"]!.GetValue<long>());
            await using(var history=new NpgsqlCommand("select assigned_modules::text from sli_agent_policy_history where agent_id=@id and revision=4",db,tx)) {
                history.Parameters.AddWithValue("id",agent);
                Assert.NotNull(AgentPolicyAssignments.FindCurrent(JsonNode.Parse((string)(await history.ExecuteScalarAsync(ct))!)!.AsArray(),"sli.workstations"));
            }
            var tampered=signed.ToJson(); tampered["signature"]="invalid";
            await Assert.ThrowsAsync<ProtocolException>(()=>ingress.ReceiveAsync(db,tx,identity,cert,tampered,ct));
            foreach(var packet in new[] { signed,Packets.Make(new EcdsaPacketSigner(key),agent.ToString("D"),2,
                new Sample("sli.workstations",host.ToString("D"),"workstations","g",new Cursor("record_id","1"),new Cursor("record_id","2"),signed.Payload),now) }) {
                var receipt=await ingress.ReceiveAsync(db,tx,identity,cert,packet.ToJson(),ct);
                Assert.Equal("rejected",receipt["status"]!.GetValue<string>());
                Assert.Equal("module_disabled",receipt["error_code"]!.GetValue<string>());
                Assert.Null(receipt["committed_cursor"]); Assert.Null(receipt["committed_at_utc"]);
                Assert.True(Receipt.IsModuleDisabled(packet.Envelope,receipt));
            }
            var assignment=JsonSerializer.SerializeToElement(new { agent_id=agent,module_id="sli.workstations",enabled=true,config=new {} });
            var error=await Assert.ThrowsAsync<AgentControlException>(()=>new AgentModuleAssignmentService(new AgentControlAudit()).AssignAsync(db,tx,assignment,"session:1",ct));
            Assert.Equal("module_disabled",error.Message);
            var unassigned=Packets.Make(new EcdsaPacketSigner(key),agent.ToString("D"),1,
                new Sample("sli.windows-eventlog",host.ToString("D"),"Security","g",new Cursor("record_id",""),new Cursor("record_id","1"),signed.Payload),now);
            Assert.Equal("module_disabled",(await ingress.ReceiveAsync(db,tx,identity,cert,unassigned.ToJson(),ct))["error_code"]!.GetValue<string>());
            // A marked body still uses storage, but no longer consumes the agent's pending share.
            Assert.Null(await AgentInboxQuota.CheckAsync(db,tx,signed.Envelope,signed.Payload,new JsonArray(),
                AgentReceipt.Make(signed.Envelope,"committed",null,now),limits,diagnostics,ct));
            await tx.CommitAsync(ct);
        }
        await using(var count=new NpgsqlCommand("select (select count(*) from sli_agent_packet_inbox),(select count(*) from sli_agent_receipts)",db)) {
            await using var rows=await count.ExecuteReaderAsync(ct); await rows.ReadAsync(ct);
            Assert.Equal(1,rows.GetInt64(0)); Assert.Equal(1,rows.GetInt64(1));
        }
        // A later disable is handled by the bounded poll, even when import excludes the module.
        await using(var reset=new NpgsqlCommand("update sli_agent_packet_inbox set module_disabled_at=null",db)) await reset.ExecuteNonQueryAsync(ct);
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            Assert.Equal(1,await AgentPolicyAssignments.MarkDisabledAsync(db,tx,1,ct));
            Assert.Equal(0,await AgentPolicyAssignments.MarkDisabledAsync(db,tx,1,ct));
            await tx.CommitAsync(ct);
        }
        await AssertMarker(true);
        // Core modules never depend on plugin state: disabled or missing sli.ad/sli.gpo keeps DC accepted and assigned.
        foreach(string plugin in new[] { "update plugin_installations_v1 set desired_activation='disabled' where plugin_id in ('sli.ad','sli.gpo')",
            "set session_replication_role=replica; delete from plugin_installations_v1 where plugin_id in ('sli.ad','sli.gpo')" }) {
            await PostCollectionPostgres.Sql(owner,plugin,ct);
            await using var tx=await db.BeginTransactionAsync(ct);
            await using(var locked=new NpgsqlCommand("select id from sli_agents where id=@id for update",db,tx)) {
                locked.Parameters.AddWithValue("id",agent); await locked.ExecuteScalarAsync(ct);
            }
            var policy=await new AgentClientControlService(new AgentControlAudit(),TimeProvider.System).CheckInAsync(db,tx,identity,ct);
            Assert.Equal(5,policy["policy_revision"]!.GetValue<long>());
            Assert.True(AgentPolicyAssignments.FindCurrent(policy["assigned_modules"]!.AsArray(),"sli.windows.ad-dc")!["enabled"]!.GetValue<bool>());
            foreach(string core in new[] { "sli.windows.ad-dc","sli.windows.ad-dc-history","sli.ad-snapshot","sli.gpo-snapshot","sli.heartbeat" })
                Assert.True(await AgentPolicyAssignments.ModuleEnabledAsync(db,tx,core,ct));
            var dc=Packets.Make(new EcdsaPacketSigner(key),agent.ToString("D"),1,
                new Sample("sli.windows.ad-dc",host.ToString("D"),"Security","g",new Cursor("record_id",""),new Cursor("record_id","1"),signed.Payload),now);
            Assert.NotEqual("module_disabled",(await ingress.ReceiveAsync(db,tx,identity,cert,dc.ToJson(),ct))["error_code"]?.GetValue<string>());
            await tx.RollbackAsync(ct);
        }
        // Explicit assignment disable marks the queue; core DC packets stay unmarked.
        foreach(string module in new[] { "sli.windows-eventlog","sli.windows.ad-dc" }) {
            var packet=Packets.Make(new EcdsaPacketSigner(key),agent.ToString("D"),1,
                new Sample(module,host.ToString("D"),"Security","g",new Cursor("record_id",""),new Cursor("record_id","1"),signed.Payload),now);
            await using var insert=new NpgsqlCommand("""
                insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
                  values(@agent,@module,1,@packet,@hash,@envelope::jsonb,@receipt::jsonb);
                insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows)
                  values(@packet,@envelope::jsonb,@payload::jsonb,'[]');
                """,owner);
            insert.Parameters.AddWithValue("agent",agent); insert.Parameters.AddWithValue("module",module);
            insert.Parameters.AddWithValue("packet",Guid.Parse(packet.Envelope.PacketId));
            insert.Parameters.AddWithValue("hash",Packets.Digest(packet.Envelope.ToJson()));
            insert.Parameters.AddWithValue("envelope",packet.Envelope.ToJson().ToJsonString());
            insert.Parameters.AddWithValue("receipt",AgentReceipt.Make(packet.Envelope,"committed",null,now).ToJsonString());
            insert.Parameters.AddWithValue("payload",packet.Payload.ToJsonString()); await insert.ExecuteNonQueryAsync(ct);
        }
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            Assert.Equal(1,await AgentPolicyAssignments.MarkDisabledAsync(db,tx,1,ct));
            Assert.Equal(0,await AgentPolicyAssignments.MarkDisabledAsync(db,tx,1,ct));
            await tx.CommitAsync(ct);
        }
        await using var deletion=NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(fixture.Dsn("sli_storage_lifecycle_delete_login")) {
            Options="-c role=adlog_storage_lifecycle_delete",CommandTimeout=0 }.ConnectionString);
        await using(var core=new NpgsqlCommand("select count(*) from sli_agent_packet_inbox where envelope->>'module_id'='sli.windows.ad-dc' and module_disabled_at is null",db)) Assert.Equal(1L,await core.ExecuteScalarAsync(ct));
        var retention=new InboxRetention(deletion,state.Files);
        Assert.Equal(0,LifecycleJson.Number(await retention.RunAsync(DateTime.UtcNow.AddDays(-7),Guid.Empty,1000,ct),"deleted_count"));
        await using(var aged=new NpgsqlCommand("update sli_agent_packet_inbox set module_disabled_at=now()-interval '10 days' where envelope->>'module_id'='sli.workstations'",db)) await aged.ExecuteNonQueryAsync(ct);
        Assert.Equal(1,LifecycleJson.Number(await retention.RunAsync(DateTime.UtcNow.AddDays(-7),Guid.Empty,1000,ct),"deleted_count"));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
