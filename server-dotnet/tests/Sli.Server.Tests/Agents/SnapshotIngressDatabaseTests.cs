using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents;
using Sli.Server.Agents.Ingress;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class SnapshotIngressDatabaseTests
{
    [Theory]
    [InlineData(SnapshotPolicy.Ad)]
    [InlineData(SnapshotPolicy.Gpo)]
    public async Task SourceAdmissionQuotaReceiptFirstChunkAndRollback(string module)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var database = await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(), ct);
        var baseline = await database.ReadBaselineAsync(ct);
        Assert.Equal(18,baseline.MajorVersion); Assert.Equal(300,baseline.SchemaVersion);
        await using var db = await database.OpenConnectionAsync(ct);
        var agent = Guid.NewGuid(); var host = Guid.NewGuid(); var source = Guid.NewGuid(); var cycle = Guid.NewGuid(); var packet = Guid.NewGuid();
        var config = new JsonObject { ["source_instance_id"] = source.ToString("D"), ["domain_sid"] = $"S-1-5-21-{Random.Shared.Next(1,int.MaxValue)}-{Random.Shared.Next(1,int.MaxValue)}-{Random.Shared.Next(1,int.MaxValue)}",
            ["domain_dns"]="example.test", ["scope"]=string.Concat(Enumerable.Repeat("😀",300)), ["policy_revision"]="١" };
        var policy = SnapshotIngressPolicy.Parse(module,config);
        var assignments = new JsonArray(new JsonObject { ["module_id"] = module, ["enabled"] = true, ["config"] = policy.Config.DeepClone() });
        var payload = new JsonObject { ["contract"] = module + ".chunk.v1", ["cycle_id"] = cycle.ToString("D"), ["family"] = policy.Families[0],
            ["slot_start_utc"] = "2026-10-07T11:00:00+00:00", ["chunk_index"] = 0, ["chunk_count"] = 1, ["total_objects"] = 0,
            ["total_bytes"] = 0, ["family_sha256"] = new string('a',64), ["records"] = new JsonArray(new JsonObject { ["data_b64"] = "" }),
            ["cycle_families"] = policy.Config["families"]!.DeepClone(), ["domain_sid"] = policy.Config["domain_sid"]!.DeepClone(),
            ["domain_dns"] = policy.Config["domain_dns"]!.DeepClone(), ["scope"] = policy.Config["scope"]!.DeepClone() };
        var envelope = new Envelope(packet.ToString("D"),agent.ToString("D"),source.ToString("D"),module,"1.0.0","١","snapshot",source.ToString("D"),1,
            Cursor.Start("snapshot"),SnapshotStream.MakeCursor(payload),module+".chunk.v1",new string('a',64),1,0,"2026-10-07T11:00:01+00:00","complete",0,0);
        var identity = new Sli.Server.Agents.AgentIdentity(agent,host,new string('a',64),"active");
        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            await using (var role = new NpgsqlCommand("select current_user",db,tx)) Assert.Equal("adlog_user",await role.ExecuteScalarAsync(ct));
            await using (var seed = new NpgsqlCommand("""
                insert into sli_agents(id,host_id,key_fingerprint) values(@agent,@host,repeat('a',64));
                insert into sli_agent_snapshot_bindings(agent_id,module_id,config,enabled) values(@agent,@module,@config,true);
                insert into sli_agent_snapshot_policies(agent_id,module_id,config,enabled) values(@agent,@module,@config,true);
                """,db,tx))
            {
                seed.Parameters.AddWithValue("agent",agent); seed.Parameters.AddWithValue("host",host); seed.Parameters.AddWithValue("module",module);
                seed.Parameters.AddWithValue("config",NpgsqlDbType.Jsonb,PacketStorageJson.Serialize(policy.Config));
                await seed.ExecuteNonQueryAsync(ct);
            }
            await using (var held = new NpgsqlCommand("select id from sli_agents where id=@agent for no key update",db,tx))
            { held.Parameters.AddWithValue("agent",agent); Assert.Equal(agent,await held.ExecuteScalarAsync(ct)); }
            var denied = await Assert.ThrowsAsync<ProtocolException>(() => SnapshotIngress.ValidateAsync(db,tx,identity,envelope,payload,new JsonArray(),ct));
            Assert.Equal("agent_module_not_assigned",denied.Code);
            var plan = await SnapshotIngress.ValidateAsync(db,tx,identity,envelope,payload,assignments,ct);
            var receipt = AgentReceipt.Make(envelope,"committed",null,DateTimeOffset.UtcNow);
            var enough = new AgentInboxLimits(1000,long.MaxValue/4,1000,long.MaxValue/4,1000,long.MaxValue/4,long.MaxValue/4);
            Assert.Null(await SnapshotIngress.CheckQuotaAsync(db,tx,plan,receipt,enough,ct));
            Assert.Equal("agent_snapshot_agent_bytes_limit",await SnapshotIngress.CheckQuotaAsync(db,tx,plan,receipt,enough with { AgentBytes=1 },ct));
            await tx.SaveAsync("before_receipt",ct);
            var fk = await Assert.ThrowsAsync<PostgresException>(() => SnapshotIngress.StoreAsync(db,tx,plan,ct));
            Assert.Equal("23503",fk.SqlState);
            await tx.RollbackAsync("before_receipt",ct);
            await new AgentPacketLedger(db,tx).StoreAsync(envelope,payload,null,receipt,ct);
            await SnapshotIngress.StoreAsync(db,tx,plan,ct);
            await using (var verify = new NpgsqlCommand("select c.policy->>'policy_revision',c.policy->>'scope',k.payload->>'family',r.packet_id from sli_agent_snapshot_cycles c join sli_agent_snapshot_chunks k using(cycle_id) join sli_agent_receipts r on r.packet_id=k.packet_id where c.cycle_id=@cycle",db,tx))
            {
                verify.Parameters.AddWithValue("cycle",cycle); await using var row=await verify.ExecuteReaderAsync(ct);
                Assert.True(await row.ReadAsync(ct)); Assert.Equal("١",row.GetString(0)); Assert.Equal(config["scope"]!.GetValue<string>(),row.GetString(1));
                Assert.Equal(policy.Families[0],row.GetString(2)); Assert.Equal(packet,row.GetGuid(3)); Assert.False(await row.ReadAsync(ct));
            }
            var conflictEnvelope = envelope with { PacketId = Guid.NewGuid().ToString("D") };
            var conflict = await Assert.ThrowsAsync<ProtocolException>(() => SnapshotIngress.ValidateAsync(db,tx,identity,conflictEnvelope,payload,assignments,ct));
            Assert.Equal("agent_snapshot_chunk_conflict",conflict.Code);
            await tx.RollbackAsync(ct);
        }
        await using (var absent = new NpgsqlCommand("select (select count(*) from sli_agents where id=@agent),(select count(*) from sli_agent_receipts where agent_id=@agent),(select count(*) from sli_agent_snapshot_cycles where cycle_id=@cycle),(select count(*) from sli_agent_snapshot_chunks where packet_id=@packet)",db))
        {
            absent.Parameters.AddWithValue("agent",agent); absent.Parameters.AddWithValue("cycle",cycle); absent.Parameters.AddWithValue("packet",packet);
            await using var row=await absent.ExecuteReaderAsync(ct); Assert.True(await row.ReadAsync(ct));
            for(int i=0;i<4;i++) Assert.Equal(0,row.GetInt64(i));
        }
    }
    [Fact]
    public async Task HistoricalSnapshotPolicyAndSameSlotConflictMatchSource()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var database = await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(), ct);
        await using var db = await database.OpenConnectionAsync(ct);
        var agent=Guid.NewGuid(); var host=Guid.NewGuid(); var source=Guid.NewGuid(); var cycle=Guid.NewGuid(); var packet=Guid.NewGuid();
        const string module=SnapshotPolicy.Gpo;
        var baseConfig = new JsonObject { ["source_instance_id"]=source.ToString("D"), ["domain_sid"]=$"S-1-5-21-{Random.Shared.Next(1,int.MaxValue)}-{Random.Shared.Next(1,int.MaxValue)}-{Random.Shared.Next(1,int.MaxValue)}", ["domain_dns"]="example.test", ["scope"]="domain", ["policy_revision"]="1" };
        var oldPolicy=SnapshotIngressPolicy.Parse(module,baseConfig);
        var currentConfig=(JsonObject)oldPolicy.Config.DeepClone(); currentConfig["policy_revision"]="2";
        var current=SnapshotIngressPolicy.Parse(module,currentConfig);
        var changedConfig=(JsonObject)oldPolicy.Config.DeepClone(); changedConfig["policy_revision"]="3"; changedConfig["domain_dns"]="changed.test";
        var assignments=new JsonArray(new JsonObject { ["module_id"]=module,["enabled"]=true,["config"]=current.Config.DeepClone() });
        var payload=new JsonObject { ["contract"]=module+".chunk.v1",["cycle_id"]=cycle.ToString("D"),["family"]=oldPolicy.Families[0],["slot_start_utc"]="2026-10-07T11:00:00+00:00",["chunk_index"]=0,["chunk_count"]=1,["total_objects"]=0,["total_bytes"]=0,["family_sha256"]=new string('a',64),["records"]=new JsonArray(new JsonObject { ["data_b64"]="" }),["cycle_families"]=oldPolicy.Config["families"]!.DeepClone(),["domain_sid"]=oldPolicy.Config["domain_sid"]!.DeepClone(),["domain_dns"]=oldPolicy.Config["domain_dns"]!.DeepClone(),["scope"]=oldPolicy.Config["scope"]!.DeepClone() };
        var envelope=new Envelope(packet.ToString("D"),agent.ToString("D"),source.ToString("D"),module,"1.0.0","1","snapshot",source.ToString("D"),1,Cursor.Start("snapshot"),SnapshotStream.MakeCursor(payload),module+".chunk.v1",new string('a',64),1,0,"2026-10-07T11:00:01+00:00","complete",0,0);
        var identity=new Sli.Server.Agents.AgentIdentity(agent,host,new string('a',64),"active");
        await using (var tx=await db.BeginTransactionAsync(ct))
        {
            await using (var seed=new NpgsqlCommand("""
                insert into sli_agents(id,host_id,key_fingerprint) values(@agent,@host,repeat('a',64));
                insert into sli_agent_snapshot_bindings(agent_id,module_id,config,enabled) values(@agent,@module,@current,true);
                insert into sli_agent_snapshot_policies(agent_id,module_id,config,enabled,superseded_at) values
                  (@agent,@module,@old,true,'2026-10-07T11:01:00Z'),(@agent,@module,@current,true,null),(@agent,@module,@changed,true,'2026-10-07T11:01:00Z');
                """,db,tx))
            {
                seed.Parameters.AddWithValue("agent",agent);seed.Parameters.AddWithValue("host",host);seed.Parameters.AddWithValue("module",module);
                seed.Parameters.AddWithValue("old",NpgsqlDbType.Jsonb,PacketStorageJson.Serialize(oldPolicy.Config));
                seed.Parameters.AddWithValue("current",NpgsqlDbType.Jsonb,PacketStorageJson.Serialize(current.Config));
                seed.Parameters.AddWithValue("changed",NpgsqlDbType.Jsonb,PacketStorageJson.Serialize(changedConfig));
                await seed.ExecuteNonQueryAsync(ct);
            }
            await using (var held=new NpgsqlCommand("select id from sli_agents where id=@agent for no key update",db,tx)) {held.Parameters.AddWithValue("agent",agent);await held.ExecuteScalarAsync(ct);}
            var tooLate=(JsonObject)payload.DeepClone(); tooLate["slot_start_utc"]="2026-10-08T11:00:00+00:00";
            var rejected=await Assert.ThrowsAsync<ProtocolException>(()=>SnapshotIngress.ValidateAsync(db,tx,identity,envelope,tooLate,assignments,ct));
            Assert.Equal("agent_snapshot_chunk_invalid",rejected.Code);
            var changedEnvelope=envelope with {PolicyRevision="3"};
            rejected=await Assert.ThrowsAsync<ProtocolException>(()=>SnapshotIngress.ValidateAsync(db,tx,identity,changedEnvelope,payload,assignments,ct));
            Assert.Equal("agent_source_not_bound",rejected.Code);
            var plan=await SnapshotIngress.ValidateAsync(db,tx,identity,envelope,payload,assignments,ct);
            var receipt=AgentReceipt.Make(envelope,"committed",null,DateTimeOffset.UtcNow);
            await new AgentPacketLedger(db,tx).StoreAsync(envelope,payload,null,receipt,ct);
            await SnapshotIngress.StoreAsync(db,tx,plan,ct);
            var other=(JsonObject)payload.DeepClone(); other["cycle_id"]=Guid.NewGuid().ToString("D");
            var otherEnvelope=envelope with {PacketId=Guid.NewGuid().ToString("D"),CursorAfter=SnapshotStream.MakeCursor(other)};
            rejected=await Assert.ThrowsAsync<ProtocolException>(()=>SnapshotIngress.ValidateAsync(db,tx,identity,otherEnvelope,other,assignments,ct));
            Assert.Equal("agent_snapshot_chunk_conflict",rejected.Code);
            await tx.RollbackAsync(ct);
        }
        await using var absent=new NpgsqlCommand("select (select count(*) from sli_agents where id=@agent),(select count(*) from sli_agent_snapshot_cycles where cycle_id=@cycle),(select count(*) from sli_agent_receipts where packet_id=@packet)",db);
        absent.Parameters.AddWithValue("agent",agent);absent.Parameters.AddWithValue("cycle",cycle);absent.Parameters.AddWithValue("packet",packet);
        await using var row=await absent.ExecuteReaderAsync(ct);Assert.True(await row.ReadAsync(ct)); for(int i=0;i<3;i++)Assert.Equal(0,row.GetInt64(i));
    }
}
