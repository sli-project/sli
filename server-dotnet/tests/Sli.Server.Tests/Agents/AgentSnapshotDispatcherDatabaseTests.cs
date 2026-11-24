using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Sli.Server.Tests.Integration;
using Xunit;
using AgentIdentity = Sli.Server.Agents.AgentIdentity;

namespace Sli.Server.Tests.Agents;

public sealed class AgentSnapshotDispatcherDatabaseTests
{
    private static readonly Guid Agent=Guid.Parse("f03c19bd-b201-4e75-a042-6fa963b76631");
    private static readonly Guid Host=Guid.Parse("e75b2e97-d1e0-42ae-a4f5-689d2940a7ad");
    private static readonly Guid Source=Guid.Parse("1cd516d7-91bc-477c-b50c-44119b11ed8f");
    private static readonly Guid Cycle=Guid.Parse("c7d60e5b-ce38-40a1-b2c8-5285d97fd6ba");
    private static readonly Guid Packet=Guid.Parse("de5e4e57-46f5-4350-a9ae-d9b3a0508c20");
    private sealed class Clock(DateTimeOffset value):TimeProvider { public override DateTimeOffset GetUtcNow()=>value; }
    [Fact]
    public async Task ReceiptFirstChunkAndCycleRollbackTogetherThroughDispatcher()
    {
        var ct=TestContext.Current.CancellationToken; var now=Iso8601.ParseUtc("2026-10-07T11:00:01+00:00");
        var config=new JsonObject { ["source_instance_id"]=Source.ToString("D"),["domain_sid"]="S-1-5-21-7101-7102-7103",["domain_dns"]="example.test",["scope"]="domain",["policy_revision"]="1" };
        var policy=SnapshotIngressPolicy.Parse(SnapshotPolicy.Gpo,config);
        var payload=new JsonObject { ["contract"]=SnapshotPolicy.Gpo+".chunk.v1",["cycle_id"]=Cycle.ToString("D"),["family"]=policy.Families[0],
            ["slot_start_utc"]="2026-10-07T11:00:00+00:00",["chunk_index"]=0,["chunk_count"]=1,["total_objects"]=0,["total_bytes"]=0,
            ["family_sha256"]=new string('a',64),["records"]=new JsonArray(new JsonObject { ["data_b64"]="" }),["cycle_families"]=policy.Config["families"]!.DeepClone(),
            ["domain_sid"]=policy.Config["domain_sid"]!.DeepClone(),["domain_dns"]=policy.Config["domain_dns"]!.DeepClone(),["scope"]=policy.Config["scope"]!.DeepClone() };
        var sample=new Sample(SnapshotPolicy.Gpo,Source.ToString("D"),"snapshot",Source.ToString("D"),Cursor.Start("snapshot"),SnapshotStream.MakeCursor(payload),payload,ContinuityState:"complete",LostCount:0);
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert=new CertificateRequest("CN=synthetic",key,HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(1));
        var signed=Packets.Make(new EcdsaPacketSigner(key),Agent.ToString("D"),1,sample,now,()=>Packet).ToJson();
        string dir=Path.Combine(Path.GetTempPath(),"sli-snapshot-dispatch-"+Guid.NewGuid().ToString("N")); var clock=new Clock(now);
        var limits=new AgentInboxLimits(4096,268435456,32768,2147483648,65536,4294967296,17179869184)
            { FreeDiskBytes = () => long.MaxValue };
        var service=new AgentPacketService(clock,limits,new AgentIngressDiagnostics(dir,NullLogger<AgentIngressDiagnostics>.Instance,clock));
        try
        {
            await using var database=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct); await using var db=await database.OpenConnectionAsync(ct);
            await using(var role=new NpgsqlCommand("select current_user",db)) Assert.Equal("adlog_user",(string)(await role.ExecuteScalarAsync(ct))!);
            await using(var tx=await db.BeginTransactionAsync(ct))
            {
                await using(var locked=new NpgsqlCommand("select id from sli_agents where id=@agent for no key update",db,tx)) { locked.Parameters.AddWithValue("agent",Agent); Assert.Equal(Agent,await locked.ExecuteScalarAsync(ct)); }
                var receipt=await service.ReceiveAsync(db,tx,new AgentIdentity(Agent,Host,new string('a',64),"active"),cert,signed,ct);
                Assert.Equal("committed",receipt["status"]!.GetValue<string>());
                await using(var check=new NpgsqlCommand("select (select count(*) from sli_agent_receipts where packet_id=@packet),(select count(*) from sli_agent_snapshot_chunks where packet_id=@packet),(select count(*) from sli_agent_snapshot_cycles where cycle_id=@cycle),(select count(*) from sli_agent_packet_inbox where packet_id=@packet)",db,tx))
                {
                    check.Parameters.AddWithValue("packet",Packet); check.Parameters.AddWithValue("cycle",Cycle); await using var reader=await check.ExecuteReaderAsync(ct);
                    Assert.True(await reader.ReadAsync(ct)); Assert.Equal(1,reader.GetInt64(0)); Assert.Equal(1,reader.GetInt64(1)); Assert.Equal(1,reader.GetInt64(2)); Assert.Equal(0,reader.GetInt64(3));
                }
                await tx.RollbackAsync(ct);
            }
            await using(var check=new NpgsqlCommand("select (select count(*) from sli_agent_receipts where packet_id=@packet),(select count(*) from sli_agent_snapshot_chunks where packet_id=@packet),(select count(*) from sli_agent_snapshot_cycles where cycle_id=@cycle)",db))
            {
                check.Parameters.AddWithValue("packet",Packet); check.Parameters.AddWithValue("cycle",Cycle); await using var reader=await check.ExecuteReaderAsync(ct);
                Assert.True(await reader.ReadAsync(ct)); for(int i=0;i<3;i++) Assert.Equal(0,reader.GetInt64(i));
            }
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir,true); }
    }
}
