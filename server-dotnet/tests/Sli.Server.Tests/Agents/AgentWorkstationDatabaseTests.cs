using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents;
using Sli.Server.Agents.Ingress;
using Sli.Server.Tests.Integration;
using Xunit;
using AgentIdentity = Sli.Server.Agents.AgentIdentity;

namespace Sli.Server.Tests.Agents;

public sealed class AgentWorkstationDatabaseTests
{
    private static readonly Guid Agent=Guid.Parse("8d7708a8-1bf7-4777-9f5a-85bbb8d536ae");
    private static readonly Guid Host=Guid.Parse("6f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f");
    private static readonly Guid Packet=Guid.Parse("22cd2e0d-deea-4f20-9375-f969efb2d667");
    private static readonly Guid RatePacket=Guid.Parse("d01b013a-3155-4124-b2d6-12ded54b97be");
    private sealed class Clock(DateTimeOffset value):TimeProvider { public override DateTimeOffset GetUtcNow()=>value; }
    private static async Task<AgentIdentity> Lock(NpgsqlConnection db,NpgsqlTransaction tx,CancellationToken ct)
    {
        await using var cmd=new NpgsqlCommand("select id,host_id,key_fingerprint,status from sli_agents where id=@id for no key update",db,tx);
        cmd.Parameters.AddWithValue("id",Agent); await using var reader=await cmd.ExecuteReaderAsync(ct);
        Assert.True(await reader.ReadAsync(ct)); return new(reader.GetGuid(0),reader.GetGuid(1),reader.GetString(2),reader.GetString(3));
    }
    private static async Task<long> Count(NpgsqlConnection db,NpgsqlTransaction tx,string table,CancellationToken ct)
    {
        Assert.Contains(table,new[]{"sli_agent_receipts","sli_agent_packet_inbox"});
        await using var cmd=new NpgsqlCommand($"select count(*) from {table} where packet_id=@id",db,tx); cmd.Parameters.AddWithValue("id",Packet);
        return (long)(await cmd.ExecuteScalarAsync(ct))!;
    }
    private static SignedPacket Signed(ECDsa key,JsonObject step,JsonObject payload,long sequence,Guid packet)
    {
        var now=Iso8601.ParseUtc(step["now"]!.GetValue<string>());
        var sample=new Sample("sli.workstations",Host.ToString("D"),"workstations",Host.ToString("D"),Cursor.FromJson(step["cursor_before"]),Cursor.FromJson(step["cursor_after"]),payload,
            ModuleVersion:"1.1.0",PolicyRevision:"1",ContinuityState:step["continuity_state"]!.GetValue<string>(),FilteredCount:step["filtered_count"]!.GetValue<long>(),LostCount:step["lost_count"]?.GetValue<long>());
        return Packets.Make(new EcdsaPacketSigner(key),Agent.ToString("D"),sequence,sample,now,()=>packet);
    }
    [Fact]
    public async Task ReceiptInboxRollbackReplayAndStoredRateLimit()
    {
        var ct=TestContext.Current.CancellationToken; var bytes=await File.ReadAllBytesAsync(Environment.GetEnvironmentVariable("SLI_WORKSTATION_VECTORS")!,ct);
        Assert.Equal("b3270f61ab52c44c60fa14fb7f219d1ebd7761a411758a165abcdca5ed0b15b2",Convert.ToHexStringLower(SHA256.HashData(bytes)));
        var fixture=JsonNode.Parse(bytes)!.AsArray().OfType<JsonObject>().Single(x=>x["name"]!.GetValue<string>()=="filtered-rate-recovery");
        var first=fixture["steps"]![0]!.AsObject(); var second=fixture["steps"]![1]!.AsObject();
        var firstPayload=JsonNode.Parse(first["payload_canonical"]!.GetValue<string>())!.AsObject();
        var secondPayload=JsonNode.Parse(second["payload_canonical"]!.GetValue<string>())!.AsObject();
        var record=secondPayload["records"]![0]!.AsObject(); var row=record["payload"]!.AsObject();
        string xml=row["xml"]!.GetValue<string>().Replace(">4625<",">4624<",StringComparison.Ordinal);
        record["payload"]=EventXml.Parse(xml,Host.ToString("D"),"localhost","Security");
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert=new CertificateRequest("CN=synthetic",key,HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(1));
        var signed=Signed(key,first,firstPayload,1,Packet).ToJson(); var limited=Signed(key,second,secondPayload,2,RatePacket).ToJson();
        string dir=Path.Combine(Path.GetTempPath(),"sli-workstation-test-"+Guid.NewGuid().ToString("N")); var clock=new Clock(Iso8601.ParseUtc(second["now"]!.GetValue<string>()));
        var service=new AgentPacketService(clock,new AgentInboxLimits(4096,268435456,32768,2147483648,65536,4294967296,17179869184),new AgentIngressDiagnostics(dir,NullLogger<AgentIngressDiagnostics>.Instance,clock));
        try
        {
            await using var database=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct); await using var db=await database.OpenConnectionAsync(ct);
            await using(var role=new NpgsqlCommand("select current_user",db)) Assert.Equal("adlog_user",(string)(await role.ExecuteScalarAsync(ct))!);
            await using(var tx=await db.BeginTransactionAsync(ct))
            {
                var receipt=await service.ReceiveAsync(db,tx,await Lock(db,tx,ct),cert,signed,ct); Assert.Equal("committed",receipt["status"]!.GetValue<string>());
                Assert.Equal(1,await Count(db,tx,"sli_agent_receipts",ct)); Assert.Equal(1,await Count(db,tx,"sli_agent_packet_inbox",ct)); await tx.RollbackAsync(ct);
            }
            await using(var tx=await db.BeginTransactionAsync(ct))
            {
                Assert.Equal(0,await Count(db,tx,"sli_agent_receipts",ct)); Assert.Equal(0,await Count(db,tx,"sli_agent_packet_inbox",ct));
                var receipt=await service.ReceiveAsync(db,tx,await Lock(db,tx,ct),cert,signed,ct); Assert.Equal("committed",receipt["status"]!.GetValue<string>()); await tx.CommitAsync(ct);
            }
            await using(var tx=await db.BeginTransactionAsync(ct))
            {
                var identity=await Lock(db,tx,ct); var duplicate=await service.ReceiveAsync(db,tx,identity,cert,signed,ct); Assert.Equal("duplicate",duplicate["status"]!.GetValue<string>());
                var rejected=await service.ReceiveAsync(db,tx,identity,cert,limited,ct); Assert.Equal("retry_later",rejected["status"]!.GetValue<string>());
                Assert.Equal("agent_workstations_rate_limit",rejected["error_code"]!.GetValue<string>()); await tx.RollbackAsync(ct);
            }
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir,true); }
    }
}
