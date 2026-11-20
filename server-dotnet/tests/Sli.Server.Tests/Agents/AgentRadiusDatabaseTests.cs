using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Server.Agents;
using Sli.Server.Agents.Ingress;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentRadiusDatabaseTests
{
    private static readonly Guid Agent=Guid.Parse("6e1760cc-84ad-42a8-aeec-387d27de1f0b");
    private static readonly Guid Host=Guid.Parse("6f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f");
    private static readonly Guid Packet=Guid.Parse("d2c490e4-4018-4a15-8c2e-b55a92d3f80a");
    private sealed class Clock(DateTimeOffset value):TimeProvider { public override DateTimeOffset GetUtcNow()=>value; }
    private static async Task<AgentIdentity> Lock(NpgsqlConnection db,NpgsqlTransaction tx,CancellationToken ct)
    {
        await using var command=new NpgsqlCommand("select id,host_id,key_fingerprint,status from sli_agents where id=@id for no key update",db,tx);
        command.Parameters.AddWithValue("id",Agent); await using var reader=await command.ExecuteReaderAsync(ct);
        Assert.True(await reader.ReadAsync(ct)); return new(reader.GetGuid(0),reader.GetGuid(1),reader.GetString(2),reader.GetString(3));
    }
    private static async Task<long> Count(NpgsqlConnection db,NpgsqlTransaction tx,string table,CancellationToken ct)
    {
        Assert.Contains(table,new[]{"sli_agent_receipts","sli_agent_packet_inbox"});
        await using var cmd=new NpgsqlCommand($"select count(*) from {table} where packet_id=@id",db,tx);
        cmd.Parameters.AddWithValue("id",Packet); return (long)(await cmd.ExecuteScalarAsync(ct))!;
    }
    [Fact]
    public async Task RadiusReceiptAndInboxCommitTogetherAndReplay()
    {
        var ct=TestContext.Current.CancellationToken;
        var bytes=await File.ReadAllBytesAsync(Environment.GetEnvironmentVariable("SLI_NPS_VECTORS")!,ct);
        Assert.Equal("977e875e70aec0cfb0c0884bd2aa4fb235e70285aac508ac1df7f45e1d3a6dd3",Convert.ToHexStringLower(SHA256.HashData(bytes)));
        var fixture=JsonNode.Parse(bytes)!.AsArray().OfType<JsonObject>().Single(x=>x["name"]!.GetValue<string>()=="radius-bom-quoted-unicode");
        var step=fixture["steps"]![0]!.AsObject(); var payload=JsonNode.Parse(step["payload_canonical"]!.GetValue<string>())!.AsObject();
        var now=Iso8601.ParseUtc(step["now"]!.GetValue<string>());
        var sample=new Sample("sli.radius-accounting","synthetic-radius","radius-accounting",Host.ToString("D"),Cursor.FromJson(step["cursor_before"]),Cursor.FromJson(step["cursor_after"]),payload,
            PolicyRevision:"1",ContinuityState:step["continuity_state"]!.GetValue<string>(),FilteredCount:step["filtered_count"]!.GetValue<long>(),LostCount:step["lost_count"]?.GetValue<long>());
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert=new CertificateRequest("CN=synthetic",key,HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(1));
        var signed=Packets.Make(new EcdsaPacketSigner(key),Agent.ToString("D"),1,sample,now,()=>Packet).ToJson();
        string dir=Path.Combine(Path.GetTempPath(),"sli-radius-test-"+Guid.NewGuid().ToString("N")); var clock=new Clock(now);
        var service=new AgentPacketService(clock,new AgentInboxLimits(4096,268435456,32768,2147483648,65536,4294967296,17179869184),new AgentIngressDiagnostics(dir,NullLogger<AgentIngressDiagnostics>.Instance,clock));
        try
        {
            await using var database=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
            await using var db=await database.OpenConnectionAsync(ct);
            await using(var role=new NpgsqlCommand("select current_user",db)) Assert.Equal("adlog_user",(string)(await role.ExecuteScalarAsync(ct))!);
            await using(var tx=await db.BeginTransactionAsync(ct))
            {
                var identity=await Lock(db,tx,ct); var receipt=await service.ReceiveAsync(db,tx,identity,cert,signed,ct);
                Assert.Equal("committed",receipt["status"]!.GetValue<string>()); Assert.Equal(1,await Count(db,tx,"sli_agent_receipts",ct)); Assert.Equal(1,await Count(db,tx,"sli_agent_packet_inbox",ct));
                await tx.RollbackAsync(ct);
            }
            await using(var tx=await db.BeginTransactionAsync(ct))
            {
                Assert.Equal(0,await Count(db,tx,"sli_agent_receipts",ct)); Assert.Equal(0,await Count(db,tx,"sli_agent_packet_inbox",ct));
                var identity=await Lock(db,tx,ct); var receipt=await service.ReceiveAsync(db,tx,identity,cert,signed,ct);
                Assert.Equal("committed",receipt["status"]!.GetValue<string>()); await tx.CommitAsync(ct);
            }
            await using(var tx=await db.BeginTransactionAsync(ct))
            {
                var identity=await Lock(db,tx,ct); var receipt=await service.ReceiveAsync(db,tx,identity,cert,signed,ct);
                Assert.Equal("duplicate",receipt["status"]!.GetValue<string>()); Assert.Equal(1,await Count(db,tx,"sli_agent_receipts",ct)); Assert.Equal(1,await Count(db,tx,"sli_agent_packet_inbox",ct)); await tx.RollbackAsync(ct);
            }
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir,true); }
    }
}
