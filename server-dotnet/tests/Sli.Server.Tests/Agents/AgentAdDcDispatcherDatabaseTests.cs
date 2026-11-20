using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;
using Sli.Server.Tests.Integration;
using Xunit;
using AgentIdentity = Sli.Server.Agents.AgentIdentity;

namespace Sli.Server.Tests.Agents;

public sealed class AgentAdDcDispatcherDatabaseTests
{
    private static readonly Guid Agent=Guid.Parse("e8084bb2-ad05-4306-90e2-2d9a1517e29a");
    private static readonly Guid Host=Guid.Parse("6f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f");
    private static readonly Guid Packet=Guid.Parse("64e44920-cde3-4b42-a8c2-4232c9514e5e");
    private static readonly Guid NextPacket=Guid.Parse("073f92f7-19a7-44de-b02d-9b690642351c");
    private sealed class Clock(DateTimeOffset value):TimeProvider { public override DateTimeOffset GetUtcNow()=>value; }
    private static async Task<AgentIdentity> Lock(NpgsqlConnection db,NpgsqlTransaction tx,CancellationToken ct)
    {
        await using var cmd=new NpgsqlCommand("select id,host_id,key_fingerprint,status from sli_agents where id=@id for no key update",db,tx); cmd.Parameters.AddWithValue("id",Agent);
        await using var reader=await cmd.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct));
        return new(reader.GetGuid(0),reader.GetGuid(1),reader.GetString(2),reader.GetString(3));
    }
    private static SignedPacket Signed(ECDsa key,JsonObject sample,JsonObject payload,long sequence,Guid packet,DateTimeOffset now)
    {
        var value=new Sample("sli.windows.ad-dc-history",Host.ToString("D"),"ad-dc",Host.ToString("D"),Cursor.FromJson(sample["cursor_before"]),Cursor.FromJson(sample["cursor_after"]),payload,
            PolicyRevision:"1",ContinuityState:sample["continuity_state"]!.GetValue<string>(),FilteredCount:sample["filtered_count"]!.GetValue<long>(),LostCount:sample["lost_count"]?.GetValue<long>());
        return Packets.Make(new EcdsaPacketSigner(key),Agent.ToString("D"),sequence,value,now,()=>packet);
    }
    [Fact]
    public async Task HistoryReceiptInboxAndPendingGuardUseCallerTransaction()
    {
        var ct=TestContext.Current.CancellationToken; var bytes=await File.ReadAllBytesAsync(Environment.GetEnvironmentVariable("SLI_AD_HISTORY_VECTORS")!,ct);
        Assert.Equal("5029b4c908befa54d4c10674e65157a52aa56c8a57172e18d9a0319d8cec1e72",Convert.ToHexStringLower(SHA256.HashData(bytes)));
        var fixtures=JsonNode.Parse(bytes)!.AsArray(); var first=fixtures[0]!["sample"]!.AsObject(); var second=(JsonObject)fixtures[1]!["sample"]!.DeepClone();
        var payload=(JsonObject)first["payload"]!.DeepClone(); var nextPayload=(JsonObject)second["payload"]!.DeepClone();
        var before=Cursor.FromJson(first["cursor_after"]); var nextState=JsonNode.Parse(before.Token)!.AsObject(); nextState["channels"]!["Security"]!["complete"]=true;
        second["cursor_before"]=before.ToJson(); second["cursor_after"]=new Cursor("bookmark",CanonicalJson.Serialize(nextState)).ToJson();
        nextPayload["header"]!["cursor"]=new JsonObject { ["after_record_id"]=101,["last_record_id"]=101 };
        var policy=AgentAdDcValidator.NormalizePolicy(fixtures[0]!["config"]!.AsObject(),true);
        var now=Iso8601.ParseUtc(payload["header"]!["observed_at_utc"]!.GetValue<string>());
        var verifyEnvelope=new Envelope(NextPacket.ToString("D"),Agent.ToString("D"),Host.ToString("D"),"sli.windows.ad-dc-history","1.0.0","1","ad-dc",Host.ToString("D"),2,before,Cursor.FromJson(second["cursor_after"]),CollectionPacket.Contract,Packets.Digest(nextPayload),0,CanonicalJson.Length(nextPayload),nextPayload["header"]!["observed_at_utc"]!.GetValue<string>(),second["continuity_state"]!.GetValue<string>(),0,second["lost_count"]?.GetValue<long>());
        Assert.Empty(AgentAdDcValidator.Validate(verifyEnvelope,nextPayload,policy,"fixture-dc"));
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256); using var cert=new CertificateRequest("CN=synthetic",key,HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(1));
        var signed=Signed(key,first,payload,1,Packet,now).ToJson(); var pending=Signed(key,second,nextPayload,2,NextPacket,now).ToJson();
        string dir=Path.Combine(Path.GetTempPath(),"sli-ad-history-test-"+Guid.NewGuid().ToString("N")); var clock=new Clock(now);
        var service=new AgentPacketService(clock,new AgentInboxLimits(4096,268435456,32768,2147483648,65536,4294967296,17179869184),new AgentIngressDiagnostics(dir,NullLogger<AgentIngressDiagnostics>.Instance,clock));
        try
        {
            await using var database=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct); await using var db=await database.OpenConnectionAsync(ct);
            await using(var role=new NpgsqlCommand("select current_user",db)) Assert.Equal("adlog_user",(string)(await role.ExecuteScalarAsync(ct))!);
            await using(var tx=await db.BeginTransactionAsync(ct))
            {
                var receipt=await service.ReceiveAsync(db,tx,await Lock(db,tx,ct),cert,signed,ct); Assert.Equal("committed",receipt["status"]!.GetValue<string>());
                await using var check=new NpgsqlCommand("select (select count(*) from sli_agent_receipts where packet_id=@packet),(select count(*) from sli_agent_packet_inbox where packet_id=@packet)",db,tx); check.Parameters.AddWithValue("packet",Packet);
                await using(var r=await check.ExecuteReaderAsync(ct)) { Assert.True(await r.ReadAsync(ct)); Assert.Equal(1,r.GetInt64(0)); Assert.Equal(1,r.GetInt64(1)); }
                await tx.RollbackAsync(ct);
            }
            await using(var tx=await db.BeginTransactionAsync(ct))
            {
                var receipt=await service.ReceiveAsync(db,tx,await Lock(db,tx,ct),cert,signed,ct); Assert.Equal("committed",receipt["status"]!.GetValue<string>()); await tx.CommitAsync(ct);
            }
            await using(var tx=await db.BeginTransactionAsync(ct))
            {
                var identity=await Lock(db,tx,ct); var duplicate=await service.ReceiveAsync(db,tx,identity,cert,signed,ct); Assert.Equal("duplicate",duplicate["status"]!.GetValue<string>());
                var refused=await service.ReceiveAsync(db,tx,identity,cert,pending,ct); Assert.Equal("retry_later",refused["status"]!.GetValue<string>()); Assert.Equal("agent_history_pending",refused["error_code"]!.GetValue<string>()); await tx.RollbackAsync(ct);
            }
        }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir,true); }
    }
}
