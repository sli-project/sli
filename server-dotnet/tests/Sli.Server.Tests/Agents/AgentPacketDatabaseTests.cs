using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using System.Text.Json;
using Npgsql;
using Microsoft.Extensions.Logging.Abstractions;
using Sli.Agent.Protocol;
using Sli.Server.Agents;
using Sli.Server.Agents.Ingress;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentPacketDatabaseTests
{
    private sealed class DiagnosticsTemp : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(),"sli-packet-diag-"+Guid.NewGuid().ToString("N"));
        public void Dispose() { if (Directory.Exists(Path)) Directory.Delete(Path,true); }
    }
    private sealed class Clock(DateTimeOffset now) : TimeProvider { public override DateTimeOffset GetUtcNow() => now; }
    private static readonly Guid Agent1=Guid.Parse("ebbac001-1111-4111-8111-111111111111");
    private static readonly Guid Agent2=Guid.Parse("ebbac002-1111-4111-8111-111111111111");
    private static readonly Guid Host1=Guid.Parse("abfac001-1111-4111-8111-111111111111");
    private static readonly Guid Host2=Guid.Parse("abfac002-1111-4111-8111-111111111111");

    private static async Task<AgentIdentity> LockAsync(NpgsqlConnection connection, NpgsqlTransaction tx, Guid id, CancellationToken ct)
    {
        await using var command=new NpgsqlCommand("select id,host_id,key_fingerprint,status from sli_agents where id=@id for no key update",connection,tx);
        command.Parameters.AddWithValue("id",id);
        await using var reader=await command.ExecuteReaderAsync(ct);
        Assert.True(await reader.ReadAsync(ct));
        return new(reader.GetGuid(0),reader.GetGuid(1),reader.GetString(2),reader.GetString(3));
    }

    private static SignedPacket Heartbeat(ECDsa key, Guid agent, Guid host, long sequence, string before, DateTimeOffset now) =>
        Packets.Make(new EcdsaPacketSigner(key),agent.ToString("D"),sequence,
            new Sample("sli.heartbeat",host.ToString("D"),"heartbeat",host.ToString("D"),new Cursor("record_id",before),
                new Cursor("record_id",sequence.ToString()),new JsonObject { ["contract"]="sli.heartbeat.v1",["status"]="alive" }),now);

    private static SignedPacket Event(ECDsa key, Guid agent, Guid host, DateTimeOffset now, string revision="1", string generation="gen", long sequence=1)
    {
        string name="synthetic.invalid"; string channel="Security";
        var row=new JsonObject { ["record_id"]=5,["xml"]="<Event />",["computer_name"]=name,["channel"]=channel };
        var payload=CollectionPacket.Make(name,channel,generation,new JsonObject { ["after_record_id"]=null,["last_record_id"]=5 },
            [new PacketRecord("event_xml",5,row)],"not_proven",null,now);
        return Packets.Make(new EcdsaPacketSigner(key),agent.ToString("D"),sequence,
            new Sample("sli.windows-eventlog",host.ToString("D"),channel,generation,new Cursor("record_id",""),new Cursor("record_id","5"),payload, PolicyRevision: revision),now);
    }

    [Fact]
    public async Task OwnedTransactionsPreserveReceiptInboxReplayRollbackAndQuota()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var database=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        await using (var roleConnection=await database.OpenConnectionAsync(ct))
        await using (var roleCheck=new NpgsqlCommand("select current_user",roleConnection))
            Assert.Equal("adlog_user",(string)(await roleCheck.ExecuteScalarAsync(ct))!);
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request=new CertificateRequest("CN=synthetic",key,HashAlgorithmName.SHA256);
        using var cert=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(1));
        var now=DateTimeOffset.UtcNow;
        using var temporary=new DiagnosticsTemp();
        var diagnostics=new AgentIngressDiagnostics(temporary.Path,NullLogger<AgentIngressDiagnostics>.Instance,TimeProvider.System);
        var service=new AgentPacketService(TimeProvider.System,new AgentInboxLimits(4096,268435456,32768,2147483648,65536,4294967296,17179869184),diagnostics);
        // Source-signed float vector uses a distinct synthetic public key and a controlled capture time.
        string vectorPath=Environment.GetEnvironmentVariable("SLI_AGENT_FLOAT_VECTOR") ?? throw new InvalidOperationException("Missing source vector");
        byte[] vectorBytes=await File.ReadAllBytesAsync(vectorPath,ct);
        Assert.Equal("3b705d141e44b90b3ee4e5f2a3dc9d2e036b6449cbaa748307e9afdc73b55981",Convert.ToHexStringLower(SHA256.HashData(vectorBytes)));
        var vector=JsonNode.Parse(vectorBytes)!; var signed=vector["packet"]!;
        using var sourcePublic=ECDsa.Create();
        sourcePublic.ImportSubjectPublicKeyInfo(Convert.FromBase64String(vector["public_spki"]!.GetValue<string>()),out _);
        using var issuerKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var issuerRequest=new CertificateRequest("CN=fixture issuer",issuerKey,HashAlgorithmName.SHA256);
        issuerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));
        issuerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign,true));
        using var issuer=issuerRequest.CreateSelfSigned(now.AddDays(-1),now.AddDays(1));
        var peerRequest=new CertificateRequest("CN=fixture peer",sourcePublic,HashAlgorithmName.SHA256);
        using var sourcePeer=peerRequest.Create(issuer,now.AddHours(-1),now.AddHours(1),RandomNumberGenerator.GetBytes(16));
        var signedAt=Iso8601.ParseUtc(signed["envelope"]!["observed_at_utc"]!.GetValue<string>());
        var sourceService=new AgentPacketService(new Clock(signedAt),new AgentInboxLimits(4096,268435456,32768,2147483648,65536,4294967296,17179869184),diagnostics);
        await using (var sourceConnection=await database.OpenConnectionAsync(ct))
        await using (var tx=await sourceConnection.BeginTransactionAsync(ct))
        {
            var identity=await LockAsync(sourceConnection,tx,Agent1,ct);
            var accepted=await sourceService.ReceiveAsync(sourceConnection,tx,identity,sourcePeer,signed,ct);
            Assert.Equal("committed",accepted["status"]!.GetValue<string>());
            await using var read=new NpgsqlCommand("select packet->'records'->0->'payload'->>'measurement',packet->'records'->0->'payload'->>'large_integer' from sli_agent_packet_inbox where packet_id=@id",sourceConnection,tx);
            read.Parameters.AddWithValue("id",Guid.Parse(signed["envelope"]!["packet_id"]!.GetValue<string>()));
            await using(var reader=await read.ExecuteReaderAsync(ct)) { Assert.True(await reader.ReadAsync(ct)); Assert.Equal("1.5",reader.GetString(0)); Assert.Equal("922337203685477580812345",reader.GetString(1)); }
            await tx.RollbackAsync(ct);
        }
        var heartbeat=Heartbeat(key,Agent1,Host1,1,"",now);
        await using (var connection=await database.OpenConnectionAsync(ct))
        {
            await using (var tx=await connection.BeginTransactionAsync(ct))
            {
                var identity=await LockAsync(connection,tx,Agent1,ct);
                var accepted=await service.ReceiveAsync(connection,tx,identity,cert,heartbeat.ToJson(),ct);
                Assert.Equal("committed",accepted["status"]!.GetValue<string>()); await tx.CommitAsync(ct);
            }
            await using (var tx=await connection.BeginTransactionAsync(ct))
            {
                var identity=await LockAsync(connection,tx,Agent1,ct);
                var duplicate=await service.ReceiveAsync(connection,tx,identity,cert,heartbeat.ToJson(),ct);
                Assert.Equal("duplicate",duplicate["status"]!.GetValue<string>()); await tx.CommitAsync(ct);
            }
            await using (var tx=await connection.BeginTransactionAsync(ct))
            {
                var identity=await LockAsync(connection,tx,Agent1,ct);
                var late=new AgentPacketService(new Clock(now.AddDays(30)),new AgentInboxLimits(1,1,1,1,1,1,1),diagnostics);
                var duplicate=await late.ReceiveAsync(connection,tx,identity,cert,heartbeat.ToJson(),ct);
                Assert.Equal("duplicate",duplicate["status"]!.GetValue<string>());
                await tx.RollbackAsync(ct);
            }
            await using (var tx=await connection.BeginTransactionAsync(ct))
            {
                var identity=await LockAsync(connection,tx,Agent1,ct);
                var result=await service.ReceiveAsync(connection,tx,identity,cert,Heartbeat(key,Agent1,Host1,2,"wrong",now).ToJson(),ct);
                Assert.Equal("agent_cursor_mismatch",result["error_code"]!.GetValue<string>());
                await tx.RollbackAsync(ct);
            }
            await using (var tx=await connection.BeginTransactionAsync(ct))
            {
                var identity=await LockAsync(connection,tx,Agent1,ct);
                await using var beforeObservation=new NpgsqlCommand("select count(*) from sli_agent_audit where target=@target and action='sequence_gap_observed'",connection,tx);
                beforeObservation.Parameters.AddWithValue("target",Agent1.ToString("D")); long observedBefore=(long)(await beforeObservation.ExecuteScalarAsync(ct))!;
                var result=await service.ReceiveAsync(connection,tx,identity,cert,Heartbeat(key,Agent1,Host1,3,"1",now).ToJson(),ct);
                Assert.Equal("retry_later",result["status"]!.GetValue<string>());
                Assert.Equal("agent_sequence_gap",result["error_code"]!.GetValue<string>());
                await using var observed=new NpgsqlCommand("select count(*) from sli_agent_audit where target=@target and action='sequence_gap_observed'",connection,tx);
                observed.Parameters.AddWithValue("target",Agent1.ToString("D")); Assert.Equal(observedBefore+1,(long)(await observed.ExecuteScalarAsync(ct))!);
                await tx.RollbackAsync(ct);
            }
            await using (var tx=await connection.BeginTransactionAsync(ct))
            {
                var identity=await LockAsync(connection,tx,Agent1,ct);
                var conflicting=Heartbeat(key,Agent1,Host1,1,"",now);
                var rejected=await service.ReceiveAsync(connection,tx,identity,cert,conflicting.ToJson(),ct);
                Assert.Equal("agent_sequence_conflict",rejected["error_code"]!.GetValue<string>()); await tx.RollbackAsync(ct);
            }
            await using (var tx=await connection.BeginTransactionAsync(ct))
            {
                var identity=await LockAsync(connection,tx,Agent1,ct);
                var result=await service.ReceiveAsync(connection,tx,identity,cert,Heartbeat(key,Agent1,Host1,2,"1",now).ToJson(),ct);
                Assert.Equal("committed",result["status"]!.GetValue<string>()); await tx.RollbackAsync(ct);
            }
            await using var count=new NpgsqlCommand("select (select count(*) from sli_agent_receipts where agent_id=@id),(select count(*) from sli_agent_packet_inbox where envelope->>'agent_id'=@text)",connection);
            count.Parameters.AddWithValue("id",Agent1); count.Parameters.AddWithValue("text",Agent1.ToString("D"));
            await using var reader=await count.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct)); Assert.Equal(1,reader.GetInt64(0)); Assert.Equal(0,reader.GetInt64(1));
        }
        // Seed an existing synthetic authorization only after the real observation; this is not an admin-authorization test.
        var gap=Heartbeat(key,Agent1,Host1,3,"1",now); long observationId;
        await using (var connection=await database.OpenConnectionAsync(ct))
        {
            await using (var tx=await connection.BeginTransactionAsync(ct))
            {
                var identity=await LockAsync(connection,tx,Agent1,ct);
                var retry=await service.ReceiveAsync(connection,tx,identity,cert,gap.ToJson(),ct);
                Assert.Equal("agent_sequence_gap",retry["error_code"]!.GetValue<string>());
                await using var find=new NpgsqlCommand("select id from sli_agent_audit where target=@agent and action='sequence_gap_observed' order by id desc limit 1",connection,tx);
                find.Parameters.AddWithValue("agent",Agent1.ToString("D")); observationId=(long)(await find.ExecuteScalarAsync(ct))!;
                await tx.CommitAsync(ct);
            }
            await using (var tx=await connection.BeginTransactionAsync(ct))
            {
                await using var insert=new NpgsqlCommand("insert into sli_agent_audit(action,actor,target,details) values('sequence_gap_authorized','session:987654321',@agent,jsonb_build_object('observation_id',@observation,'module_id','sli.heartbeat','confirm_loss',true))",connection,tx);
                insert.Parameters.AddWithValue("agent",Agent1.ToString("D")); insert.Parameters.AddWithValue("observation",observationId.ToString());
                await insert.ExecuteNonQueryAsync(ct); await tx.CommitAsync(ct);
            }
            await using (var tx=await connection.BeginTransactionAsync(ct))
            {
                var identity=await LockAsync(connection,tx,Agent1,ct);
                var accepted=await service.ReceiveAsync(connection,tx,identity,cert,gap.ToJson(),ct);
                Assert.Equal("committed",accepted["status"]!.GetValue<string>());
                await using var proof=new NpgsqlCommand("select (select count(*) from sli_agent_receipts where packet_id=@packet),(select count(*) from sli_agent_audit where action='sequence_gap_accepted' and details->>'observation_id'=@observation)",connection,tx);
                proof.Parameters.AddWithValue("packet",Guid.Parse(gap.Envelope.PacketId)); proof.Parameters.AddWithValue("observation",observationId.ToString());
                await using(var reader=await proof.ExecuteReaderAsync(ct)) { Assert.True(await reader.ReadAsync(ct)); Assert.Equal(1L,reader.GetInt64(0)); Assert.Equal(1L,reader.GetInt64(1)); }
                await tx.CommitAsync(ct);
            }
        }
        await using (var connection=await database.OpenConnectionAsync(ct))
        await using (var tx=await connection.BeginTransactionAsync(ct))
        {
            var identity=await LockAsync(connection,tx,Agent2,ct);
            var mismatched=Event(key,Agent2,Host1,now);
            var result=await service.ReceiveAsync(connection,tx,identity,cert,mismatched.ToJson(),ct);
            Assert.Equal("agent_source_not_bound",result["error_code"]!.GetValue<string>());
            await tx.RollbackAsync(ct);
        }
        await using (var connection=await database.OpenConnectionAsync(ct))
        await using (var tx=await connection.BeginTransactionAsync(ct))
        {
            var identity=await LockAsync(connection,tx,Agent1,ct);
            var rejected=await service.ReceiveAsync(connection,tx,identity,cert,Event(key,Agent1,Host1,now,revision:"2").ToJson(),ct);
            Assert.Equal("agent_source_not_bound",rejected["error_code"]!.GetValue<string>());
            await tx.RollbackAsync(ct);
        }
        await using (var connection=await database.OpenConnectionAsync(ct))
        await using (var tx=await connection.BeginTransactionAsync(ct))
        {
            var identity=await LockAsync(connection,tx,Agent1,ct);
            var pending=await service.ReceiveAsync(connection,tx,identity,cert,Event(key,Agent1,Host1,now).ToJson(),ct);
            Assert.Equal("committed",pending["status"]!.GetValue<string>());
            await tx.RollbackAsync(ct);
        }
        await using (var connection=await database.OpenConnectionAsync(ct))
        await using (var tx=await connection.BeginTransactionAsync(ct))
        {
            var identity=await LockAsync(connection,tx,Agent2,ct);
            var template=Event(key,Agent2,Host2,now);
            var e=template.Envelope;
            var sample=new Sample(e.ModuleId,e.SourceInstanceId,e.Channel,e.Generation,e.CursorBefore,e.CursorAfter,template.Payload,
                e.ModuleVersion,e.PolicyRevision,e.ContinuityState,e.FilteredCount,e.LostCount);
            var collision=Packets.Make(new EcdsaPacketSigner(key),Agent2.ToString("D"),1,sample,now,()=>Guid.Parse(heartbeat.Envelope.PacketId));
            var rejected=await service.ReceiveAsync(connection,tx,identity,cert,collision.ToJson(),ct);
            Assert.Equal("agent_packet_id_conflict",rejected["error_code"]!.GetValue<string>());
            await tx.RollbackAsync(ct);
        }
        var packet1=Event(key,Agent1,Host1,now); var packet2=Event(key,Agent2,Host2,now);
        // Both transactions race different agent locks; global quota advisory lock admits exactly one input.
        var bounded=new AgentPacketService(TimeProvider.System,new AgentInboxLimits(4096,268435456,32768,2147483648,1,4294967296,17179869184),diagnostics);
        async Task<JsonObject> Deliver(Guid agent,SignedPacket packet)
        {
            await using var connection=await database.OpenConnectionAsync(ct); await using var tx=await connection.BeginTransactionAsync(ct);
            var identity=await LockAsync(connection,tx,agent,ct);
            var receipt=await bounded.ReceiveAsync(connection,tx,identity,cert,packet.ToJson(),ct);
            await tx.CommitAsync(ct); return receipt;
        }
        var results=await Task.WhenAll(Deliver(Agent1,packet1),Deliver(Agent2,packet2));
        Assert.Equal(1,results.Count(x=>x["status"]!.GetValue<string>()=="committed")); Assert.Equal(1,results.Count(x=>x["status"]!.GetValue<string>()=="retry_later"));
        string auditPath=System.IO.Path.Combine(temporary.Path,"logs","audit-actions.log");
        Assert.True(File.Exists(auditPath));
        string auditLine=File.ReadAllLines(auditPath).Last();
        Assert.DoesNotContain("synthetic.invalid",auditLine); Assert.DoesNotContain("<Event",auditLine);
        using (var audit=JsonDocument.Parse(auditLine))
        {
            Assert.Equal("agent_inbox_global_count_limit",audit.RootElement.GetProperty("error_code").GetString());
            Assert.Equal(1,audit.RootElement.GetProperty("usage").GetProperty("global_count").GetInt64());
            Assert.Equal(1,audit.RootElement.GetProperty("limit").GetInt64());
            Assert.True(audit.RootElement.GetProperty("packet_bytes").GetInt64()>0);
        }
        Assert.Equal("agent_inbox_global_count_limit",results.Single(x=>x["status"]!.GetValue<string>()=="retry_later")["error_code"]!.GetValue<string>());
        Guid loser=results[0]["status"]!.GetValue<string>()=="retry_later" ? Agent1 : Agent2;
        SignedPacket rejectedPacket=results[0]["status"]!.GetValue<string>()=="retry_later" ? packet1 : packet2;
        string unwritable=System.IO.Path.Combine(temporary.Path,"logs","audit-actions.log");
        var brokenDiagnostics=new AgentIngressDiagnostics(unwritable,NullLogger<AgentIngressDiagnostics>.Instance,TimeProvider.System);
        var stillBounded=new AgentPacketService(TimeProvider.System,new AgentInboxLimits(4096,268435456,32768,2147483648,1,4294967296,17179869184),brokenDiagnostics);
        await using (var connection=await database.OpenConnectionAsync(ct))
        await using (var tx=await connection.BeginTransactionAsync(ct))
        {
            var identity=await LockAsync(connection,tx,loser,ct);
            var refusal=await stillBounded.ReceiveAsync(connection,tx,identity,cert,rejectedPacket.ToJson(),ct);
            Assert.Equal("retry_later",refusal["status"]!.GetValue<string>());
            Assert.Equal("agent_inbox_global_count_limit",refusal["error_code"]!.GetValue<string>());
            await tx.CommitAsync(ct);
        }
        Guid winner=results[0]["status"]!.GetValue<string>()=="committed" ? Agent1 : Agent2;
        SignedPacket acceptedPacket=results[0]["status"]!.GetValue<string>()=="committed" ? packet1 : packet2;
        await using (var connection=await database.OpenConnectionAsync(ct))
        await using (var tx=await connection.BeginTransactionAsync(ct))
        {
            var identity=await LockAsync(connection,tx,winner,ct);
            var duplicate=await bounded.ReceiveAsync(connection,tx,identity,cert,acceptedPacket.ToJson(),ct);
            Assert.Equal("duplicate",duplicate["status"]!.GetValue<string>());
            await tx.CommitAsync(ct);
        }
        await using (var connection=await database.OpenConnectionAsync(ct))
        await using (var tx=await connection.BeginTransactionAsync(ct))
        {
            var identity=await LockAsync(connection,tx,winner,ct);
            Guid host=winner==Agent1 ? Host1 : Host2;
            var reset=await service.ReceiveAsync(connection,tx,identity,cert,Event(key,winner,host,now,generation:"new-gen",sequence:2).ToJson(),ct);
            Assert.Equal("agent_reset_invalid",reset["error_code"]!.GetValue<string>());
            await tx.RollbackAsync(ct);
        }
        await using (var connection=await database.OpenConnectionAsync(ct))
        await using (var check=new NpgsqlCommand("select count(*) from sli_agent_receipts r join sli_agent_packet_inbox i using(packet_id) where r.agent_id=any(@ids) and r.module_id='sli.windows-eventlog'",connection))
        {
            check.Parameters.AddWithValue("ids",new[]{Agent1,Agent2}); Assert.Equal(1L,(long)(await check.ExecuteScalarAsync(ct))!);
        }
    }
}











