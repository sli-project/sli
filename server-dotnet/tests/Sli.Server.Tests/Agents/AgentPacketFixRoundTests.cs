using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Server.Agents;
using Sli.Server.Agents.Ingress;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Agents;

public class AgentPacketFixRoundTests
{
    private static async Task<SyntheticDatabase> OpenDatabase(CancellationToken ct)
    {
        Assert.SkipWhen(Environment.GetEnvironmentVariable("SLI_T2_RUN_ID") is null, "Owned PostgreSQL binding required");
        var database=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        var baseline=await database.ReadBaselineAsync(ct);
        Assert.Equal(18,baseline.MajorVersion); Assert.Equal(300,baseline.SchemaVersion);
        return database;
    }

    [Fact]
    public async Task Actual_jsonb_ledger_and_quota_match_source_float_normalization()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var db=await OpenDatabase(ct);
        await using var c=await db.OpenConnectionAsync(ct);
        await using var tx=await c.BeginTransactionAsync(ct);
        await using (var role=new NpgsqlCommand("select current_user",c,tx)) Assert.Equal("adlog_user",await role.ExecuteScalarAsync(ct));
        var host=Guid.NewGuid(); var agent=Guid.NewGuid();
        await using (var seed=new NpgsqlCommand("insert into sli_agents(id,host_id,key_fingerprint) values(@id,@host,repeat('a',64))",c,tx))
        { seed.Parameters.AddWithValue("id",agent); seed.Parameters.AddWithValue("host",host); await seed.ExecuteNonQueryAsync(ct); }
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var now=DateTimeOffset.UtcNow;
        var vectorCases=new[] {
            ("{\"n\":1e0}", "{\"n\": 1.0}"),
            ("{\"n\":1.234567890123456789}", "{\"n\": 1.2345678901234567}"),
            ("{\"a\":-0.0,\"b\":1.0,\"text\":\"привет мир\",\"big\":922337203685477580812345}", "{\"a\": -0.0, \"b\": 1.0, \"text\": \"\\u043f\\u0440\\u0438\\u0432\\u0435\\u0442 \\u043c\\u0438\\u0440\", \"big\": 922337203685477580812345}"),
            ("{\"n\":1e-7,\"z\":1e20}", "{\"n\": 1e-07, \"z\": 1e+20}")
        };
        foreach (var (raw,source) in vectorCases)
        {
            var payload=JsonNode.Parse(raw)!.AsObject();
            await using var q=new NpgsqlCommand("select @native::jsonb::text=@source::jsonb::text, octet_length(@native::jsonb::text),octet_length(@source::jsonb::text)",c,tx);
            q.Parameters.AddWithValue("native",NpgsqlDbType.Jsonb,PacketStorageJson.Serialize(payload));
            q.Parameters.AddWithValue("source",NpgsqlDbType.Jsonb,source);
            await using var r=await q.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct)); Assert.True(r.GetBoolean(0)); Assert.Equal(r.GetInt32(1),r.GetInt32(2));
        }
        var data=JsonNode.Parse("{\"contract\":\"sli.collection-packet.v1\",\"n\":1e0}")!.AsObject();
        var rows=new JsonArray(data.DeepClone());
        var packet=Packets.Make(new EcdsaPacketSigner(key),agent.ToString("D"),1,
            new Sample("sli.windows-eventlog",host.ToString("D"),"Security","g",new Cursor("record_id",""),new Cursor("record_id","5"),data),now);
        var e=packet.Envelope; var receipt=AgentReceipt.Make(e,"committed",null,now);
        var docs=new[] { e.ToJson().ToJsonString(),receipt.ToJsonString(),e.ToJson().ToJsonString(),"{\"contract\": \"sli.collection-packet.v1\", \"n\": 1.0}","[{\"contract\": \"sli.collection-packet.v1\", \"n\": 1.0}]" };
        long expected;
        await using (var measure=new NpgsqlCommand("select 2048+coalesce(sum(octet_length(document::text)),0) from unnest(@docs::jsonb[]) as document",c,tx))
        { measure.Parameters.AddWithValue("docs",NpgsqlDbType.Array|NpgsqlDbType.Jsonb,docs); expected=Convert.ToInt64(await measure.ExecuteScalarAsync(ct)); }
        var blocked=Path.Combine(Path.GetTempPath(),"sli-packet-fix-"+Guid.NewGuid().ToString("N"));
        await File.WriteAllTextAsync(blocked,"synthetic",ct);
        try
        {
            var diagnostics=new AgentIngressDiagnostics(blocked,NullLogger<AgentIngressDiagnostics>.Instance,TimeProvider.System);
            var exactLimits=new AgentInboxLimits(4096,expected,32768,long.MaxValue/4,65536,long.MaxValue/4,long.MaxValue/4);
            Assert.Null(await AgentInboxQuota.CheckAsync(c,tx,e,data,rows,receipt,exactLimits,diagnostics,ct));
            var limits=new AgentInboxLimits(4096,expected-1,32768,long.MaxValue/4,65536,long.MaxValue/4,long.MaxValue/4);
            Assert.Equal("agent_inbox_agent_bytes_limit",await AgentInboxQuota.CheckAsync(c,tx,e,data,rows,receipt,limits,diagnostics,ct));
            await new AgentPacketLedger(c,tx).StoreAsync(e,data,rows,receipt,ct);
            await using var stored=new NpgsqlCommand("select packet::text=@payload::jsonb::text,event_rows::text=@rows::jsonb::text,octet_length(packet::text)=octet_length(@payload::jsonb::text) from sli_agent_packet_inbox where packet_id=@id",c,tx);
            stored.Parameters.AddWithValue("id",Guid.Parse(e.PacketId)); stored.Parameters.AddWithValue("payload",NpgsqlDbType.Jsonb,"{\"contract\": \"sli.collection-packet.v1\", \"n\": 1.0}"); stored.Parameters.AddWithValue("rows",NpgsqlDbType.Jsonb,"[{\"contract\": \"sli.collection-packet.v1\", \"n\": 1.0}]");
            await using var reader=await stored.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct)); Assert.True(reader.GetBoolean(0)); Assert.True(reader.GetBoolean(1)); Assert.True(reader.GetBoolean(2));
        }
        finally { File.Delete(blocked); }
        await tx.RollbackAsync(ct);
        await using var absent = new NpgsqlCommand("select (select count(*) from sli_agents where id=@id), (select count(*) from sli_agent_receipts where agent_id=@id), (select count(*) from sli_agent_packet_inbox where envelope->>'agent_id'=@text)",c);
        absent.Parameters.AddWithValue("id",agent); absent.Parameters.AddWithValue("text",agent.ToString("D"));
        await using var remaining = await absent.ExecuteReaderAsync(ct); Assert.True(await remaining.ReadAsync(ct));
        Assert.Equal(0L,remaining.GetInt64(0)); Assert.Equal(0L,remaining.GetInt64(1)); Assert.Equal(0L,remaining.GetInt64(2));
    }

    [Fact]
    public async Task Max_sequence_unknown_lower_packet_returns_replay_receipt()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var db=await OpenDatabase(ct);
        await using var c=await db.OpenConnectionAsync(ct);
        await using var tx=await c.BeginTransactionAsync(ct);
        var host=Guid.NewGuid(); var agent=Guid.NewGuid();
        await using (var seed=new NpgsqlCommand("insert into sli_agents(id,host_id,key_fingerprint) values(@id,@host,repeat('b',64))",c,tx))
        { seed.Parameters.AddWithValue("id",agent); seed.Parameters.AddWithValue("host",host); await seed.ExecuteNonQueryAsync(ct); }
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var certRequest=new CertificateRequest("CN=synthetic",key,HashAlgorithmName.SHA256);
        using var cert=certRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(1));
        var now=DateTimeOffset.UtcNow;
        SignedPacket Make(long sequence) => Packets.Make(new EcdsaPacketSigner(key),agent.ToString("D"),sequence,
            new Sample("sli.heartbeat",host.ToString("D"),"heartbeat",host.ToString("D"),new Cursor("record_id",""),new Cursor("record_id",sequence.ToString()),new JsonObject { ["contract"]="sli.heartbeat.v1",["status"]="alive" }),now);
        var terminal=Make(long.MaxValue);
        await new AgentPacketLedger(c,tx).StoreAsync(terminal.Envelope,terminal.Payload,null,AgentReceipt.Make(terminal.Envelope,"committed",null,now),ct);
        var diagnostics=new AgentIngressDiagnostics(Path.GetTempPath(),NullLogger<AgentIngressDiagnostics>.Instance,TimeProvider.System);
        var service=new AgentPacketService(TimeProvider.System,new AgentInboxLimits(4096,268435456,32768,2147483648,65536,4294967296,17179869184),diagnostics);
        var result=await service.ReceiveAsync(c,tx,new AgentIdentity(agent,host,new string('b',64),"active"),cert,Make(1).ToJson(),ct);
        Assert.Equal("rejected",result["status"]!.GetValue<string>());
        Assert.Equal("agent_sequence_replayed",result["error_code"]!.GetValue<string>());
        await tx.RollbackAsync(ct);
        await using var absent = new NpgsqlCommand("select (select count(*) from sli_agents where id=@id), (select count(*) from sli_agent_receipts where agent_id=@id), (select count(*) from sli_agent_packet_inbox where envelope->>'agent_id'=@text)",c);
        absent.Parameters.AddWithValue("id",agent); absent.Parameters.AddWithValue("text",agent.ToString("D"));
        await using var remaining = await absent.ExecuteReaderAsync(ct); Assert.True(await remaining.ReadAsync(ct));
        Assert.Equal(0L,remaining.GetInt64(0)); Assert.Equal(0L,remaining.GetInt64(1)); Assert.Equal(0L,remaining.GetInt64(2));
    }
}
