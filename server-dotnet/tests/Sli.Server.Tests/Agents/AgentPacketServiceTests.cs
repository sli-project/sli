using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Server.Agents;
using Sli.Server.Agents.Ingress;
using Sli.Server.InstallationSetup;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentPacketServiceTests
{
    private sealed class Clock(DateTimeOffset now) : TimeProvider { public override DateTimeOffset GetUtcNow() => now; }

    [Fact]
    public void Published_gaps_keep_the_missing_source_and_valid_interval()
    {
        var expiry = JsonNode.Parse("""
            {
              "sli.windows.ad-dc": {"data_gap": {"from_utc": "2026-11-21T10:21:00Z", "to_utc": "2026-11-21T10:22:00Z"}},
              "sli.ad-snapshot": {"data_gap": {"from_utc": "2026-11-21T11:00:00Z", "to_utc": "2026-11-21T10:00:00Z"}}
            }
            """);
        var gap = Assert.Single(SetupCollectionHealth.DataGaps(expiry))!;
        Assert.Equal("sli.windows.ad-dc", gap["module_id"]!.GetValue<string>());
        Assert.Equal("2026-11-21T10:21:00Z", gap["from_utc"]!.GetValue<string>());
        Assert.Equal("2026-11-21T10:22:00Z", gap["to_utc"]!.GetValue<string>());
    }

    [Fact]
    public async Task ExpiryAdvancesOnlyTheSignedNextPositionWithoutAcceptingOldData()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture();
        await fixture.StartAsync(ct,throughVersion:340);
        string migration=Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/348_agent_packet_expiry.sql");
        await fixture.Pg.ApplyFileAsync(migration,null,ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration,".rollback.sql"),null,ct);
        // Keep the predecessor and rollback check before the current ingress runs on its complete schema.
        foreach (var pending in MigrationDirectory.Read(341))
            await fixture.Pg.ApplyFileAsync(pending.Path, null, ct);
        await using var db=new NpgsqlConnection(fixture.Dsn("adlog_user")); await db.OpenAsync(ct);
        await using var tx=await db.BeginTransactionAsync(ct);
        Guid agent=Guid.NewGuid(),host=Guid.NewGuid();
        await using(var seed=new NpgsqlCommand("insert into sli_agents(id,host_id,key_fingerprint,registration_host_name) values(@agent,@host,repeat('a',64),'dc.example.test')",db,tx))
        { seed.Parameters.AddWithValue("agent",agent); seed.Parameters.AddWithValue("host",host); await seed.ExecuteNonQueryAsync(ct); }
        var identity=new AgentIdentity(agent,host,new string('a',64),"active");
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var now=Iso8601.Truncate(DateTimeOffset.UtcNow);
        using var cert=new CertificateRequest("CN=example.test",key,HashAlgorithmName.SHA256).CreateSelfSigned(now.AddDays(-1),now.AddDays(1));
        var diagnostics=new AgentIngressDiagnostics(fixture.Pg.Root,NullLogger<AgentIngressDiagnostics>.Instance,TimeProvider.System);
        AgentPacketService Service(DateTimeOffset time) => new(new Clock(time),new AgentInboxLimits(4096,268435456,32768,2147483648,65536,4294967296,17179869184),diagnostics);
        SignedPacket Make(long sequence,string before,DateTimeOffset time,string continuity="not_proven") =>
            Packets.Make(new EcdsaPacketSigner(key),agent.ToString("D"),sequence,
                new Sample("sli.heartbeat",host.ToString("D"),"heartbeat",host.ToString("D"),new Cursor("record_id",before),
                    new Cursor("record_id",sequence.ToString()),new JsonObject { ["contract"]="sli.heartbeat.v1",["status"]="alive" },ContinuityState:continuity),time);
        Task<JsonObject> Receive(SignedPacket packet,DateTimeOffset? time=null) => Service(time??now).ReceiveAsync(db,tx,identity,cert,packet.ToJson(),ct);

        var accepted=Make(1,"",now.AddDays(-10));
        Assert.Equal("committed",(await Receive(accepted,now.AddDays(-10)))["status"]!.GetValue<string>());
        Assert.Equal("duplicate",(await Receive(accepted))["status"]!.GetValue<string>());
        var expired=Make(2,"1",now.AddDays(-8));
        var refusal=await Receive(expired);
        Assert.Equal("rejected",refusal["status"]!.GetValue<string>());
        Assert.Equal("agent_packet_expired",refusal["error_code"]!.GetValue<string>());
        Assert.Null(refusal["committed_cursor"]); Assert.Null(refusal["evidence_ref"]);
        Assert.Equal("agent_packet_expired",(await Receive(expired))["error_code"]!.GetValue<string>());
        Assert.Equal("agent_sequence_conflict",(await Receive(Make(2,"1",now.AddDays(-8))))["error_code"]!.GetValue<string>());

        var ledger=new AgentPacketLedger(db,tx);
        // An unobserved old sequence cannot authorize jumping over missing packets.
        Assert.Equal("agent_packet_expired",(await Receive(Make(6,"5",now.AddDays(-8))))["error_code"]!.GetValue<string>());
        Assert.Equal(2L,(await ledger.LatestAsync(expired.Envelope,ct))!["sequence"]!.GetValue<long>());
        var tampered=expired.ToJson(); tampered["envelope"]!["sequence"]=3;
        await Assert.ThrowsAsync<ProtocolException>(()=>Service(now).ReceiveAsync(db,tx,identity,cert,tampered,ct));
        var wrongPayload=expired.ToJson(); wrongPayload["payload"]!["status"]="changed";
        await Assert.ThrowsAsync<ProtocolException>(()=>Service(now).ReceiveAsync(db,tx,identity,cert,wrongPayload,ct));
        var reused=Make(3,"2",now,"gap");
        var reusedEnvelope=reused.Envelope with { PacketId=expired.Envelope.PacketId };
        reused=reused with { Envelope=reusedEnvelope,Signature=Convert.ToBase64String(new EcdsaPacketSigner(key).Sign(Packets.SignedMessage(reusedEnvelope))) };
        Assert.Equal("agent_packet_id_conflict",(await Receive(reused))["error_code"]!.GetValue<string>());
        Assert.Equal("agent_replay_window",(await Receive(Make(3,"2",now.AddMinutes(6))))["error_code"]!.GetValue<string>());
        Assert.Equal("agent_reset_invalid",(await Receive(Make(3,"2",now)))["error_code"]!.GetValue<string>());
        Assert.Equal("agent_cursor_mismatch",(await Receive(Make(3,"wrong",now)))["error_code"]!.GetValue<string>());
        var next=Make(3,"2",now,"gap");
        Assert.Equal("committed",(await Receive(next))["status"]!.GetValue<string>());
        Assert.Equal("duplicate",(await Receive(next))["status"]!.GetValue<string>());
        Assert.Equal("committed",(await Receive(Make(4,"3",now)))["status"]!.GetValue<string>());
        var state=await ledger.SummaryAsync(next.Envelope,ct);
        Assert.False(state!["expiry_pending"]!.GetValue<bool>());
        var gaps=SetupCollectionHealth.DataGaps(new JsonObject { ["sli.heartbeat"]=state.DeepClone() });
        Assert.Equal("sli.heartbeat",gaps[0]!["module_id"]!.GetValue<string>());
        Assert.Equal(Iso8601.Format(now.AddDays(-10)),gaps[0]!["from_utc"]!.GetValue<string>());
        Assert.Equal(Iso8601.Format(now),gaps[0]!["to_utc"]!.GetValue<string>());
        await using(var count=new NpgsqlCommand("select (select count(*) from sli_agent_receipts where agent_id=@agent),(select count(*) from sli_agent_packet_inbox where envelope->>'agent_id'=@agent::text)",db,tx))
        {
            count.Parameters.AddWithValue("agent",agent); await using var rows=await count.ExecuteReaderAsync(ct);
            Assert.True(await rows.ReadAsync(ct)); Assert.Equal(3L,rows.GetInt64(0)); Assert.Equal(0L,rows.GetInt64(1));
        }
        await tx.RollbackAsync(ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
