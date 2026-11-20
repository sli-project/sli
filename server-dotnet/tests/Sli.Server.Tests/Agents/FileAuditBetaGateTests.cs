using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Server.Agents;
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.FileAudit;
using Sli.Server.Agents.Ingress;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class FileAuditBetaGateTests
{
    private sealed class Clock(DateTimeOffset now) : TimeProvider { public override DateTimeOffset GetUtcNow() => now; }

    [Fact]
    public async Task AssignmentIsDisabledBeforeAnyPolicyIsWritten()
    {
        var body=JsonSerializer.SerializeToElement(new { agent_id=Guid.NewGuid(),module_id="sli.file-audit",enabled=true,config=new { } });
        var error=await Assert.ThrowsAsync<AgentControlException>(()=>new AgentModuleAssignmentService(new AgentControlAudit())
            .AssignAsync(null!,null!,body,"session:1",TestContext.Current.CancellationToken));
        Assert.Equal("module_disabled",error.Message); Assert.Equal(503,error.Status);
    }

    [Fact]
    public async Task AuthenticatedReportCannotWriteSnapshots()
    {
        var error=await Assert.ThrowsAsync<AgentControlException>(()=>new FileAuditIngestService(null!)
            .Ingest(null!,null!,new AgentIdentity(Guid.NewGuid(),Guid.NewGuid(),new string('a',64),"active"),new JsonObject(),TestContext.Current.CancellationToken));
        Assert.Equal("module_disabled",error.Message); Assert.Equal(503,error.Status);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SignedPacketIsRejectedAndQueuedPacketIsNotImportedOrHeldForever(bool dedicatedConsumer)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var schema=new NpgsqlConnection(fixture.Pg.ConnectionString); await schema.OpenAsync(ct);
        var vector=JsonNode.Parse(File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(),"agent-dotnet/tests/vectors/file-audit-scenarios.json")))!
            .AsArray().OfType<JsonObject>().Single(x=>x["name"]!.GetValue<string>()=="events-restart-filter");
        var step=vector["steps"]![0]!;
        var payload=JsonNode.Parse(step["payload_canonical"]!.GetValue<string>())!.AsObject();
        var config=vector["config"]!.DeepClone();
        Guid agent=Guid.NewGuid(),host=Guid.Parse(vector["host_id"]!.GetValue<string>());
        var now=Iso8601.ParseUtc(step["now"]!.GetValue<string>());
        var identity=new AgentIdentity(agent,host,new string('a',64),"active");
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert=new CertificateRequest("CN=example.test",key,HashAlgorithmName.SHA256).CreateSelfSigned(now.AddDays(-1),now.AddDays(1));
        var sample=new Sample("sli.file-audit",host.ToString("D"),"Security",payload["header"]!["generation"]!.GetValue<string>(),
            Cursor.FromJson(step["cursor_before"]),Cursor.FromJson(step["cursor_after"]),payload,PolicyRevision:"1",
            ContinuityState:step["continuity_state"]!.GetValue<string>(),FilteredCount:step["filtered_count"]!.GetValue<long>(),LostCount:step["lost_count"]?.GetValue<long>());
        var signed=Packets.Make(new EcdsaPacketSigner(key),agent.ToString("D"),1,sample,now);
        // Use a real signed collection packet; no importer/ledger mocks.
        _=AgentFileAuditValidator.Validate(signed.Envelope,payload,AgentFileAuditPolicy.Parse(config.AsObject()),host);
        var envelope=signed.Envelope.ToJson();
        var rows=new JsonArray(payload["records"]!.AsArray().Select(r=>r!["payload"]!.DeepClone()).ToArray());
        await using var db=new NpgsqlConnection(fixture.Dsn("adlog_user")); await db.OpenAsync(ct);
        async Task Sql(string sql,params (string Name,object Value)[] args) {
            await using var command=new NpgsqlCommand(sql,db);
            foreach(var (name,value) in args) {
                if(value is JsonNode node) command.Parameters.AddWithValue(name,NpgsqlDbType.Jsonb,node.ToJsonString());
                else command.Parameters.AddWithValue(name,value);
            }
            await command.ExecuteNonQueryAsync(ct);
        }
        await Sql("insert into sli_agents(id,host_id,key_fingerprint,assigned_modules) values(@agent,@host,repeat('a',64),@modules)",
            ("agent",agent),("host",host),("modules",new JsonArray(new JsonObject { ["module_id"]="sli.file-audit",["enabled"]=true,["config"]=config })));
        using var state=new StorageLifecycleTests.State(); var clock=new Clock(now);
        var service=new AgentPacketService(clock,new AgentInboxLimits(4096,268435456,32768,2147483648,65536,4294967296,17179869184),
            new AgentIngressDiagnostics(state.Path,NullLogger<AgentIngressDiagnostics>.Instance,clock));
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            var tampered=signed.ToJson(); tampered["signature"]="invalid";
            await Assert.ThrowsAsync<ProtocolException>(()=>service.ReceiveAsync(db,tx,identity,cert,tampered,ct));
            var result=await service.ReceiveAsync(db,tx,identity,cert,signed.ToJson(),ct);
            Assert.Equal("rejected",result["status"]!.GetValue<string>()); Assert.Equal("module_disabled",result["error_code"]!.GetValue<string>());
            await tx.CommitAsync(ct);
        }
        await using(var count=new NpgsqlCommand("select count(*) from sli_agent_packet_inbox",db))
            Assert.Equal(0L,(long)(await count.ExecuteScalarAsync(ct))!);
        // A previously accepted packet must also stop growing module data.
        await Sql("""
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt,received_at)
            values(@agent,'sli.file-audit',1,@packet,@hash,@envelope,'{"status":"committed"}',now()-interval '10 days');
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at)
            values(@packet,@envelope,@payload,@rows,now()-interval '10 days');
            """,("agent",agent),("packet",Guid.Parse(signed.Envelope.PacketId)),("hash",Packets.Digest(envelope)),("envelope",envelope),("payload",payload),("rows",rows));
        await using(var tx=await db.BeginTransactionAsync(ct)) {
            var invalidRows=(JsonArray)rows.DeepClone(); invalidRows.Clear();
            var denied=await Assert.ThrowsAsync<FileAuditPending>(()=>FileAuditInboxConsumer.ImportClaimedAsync(db,tx,
                Guid.Parse(signed.Envelope.PacketId),envelope,payload,invalidRows,ct));
            Assert.Equal("agent_packet_attestation_invalid",denied.Code);
            Assert.Equal("module_disabled",(await service.ReceiveAsync(db,tx,identity,cert,signed.ToJson(),ct))["error_code"]!.GetValue<string>());
            if(dedicatedConsumer) {
                var result=await FileAuditInboxConsumer.ProcessNextAsync(db,tx,null,ct);
                Assert.True(result.Scanned); Assert.False(result.Imported); Assert.Equal("module_disabled",result.PendingReason);
                Assert.False((await FileAuditInboxConsumer.ProcessNextAsync(db,tx,null,ct)).Scanned);
            } else {
                var result=await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,null,ct);
                Assert.True(result.Scanned); Assert.False(result.Imported); Assert.Equal("module_disabled",result.PendingReason);
                Assert.False((await AgentWorkstationInboxConsumer.ProcessNextAsync(db,tx,null,ct)).Scanned);
            }
            await tx.CommitAsync(ct);
        }
        await using(var terminal=new NpgsqlCommand("select imported_at,module_disabled_at,packet is not null from sli_agent_packet_inbox",db)) {
            await using var row=await terminal.ExecuteReaderAsync(ct); Assert.True(await row.ReadAsync(ct));
            Assert.True(row.IsDBNull(0)); Assert.False(row.IsDBNull(1)); Assert.True(row.GetBoolean(2));
        }
        await using(var privileges=new NpgsqlCommand("select has_column_privilege(current_user,'sli_agent_packet_inbox','packet','UPDATE')",db))
            Assert.Equal(false,await privileges.ExecuteScalarAsync(ct));
        // Inspect module storage through the fixture owner; runtime permissions stay narrow.
        await using var owner=new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        await using(var count=new NpgsqlCommand("select (select count(*) from sli_plugin_file_audit.observations)+(select count(*) from sli_plugin_file_audit.access_snapshots)",owner))
            Assert.Equal(0L,(long)(await count.ExecuteScalarAsync(ct))!);
        // Expiration still uses the ordinary seven-day queue cutoff.
        await using var deletion=NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(fixture.Dsn("sli_storage_lifecycle_delete_login")) {
            Options="-c role=adlog_storage_lifecycle_delete",CommandTimeout=0 }.ConnectionString);
        var retention=new InboxRetention(deletion,state.Files);
        var recent=await retention.RunAsync(DateTime.UtcNow.AddDays(-7),Guid.Empty,1000,ct);
        Assert.Equal(0,LifecycleJson.Number(recent,"deleted_count"));
        await Sql("update sli_agent_packet_inbox set module_disabled_at=now()-interval '10 days'");
        var expired=await retention.RunAsync(DateTime.UtcNow.AddDays(-7),Guid.Empty,1000,ct);
        Assert.Equal(1,LifecycleJson.Number(expired,"deleted_count")); Assert.Equal(0,LifecycleJson.Number(expired,"held_count"));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
