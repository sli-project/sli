using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents;
using Sli.Server.Agents.Ingress;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class GpoPublicationDatabaseTests
{
    private sealed class FixedClock(DateTimeOffset now):TimeProvider { public override DateTimeOffset GetUtcNow()=>now; }
    [Fact]
    public async Task ActualIngressAndWorkerPublishTheSameOwnedCycle()
    {
        var ct=TestContext.Current.CancellationToken;
        var intent=JsonNode.Parse(File.ReadAllText(Environment.GetEnvironmentVariable("SLI_GPO_FIXTURE_INTENT")!))!.AsObject();
        var vector=JsonNode.Parse(File.ReadAllText(Environment.GetEnvironmentVariable("SLI_GPO_OWNED_VECTOR")!))!.AsObject();
        var secret=JsonNode.Parse(File.ReadAllText(Environment.GetEnvironmentVariable("SLI_GPO_WORKER_SECRET")!))!.AsObject();
        Guid agent=Guid.Parse(intent["agent_id"]!.GetValue<string>()), host=Guid.Parse(intent["host_id"]!.GetValue<string>()), cycle=Guid.Parse(intent["cycle_id"]!.GetValue<string>());
        var policy=new SnapshotPolicy(SnapshotPolicy.Gpo,vector["config"]!.AsObject());
        var families=vector["families"]!.AsObject();
        var now=Iso8601.ParseUtc("2026-10-08T12:00:00+00:00"); Cursor before=Cursor.Start("snapshot");
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cert=new CertificateRequest("CN=owned-synthetic",key,HashAlgorithmName.SHA256).CreateSelfSigned(now.AddDays(-1),now.AddDays(1));
        var clock=new FixedClock(now); string temp=Path.Combine(Path.GetTempPath(),"sli-gpo-owned-"+Guid.NewGuid().ToString("N"));
        var service=new AgentPacketService(clock,new AgentInboxLimits(4096,268435456,32768,2147483648,65536,4294967296,17179869184),new AgentIngressDiagnostics(temp,NullLogger<AgentIngressDiagnostics>.Instance,clock));
        try
        {
            await using var database=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
            var cs=new NpgsqlConnectionStringBuilder { Host="127.0.0.1",Port=49248,Database="sli_oracle",Username=secret["username"]!.GetValue<string>(),Password=secret["password"]!.GetValue<string>(),Pooling=false,SslMode=SslMode.Disable };
            await using var worker=new NpgsqlConnection(cs.ConnectionString); await worker.OpenAsync(ct);
            await using(var role=new NpgsqlCommand("set role adlog_context_worker",worker)) await role.ExecuteNonQueryAsync(ct);
            await using(var who=new NpgsqlCommand("select session_user,current_user",worker))
            { await using var r=await who.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct)); Assert.Equal(secret["username"]!.GetValue<string>(),r.GetString(0)); Assert.Equal("adlog_context_worker",r.GetString(1)); }
            var badFamilies=families.ToDictionary(x=>x.Key,x=>(JsonObject)x.Value!.DeepClone());
            badFamilies["gpo_v2"]["started_at"]="2026-10-09T12:00:00Z";
            var badBundle=GpoPublicationPreparation.Prepare(intent["domain_sid"]!.GetValue<string>(),policy.Config,badFamilies);
            await using(var failTx=await worker.BeginTransactionAsync(ct))
            {
                await failTx.SaveAsync("failed_import",ct);
                var failure=await Assert.ThrowsAsync<PostgresException>(()=>GpoGovernanceStore.ImportAsync(worker,failTx,badBundle,ct));
                Assert.Equal("23514",failure.SqlState); Assert.Contains("gpo_report_v2_source_snapshots",failure.ConstraintName);
                await failTx.RollbackAsync("failed_import",ct);
                await using var absent=new NpgsqlCommand("select (select count(*) from ad_context_runs where run_id=@run),(select count(*) from ad_context_evidence where source_run_id=@run),(select count(*) from entities_v2 where natural_key=@key),(select count(*) from gpo_report_v2_source_snapshots where source_run_id=@run)",worker,failTx);
                absent.Parameters.AddWithValue("run",Guid.Parse(intent["run_uuid"]!.GetValue<string>())); absent.Parameters.AddWithValue("key",badBundle["records"]![0]!["record_key"]!.GetValue<string>());
                await using(var r=await absent.ExecuteReaderAsync(ct)) { Assert.True(await r.ReadAsync(ct)); Assert.Equal(0L,r.GetInt64(0)); Assert.Equal(0L,r.GetInt64(1)); Assert.Equal(0L,r.GetInt64(2)); Assert.Equal(0L,r.GetInt64(3)); }
                await failTx.CommitAsync(ct);
            }
            await using(var db=await database.OpenConnectionAsync(ct))
            {
                await using var tx=await db.BeginTransactionAsync(ct);
                await using(var who=new NpgsqlCommand("select current_user",db,tx)) Assert.Equal("adlog_user",(string)(await who.ExecuteScalarAsync(ct))!);
                await using(var locked=new NpgsqlCommand("select id from sli_agents where id=@id for no key update",db,tx)) { locked.Parameters.AddWithValue("id",agent); Assert.Equal(agent,await locked.ExecuteScalarAsync(ct)); }
                int sequence=0;
                foreach(var family in policy.Families)
                {
                    byte[] bytes=CanonicalJson.ToBytes(families[family]);
                    Assert.True(bytes.Length<=SnapshotStream.FragmentBytes);
                    var payload=new JsonObject { ["contract"]=SnapshotPolicy.Gpo+".chunk.v1",["cycle_id"]=cycle.ToString("D"),["family"]=family,
                        ["slot_start_utc"]="2026-10-08T11:00:00+00:00",["chunk_index"]=0,["chunk_count"]=1,
                        ["total_objects"]=families[family]![family=="gpo_v2" ? "gpos" : "records"]!.AsArray().Count,["total_bytes"]=bytes.Length,
                        ["family_sha256"]=Convert.ToHexStringLower(SHA256.HashData(bytes)),["records"]=new JsonArray(new JsonObject { ["data_b64"]=Convert.ToBase64String(bytes) }),
                        ["cycle_families"]=policy.Config["families"]!.DeepClone(),["domain_sid"]=policy.Config["domain_sid"]!.DeepClone(),["domain_dns"]=policy.Config["domain_dns"]!.DeepClone(),["scope"]=policy.Config["scope"]!.DeepClone() };
                    var after=SnapshotStream.MakeCursor(payload);
                    var sample=new Sample(SnapshotPolicy.Gpo,policy.SourceId,"snapshot",policy.SourceId,before,after,payload,ContinuityState:"complete",LostCount:0);
                    string packetName=family=="gpo_v2" ? "packet_gpo" : "packet_governance";
                    var packet=Packets.Make(new EcdsaPacketSigner(key),agent.ToString("D"),++sequence,sample,now,()=>Guid.Parse(intent[packetName]!.GetValue<string>())).ToJson();
                    var receipt=await service.ReceiveAsync(db,tx,new Sli.Server.Agents.AgentIdentity(agent,host,new string('a',64),"active"),cert,packet,ct);
                    Assert.Equal("committed",receipt["status"]!.GetValue<string>()); before=after;
                }
                await tx.CommitAsync(ct);
            }
            var result=await GpoSnapshotPublisher.ProcessAsync(worker,cycle,ct);
            Assert.Equal("published",result.PublicationState);
            await using var check=new NpgsqlCommand("""
                select c.transport_state,c.publication_state,c.gpo_source_run_id,
                (select count(*) from sli_agent_snapshot_chunks k where k.cycle_id=c.cycle_id),
                (select count(*) from ad_context_runs r where r.run_id=c.gpo_source_run_id and r.status='completed'),
                (select count(*) from gpo_report_v2_source_snapshots s where s.source_run_id=c.gpo_source_run_id and s.import_status='completed'),
                (select encode(bundle_sha256,'hex') from ad_context_runs r where r.run_id=c.gpo_source_run_id),
                (select encode(payload_sha256,'hex') from gpo_report_v2_source_snapshots s where s.source_run_id=c.gpo_source_run_id),
                (select count(*) from ad_context_sections s where s.run_id=c.gpo_source_run_id and s.section_name='gpo_governance'),
                (select count(*) from ad_context_evidence e where e.source_run_id=c.gpo_source_run_id),
                (select encode(v.content_sha256,'hex') from ad_context_entity_versions v where v.source_run_id=c.gpo_source_run_id)
                from sli_agent_snapshot_cycles c where c.cycle_id=@id
                """,worker);
            check.Parameters.AddWithValue("id",cycle); await using var reader=await check.ExecuteReaderAsync(ct);
            Assert.True(await reader.ReadAsync(ct)); Assert.Equal("complete",reader.GetString(0)); Assert.Equal("published",reader.GetString(1));
            Assert.Equal(Guid.Parse(intent["run_uuid"]!.GetValue<string>()),reader.GetGuid(2)); Assert.Equal(2L,reader.GetInt64(3)); Assert.Equal(1L,reader.GetInt64(4)); Assert.Equal(1L,reader.GetInt64(5));
            Assert.Equal(vector["expected_bundle_sha256"]!.GetValue<string>(),reader.GetString(6)); Assert.Equal(vector["expected_gpo_sha256"]!.GetValue<string>(),reader.GetString(7));
            Assert.Equal(1L,reader.GetInt64(8)); Assert.Equal(1L,reader.GetInt64(9)); Assert.Equal(vector["expected_record_sha256"]!.GetValue<string>(),reader.GetString(10));
            await reader.DisposeAsync();
            await GpoSnapshotPublisher.ProcessAsync(worker,cycle,ct);
            await using var replay=new NpgsqlCommand("select (select count(*) from ad_context_runs where run_id=@run),(select count(*) from gpo_report_v2_source_snapshots where source_run_id=@run),(select count(*) from ad_context_evidence where source_run_id=@run)",worker);
            replay.Parameters.AddWithValue("run",Guid.Parse(intent["run_uuid"]!.GetValue<string>())); await using var rr=await replay.ExecuteReaderAsync(ct); Assert.True(await rr.ReadAsync(ct));
            Assert.Equal(1L,rr.GetInt64(0)); Assert.Equal(1L,rr.GetInt64(1)); Assert.Equal(1L,rr.GetInt64(2));
        }
        finally { if(Directory.Exists(temp)) Directory.Delete(temp,true); }
    }
}
