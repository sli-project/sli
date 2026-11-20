using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Agents;
using Sli.Server.Agents.Certificates;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Registry;
using Sli.Server.Agents.Updates;
using Sli.Server.Tests.Integration;
using Xunit;
namespace Sli.Server.Tests.Agents;

[Collection("Owned agent recovery")]
public sealed class AgentUpdateDatabaseTests
{
    [Fact]
    public async Task CertificateBoundAssignedArchiveAndAtomicResultWaveProgressionUseOrdinarySourceRole()
    {
        var ct=TestContext.Current.CancellationToken;
        string proof=Environment.GetEnvironmentVariable("SLI_AGENT_UPDATE_PROOF")??throw new InvalidOperationException("Missing own update proof directory");
        var plan=JsonNode.Parse(await File.ReadAllTextAsync(Path.Combine(proof,"input-plan.json"),ct))!;
        Guid wave=Guid.Parse(plan["wave"]!.GetValue<string>());string marker=plan["namespace"]!.GetValue<string>();
        Guid[] hosts=plan["hosts"]!.AsArray().Select(x=>Guid.Parse(x!.GetValue<string>())).ToArray();Assert.Equal(3,hosts.Length);
        Assert.Matches("\\A[0-9a-f]{32}\\z",marker);
        byte[] archive;
        using(var memory=new MemoryStream()) {
            using(var zip=new ZipArchive(memory,ZipArchiveMode.Create,true)) {
                var entry=zip.CreateEntry("synthetic-agent.txt");entry.LastWriteTime=new DateTimeOffset(2026,1,1,0,0,0,TimeSpan.Zero);
                using var output=entry.Open();output.Write(Encoding.UTF8.GetBytes("synthetic update transport fixture "+marker));
            }
            archive=memory.ToArray();
        }
        string sha=Convert.ToHexStringLower(SHA256.HashData(archive));
        await File.WriteAllTextAsync(Path.Combine(proof,"pre-dml-plan.json"),JsonSerializer.Serialize(new { wave,marker,hosts,package=sha,archive_bytes=archive.Length,native_ids_generated_during_transaction=true }),ct);
        await using var fixture=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        await using var db=await fixture.OpenConnectionAsync(ct);await using var tx=await db.BeginTransactionAsync(ct);
        await using(var role=new NpgsqlCommand("select current_user",db,tx))Assert.Equal("adlog_user",await role.ExecuteScalarAsync(ct));
        string baseline=await Baseline(db,tx,ct);
        await using(var collision=new NpgsqlCommand("select (select count(*) from sli_agents where host_id=any(@hosts)),(select count(*) from sli_agent_update_packages where sha256=@package),(select count(*) from sli_agent_update_waves where id=@wave)",db,tx)) {
            collision.Parameters.AddWithValue("hosts",hosts);collision.Parameters.AddWithValue("package",sha);collision.Parameters.AddWithValue("wave",wave);
            await using var reader=await collision.ExecuteReaderAsync(ct);Assert.True(await reader.ReadAsync(ct));for(int i=0;i<3;i++)Assert.Equal(0L,reader.GetInt64(i));
        }
        using var rootKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);using var root=CaRequest("CN=synthetic update root",rootKey,1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddYears(2));
        using var issuerKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);using var issuerPublic=CaRequest("CN=synthetic update issuer",issuerKey,0).Create(root,DateTimeOffset.UtcNow.AddHours(-1),DateTimeOffset.UtcNow.AddYears(1),RandomNumberGenerator.GetBytes(16));
        using var issuer=issuerPublic.CopyWithPrivateKey(issuerKey);using var ca=new AgentIssuingCa(root,issuer);
        var auth=new AgentIdentityService(ca);var audit=new AgentControlAudit();var management=new AgentManagementService(audit);var enrollment=new AgentEnrollmentService(ca,auth);var service=new AgentUpdateService(audit);
        var ids=new List<Guid>();var tokens=new List<Guid>();var certificates=new List<X509Certificate2>();
        try {
            async Task<AgentIdentity> Enroll(int number) {
                using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);Guid host=hosts[number-1];
                string name="update-"+marker+"-"+number+".example",fp=Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
                var token=await management.CreateTokenAsync(db,tx,JsonSerializer.SerializeToElement(new { host_id=host,key_fingerprint=fp,registration_host_name=name }),"session:101",ct);
                tokens.Add(token.GetProperty("id").GetGuid());await Capture();var csr=new CertificateRequest($"CN={host}",key,HashAlgorithmName.SHA256);
                var issued=await enrollment.EnrollAsync(db,tx,new JsonObject { ["token"]=token.GetProperty("token").GetString(),["csr_pem"]=csr.CreateSigningRequestPem(),["reported_hostname"]=name },ct);
                Guid id=Guid.Parse(issued["agent_id"]!.GetValue<string>());ids.Add(id);await Capture();var cert=X509Certificate2.CreateFromPem(issued["certificate_pem"]!.GetValue<string>());certificates.Add(cert);
                await AgentClientControlService.LockUpdateWavesAsync(db,tx,ct);return await auth.AuthenticateAsync(db,tx,cert,false,ct);
            }
            // Source route lock order, then actual registry/certificate authority.
            await AgentClientControlService.LockUpdateWavesAsync(db,tx,ct);
            var first=await Enroll(1);var second=await Enroll(2);var foreign=await Enroll(3);
            await using(var observer=await fixture.OpenConnectionAsync(ct)) {
                await using var observerTx=await observer.BeginTransactionAsync(ct);
                await using var held=new NpgsqlCommand("select pg_try_advisory_xact_lock(hashtext('sli_agent_update_waves'))",observer,observerTx);
                Assert.Equal(false,await held.ExecuteScalarAsync(ct));await observerTx.RollbackAsync(ct);
            }
            await using(var seed=new NpgsqlCommand("""
                insert into sli_agent_update_packages(sha256,version,manifest,archive) values(@package,'1.2.3','{"component":"agent","package_id":"sli.agent"}'::jsonb,@archive);
                insert into sli_agent_update_waves(id,package_sha256,version,batch_size,error_threshold,created_by,current_batch) values(@wave,@package,'1.2.3',1,0,'synthetic:update-fixture',1);
                insert into sli_agent_update_wave_members(wave_id,agent_id,package_sha256,batch_number,state,issued_at) values(@wave,@first,@package,1,'pending',clock_timestamp()),(@wave,@second,@package,2,'queued',null);
                insert into sli_agent_update_policy(agent_id,package_sha256) values(@first,@package)
                """,db,tx)) {
                seed.Parameters.AddWithValue("package",sha);seed.Parameters.AddWithValue("archive",archive);seed.Parameters.AddWithValue("wave",wave);seed.Parameters.AddWithValue("first",first.Id);seed.Parameters.AddWithValue("second",second.Id);await seed.ExecuteNonQueryAsync(ct);
            }
            await audit.AppendAsync(db,tx,"update_assign","synthetic:update-fixture",first.Id.ToString("D"),new { sha256=sha,wave_id=wave.ToString("D"),batch=1 },ct);
            string temporary;
            await using(var content=await service.DownloadAsync(db,tx,first,sha,ct)) {
                temporary=content.Name;Assert.Equal(archive.Length,content.Length);using var memory=new MemoryStream();await content.CopyToAsync(memory,ct);Assert.Equal(archive,memory.ToArray());
            }
            Assert.False(File.Exists(temporary));
            var notAssigned=await Assert.ThrowsAsync<AgentControlException>(()=>service.DownloadAsync(db,tx,second,sha,ct));Assert.Equal(404,notAssigned.Status);
            JsonObject Report(string status="updated",string? reason=null,string version="1.2.3")=>new() { ["sha256"]=sha,["status"]=status,["reason"]=reason,["version"]=version };
            Assert.Equal(404,(await Assert.ThrowsAsync<AgentControlException>(()=>service.ReportAsync(db,tx,foreign,Report(),ct))).Status);
            await tx.SaveAsync("audit_failure",ct);
            await Assert.ThrowsAsync<InvalidOperationException>(()=>new AgentUpdateService(new FailAudit()).ReportAsync(db,tx,first,Report("rejected","agent_update_stage_failed"),ct));
            await tx.RollbackAsync("audit_failure",ct);
            Assert.Equal(0L,await Count("select count(*) from sli_agent_update_results where package_sha256=@package"));
            Assert.Equal("recorded",(await service.ReportAsync(db,tx,first,Report(),ct))["status"]!.GetValue<string>());
            await service.ReportAsync(db,tx,first,Report(),ct);
            Assert.Equal(1L,await Count("select count(*) from sli_agent_update_results where package_sha256=@package"));
            await using(var check=new NpgsqlCommand("select current_batch from sli_agent_update_waves where id=@wave",db,tx)){check.Parameters.AddWithValue("wave",wave);Assert.Equal(2,await check.ExecuteScalarAsync(ct));}
            await using(var content=await service.DownloadAsync(db,tx,second,sha,ct))Assert.Equal(archive.Length,content.Length);
            await service.ReportAsync(db,tx,second,Report("rejected","agent_update_msi_required","1.0.0"),ct);
            await using(var check=new NpgsqlCommand("select status,reason from sli_agent_update_waves where id=@wave",db,tx)) {
                check.Parameters.AddWithValue("wave",wave);await using var reader=await check.ExecuteReaderAsync(ct);Assert.True(await reader.ReadAsync(ct));Assert.Equal("stopped",reader.GetString(0));Assert.Equal("agent_update_error_threshold_exceeded",reader.GetString(1));
            }
            Assert.Equal(0L,await Count("select count(*) from sli_agent_update_policy where package_sha256=@package"));
            Assert.Equal(404,(await Assert.ThrowsAsync<AgentControlException>(()=>service.DownloadAsync(db,tx,first,sha,ct))).Status);
            // Source assignment history permits late results after withdrawal.
            await service.ReportAsync(db,tx,first,Report("rejected","agent_update_download_failed"),ct);
            Assert.Equal(3L,await Count("select count(*) from sli_agent_update_results where package_sha256=@package"));
            Assert.Equal(3L,await Count("select count(*) from sli_agent_audit where action='update_result' and target=@package"));
            await tx.RollbackAsync(ct);
            await using(var absent=new NpgsqlCommand("""
                select (select count(*) from sli_agents where id=any(@ids)),
                (select count(*) from sli_agent_enrollment_tokens where id=any(@tokens)),
                (select count(*) from sli_agent_update_packages where sha256=@package),
                (select count(*) from sli_agent_update_waves where id=@wave),
                (select count(*) from sli_agent_audit where target=any(@targets))
                """,db)) {
                absent.Parameters.AddWithValue("ids",ids.ToArray());absent.Parameters.AddWithValue("tokens",tokens.ToArray());absent.Parameters.AddWithValue("package",sha);absent.Parameters.AddWithValue("wave",wave);
                absent.Parameters.AddWithValue("targets",ids.Concat(tokens).Select(i=>i.ToString("D")).Append(sha).Append(wave.ToString("D")).ToArray());
                await using var reader=await absent.ExecuteReaderAsync(ct);Assert.True(await reader.ReadAsync(ct));for(int i=0;i<5;i++)Assert.Equal(0L,reader.GetInt64(i));
            }
            Assert.Equal(baseline,await Baseline(db,null,ct));
            await File.WriteAllTextAsync(Path.Combine(proof,"database-result.json"),JsonSerializer.Serialize(new { ordinary_role="adlog_user",agents=ids,tokens,wave,package=sha,archive_bytes=archive.Length,rollback_absent=true,synthetic_report_not_installation=true,update_tables_sha256_before=baseline,update_tables_sha256_after=baseline }),ct);
            async Task<long> Count(string sql) {await using var command=new NpgsqlCommand(sql,db,tx);command.Parameters.AddWithValue("package",sha);return (long)(await command.ExecuteScalarAsync(ct))!;}
            Task Capture()=>File.WriteAllTextAsync(Path.Combine(proof,"generated-ids.json"),JsonSerializer.Serialize(new { agents=ids,tokens,hosts,wave,package=sha }),ct);
        } finally {foreach(var cert in certificates)cert.Dispose();}
    }
    private static async Task<string> Baseline(NpgsqlConnection db,NpgsqlTransaction? tx,CancellationToken ct)
    {
        await using var command=new NpgsqlCommand("""
            select jsonb_build_array(
              (select jsonb_agg(jsonb_build_array(sha256,version,manifest,md5(archive),created_at) order by sha256) from sli_agent_update_packages),
              (select jsonb_agg(to_jsonb(p) order by agent_id) from sli_agent_update_policy p),
              (select jsonb_agg(to_jsonb(r) order by agent_id,package_sha256,status,reason_key) from sli_agent_update_results r),
              (select jsonb_agg(to_jsonb(w) order by id) from sli_agent_update_waves w),
              (select jsonb_agg(to_jsonb(m) order by wave_id,agent_id) from sli_agent_update_wave_members m))::text
            """,db,tx);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes((string)(await command.ExecuteScalarAsync(ct))!)));
    }
    private sealed class FailAudit:IAgentControlAudit
    {public Task AppendAsync(NpgsqlConnection db,NpgsqlTransaction tx,string action,string actor,string target,object details,CancellationToken ct)=>throw new InvalidOperationException("synthetic update audit failure");}
    private static CertificateRequest CaRequest(string name,ECDsa key,int path) {
        var request=new CertificateRequest(name,key,HashAlgorithmName.SHA256);request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,true,path,true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign|X509KeyUsageFlags.CrlSign,true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") },false));return request;
    }
}
