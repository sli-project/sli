using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
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
public sealed class AgentUpdateAdministrationDatabaseTests
{
    [Fact]
    public async Task RealSignedUploadAssignmentWavesAndCertificateClientShareSourceTransactions()
    {
        var ct=TestContext.Current.CancellationToken;string proof=Environment.GetEnvironmentVariable("SLI_AGENT_UPDATE_ADMIN_PROOF")??throw new InvalidOperationException("Missing own update proof directory");
        var plan=JsonNode.Parse(await File.ReadAllTextAsync(Path.Combine(proof,"input-plan.json"),ct))!;string marker=plan["namespace"]!.GetValue<string>();Assert.Matches("\\A[0-9a-f]{32}\\z",marker);
        Guid[] hosts=plan["hosts"]!.AsArray().Select(x=>Guid.Parse(x!.GetValue<string>())).ToArray();Assert.Equal(3,hosts.Length);
        var cases=AgentPackageTests.Fixture()["cases"]!.AsArray();var a=cases.First(x=>x!["name"]!.GetValue<string>()=="valid stored")!;var b=cases.First(x=>x!["name"]!.GetValue<string>()=="valid deflated")!;
        byte[] archiveA=Convert.FromBase64String(a["archive"]!.GetValue<string>()),archiveB=Convert.FromBase64String(b["archive"]!.GetValue<string>());string shaA=a["output"]!["sha256"]!.GetValue<string>(),shaB=b["output"]!["sha256"]!.GetValue<string>();
        string trustFile=Path.Combine(proof,"synthetic-trust-"+marker+".json");await File.WriteAllTextAsync(trustFile,a["trust"]!.GetValue<string>(),ct);
        var ids=new List<Guid>();var tokens=new List<Guid>();var waves=new List<Guid>();var certificates=new Dictionary<Guid,X509Certificate2>();
        Task Capture()=>File.WriteAllTextAsync(Path.Combine(proof,"generated-ids.json"),JsonSerializer.Serialize(new { agents=ids,tokens,waves,hosts,package_ids=new[]{shaA,shaB} }),ct);
        await File.WriteAllTextAsync(Path.Combine(proof,"pre-dml-plan.json"),JsonSerializer.Serialize(new { marker,hosts,package_ids=new[]{shaA,shaB},native_ids_generated_during_transaction=true }),ct);
        try {
            await using var fixture=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
            await using var db=await fixture.OpenConnectionAsync(ct);await using var tx=await db.BeginTransactionAsync(ct);
            await using(var role=new NpgsqlCommand("select current_user",db,tx))Assert.Equal("adlog_user",await role.ExecuteScalarAsync(ct));
            string baseline=await Baseline(db,tx,ct);
            await using(var check=new NpgsqlCommand("select (select count(*) from sli_agents where host_id=any(@hosts)),(select count(*) from sli_agent_update_packages where sha256=any(@packages))",db,tx)) {
                check.Parameters.AddWithValue("hosts",hosts);check.Parameters.AddWithValue("packages",new[]{shaA,shaB});await using var reader=await check.ExecuteReaderAsync(ct);Assert.True(await reader.ReadAsync(ct));Assert.Equal(0L,reader.GetInt64(0));Assert.Equal(0L,reader.GetInt64(1));
            }
            using var rootKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);using var root=CaRequest("CN=synthetic update admin root",rootKey,1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddYears(2));
            using var issuerKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);using var issuerPublic=CaRequest("CN=synthetic update admin issuer",issuerKey,0).Create(root,DateTimeOffset.UtcNow.AddHours(-1),DateTimeOffset.UtcNow.AddYears(1),RandomNumberGenerator.GetBytes(16));
            using var issuer=issuerPublic.CopyWithPrivateKey(issuerKey);using var ca=new AgentIssuingCa(root,issuer);var auth=new AgentIdentityService(ca);var audit=new AgentControlAudit();
            var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:AgentUpdateTrustFile"]=trustFile }).Build();
            var admin=new AgentUpdateAdministration(audit,config);var client=new AgentUpdateService(audit);var management=new AgentManagementService(audit);var enrollment=new AgentEnrollmentService(ca,auth);
            await AgentClientControlService.LockUpdateWavesAsync(db,tx,ct);
            for(int index=0;index<3;index++) {
                using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);string name="update-admin-"+marker+"-"+index+".example";string fp=Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
                var token=await management.CreateTokenAsync(db,tx,JsonSerializer.SerializeToElement(new { host_id=hosts[index],key_fingerprint=fp,registration_host_name=name }),"session:101",ct);tokens.Add(token.GetProperty("id").GetGuid());await Capture();
                var csr=new CertificateRequest($"CN={hosts[index]}",key,HashAlgorithmName.SHA256);
                var result=await enrollment.EnrollAsync(db,tx,new JsonObject { ["token"]=token.GetProperty("token").GetString(),["csr_pem"]=csr.CreateSigningRequestPem(),["reported_hostname"]=name },ct);
                Guid id=Guid.Parse(result["agent_id"]!.GetValue<string>());ids.Add(id);await Capture();certificates.Add(id,X509Certificate2.CreateFromPem(result["certificate_pem"]!.GetValue<string>()));
            }
            await tx.SaveAsync("upload_audit",ct);
            await Assert.ThrowsAsync<InvalidOperationException>(()=>new AgentUpdateAdministration(new FailAt("update_upload",audit),config).UploadAsync(db,tx,archiveA,"session:101",ct));
            await tx.RollbackAsync("upload_audit",ct);
            Assert.Equal(0L,await Count("select count(*) from sli_agent_update_packages where sha256=@package",shaA));
            Assert.Equal(shaA,(await admin.UploadAsync(db,tx,archiveA,"session:101",ct)).GetProperty("sha256").GetString());
            await admin.UploadAsync(db,tx,archiveA,"session:101",ct);await admin.UploadAsync(db,tx,archiveB,"session:101",ct);
            Assert.Equal(1L,await Count("select count(*) from sli_agent_update_packages where sha256=@package",shaA));
            byte[] badCrc=Convert.FromBase64String(cases.First(x=>x!["name"]!.GetValue<string>().StartsWith("CRC payload/",StringComparison.Ordinal))!["archive"]!.GetValue<string>());
            Assert.Equal("agent_package_verification_failed",(await Assert.ThrowsAsync<AgentControlException>(()=>admin.UploadAsync(db,tx,badCrc,"session:101",ct))).Message);
            var packages=await admin.ListPackagesAsync(db,tx,"session:101",ct);Assert.Contains(packages.GetProperty("items").EnumerateArray(),p=>p.GetProperty("sha256").GetString()==shaA);
            async Task Assign(Guid id,string? sha)=>await admin.AssignAsync(db,tx,JsonSerializer.SerializeToElement(new { agent_id=id,sha256=sha }),"session:101",ct);
            await Assign(ids[2],shaB);await Assign(ids[2],null);
            JsonElement Selection(string sha,Guid[] agents)=>JsonSerializer.SerializeToElement(new { agent_ids=agents,sha256=sha,batch_size=1,error_threshold=0 });
            Assert.Equal("agent_update_package_already_attempted",(await Assert.ThrowsAsync<AgentControlException>(()=>admin.CreateWaveAsync(db,tx,Selection(shaB,[ids[2]]),"session:101",ct))).Message);
            await tx.SaveAsync("wave_audit",ct);
            await Assert.ThrowsAsync<InvalidOperationException>(()=>new AgentUpdateAdministration(new FailAt("update_wave_create",audit,target=>{waves.Add(Guid.Parse(target));Capture().GetAwaiter().GetResult();}),config).CreateWaveAsync(db,tx,Selection(shaA,ids.Take(2).ToArray()),"session:101",ct));
            await tx.RollbackAsync("wave_audit",ct);
            Assert.Equal(0L,await Count("select count(*) from sli_agent_update_waves where package_sha256=@package",shaA));
            var waveA=await admin.CreateWaveAsync(db,tx,Selection(shaA,ids.Take(2).ToArray()),"session:101",ct);Guid waveIdA=waveA.GetProperty("id").GetGuid();waves.Add(waveIdA);await Capture();
            Assert.Equal(1,waveA.GetProperty("current_batch").GetInt32());Assert.Equal("agent_update_awaiting_version",waveA.GetProperty("waiting_reason").GetString());
            Guid first=waveA.GetProperty("members")[0].GetProperty("agent_id").GetGuid(),second=waveA.GetProperty("members")[1].GetProperty("agent_id").GetGuid();
            var firstIdentity=await auth.AuthenticateAsync(db,tx,certificates[first],false,ct);var secondIdentity=await auth.AuthenticateAsync(db,tx,certificates[second],false,ct);var foreign=await auth.AuthenticateAsync(db,tx,certificates[ids[2]],false,ct);
            var offer=await new AgentClientControlService(audit,TimeProvider.System).CheckInAsync(db,tx,firstIdentity,ct);Assert.Equal(shaA,offer["agent_update"]!["sha256"]!.GetValue<string>());
            await using(var file=await client.DownloadAsync(db,tx,firstIdentity,shaA,ct)){using var bytes=new MemoryStream();await file.CopyToAsync(bytes,ct);Assert.Equal(archiveA,bytes.ToArray());}
            JsonObject Report(string sha,string status="updated",string? reason=null)=>new() { ["sha256"]=sha,["status"]=status,["reason"]=reason,["version"]="1.2.3" };
            Assert.Equal(404,(await Assert.ThrowsAsync<AgentControlException>(()=>client.ReportAsync(db,tx,foreign,Report(shaA),ct))).Status);
            await client.ReportAsync(db,tx,firstIdentity,Report(shaA),ct);await client.ReportAsync(db,tx,firstIdentity,Report(shaA),ct);
            await using(var file=await client.DownloadAsync(db,tx,secondIdentity,shaA,ct))Assert.Equal(archiveA.Length,file.Length);
            await client.ReportAsync(db,tx,secondIdentity,Report(shaA,"rejected","agent_update_msi_required"),ct);
            var stopped=await admin.ListWavesAsync(db,tx,waveIdA,"session:101",ct);Assert.Equal("stopped",stopped.GetProperty("items")[0].GetProperty("status").GetString());
            await client.ReportAsync(db,tx,firstIdentity,Report(shaA,"rejected","agent_update_download_failed"),ct);
            Assert.Equal(404,(await Assert.ThrowsAsync<AgentControlException>(()=>client.DownloadAsync(db,tx,firstIdentity,shaA,ct))).Status);
            var waveB=await admin.CreateWaveAsync(db,tx,Selection(shaB,ids.Take(2).ToArray()),"session:101",ct);Guid waveIdB=waveB.GetProperty("id").GetGuid();waves.Add(waveIdB);await Capture();
            var stopBody=JsonSerializer.SerializeToElement(new { wave_id=waveIdB });var manual=await admin.StopWaveAsync(db,tx,stopBody,"session:101",ct);var replay=await admin.StopWaveAsync(db,tx,stopBody,"session:101",ct);
            Assert.Equal("agent_update_stopped_by_admin",manual.GetProperty("reason").GetString());Assert.Equal(manual.GetProperty("finished_at").GetString(),replay.GetProperty("finished_at").GetString());
            Assert.Equal(0L,await Count("select count(*) from sli_agent_update_policy where package_sha256=@package",shaB));
            Assert.Equal("agent_update_package_already_attempted",(await Assert.ThrowsAsync<AgentControlException>(()=>admin.CreateWaveAsync(db,tx,Selection(shaA,ids.Take(2).ToArray()),"session:101",ct))).Message);
            await tx.RollbackAsync(ct);Assert.Equal(baseline,await Baseline(db,null,ct));
            await using(var absence=new NpgsqlCommand("select (select count(*) from sli_agents where id=any(@ids)),(select count(*) from sli_agent_enrollment_tokens where id=any(@tokens)),(select count(*) from sli_agent_update_packages where sha256=any(@packages)),(select count(*) from sli_agent_update_waves where id=any(@waves))",db)) {
                absence.Parameters.AddWithValue("ids",ids.ToArray());absence.Parameters.AddWithValue("tokens",tokens.ToArray());absence.Parameters.AddWithValue("packages",new[]{shaA,shaB});absence.Parameters.AddWithValue("waves",waves.ToArray());await using var reader=await absence.ExecuteReaderAsync(ct);Assert.True(await reader.ReadAsync(ct));for(int i=0;i<4;i++)Assert.Equal(0L,reader.GetInt64(i));
            }
            await File.WriteAllTextAsync(Path.Combine(proof,"database-result.json"),JsonSerializer.Serialize(new { role="adlog_user",agents=ids,tokens,waves,packages=new[]{shaA,shaB},source_producers=true,sql_package_wave_seeds=false,rollback_absent=true,update_and_audit_sha256_before=baseline,update_and_audit_sha256_after=baseline,synthetic_reports_not_installation=true }),ct);
            async Task<long> Count(string sql,string package){await using var query=new NpgsqlCommand(sql,db,tx);query.Parameters.AddWithValue("package",package);return (long)(await query.ExecuteScalarAsync(ct))!;}
        } finally {foreach(var cert in certificates.Values)cert.Dispose();File.Delete(trustFile);}
    }
    private sealed class FailAt(string action,IAgentControlAudit inner,Action<string>? observe=null):IAgentControlAudit
    {
        public Task AppendAsync(NpgsqlConnection db,NpgsqlTransaction tx,string current,string actor,string target,object details,CancellationToken ct)
        {if(current==action){observe?.Invoke(target);throw new InvalidOperationException("synthetic own audit failure");}return inner.AppendAsync(db,tx,current,actor,target,details,ct);}
    }
    private static async Task<string> Baseline(NpgsqlConnection db,NpgsqlTransaction? tx,CancellationToken ct)
    {
        await using var query=new NpgsqlCommand("""
            select jsonb_build_array(
             (select jsonb_agg(jsonb_build_array(sha256,version,manifest,md5(archive),created_at) order by sha256) from sli_agent_update_packages),
             (select jsonb_agg(to_jsonb(p) order by agent_id) from sli_agent_update_policy p),
             (select jsonb_agg(to_jsonb(r) order by agent_id,package_sha256,status,reason_key) from sli_agent_update_results r),
             (select jsonb_agg(to_jsonb(w) order by id) from sli_agent_update_waves w),
             (select jsonb_agg(to_jsonb(m) order by wave_id,agent_id) from sli_agent_update_wave_members m),
             (select jsonb_agg(to_jsonb(a) order by id) from sli_agent_audit a))::text
            """,db,tx);return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes((string)(await query.ExecuteScalarAsync(ct))!)));
    }
    private static CertificateRequest CaRequest(string name,ECDsa key,int path)
    {var r=new CertificateRequest(name,key,HashAlgorithmName.SHA256);r.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,true,path,true));r.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign|X509KeyUsageFlags.CrlSign,true));r.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") },false));return r;}
}
