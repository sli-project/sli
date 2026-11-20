using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Agents;
using Sli.Server.Agents.Certificates;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Registry;
using Sli.Server.Tests.Integration;
using Xunit;
namespace Sli.Server.Tests.Agents;

[Collection("Owned agent recovery")]
public sealed class AgentClientControlDatabaseTests
{
    private static JsonElement Json(object value)=>JsonSerializer.SerializeToElement(value);
    [Fact]
    public async Task RealEnrollmentAndCertificateBoundClientReportsReleaseReplacementWithoutSeededAcknowledgement()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        await using var db=await fixture.OpenConnectionAsync(ct);await using var tx=await db.BeginTransactionAsync(ct);
        await using(var check=new NpgsqlCommand("select current_user",db,tx))Assert.Equal("adlog_user",await check.ExecuteScalarAsync(ct));
        using var rootKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);using var root=CaRequest("CN=synthetic control root",rootKey,1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddYears(2));
        using var issuerKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);using var issuerPublic=CaRequest("CN=synthetic control issuer",issuerKey,0).Create(root,DateTimeOffset.UtcNow.AddHours(-1),DateTimeOffset.UtcNow.AddYears(1),RandomNumberGenerator.GetBytes(16));
        using var issuer=issuerPublic.CopyWithPrivateKey(issuerKey);using var ca=new AgentIssuingCa(root,issuer);
        var auth=new AgentIdentityService(ca);var audit=new AgentControlAudit();var management=new AgentManagementService(audit);
        var enrollment=new AgentEnrollmentService(ca,auth);var lifecycle=new AgentLifecycleService(management,audit);
        var service=new AgentClientControlService(audit,TimeProvider.System);var replacement=new AgentReplacementService();
        var ids=new List<Guid>();var tokens=new List<Guid>();var hosts=new List<Guid>();string name="control-"+Guid.NewGuid().ToString("N")+".example";
        async Task<(Guid Id,X509Certificate2 Cert)> Enroll(Guid? replaces=null,string? display=null) {
            using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);Guid host=Guid.NewGuid();hosts.Add(host);
            string registration=display ?? name;
            string fp=Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
            var input=new JsonObject { ["host_id"]=host.ToString("D"),["key_fingerprint"]=fp,["registration_host_name"]=registration };
            if(replaces is not null)input["replacement_for"]=replaces.Value.ToString("D");
            var token=await management.CreateTokenAsync(db,tx,Json(input),"session:101",ct);tokens.Add(token.GetProperty("id").GetGuid());
            var csr=new CertificateRequest($"CN={host}",key,HashAlgorithmName.SHA256);
            var result=await enrollment.EnrollAsync(db,tx,new JsonObject { ["token"]=token.GetProperty("token").GetString(),["csr_pem"]=csr.CreateSigningRequestPem(),["reported_hostname"]=registration },ct);
            Guid id=Guid.Parse(result["agent_id"]!.GetValue<string>());ids.Add(id);return(id,X509Certificate2.CreateFromPem(result["certificate_pem"]!.GetValue<string>()));
        }
        var old=await Enroll();using var oldCert=old.Cert;var next=await Enroll(old.Id);using var newCert=next.Cert;
        await lifecycle.RequestProbeAsync(db,tx,Json(new { agent_id=next.Id }),"session:101",ct);
        JsonElement Switch(string phase)=>Json(new { old_agent_id=old.Id,new_agent_id=next.Id,phase,confirm=true });
        Assert.Equal("draining",(await replacement.ReplaceAsync(db,tx,Switch("prepare"),"session:101",ct)).GetProperty("state").GetString());
        await tx.SaveAsync("not_ready",ct);Assert.Equal("agent_replacement_not_ready",(await Assert.ThrowsAsync<AgentControlException>(()=>replacement.ReplaceAsync(db,tx,Switch("complete"),"session:101",ct))).Message);await tx.RollbackAsync("not_ready",ct);
        foreach(var item in new[]{old,next}) {
            await AgentClientControlService.LockUpdateWavesAsync(db,tx,ct);var identity=await auth.AuthenticateAsync(db,tx,item.Cert,false,ct);
            var wire=await service.CheckInAsync(db,tx,identity,ct);Assert.Null(wire["agent_update"]);
            var policy=AgentPolicy.Parse(wire,item.Id.ToString("D"),EventCatalog.Load());Assert.Equal("drain",policy.Control.State);
            var applied=await service.ReportAsync(db,tx,identity,policy.Report("paused","allowed"),ct);
            Assert.Equal(policy.Revision,applied["applied_policy_revision"]!.GetValue<long>());Assert.Equal("paused",applied["applied_collection_state"]!.GetValue<string>());
            await service.ReportAsync(db,tx,identity,new JsonObject { ["delivery_diagnostics"]=new JsonArray() },ct);
            await service.ReportAsync(db,tx,identity,new JsonObject { ["applied_policy_revision"]=0,["collection_state"]="active" },ct);
        }
        Assert.Equal("completed",(await replacement.ReplaceAsync(db,tx,Switch("complete"),"session:101",ct)).GetProperty("state").GetString());
        Assert.Equal("completed",(await replacement.ReplaceAsync(db,tx,Switch("complete"),"session:101",ct)).GetProperty("state").GetString());
        await Assert.ThrowsAsync<AgentCertificateException>(()=>auth.AuthenticateAsync(db,tx,oldCert,false,ct));
        var newIdentity=await auth.AuthenticateAsync(db,tx,newCert,false,ct);var resumed=await service.CheckInAsync(db,tx,newIdentity,ct);
        Assert.Equal(hosts[0].ToString("D"),resumed["runtime_handoff"]!["source_host_id"]!.GetValue<string>());
        Assert.NotNull(AgentPolicy.Parse(resumed,next.Id.ToString("D"),EventCatalog.Load()).Handoff);
        await using(var count=new NpgsqlCommand("select count(*) from sli_agent_audit where target=any(@targets) and action='policy_ack'",db,tx)) {
            count.Parameters.AddWithValue("targets",ids.Select(x=>x.ToString("D")).ToArray());Assert.Equal(2L,await count.ExecuteScalarAsync(ct));
        }
        // A separate enrolled own agent proves the removal-only certificate path.
        var removed=await Enroll(display:"removal-"+name);using var removedCert=removed.Cert;
        await lifecycle.RequestRemovalAsync(db,tx,Json(new { operation_id=Guid.NewGuid(),agent_ids=new[]{removed.Id} }),"session:101",ct);
        await Assert.ThrowsAsync<AgentCertificateException>(()=>auth.AuthenticateAsync(db,tx,removedCert,false,ct));
        var removalIdentity=await auth.AuthenticateRemovalAsync(db,tx,removedCert,ct);var command=await AgentClientControlService.RemovalCommandAsync(db,tx,removalIdentity,ct);
        Assert.Equal("uninstall",command["agent_removal"]!["action"]!.GetValue<string>());
        await tx.RollbackAsync(ct);
        await using(var absent=new NpgsqlCommand("select (select count(*) from sli_agents where id=any(@ids)),(select count(*) from sli_agent_enrollment_tokens where id=any(@tokens)),(select count(*) from sli_agent_audit where target=any(@targets))",db)) {
            absent.Parameters.AddWithValue("ids",ids.ToArray());absent.Parameters.AddWithValue("tokens",tokens.ToArray());absent.Parameters.AddWithValue("targets",ids.Concat(tokens).Select(x=>x.ToString("D")).ToArray());
            await using var reader=await absent.ExecuteReaderAsync(ct);Assert.True(await reader.ReadAsync(ct));for(int i=0;i<3;i++)Assert.Equal(0L,reader.GetInt64(i));
        }
        if(Environment.GetEnvironmentVariable("SLI_AGENT_CLIENT_PROOF") is string proof)await File.WriteAllTextAsync(Path.Combine(proof,"database-result.json"),JsonSerializer.Serialize(new { ordinary_role="adlog_user",agents=ids,tokens,source296="completed",native_client_reports=true,manual_ack_seed=false,rollback_absent=true }),ct);
    }
    private static CertificateRequest CaRequest(string name,ECDsa key,int path) {
        var request=new CertificateRequest(name,key,HashAlgorithmName.SHA256);request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,true,path,true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign|X509KeyUsageFlags.CrlSign,true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") },false));return request;
    }
}
