using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Certificates;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Groups;
using Sli.Server.Agents.Registry;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests;

[Collection("Owned agent recovery")]
public sealed class AgentGroupDatabaseTests
{
    [Fact]
    public async Task ActualTemplateProducerAndGroupApprovalEnrollmentUseCallerTransactionOn305()
    {
        var ct=TestContext.Current.CancellationToken;
        string proof=Environment.GetEnvironmentVariable("SLI_AGENT_GROUP_PROOF")??throw new InvalidOperationException("Missing exact group fixture plan");
        var plan=JsonNode.Parse(File.ReadAllBytes(Path.Combine(proof,"input-plan.json")))!;
        long domain=plan["domain"]!.GetValue<long>(),ou=plan["ou"]!.GetValue<long>();
        long[] computers=plan["computers"]!.AsArray().Select(x=>x!.GetValue<long>()).ToArray();Assert.Equal(4,computers.Length);
        Guid[] hosts=plan["hosts"]!.AsArray().Select(x=>Guid.Parse(x!.GetValue<string>())).ToArray();Assert.Equal(4,hosts.Length);
        Guid template=Guid.Parse(plan["template"]!.GetValue<string>());
        var source=JsonNode.Parse(File.ReadAllBytes(FindVector()))!;
        await using var fixture=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        await using var db=await fixture.OpenConnectionAsync(ct);await using var tx=await db.BeginTransactionAsync(ct);
        await using(var q=new NpgsqlCommand("select current_user,max(version) from schema_migrations group by current_user",db,tx))
        {await using var r=await q.ExecuteReaderAsync(ct);Assert.True(await r.ReadAsync(ct));Assert.Equal("adlog_user",r.GetString(0));Assert.Equal(305,r.GetInt32(1));}
        string baseline=await Baseline(db,tx,ct);
        Assert.Equal(0L,await Scalar("select count(*) from sli_agents where host_id=any(@hosts)",("hosts",hosts)));
        Assert.Equal(0L,await Scalar("select count(*) from sli_agent_policy_templates where id=@id",("id",template)));
        var templateProducer=new AgentTemplateService(new AgentControlAudit());
        object TemplateBody(long expected,string state="active")=>new{template_id=template,expected_version=expected,assigned_modules=new[]{new{module_id="sli.workstations",enabled=true,config=new{}}},collection_policy=new{state}};
        var savedTemplate=await templateProducer.SaveAsync(db,tx,JsonSerializer.SerializeToElement(TemplateBody(0)),"session:101",ct);
        Assert.Equal(source["fixture_template_sha256"]!.GetValue<string>(),savedTemplate.GetProperty("policy_sha256").GetString());
        Assert.Equal(1L,savedTemplate.GetProperty("version").GetInt64());
        var stale=await Assert.ThrowsAsync<AgentControlException>(()=>templateProducer.SaveAsync(db,tx,JsonSerializer.SerializeToElement(TemplateBody(0)),"session:101",ct));Assert.Equal(409,stale.Status);Assert.Equal("agent_template_version_conflict",stale.Message);
        var secondVersion=await templateProducer.SaveAsync(db,tx,JsonSerializer.SerializeToElement(TemplateBody(1,"paused")),"session:101",ct);Assert.Equal(2L,secondVersion.GetProperty("version").GetInt64());
        await tx.SaveAsync("template_audit_failure",ct);
        await Assert.ThrowsAsync<InvalidOperationException>(()=>new AgentTemplateService(new FailAudit()).SaveAsync(db,tx,JsonSerializer.SerializeToElement(TemplateBody(2)),"session:101",ct));
        await tx.RollbackAsync("template_audit_failure",ct);
        Assert.Equal(2L,await Scalar("select max(version) from sli_agent_policy_templates where id=@id",("id",template)));
        var latest=await templateProducer.ListAsync(db,tx,"session:101",ct);var ownTemplate=Assert.Single(latest.GetProperty("items").EnumerateArray(),x=>x.GetProperty("id").GetGuid()==template);Assert.Equal(2L,ownTemplate.GetProperty("version").GetInt64());
        Assert.Equal(source["fixture_template_sha256"]!.GetValue<string>(),await Scalar("select policy_sha256 from sli_agent_policy_templates where id=@id and version=1",("id",template)));
        await using(var observer=await fixture.OpenConnectionAsync(ct))
        {await using var held=new NpgsqlCommand("select pg_try_advisory_xact_lock(hashtext(@key))",observer);held.Parameters.AddWithValue("key","sli-agent-template:"+template);Assert.Equal(false,await held.ExecuteScalarAsync(ct));}
        using var rootKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);using var root=CaRequest("CN=synthetic group root",rootKey,1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddYears(2));
        using var issuerKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);using var issuerPublic=CaRequest("CN=synthetic group issuer",issuerKey,0).Create(root,DateTimeOffset.UtcNow.AddHours(-1),DateTimeOffset.UtcNow.AddYears(1),RandomNumberGenerator.GetBytes(16));
        using var issuer=issuerPublic.CopyWithPrivateKey(issuerKey);using var ca=new AgentIssuingCa(root,issuer);
        var identity=new AgentIdentityService(ca);var enroll=new AgentEnrollmentService(ca,identity);var audit=new AgentControlAudit();var service=new AgentGroupService(new CredentialTokens(),audit);
        var keys=hosts.Select(_=>ECDsa.Create(ECCurve.NamedCurves.nistP256)).ToArray();
        var groupTokens=new List<Guid>();var groups=new List<Guid>();var requests=new List<Guid>();var agents=new List<Guid>();var preparedTokens=new HashSet<Guid>();
        try
        {
            string Fp(int i)=>Convert.ToHexStringLower(SHA256.HashData(keys[i].ExportSubjectPublicKeyInfo()));
            JsonObject Claim(int i,string raw)=>new(){["token"]=raw,["host_id"]=hosts[i].ToString(),["instance_name"]=null,["csr_pem"]=new CertificateRequest("CN="+hosts[i],keys[i],HashAlgorithmName.SHA256).CreateSigningRequestPem(),["computer_entity_id"]=computers[i]};
            object Binding(int i,Guid id)=>new{request_id=id,host_id=hosts[i],instance_name=(string?)null,key_fingerprint=Fp(i),computer_entity_id=computers[i]};
            async Task<JsonElement> Create(object b)
            {var result=await service.CreateAsync(db,tx,JsonSerializer.SerializeToElement(b),"session:101",ct);groupTokens.Add(result.GetProperty("id").GetGuid());groups.Add(result.GetProperty("group_id").GetGuid());await Capture();return result;}
            async Task<JsonObject> Submit(int i,JsonElement token)
            {var result=await service.SubmitAsync(db,tx,JsonSerializer.SerializeToElement(Claim(i,token.GetProperty("token").GetString()!)),ct);Guid id=Guid.Parse(result["request_id"]!.GetValue<string>());if(!requests.Contains(id))requests.Add(id);await Capture();return result;}
            var manual=await Create(new{domain_id=domain,ou_entity_ids=new[]{ou},computer_entity_ids=computers.Take(2),max_uses=1});
            var pending=await Submit(0,manual);Assert.Equal("pending",pending["status"]!.GetValue<string>());Guid firstRequest=requests[0];
            Assert.Equal(firstRequest.ToString(),(await Submit(0,manual))["request_id"]!.GetValue<string>());
            Assert.Equal(1L,await Scalar("select uses_count::bigint from sli_agent_group_tokens where id=@id",("id",groupTokens[0])));
            await Assert.ThrowsAsync<AgentGroupAuditedRejection>(()=>service.SubmitAsync(db,tx,JsonSerializer.SerializeToElement(Claim(1,manual.GetProperty("token").GetString()!)),ct));
            Assert.Equal(1L,await Scalar("select count(*) from sli_agent_group_requests where token_id=@id",("id",groupTokens[0])));
            var filter=new{group_id=manual.GetProperty("group_id").GetGuid(),token_id=groupTokens[0]};
            var listed=await service.PendingAsync(db,tx,JsonSerializer.SerializeToElement(filter),"session:101",ct);Assert.Single(listed.GetProperty("items").EnumerateArray());
            var wrong=await service.ApproveAsync(db,tx,JsonSerializer.SerializeToElement(new{filter,evidence=new[]{Binding(1,firstRequest)}}),"session:101",ct);
            Assert.Equal("key_identity_unverified",wrong.GetProperty("items")[0].GetProperty("reason").GetString());
            Assert.Equal("pending",await Scalar("select status from sli_agent_group_requests where id=@id",("id",firstRequest)));
            var approved=await service.ApproveAsync(db,tx,JsonSerializer.SerializeToElement(new{filter,evidence=new[]{Binding(0,firstRequest)}}),"session:101",ct);
            await Capture();
            string original=approved.GetProperty("items")[0].GetProperty("token").GetString()!;
            var delivered=await Submit(0,manual);string rotated=delivered["token"]!.GetValue<string>();Assert.True(original!=rotated,"Unused approval credential must rotate");
            Assert.Equal(1L,await Scalar("select count(*) from sli_agent_audit where action='group_approval_delivery' and target=@id",("id",firstRequest.ToString())));
            var ordinary=Claim(0,original);ordinary.Remove("host_id");ordinary.Remove("computer_entity_id");
            Assert.Equal("enrollment_token_rejected",(await Assert.ThrowsAsync<AgentCertificateException>(()=>enroll.EnrollAsync(db,tx,ordinary,ct))).Code);
            ordinary["token"]=rotated;var issued=await enroll.EnrollAsync(db,tx,ordinary,ct);agents.Add(Guid.Parse(issued["agent_id"]!.GetValue<string>()));await Capture();
            Assert.Equal(1L,await Scalar("select count(*) from sli_agent_group_members where agent_id=@id",("id",agents[0])));
            var progress=await service.ProgressAsync(db,tx,groupTokens[0].ToString(),"session:101",ct);Assert.Equal("registered",progress.GetProperty("items")[0].GetProperty("deployment_status").GetString());
            using(var cert=X509Certificate2.CreateFromPem(issued["certificate_pem"]!.GetValue<string>()))_=await identity.AuthenticateAsync(db,tx,cert,false,ct);
            progress=await service.ProgressAsync(db,tx,groupTokens[0].ToString(),"session:101",ct);Assert.Equal("signaled",progress.GetProperty("items")[0].GetProperty("deployment_status").GetString());
            await Assert.ThrowsAsync<AgentGroupAuditedRejection>(()=>service.SubmitAsync(db,tx,JsonSerializer.SerializeToElement(Claim(0,manual.GetProperty("token").GetString()!)),ct));

            var templated=await Create(new{domain_id=domain,ou_entity_ids=new[]{ou},max_uses=1});var templatePending=await Submit(1,templated);Guid templateRequest=Guid.Parse(templatePending["request_id"]!.GetValue<string>());
            await tx.SaveAsync("approval_audit_failure",ct);
            await Assert.ThrowsAsync<InvalidOperationException>(()=>new AgentGroupService(new CredentialTokens(),new FailAudit()).OnboardAsync(db,tx,JsonSerializer.SerializeToElement(new{token_id=groupTokens[1],template_id=template,template_version=1,mode="selected",request_ids=new[]{templateRequest},evidence=new[]{Binding(1,templateRequest)}}),"session:101",ct));
            await Capture();
            await tx.RollbackAsync("approval_audit_failure",ct);
            Assert.Equal("pending",await Scalar("select status from sli_agent_group_requests where id=@id",("id",templateRequest)));
            Assert.Equal(0L,await Scalar("select count(*) from sli_agent_onboarding_copies where request_id=@id",("id",templateRequest)));
            var onboarded=await service.OnboardAsync(db,tx,JsonSerializer.SerializeToElement(new{token_id=groupTokens[1],template_id=template,template_version=1,mode="selected",request_ids=new[]{templateRequest},evidence=new[]{Binding(1,templateRequest)}}),"session:101",ct);
            await Capture();
            var normal=Claim(1,onboarded.GetProperty("items")[0].GetProperty("token").GetString()!);normal.Remove("host_id");normal.Remove("computer_entity_id");
            var templateIssued=await enroll.EnrollAsync(db,tx,normal,ct);agents.Add(Guid.Parse(templateIssued["agent_id"]!.GetValue<string>()));await Capture();
            Assert.Equal(source["fixture_template_sha256"]!.GetValue<string>(),await Scalar("select template_sha256 from sli_agents where id=@id",("id",agents[1])));
            Assert.Equal(1L,await Scalar("select policy_revision from sli_agents where id=@id",("id",agents[1])));

            var automatic=await Create(new{domain_id=domain,ou_entity_ids=new[]{ou},max_uses=2,template_id=template,template_version=1,auto_approve=true,trusted_bindings=new[]{new{host_id=hosts[2],instance_name=(string?)null,key_fingerprint=Fp(2),computer_entity_id=computers[2]}}});
            Assert.Equal("approved",(await Submit(2,automatic))["status"]!.GetValue<string>());
            Assert.Equal("approved",(await Submit(2,automatic))["status"]!.GetValue<string>());
            Assert.Equal("pending",(await Submit(3,automatic))["status"]!.GetValue<string>());
            await service.RevokeAsync(db,tx,JsonSerializer.SerializeToElement(new{id=groupTokens[2]}),"session:101",ct);
            Assert.Equal(2L,await Scalar("select count(*) from sli_agent_group_requests where token_id=@id and status='cancelled'",("id",groupTokens[2])));
            Assert.Equal("active",await Scalar("select status from sli_agents where id=@id",("id",agents[0])));
            var tokens=await service.ListAsync(db,tx,"session:101",ct);Assert.True(tokens.GetProperty("items").GetArrayLength()>=3);
            foreach(var item in tokens.GetProperty("items").EnumerateArray()){Assert.False(item.TryGetProperty("token_hash",out _));Assert.False(item.TryGetProperty("enrollment_policy",out _));}
            await tx.RollbackAsync(ct);
            Assert.Equal(baseline,await Baseline(db,null,ct));
            await using(var absent=new NpgsqlCommand("select (select count(*) from sli_agent_group_tokens where id=any(@tokens)),(select count(*) from sli_agent_group_requests where id=any(@requests)),(select count(*) from sli_agents where id=any(@agents)),(select count(*) from sli_agent_policy_templates where id=@template),(select count(*) from sli_agent_enrollment_tokens where id=any(@prepared)),(select count(*) from sli_agent_enrollment_groups where id=any(@groups))",db))
            {absent.Parameters.AddWithValue("tokens",groupTokens.ToArray());absent.Parameters.AddWithValue("requests",requests.ToArray());absent.Parameters.AddWithValue("agents",agents.ToArray());absent.Parameters.AddWithValue("template",template);absent.Parameters.AddWithValue("prepared",preparedTokens.ToArray());absent.Parameters.AddWithValue("groups",groups.ToArray());await using var r=await absent.ExecuteReaderAsync(ct);Assert.True(await r.ReadAsync(ct));for(int i=0;i<6;i++)Assert.Equal(0L,r.GetInt64(i));}

            async Task Capture()
            {
                await using(var q=new NpgsqlCommand("select enrollment_token_id from sli_agent_group_approval_links where request_id=any(@ids)",db,tx))
                {q.Parameters.AddWithValue("ids",requests.ToArray());await using var r=await q.ExecuteReaderAsync(ct);while(await r.ReadAsync(ct))preparedTokens.Add(r.GetGuid(0));}
                await File.WriteAllTextAsync(Path.Combine(proof,"native-generated-ids.json"),JsonSerializer.Serialize(new{group_tokens=groupTokens,groups,requests,agents,prepared_tokens=preparedTokens,template,hosts}),ct);
            }
        }
        finally{foreach(var key in keys)key.Dispose();}
        async Task<object?> Scalar(string sql,params(string Key,object Value)[] args){await using var q=new NpgsqlCommand(sql,db,tx);foreach(var (key,value) in args)q.Parameters.AddWithValue(key,value);return await q.ExecuteScalarAsync(ct);}
    }
    private static async Task<string> Baseline(NpgsqlConnection db,NpgsqlTransaction? tx,CancellationToken ct)
    {
        await using var q=new NpgsqlCommand("""
        select jsonb_build_array(
          (select jsonb_agg(to_jsonb(x) order by id) from sli_agent_group_tokens x),
          (select jsonb_agg(to_jsonb(x) order by id) from sli_agent_group_requests x),
          (select jsonb_agg(to_jsonb(x) order by id) from sli_agent_enrollment_groups x),
          (select jsonb_agg(to_jsonb(x) order by request_id) from sli_agent_group_approvals x),
          (select jsonb_agg(to_jsonb(x) order by enrollment_token_id) from sli_agent_onboarding_copies x),
          (select jsonb_agg(to_jsonb(x) order by agent_id) from sli_agent_group_members x),
          (select jsonb_agg(to_jsonb(x) order by id) from sli_agent_enrollment_tokens x),
          (select jsonb_agg(to_jsonb(x) order by id) from sli_agents x),
          (select jsonb_agg(to_jsonb(x) order by id) from sli_agent_certificates x),
          (select jsonb_agg(to_jsonb(x) order by agent_id,revision) from sli_agent_policy_history x),
          (select jsonb_agg(to_jsonb(x) order by id,version) from sli_agent_policy_templates x),
          (select jsonb_agg(to_jsonb(x) order by id) from sli_agent_audit x))::text
        """,db,tx);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes((string)(await q.ExecuteScalarAsync(ct))!)));
    }
    private static string FindVector([System.Runtime.CompilerServices.CallerFilePath]string path="")
    {for(var d=new FileInfo(path).Directory;d is not null;d=d.Parent){string f=Path.Combine(d.FullName,"server-dotnet/tests/vectors/agent-groups.json");if(File.Exists(f))return f;}throw new IOException();}
    private sealed class FailAudit:IAgentControlAudit
    {public Task AppendAsync(NpgsqlConnection db,NpgsqlTransaction tx,string action,string actor,string target,object details,CancellationToken ct)=>throw new InvalidOperationException("synthetic group audit failure");}
    private static CertificateRequest CaRequest(string name,ECDsa key,int path)
    {var r=new CertificateRequest(name,key,HashAlgorithmName.SHA256);r.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,true,path,true));r.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign|X509KeyUsageFlags.CrlSign,true));r.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection{new Oid("1.3.6.1.5.5.7.3.2")},false));return r;}
}
