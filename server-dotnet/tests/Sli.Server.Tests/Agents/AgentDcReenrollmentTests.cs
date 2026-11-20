using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Certificates;
using Sli.Server.Agents.Registry;
using Sli.Server.Storage.Direct;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Ingress;
using Sli.Server.Agents;
using Sli.Agent.Protocol;
using Sli.Server.InstallationSetup;
using Sli.Server.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Sli.Server.Operations;
using System.Text.Json;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentDcReenrollmentTests
{
    private sealed class Connections(string dsn) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        { var db=new NpgsqlConnection(dsn); await db.OpenAsync(ct); return db; }
    }
    private sealed class Clock(DateTimeOffset now) : TimeProvider { public override DateTimeOffset GetUtcNow()=>now; }
    [Fact]
    public async Task Approved_short_name_binds_canonical_dc_and_reenrollment_retires_previous_transport()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var admin=new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(ct);
        await PostCollectionPostgres.Sql(admin,"""
            update domains set domain_sid='S-1-5-21-100000001-200000002-300000003' where fqdn='example.test';
            insert into servers(domain_id,hostname,fqdn,role)
            select id,'dc.example.test','dc.example.test','domain_controller' from domains where fqdn='example.test';
            """,ct);
        using var rootKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root=CaRequest("CN=synthetic root",rootKey,1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddYears(2));
        using var issuerKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var issuerPublic=CaRequest("CN=synthetic issuer",issuerKey,0).Create(root,DateTimeOffset.UtcNow.AddHours(-1),DateTimeOffset.UtcNow.AddYears(1),RandomNumberGenerator.GetBytes(16));
        using var issuer=issuerPublic.CopyWithPrivateKey(issuerKey);
        var ca=new AgentIssuingCa(root,issuer);
        var service=new AgentEnrollmentService(ca,new AgentIdentityService(ca));
        var publicCertificates=new Dictionary<Guid,string>();
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user")); await app.OpenAsync(ct);
        async Task<Guid> Enroll(string approved,string reported,string? version,Guid? claimedHost=null)
        {
            using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256); var host=claimedHost ?? Guid.NewGuid(); var tokenId=Guid.NewGuid();
            var csr=new CertificateRequest($"CN={host}",key,HashAlgorithmName.SHA256);
            string token=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+','-').Replace('/','_');
            await using var tx=await app.BeginTransactionAsync(ct);
            await using(var seed=new NpgsqlCommand("""
                insert into sli_agent_enrollment_tokens(id,token_hash,host_id,key_fingerprint,created_at,expires_at)
                values(@id,@hash,@host,@key,clock_timestamp(),clock_timestamp()+interval '15 minutes');
                insert into sli_agent_audit(action,actor,target,details)
                values('token_create','synthetic',@target,jsonb_build_object('registration_host_name',@name::text));
                """,app,tx)) {
                seed.Parameters.AddWithValue("id",tokenId); seed.Parameters.AddWithValue("target",tokenId.ToString());
                seed.Parameters.AddWithValue("hash",Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(token))));
                seed.Parameters.AddWithValue("host",host); seed.Parameters.AddWithValue("key",Convert.ToHexStringLower(SHA256.HashData(csr.PublicKey.ExportSubjectPublicKeyInfo())));
                seed.Parameters.AddWithValue("name",approved); await seed.ExecuteNonQueryAsync(ct);
            }
            var input=new JsonObject { ["token"]=token,["csr_pem"]=csr.CreateSigningRequestPem(),["reported_hostname"]=reported,["machine_role"]="domain_controller" };
            if(version is not null)input["agent_version"]=version;
            var result=await service.EnrollAsync(app,tx,input,ct);
            if(claimedHost is not null) {
                Assert.Equal("agent_identity_computer_conflict",(string?)result["error"]); await tx.CommitAsync(ct); return Guid.Empty;
            }
            var id=Guid.Parse((string)result["agent_id"]!); publicCertificates[id]=(string)result["certificate_pem"]!;
            await tx.CommitAsync(ct); return id;
        }
        var old=await Enroll("dc.example.test","DC",null);
        await using(var binding=new NpgsqlCommand("select source_name from sli_agent_module_bindings where agent_id=@id and module_id='sli.windows.ad-dc'",app)) {
            binding.Parameters.AddWithValue("id",old); Assert.Equal("dc.example.test",await binding.ExecuteScalarAsync(ct));
        }
        var current=await Enroll("dc","DC.example.test","1.1.0");
        await using(var tx=await app.BeginTransactionAsync(ct)) {
            using var retiredCertificate=X509Certificate2.CreateFromPem(publicCertificates[old]);
            var rejection=await Assert.ThrowsAsync<AgentCertificateException>(()=>new AgentIdentityService(ca).AuthenticateAsync(app,tx,retiredCertificate,false,ct));
            Assert.Equal("agent_certificate_rejected",rejection.Code); await tx.RollbackAsync(ct);
        }
        var older=await Enroll("dc","DC","1.0.0");
        await using(var losing=new NpgsqlCommand("select status from sli_agents where id=@id",app)) {
            losing.Parameters.AddWithValue("id",older); Assert.Equal("replaced",await losing.ExecuteScalarAsync(ct));
        }
        await using(var state=new NpgsqlCommand("""
            select a.status,(select status from sli_agents where id=@current),
                (select count(*) from sli_agent_certificates where agent_id=@old and revoked_at is not null),
                (select details->>'replaced_by' from sli_agent_audit where target=@target and action='disable' order by id desc limit 1)
            from sli_agents a where a.id=@old
            """,app)) {
            state.Parameters.AddWithValue("old",old); state.Parameters.AddWithValue("current",current); state.Parameters.AddWithValue("target",old.ToString());
            await using var reader=await state.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct));
            Assert.Equal("replaced",reader.GetString(0)); Assert.Equal("active",reader.GetString(1)); Assert.Equal(0,reader.GetInt64(2)); Assert.Equal(current.ToString(),reader.GetString(3));
        }
        await PostCollectionPostgres.Sql(admin,"insert into servers(domain_id,hostname,fqdn,role) select id,'other-dc.example.test','other-dc.example.test','domain_controller' from domains where fqdn='example.test'",ct);
        Guid registeredHost;
        await using(var tx=await app.BeginTransactionAsync(ct))
        {
            AgentIdentity identity;
            await using(var read=new NpgsqlCommand("select host_id,key_fingerprint from sli_agents where id=@id for no key update",app,tx)) {
                read.Parameters.AddWithValue("id",current); await using var r=await read.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct));
                identity=new AgentIdentity(current,r.GetGuid(0),r.GetString(1),"active");
                registeredHost=identity.HostId;
            }
            var clone=AgentInboxDeferralTests.Sample(current,identity.HostId,"dc.example.test",3,"other-dc.example.test");
            clone.Payload["context"]!["ad_dc"]!["policy_revision"]="2";
            clone.Payload["context"]!["ad_dc"]!["channels"]!["System"]=true;
            clone.Payload["context"]!["ad_dc"]!["channels"]!["Directory Service"]=true;
            clone.Payload["records"]![0]!["payload"]!["connect_address"]="dc.example.test";
            var envelope=Envelope.Parse(clone.Envelope) with { PolicyRevision="2",PayloadSha256=Packets.Digest(clone.Payload),PayloadBytes=CanonicalJson.Length(clone.Payload) };
            await using(var policy=new NpgsqlCommand("select assigned_modules from sli_agents where id=@id",app,tx)) {
                policy.Parameters.AddWithValue("id",current);
                var assignments=JsonNode.Parse((string)(await policy.ExecuteScalarAsync(ct))!)!.AsArray();
                var config=assignments.OfType<JsonObject>().Single(m=>(string?)m["module_id"]==AgentAdDcValidator.Live)["config"]!.AsObject();
                Assert.Single(AgentAdDcValidator.Validate(envelope,clone.Payload,AgentAdDcValidator.NormalizePolicy(config,false),"dc.example.test"));
            }
            using var cloneKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var cloneCert=new CertificateRequest("CN=synthetic clone",cloneKey,HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(1));
            var packet=new SignedPacket(envelope,clone.Payload,Convert.ToBase64String(new EcdsaPacketSigner(cloneKey).Sign(Packets.SignedMessage(envelope))));
            var clock=new Clock(Iso8601.ParseUtc(envelope.ObservedAtUtc));
            var servicePacket=new AgentPacketService(clock,new AgentInboxLimits(4096,268435456,32768,2147483648,65536,4294967296,17179869184),new AgentIngressDiagnostics(fixture.Pg.Root,NullLogger<AgentIngressDiagnostics>.Instance,clock));
            var receipt=await servicePacket.ReceiveAsync(app,tx,identity,cloneCert,packet.ToJson(),ct);
            Assert.Equal("rejected",(string?)receipt["status"]); Assert.Equal("agent_identity_computer_conflict",(string?)receipt["error_code"]);
            await using var stored=new NpgsqlCommand("select count(*) from sli_agent_receipts where packet_id=@id",app,tx); stored.Parameters.AddWithValue("id",Guid.Parse(envelope.PacketId)); Assert.Equal(0L,await stored.ExecuteScalarAsync(ct));
            await tx.CommitAsync(ct);
        }
        Assert.Equal(Guid.Empty,await Enroll("other-dc.example.test","OTHER-DC","1.1.0",registeredHost));
        await using(var tx=await app.BeginTransactionAsync(ct)) {
            var inventory=await new AgentManagementService(new AgentControlAudit()).ListAgentsAsync(app,tx,null,"synthetic",ct);
            var retired=inventory.GetProperty("items").EnumerateArray().Where(a=>a.GetProperty("status").GetString()=="replaced").ToArray();
            Assert.Equal(2,retired.Length); Assert.All(retired,a=>Assert.Equal("1.1.0",a.GetProperty("replacement_version").GetString()));
            await tx.CommitAsync(ct);
        }
        var health=await SetupCollectionHealth.ReadAsync(new InstallationDatabase(new Connections(fixture.Dsn("adlog_user"))),ct);
        Assert.Null(health["diagnostics"]); Assert.NotEqual("unavailable",(string?)health["state"]);
        var source=Assert.Single(health["items"]!.AsArray()); Assert.Equal("dc.example.test",(string?)source!["name"]);
        Assert.True((bool)source["identity_conflict"]!); Assert.Equal(2,health["replaced_agents"]!.AsArray().Count);
        await PostCollectionPostgres.Sql(admin,"update servers set hostname='renamed-dc.example.test',fqdn='renamed-dc.example.test' where hostname='dc.example.test'",ct);
        var renamedHealth=await SetupCollectionHealth.ReadAsync(new InstallationDatabase(new Connections(fixture.Dsn("adlog_user"))),ct);
        Assert.Equal("renamed-dc.example.test",(string?)Assert.Single(renamedHealth["items"]!.AsArray())!["name"]);
        var renamed=await Enroll("renamed-dc","RENAMED-DC","1.2.0");
        await using(var binding=new NpgsqlCommand("select source_name from sli_agent_module_bindings where agent_id=@id",app)) {
            binding.Parameters.AddWithValue("id",renamed); Assert.Equal("renamed-dc.example.test",await binding.ExecuteScalarAsync(ct));
        }
        var operationAgents=new JsonArray();
        await using(var query=new NpgsqlCommand("select to_jsonb(r)::text from ("+OperationsSql.Agents+") r",app))
        await using(var reader=await query.ExecuteReaderAsync(ct))
            while(await reader.ReadAsync(ct))operationAgents.Add(JsonNode.Parse(reader.GetString(0)));
        var operations=OperationsService.AgentView(operationAgents,new JsonArray(),DateTimeOffset.UtcNow);
        Assert.Equal("renamed-dc.example.test",(string?)Assert.Single(operations["items"]!.AsArray())!["name"]);
        var audit=new AgentControlAudit();
        await using(var tx=await app.BeginTransactionAsync(ct)) {
            var lifecycle=new AgentLifecycleService(new AgentManagementService(audit),audit);
            await lifecycle.RequestRemovalAsync(app,tx,JsonSerializer.SerializeToElement(new { operation_id=Guid.NewGuid(),agent_ids=new[] { old } }),"synthetic",ct);
            await tx.CommitAsync(ct);
        }
        await using(var tx=await app.BeginTransactionAsync(ct)) {
            using var oldCertificate=X509Certificate2.CreateFromPem(publicCertificates[old]);
            var authentication=new AgentIdentityService(ca);
            var removalIdentity=await authentication.AuthenticateRemovalAsync(app,tx,oldCertificate,ct);
            Assert.Equal(old,removalIdentity.Id); Assert.Equal("disabled",removalIdentity.Status);
            var rejection=await Assert.ThrowsAsync<AgentCertificateException>(()=>authentication.AuthenticateAsync(app,tx,oldCertificate,false,ct));
            Assert.Equal("agent_certificate_rejected",rejection.Code);
            await tx.RollbackAsync(ct);
        }
        await using(var recovery=new NpgsqlCommand("""
            update sli_agents set rights_probe=jsonb_set(rights_probe,'{certificate_reissue_required}','true'::jsonb) where id=@id;
            update sli_agent_certificates set revoked_at=clock_timestamp() where agent_id=@id;
            """,app))
        { recovery.Parameters.AddWithValue("id",older); await recovery.ExecuteNonQueryAsync(ct); }
        var stale=await Enroll("renamed-dc","RENAMED-DC","2.0.0");
        var recoveredHealth=await SetupCollectionHealth.ReadAsync(new InstallationDatabase(new Connections(fixture.Dsn("adlog_user"))),ct);
        var recoveredRow=Assert.Single(recoveredHealth["replaced_agents"]!.AsArray(),a=>(string?)a!["id"]==older.ToString());
        Assert.False((bool)recoveredRow!["certificate_reissue_required"]!);
        await using(var certificate=new NpgsqlCommand("select revoked_at is not null from sli_agent_certificates where agent_id=@id",app))
        { certificate.Parameters.AddWithValue("id",older); Assert.Equal(true,await certificate.ExecuteScalarAsync(ct)); }
        await using(var contact=new NpgsqlCommand("update sli_agents set last_seen=clock_timestamp()-interval '1 day' where id=@id",app))
        { contact.Parameters.AddWithValue("id",stale); await contact.ExecuteNonQueryAsync(ct); }
        var reinstalled=await Enroll("renamed-dc","RENAMED-DC","1.3.0");
        await using(var state=new NpgsqlCommand("select status,(select status from sli_agents where id=@current),(select count(*) from sli_agent_certificates where agent_id=@old and revoked_at is not null) from sli_agents where id=@old",app))
        {
            state.Parameters.AddWithValue("old",stale); state.Parameters.AddWithValue("current",reinstalled);
            await using var row=await state.ExecuteReaderAsync(ct); Assert.True(await row.ReadAsync(ct));
            Assert.Equal("replaced",row.GetString(0)); Assert.Equal("active",row.GetString(1)); Assert.Equal(0L,row.GetInt64(2));
        }
    }

    [Theory]
    [InlineData("DC")]
    [InlineData("DC.EXAMPLE.TEST")]
    public async Task Import_resolves_aliases_but_refuses_ambiguous_short_names(string name)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db,"""
            insert into servers(domain_id,hostname,fqdn,role) select id,'dc.example.test','dc.example.test','domain_controller' from domains where fqdn='example.test';
            """,ct);
        await using var tx=await db.BeginTransactionAsync(ct);
        var source=await DirectAdDcPacket.SourceAsync(db,tx,name,ct); Assert.True(source.Server>0);
        await using(var second=new NpgsqlCommand("insert into servers(domain_id,hostname,fqdn,role) select id,'dc.other.example.test','dc.other.example.test','domain_controller' from domains where fqdn='example.test'",db,tx)) await second.ExecuteNonQueryAsync(ct);
        var error=await Assert.ThrowsAsync<InvalidOperationException>(()=>DirectAdDcPacket.SourceAsync(db,tx,"dc",ct));
        Assert.Equal("agent_ad_dc_source_not_configured",error.Message);
        Assert.Equal(source,await DirectAdDcPacket.SourceAsync(db,tx,"DC.EXAMPLE.TEST",ct));
        await tx.RollbackAsync(ct);
    }

    private static CertificateRequest CaRequest(string name,ECDsa key,int path)
    {
        var request=new CertificateRequest(name,key,HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,true,path,true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign|X509KeyUsageFlags.CrlSign,true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") },false));
        return request;
    }
}
