using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Certificates;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Registry;
using Sli.Server.Infrastructure;
using Sli.Server.InstallationSetup;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Semantic;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Agents;

[Collection("Semantic producer environment")]
public sealed class PasswordDomainAutoPostgresTests
{
    private static string Migration => Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/371_password_domain_auto.sql");
    private sealed class Connections(string dsn) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        { var db=new NpgsqlConnection(dsn); await db.OpenAsync(ct); return db; }
    }

    [Theory]
    [InlineData("example.test", "example.test", true, null)]
    [InlineData("child.forest.example.test", "forest.example.test", true, null)]
    [InlineData("example.test", "other.example.test", false, null)]
    [InlineData(null, null, false, null)]
    [InlineData("example.test", "example.test", true, "S-1-5-21-100000001-200000002-300000003")]
    [InlineData("example.test", "example.test", false, "invalid-sid")]
    public async Task Console_enrollment_uses_directory_dns_names_without_a_preconfigured_controller(
        string? dns, string? forest, bool configured, string? sid)
    {
        var ct = TestContext.Current.CancellationToken;
        using var environment = new SemanticProducerPostgresTests.Admission();
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root = CaRequest("CN=synthetic root", rootKey, 1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var issuerPublic = CaRequest("CN=synthetic issuer", issuerKey, 0)
            .Create(root, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(16));
        using var issuer = issuerPublic.CopyWithPrivateKey(issuerKey);
        var ca = new AgentIssuingCa(root, issuer);
        var enrollment = new AgentEnrollmentService(ca, new AgentIdentityService(ca));

        const string computer = "LAB-DC01";
        var host = Guid.NewGuid();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256);
        string token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        await using var app = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await app.OpenAsync(ct);
        await using var tx = await app.BeginTransactionAsync(ct);
        await using (var grant = new NpgsqlCommand("""
            insert into sli_agent_console_tokens(id,token_hash,created_at,expires_at,host_limit,remaining)
            values(@id,@hash,statement_timestamp(),statement_timestamp()+interval '15 minutes',1,1)
            """, app, tx))
        {
            grant.Parameters.AddWithValue("id", Guid.NewGuid());
            grant.Parameters.AddWithValue("hash", Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(token))));
            await grant.ExecuteNonQueryAsync(ct);
        }
        var request = new JsonObject
        {
            ["token"] = token, ["csr_pem"] = csr.CreateSigningRequestPem(),
            ["reported_hostname"] = computer, ["machine_role"] = "domain_controller",
        };
        if (dns is not null) request["domain_dns"] = dns.ToUpperInvariant();
        if (forest is not null) request["forest_dns"] = forest.ToUpperInvariant();
        if (sid is not null) request["domain_sid"] = sid;
        var result = await enrollment.EnrollAsync(app, tx, request, ct);
        var id = Guid.Parse((string)result["agent_id"]!);
        var dc = await AgentEnrollmentService.ResolveDcAsync(app, tx, computer, ct, id);
        await tx.CommitAsync(ct);

        await using (var snapshots = new NpgsqlCommand("""
            select exists(select 1 from sli_agent_snapshot_bindings where agent_id=@agent and enabled)
            """, app))
        {
            snapshots.Parameters.AddWithValue("agent", id);
            Assert.Equal(configured && sid is not null, Assert.IsType<bool>(await snapshots.ExecuteScalarAsync(ct)));
        }

        var health = await SetupCollectionHealth.ReadAsync(new InstallationDatabase(new Connections(fixture.Dsn("adlog_user"))), ct);
        Assert.Null(health["diagnostics"]);
        var agent = Assert.Single(health["items"]!.AsArray())!;
        Assert.Equal(configured ? null : true, (bool?)agent["password_domain_required"]);
        if (!configured)
        {
            Assert.Null(dc);
            return;
        }
        Assert.NotNull(dc);
        await using (var domain = new NpgsqlCommand("""
            select d.id,d.fqdn,f.name from sli_agent_module_bindings b
            join domains d on d.id=b.password_detection_domain_id join forests f on f.id=d.forest_id
            where b.agent_id=@agent and b.module_id='sli.windows.ad-dc'
            """, app))
        {
            domain.Parameters.AddWithValue("agent", id);
            await using var row = await domain.ExecuteReaderAsync(ct);
            Assert.True(await row.ReadAsync(ct));
            Assert.Equal(dc.Value.Domain, row.GetInt64(0));
            Assert.Equal(dns, row.GetString(1));
            Assert.Equal(forest, row.GetString(2));
        }
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var events = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct, hostName: computer,
            eventKinds: Enumerable.Repeat(4625, 10).ToArray(), registered: (id, host, dc.Value.Server, dc.Value.Domain));
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, events, ct);
        await using var runtime = PasswordProducerRuntime.Create(
            name => name == "ADLOG_SEMANTIC_WORKER_DSN" ? fixture.Dsn("sli_semantic_login") : null, _ => throw new InvalidOperationException());
        await using var worker = await runtime.OpenAsync(ct);
        await using var source = new NpgsqlCommand("""
            select source->'scope' from public.default_detection_sources() where source#>>'{scope,source_instance_id}'=@host
            """, worker);
        source.Parameters.AddWithValue("host", host.ToString());
        var scope = PasswordScope.Read(JsonNode.Parse(Assert.IsType<string>(await source.ExecuteScalarAsync(ct))));
        var detection = await new PasswordProducer().RunAsync(worker, new PasswordRule(scope), ct);
        Assert.False(detection.Failed, detection.Diagnostic?.ToJsonString());
        Assert.True(detection.Jobs > 0);
        await using var checkpoint = new NpgsqlCommand("select distinct owner_domain_id from semantic_password_checkpoints", owner);
        Assert.Equal(dc.Value.Domain, await checkpoint.ExecuteScalarAsync(ct));
    }

    [Fact]
    public async Task Dc_reenrollment_automatically_enables_password_production_without_operator_configuration()
    {
        var ct=TestContext.Current.CancellationToken;
        using var environment=new SemanticProducerPostgresTests.Admission();
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(owner,"insert into servers(id,domain_id,hostname,fqdn,role) values(900001,1,'dc.example.test','dc.example.test','domain_controller')",ct);
        using var rootKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root=CaRequest("CN=synthetic root",rootKey,1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddYears(2));
        using var issuerKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var issuerPublic=CaRequest("CN=synthetic issuer",issuerKey,0).Create(root,DateTimeOffset.UtcNow.AddHours(-1),DateTimeOffset.UtcNow.AddYears(1),RandomNumberGenerator.GetBytes(16));
        using var issuer=issuerPublic.CopyWithPrivateKey(issuerKey);
        var ca=new AgentIssuingCa(root,issuer);
        var enrollment=new AgentEnrollmentService(ca,new AgentIdentityService(ca));
        await using var app=new NpgsqlConnection(fixture.Dsn("adlog_user")); await app.OpenAsync(ct);
        async Task<(Guid Agent,Guid Host,long Server,long Domain)> Enroll()
        {
            using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var host=Guid.NewGuid(); var tokenId=Guid.NewGuid();
            var csr=new CertificateRequest($"CN={host}",key,HashAlgorithmName.SHA256);
            string token=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+','-').Replace('/','_');
            await using var tx=await app.BeginTransactionAsync(ct);
            await using(var seed=new NpgsqlCommand("""
                insert into sli_agent_enrollment_tokens(id,token_hash,host_id,key_fingerprint,created_at,expires_at)
                values(@id,@hash,@host,@key,clock_timestamp(),clock_timestamp()+interval '15 minutes');
                insert into sli_agent_audit(action,actor,target,details)
                values('token_create','synthetic',@target,'{"registration_host_name":"dc.example.test"}');
                """,app,tx)) {
                seed.Parameters.AddWithValue("id",tokenId); seed.Parameters.AddWithValue("target",tokenId.ToString());
                seed.Parameters.AddWithValue("hash",Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(token))));
                seed.Parameters.AddWithValue("host",host); seed.Parameters.AddWithValue("key",Convert.ToHexStringLower(SHA256.HashData(csr.PublicKey.ExportSubjectPublicKeyInfo())));
                await seed.ExecuteNonQueryAsync(ct);
            }
            var result=await enrollment.EnrollAsync(app,tx,new JsonObject { ["token"]=token,["csr_pem"]=csr.CreateSigningRequestPem(),
                ["reported_hostname"]="DC",["machine_role"]="domain_controller",["agent_version"]="1.1.0" },ct);
            var id=Guid.Parse((string)result["agent_id"]!);
            await tx.CommitAsync(ct);
            await using var binding=new NpgsqlCommand("select password_detection_domain_id from sli_agent_module_bindings where agent_id=@id and module_id='sli.windows.ad-dc'",app);
            binding.Parameters.AddWithValue("id",id); Assert.Equal(1L,await binding.ExecuteScalarAsync(ct));
            return (id,host,900001,1);
        }
        var old=await Enroll(); var current=await Enroll();
        await using(var retired=new NpgsqlCommand("select status from sli_agents where id=@id",app)) {
            retired.Parameters.AddWithValue("id",old.Agent); Assert.Equal("replaced",await retired.ExecuteScalarAsync(ct));
        }
        var rows=await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,eventKinds:Enumerable.Repeat(4625,10).Concat(Enumerable.Repeat(4776,10)).ToArray(),registered:current);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await using var runtime=PasswordProducerRuntime.Create(n=>n=="ADLOG_SEMANTIC_WORKER_DSN"?fixture.Dsn("sli_semantic_login"):null,_=>throw new InvalidOperationException());
        await using var worker=await runtime.OpenAsync(ct);
        await using var source=new NpgsqlCommand("select source->'scope' from public.default_detection_sources() where source#>>'{scope,source_instance_id}'=@host",worker);
        source.Parameters.AddWithValue("host",current.Host.ToString());
        var scope=PasswordScope.Read(JsonNode.Parse((string)(await source.ExecuteScalarAsync(ct))!));
        await using(var ready=new NpgsqlCommand("select public.password_source_ready_v314(@s::jsonb)",worker)) {
            ready.Parameters.AddWithValue("s",scope.Document.ToJsonString()); Assert.Equal(true,await ready.ExecuteScalarAsync(ct));
        }
        var brute=await new PasswordProducer().RunAsync(worker,new PasswordRule(scope),ct);
        Assert.False(brute.Failed,brute.Diagnostic?.ToJsonString()); Assert.True(brute.Jobs>0);
        var spray=await new PasswordProducer().RunAsync(worker,new PasswordRule(scope,"spray"),ct);
        Assert.False(spray.Failed,spray.Diagnostic?.ToJsonString()); Assert.Equal("committed",spray.Status);
        await using(var tx=await worker.BeginTransactionAsync(ct)) {
            var denied=await Assert.ThrowsAsync<PostgresException>(async ()=> {
                await using var forged=new NpgsqlCommand("select public.password_source_ready_v314(@s::jsonb)",worker,tx);
                forged.Parameters.AddWithValue("s",(scope with { SourceGeneration="unbound" }).Document.ToJsonString());
                await forged.ExecuteScalarAsync(ct);
            });
            Assert.Equal("42501",denied.SqlState); await tx.RollbackAsync(ct);
        }
    }

    [Fact]
    public async Task Upgrade_repairs_existing_binding_and_rollback_preserves_ownership_and_events()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct,throughVersion:370);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct);
        await PostCollectionPostgres.Sql(owner,"""
            with scope as (
                select jsonb_build_object('installation_id',installation_id::text,'plugin_id','sli.windows.ad-dc',
                    'source_instance_id',b.source_instance_id,'source_generation',b.source_instance_id,'collection_scope_id','') s
                from semantic_default_installation cross join sli_agent_module_bindings b
            ), execution as (select s,public.password_v2_coverage_execution(s,'qw.password-brute-force') x from scope)
            insert into semantic_password_checkpoints(scope_digest,pin,scope_json,execution_json)
                select public.password_v2_scope_key(s),encode(sha256(convert_to(public.password_v2_json_compact(x),'UTF8')),'hex'),s,x from execution;
            """,ct);
        await fixture.Pg.ApplyFileAsync(Migration,null,ct);
        async Task AssertOwner() {
            await using var query=new NpgsqlCommand("select password_detection_domain_id from sli_agent_module_bindings where agent_id=@id",owner);
            query.Parameters.AddWithValue("id",ShortEventAdmissionPostgresTests.Agent);
            Assert.Equal(1L,await query.ExecuteScalarAsync(ct));
            await using var checkpoint=new NpgsqlCommand("select owner_domain_id from semantic_password_checkpoints",owner);
            Assert.Equal(1L,await checkpoint.ExecuteScalarAsync(ct));
        }
        await AssertOwner();
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(Migration,".rollback.sql"),null,ct);
        await AssertOwner();
        await using(var events=new NpgsqlCommand("select exists(select 1 from sli_agent_packet_inbox)",owner)) Assert.Equal(true,await events.ExecuteScalarAsync(ct));
        await fixture.Pg.ApplyFileAsync(Migration,null,ct); await AssertOwner();
        // The historical upgrade/rollback above runs at 371. Exercise today's
        // application only after installing its subsequent schema dependencies.
        foreach(var migration in MigrationDirectory.Read(372))
            await fixture.Pg.ApplyFileAsync(migration.Path,null,ct);
        // The operator's normal module-assignment path also fills ownership;
        // it must not require a separate password-domain request.
        await using(var app=new NpgsqlConnection(fixture.Dsn("adlog_user"))) {
            await app.OpenAsync(ct); await using var tx=await app.BeginTransactionAsync(ct);
            var id=Guid.NewGuid(); var host=Guid.NewGuid();
            await using(var seed=new NpgsqlCommand("insert into sli_agents(id,host_id,key_fingerprint,registration_host_name) values(@id,@host,repeat('d',64),'dc.example.test')",app,tx)) {
                seed.Parameters.AddWithValue("id",id); seed.Parameters.AddWithValue("host",host); await seed.ExecuteNonQueryAsync(ct);
            }
            var config=AgentEnrollmentService.DefaultModules(null,"domain_controller",host,"dc.example.test",null)[0]!["config"]!.DeepClone();
            await new AgentModuleAssignmentService(new AgentControlAudit()).AssignAsync(app,tx,
                JsonSerializer.SerializeToElement(new { agent_id=id,module_id="sli.windows.ad-dc",enabled=true,expected_revision=1,config }),"session:1",ct);
            await using var binding=new NpgsqlCommand("select password_detection_domain_id from sli_agent_module_bindings where agent_id=@id",app,tx);
            binding.Parameters.AddWithValue("id",id); Assert.Equal(1L,await binding.ExecuteScalarAsync(ct));
            await tx.RollbackAsync(ct);
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Ambiguous_dc_domain_is_not_chosen_and_is_exposed_to_system_status()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct,throughVersion:370);
        await using var owner=await fixture.Pg.OpenAsync(ct);
        await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct);
        await PostCollectionPostgres.Sql(owner,"""
            insert into domains(forest_id,fqdn) select forest_id,'other.example.test' from domains where fqdn='example.test';
            insert into servers(domain_id,hostname,fqdn,role)
                select id,'dc.example.test','dc.other.example.test','domain_controller' from domains where fqdn='other.example.test';
            """,ct);
        await fixture.Pg.ApplyFileAsync(Migration,null,ct);
        await using(var query=new NpgsqlCommand("select password_detection_domain_id from sli_agent_module_bindings",owner)) Assert.Equal(DBNull.Value,await query.ExecuteScalarAsync(ct));
        var health=await SetupCollectionHealth.ReadAsync(new InstallationDatabase(new Connections(fixture.Dsn("adlog_user"))),ct);
        Assert.Null(health["diagnostics"]);
        var agent=Assert.Single(health["items"]!.AsArray())!;
        Assert.Equal("dc.example.test",(string?)agent["name"]); Assert.Equal(true,(bool?)agent["password_domain_required"]);
        // An explicit registration decision disambiguates the same name.
        await PostCollectionPostgres.Sql(owner,$"insert into sli_agent_audit(action,actor,target,details) values('issue','synthetic','{ShortEventAdmissionPostgresTests.Agent}','{{\"server_id\":900001}}')",ct);
        await using(var app=new NpgsqlConnection(fixture.Dsn("adlog_user"))) {
            await app.OpenAsync(ct); await using var tx=await app.BeginTransactionAsync(ct);
            await AgentModuleAssignmentService.ReconcilePasswordDomainAsync(app,tx,ShortEventAdmissionPostgresTests.Agent,ct);
            await tx.CommitAsync(ct);
        }
        var repaired=await SetupCollectionHealth.ReadAsync(new InstallationDatabase(new Connections(fixture.Dsn("adlog_user"))),ct);
        Assert.Null(Assert.Single(repaired["items"]!.AsArray())!["password_domain_required"]);
        await fixture.AssertNoSqlErrorsAsync(ct);
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
