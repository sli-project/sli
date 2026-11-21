using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Certificates;
using Sli.Server.Agents.ClientControl;
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Ingress;
using Sli.Server.Agents.Registry;
using Sli.Server.Agents.SnapshotPublication;
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
    [InlineData("enrollment")]
    [InlineData("startup")]
    [InlineData("identity_report")]
    [InlineData("known_domain")]
    [InlineData("legacy_fqdn")]
    public async Task Dc_source_and_snapshot_policy_are_provisioned_and_retained_packets_import(string path)
    {
        var ct = TestContext.Current.CancellationToken;
        const string hostname = "LAB-DC01";
        string computer = path == "legacy_fqdn" ? "LAB-DC01.example.test" : hostname;
        const string sid = "S-1-5-21-100000001-200000002-300000003";
        var host = Guid.NewGuid();
        using var environment = new SemanticProducerPostgresTests.Admission();
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(owner, "update plugin_installations_v1 set desired_activation='enabled_manual' where plugin_id='sli.ad'", ct);
        if (path == "known_domain")
            await PostCollectionPostgres.Sql(owner, "update domains set domain_sid='S-1-5-21-100000001-200000002-300000003' where fqdn='example.test'", ct);
        if (path == "legacy_fqdn")
            await PostCollectionPostgres.Sql(owner, "update domains set fqdn='unregistered.example.test' where fqdn='example.test'", ct);
        await AgentInboxDeferralTests.AuthorizeStorageAsync(owner, fixture.Pg.Root, ct);
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root = CaRequest("CN=synthetic root", rootKey, 1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var issuerPublic = CaRequest("CN=synthetic issuer", issuerKey, 0)
            .Create(root, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(16));
        using var issuer = issuerPublic.CopyWithPrivateKey(issuerKey);
        var ca = new AgentIssuingCa(root, issuer);
        var identity = new AgentIdentityService(ca);
        var enrollment = new AgentEnrollmentService(ca, identity);
        var clients = new AgentClientControlService(new AgentControlAudit(), TimeProvider.System);
        var report = new JsonObject { ["machine_role"] = "domain_controller", ["reported_hostname"] = computer,
            ["domain_dns"] = "example.test", ["forest_dns"] = "example.test", ["domain_sid"] = sid };
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256);
        string token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var connections = new Connections(fixture.Dsn("adlog_user"));
        await using var app = await connections.OpenAsync(ct);
        JsonObject enrolled;
        await using (var tx = await app.BeginTransactionAsync(ct))
        {
            await using var grant = new NpgsqlCommand("""
                insert into sli_agent_console_tokens(id,token_hash,created_at,expires_at,host_limit,remaining)
                values(@id,@hash,statement_timestamp(),statement_timestamp()+interval '15 minutes',1,1)
                """, app, tx);
            grant.Parameters.AddWithValue("id", Guid.NewGuid());
            grant.Parameters.AddWithValue("hash", Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(token))));
            await grant.ExecuteNonQueryAsync(ct);
            var request = path == "enrollment" ? report.DeepClone().AsObject() : new JsonObject {
                ["machine_role"] = "domain_controller", ["reported_hostname"] = computer };
            request["token"] = token;
            request["csr_pem"] = csr.CreateSigningRequestPem();
            enrolled = await enrollment.EnrollAsync(app, tx, request, ct);
            await tx.CommitAsync(ct);
        }
        var agent = Guid.Parse((string)enrolled["agent_id"]!);
        int packets = path == "enrollment" ? 1 : 3;
        await using (var tx = await owner.BeginTransactionAsync(ct))
        {
            for (int i = 1; i <= packets; i++)
            {
                var sample = AgentInboxDeferralTests.Sample(agent, host, computer, i, policyRevision: "2");
                await AgentInboxDeferralTests.InsertAsync(owner, tx, sample, i, ct);
            }
            await tx.CommitAsync(ct);
        }
        await using var runtime = DirectAdDcRuntime.TryCreate(name => name == "ADLOG_STORAGE_V2_WORKER_DSN" ? fixture.Dsn("sli_storage_login") : null,
            _ => throw new InvalidOperationException(), Path.Combine(PostCollectionPostgres.Repository(), "config/event_catalog.json"));
        Assert.NotNull(runtime);
        var consumer = new AgentWorkstationInboxConsumer(connections, runtime);
        if (path != "enrollment")
        {
            var held = await consumer.RunOnceAsync(1, ct);
            Assert.Equal(0, held.Imported);
            Assert.Equal(1, held.PendingReasons[AdDcProjectionFailure.SourceNotConfigured]);
            Assert.Equal(packets - 1, held.Skipped);
        }
        if (path == "startup")
        {
            // This inventory was verified before the upgrade, independently of the agent's report.
            await using var inventory = new NpgsqlCommand("""
                update domains set domain_sid=@sid where fqdn='example.test';
                insert into servers(domain_id,hostname,fqdn,role)
                select id,@host,'lab-dc01.example.test','domain_controller' from domains where fqdn='example.test'
                """, owner);
            inventory.Parameters.AddWithValue("host", computer);
            inventory.Parameters.AddWithValue("sid", sid);
            await inventory.ExecuteNonQueryAsync(ct);
            await ReconcileStartup();
        }
        if (path == "legacy_fqdn")
        {
            await PostCollectionPostgres.Sql(owner, """
                update domains set fqdn='example.test',domain_sid='S-1-5-21-100000001-200000002-300000003'
                where fqdn='unregistered.example.test';
                update sli_agent_certificates set revoked_at=clock_timestamp();
                """, ct);
            await ReconcileSources();
            await using (var count = new NpgsqlCommand("select count(*) from servers", owner))
                Assert.Equal(0L, await count.ExecuteScalarAsync(ct));
            await PostCollectionPostgres.Sql(owner, "update sli_agent_certificates set revoked_at=null", ct);
            await ReconcileSources();
        }
        if (path is "identity_report" or "known_domain")
        {
            using var cert = X509Certificate2.CreateFromPem((string)enrolled["certificate_pem"]!);
            await using (var tx = await app.BeginTransactionAsync(ct))
            {
                var authenticated = await identity.AuthenticateAsync(app, tx, cert, false, ct);
                var assignment = await clients.CheckInAsync(app, tx, authenticated, ct);
                Assert.True((bool)assignment["dc_identity_required"]!);
                await tx.CommitAsync(ct);
            }
            var wrongComputer = report.DeepClone().AsObject();
            wrongComputer["reported_hostname"] = "LAB-DC02";
            await ReportIdentity(wrongComputer);
            Assert.Equal(0, (await consumer.RunOnceAsync(1, ct)).Imported);
            if (path == "identity_report")
            {
                var dnsOnly = report.DeepClone().AsObject();
                dnsOnly.Remove("domain_sid");
                await ReportIdentity(dnsOnly);
                await using var intermediate = new NpgsqlCommand("""
                    select (select count(*) from servers where fqdn='lab-dc01.example.test'),
                           (select count(*) from sli_agent_snapshot_bindings)
                    """, owner);
                await using var row = await intermediate.ExecuteReaderAsync(ct);
                Assert.True(await row.ReadAsync(ct));
                Assert.Equal(1L, row.GetInt64(0));
                Assert.Equal(0L, row.GetInt64(1));
            }
            await ReportIdentity(report);

            async Task ReportIdentity(JsonObject dcIdentity)
            {
                await using var tx = await app.BeginTransactionAsync(ct);
                await AgentEnrollmentService.LockRegistrationAsync(app, tx, ct);
                var authenticated = await identity.AuthenticateAsync(app, tx, cert, false, ct);
                await clients.ReportAsync(app, tx, authenticated, new JsonObject { ["applied_policy_revision"] = 2,
                    ["collection_state"] = "active", ["dc_identity"] = dcIdentity.DeepClone() }, ct);
                await tx.CommitAsync(ct);
            }
        }

        await using var configured = new NpgsqlCommand("""
            select t.connect_address,t.hostname,d.domain_sid,
                (select count(*) from sli_agent_snapshot_policies p where p.agent_id=@agent and p.module_id='sli.ad-snapshot' and p.enabled),
                (select policy_revision from sli_agents where id=@agent),
                (select policy_revision from sli_agent_module_bindings where agent_id=@agent and module_id='sli.windows.ad-dc'),
                (select count(*) from sli_agent_audit where action='module_assign' and target=@agent::text
                    and details->>'source'='agent_reported')
            from domain_controller_targets t join domains d on d.id=t.domain_id
            """, app);
        configured.Parameters.AddWithValue("agent", agent);
        await ReconcileSources();
        await ReconcileStartup();
        await using (var row = await configured.ExecuteReaderAsync(ct))
        {
            Assert.True(await row.ReadAsync(ct));
            Assert.Equal("lab-dc01.example.test", row.GetString(0));
            Assert.Equal(hostname, row.GetString(1));
            Assert.Equal(sid, row.GetString(2));
            Assert.Equal(1L, row.GetInt64(3));
            Assert.Equal(path == "enrollment" ? 2L : 3L, row.GetInt64(4));
            Assert.Equal("2", row.GetString(5));
            Assert.Equal(path == "startup" ? 0L : 1L, row.GetInt64(6));
            Assert.False(await row.ReadAsync(ct));
        }
        if (path == "enrollment") await PublishFirstSnapshot();
        int imported = 0;
        if (path != "enrollment")
        {
            var result = await consumer.RunOnceAsync(1, ct);
            Assert.Equal(1, result.Imported);
            await using var first = new NpgsqlCommand("select (envelope->>'sequence')::bigint from sli_agent_packet_inbox where imported_at is not null", owner);
            Assert.Equal(1L, await first.ExecuteScalarAsync(ct));
            imported += result.Imported;
        }
        for (int i = 0; i < 2; i++)
        {
            var result = await consumer.RunOnceAsync(16, ct);
            Assert.Empty(result.PendingReasons);
            Assert.Equal(0, result.Quarantined);
            imported += result.Imported;
        }
        Assert.Equal(packets, imported);
        await using var remaining = new NpgsqlCommand("select count(*) from sli_agent_packet_inbox where imported_at is null", owner);
        Assert.Equal(0L, await remaining.ExecuteScalarAsync(ct));

        async Task ReconcileStartup()
        {
            await using var tx = await app.BeginTransactionAsync(ct);
            await AgentEnrollmentService.ReconcileRegistrationsAsync(app, tx, ct);
            await tx.CommitAsync(ct);
        }

        async Task ReconcileSources()
        {
            await using var tx = await app.BeginTransactionAsync(ct);
            await AgentEnrollmentService.ReconcileDcSourcesAsync(app, tx, null, ct);
            await tx.CommitAsync(ct);
        }

        async Task PublishFirstSnapshot()
        {
            using var cert = X509Certificate2.CreateFromPem((string)enrolled["certificate_pem"]!);
            var vector = JsonNode.Parse(File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(),
                "server-dotnet/tests/Sli.Server.Tests/Agents/ad-publication-source-vector.json"))
                .Replace("directory.invalid", "example.test").Replace("DC=directory,DC=invalid", "DC=example,DC=test")
                .Replace("host.invalid", "lab-dc01.example.test").Replace("object-10001", "lab-dc01"))!;
            var now = Iso8601.ParseUtc("2026-10-08T12:00:00+00:00");
            var clock = new SnapshotClock(now);
            var ingress = new AgentPacketService(clock, new AgentInboxLimits(4096, 268435456, 32768, 2147483648,
                65536, 4294967296, 17179869184), new AgentIngressDiagnostics(fixture.Pg.Root,
                NullLogger<AgentIngressDiagnostics>.Instance, clock));
            var stream = new SnapshotStream(fixture.Pg.Root, SnapshotPolicy.Ad, new PhysicalDurableFiles());
            Guid cycle;
            await using (var tx = await app.BeginTransactionAsync(ct))
            {
                var authenticated = await identity.AuthenticateAsync(app, tx, cert, false, ct);
                var response = await clients.CheckInAsync(app, tx, authenticated, ct);
                var assignment = response["assigned_modules"]!.AsArray().Single(m => (string?)m?["module_id"] == SnapshotPolicy.Ad)!;
                var policy = SnapshotPolicy.Parse(SnapshotPolicy.Ad, assignment["config"]!.AsObject());
                var state = stream.Begin(policy, now)!;
                cycle = Guid.Parse((string)state["cycle_id"]!);
                var families = policy.Families.ToDictionary(family => family, family =>
                {
                    var data = vector["families"]![family]!.AsObject();
                    data.Remove("bundle_sha256");
                    return new SnapshotFamily(data, data[family == "computers_v6" ? "objects" : "records"]!.AsArray().Count);
                });
                stream.Freeze(state, families);
                CapturedPosition? captured = null;
                var signer = new EcdsaPacketSigner(key);
                long sequence = 0;
                while (stream.NextSample(captured) is { } sample)
                {
                    var packet = Packets.Make(signer, agent.ToString("D"), ++sequence, sample, now);
                    var receipt = await ingress.ReceiveAsync(app, tx, authenticated, cert, packet.ToJson(), ct);
                    Assert.Equal("committed", (string?)receipt["status"]);
                    captured = new CapturedPosition(policy.SourceId, sample.CursorAfter);
                }
                Assert.True(sequence > 0);
                await tx.CommitAsync(ct);
            }
            await using var worker = new NpgsqlConnection(fixture.Dsn("sli_context_login"));
            await worker.OpenAsync(ct);
            await PostCollectionPostgres.Sql(worker, "set role adlog_context_worker", ct);
            var publication = await AdSnapshotPublisher.ProcessAsync(worker, cycle, ct);
            Assert.True(publication.PublicationState == "published", publication.PendingReason);
            await ReconcileSources();
            await using var check = new NpgsqlCommand("""
                select (select count(*) from servers where lower(fqdn)='lab-dc01.example.test'),
                       (select count(*) from computers_v6_source_snapshots)
                """, owner);
            await using var row = await check.ExecuteReaderAsync(ct);
            Assert.True(await row.ReadAsync(ct));
            Assert.Equal(1L, row.GetInt64(0));
            Assert.Equal(1L, row.GetInt64(1));
        }
    }

    private sealed class SnapshotClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
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
