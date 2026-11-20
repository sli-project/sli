using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Certificates;
using Sli.Server.Agents.Registry;
using Sli.Server.Tests.Integration;
using Xunit;
using Microsoft.Extensions.Configuration;
using System.Text.Json;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.ClientControl;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Sli.Server.Tests.Agents;

public class AgentEnrollmentTests
{
    [Fact]
    public async Task Agent_command_denies_non_root_before_loading_configuration()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        Assert.Equal(1, await AgentCommandConsole.RunAsync([], false, output, error));
        Assert.Empty(output.ToString());
        Assert.Equal("host_root_required", error.ToString().Trim());
    }

    [Theory]
    [InlineData("https://agents.example.test:8443", "https://agents.example.test:8443/")]
    [InlineData("https://branch.dc.example.test", "https://branch.dc.example.test/")]
    [InlineData("https://192.0.2.40:8443", "https://192.0.2.40:8443/")]
    [InlineData("https://[2001:db8::40]:8443", "https://[2001:db8::40]:8443/")]
    [InlineData("http://agents.example.test", null)]
    [InlineData("https://cn.example.test", null)]
    [InlineData("https://missing.example.test", null)]
    [InlineData("https://nested.branch.dc.example.test", null)]
    [InlineData("https://192.0.2.41", null)]
    [InlineData("https://agents.example.test/path/..", null)]
    [InlineData("https://agents.example.test:0", null)]
    [InlineData("https://user@agents.example.test", null)]
    public void Console_addresses_require_https_and_a_certificate_san(string address, string? expected)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=cn.example.test", key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("agents.example.test");
        san.AddDnsName("*.dc.example.test");
        san.AddIpAddress(IPAddress.Parse("192.0.2.40"));
        san.AddIpAddress(IPAddress.Parse("2001:db8::40"));
        request.CertificateExtensions.Add(san.Build());
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        if (expected is not null)
            Assert.Equal(expected, AgentConsolePackage.ValidateOrigin(address, certificate).AbsoluteUri);
        else
        {
            var error = Assert.Throws<AgentControlException>(() => AgentConsolePackage.ValidateOrigin(address, certificate));
            Assert.Equal("invalid_agent_console_server_url", error.Message);
            Assert.Equal(new[] { "agents.example.test", "*.dc.example.test", "192.0.2.40", "2001:db8::40" }, error.AllowedHosts);
        }
    }

    [Fact]
    public async Task Console_token_binds_first_keys_and_rejects_reuse_expiry_and_revocation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 389);
        var migration = MigrationDirectory.Read(390).Single(item => item.Version == 390).Path;
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await using (var admin = new NpgsqlConnection(fixture.Pg.ConnectionString))
        {
            await admin.OpenAsync(ct);
            await PostCollectionPostgres.Sql(admin, """
                insert into servers(domain_id,hostname,fqdn,role)
                select id,'fixture.example.test','fixture.example.test','domain_controller' from domains where fqdn='example.test';
                """, ct);
        }
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root = CaRequest("CN=console test root", rootKey, 1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var pub = CaRequest("CN=console test issuer", issuerKey, 0).Create(root, DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(16));
        using var ca = new AgentIssuingCa(new X509Certificate2(root), pub.CopyWithPrivateKey(issuerKey));
        var service = new AgentEnrollmentService(ca, new AgentIdentityService(ca));
        var management = new AgentManagementService(new AgentControlAudit());
        string caPath = Path.Combine(fixture.Pg.Root, "fixture-ca.crt");
        string certificatePath = Path.Combine(fixture.Pg.Root, "fixture-server.crt");
        string msiPath = Path.Combine(fixture.Pg.Root, "fixture.msi");
        await File.WriteAllTextAsync(caPath, root.ExportCertificatePem(), ct);
        using var serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=sli.example.test", serverKey, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("sli.example.test");
        san.AddIpAddress(IPAddress.Parse("192.0.2.40"));
        request.CertificateExtensions.Add(san.Build());
        using var certificate = request.Create(root, DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(16));
        await File.WriteAllTextAsync(certificatePath, certificate.ExportCertificatePem(), ct);
        await File.WriteAllTextAsync(msiPath, "synthetic package bytes", ct);
        using var configuration = new ConfigurationManager();
        configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Sli:AgentServerCaFile"] = caPath, ["Sli:AgentInstallerPath"] = msiPath,
            ["Kestrel:Certificates:Default:Path"] = certificatePath,
            ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user"),
        });
        using var sp = new ServiceCollection().AddSingleton<IConfiguration>(configuration).BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = sp };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("sli.example.test");
        await using var db = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await db.OpenAsync(ct);

        const string savedAddress = "https://192.0.2.40:8443/";
        async Task<(Guid Id, string Token)> Issue(int count, bool? manageWindowsAudit = null, string? address = null)
        {
            var payload = new JsonObject { ["host_limit"] = count };
            if (manageWindowsAudit is { } enabled) payload["manage_windows_audit"] = enabled;
            if (address is not null) payload["server_url"] = address;
            await using var tx = await db.BeginTransactionAsync(ct);
            var issued = await management.CreateConsoleTokenAsync(db, tx,
                JsonSerializer.SerializeToElement(payload), "synthetic", context, ct);
            await tx.CommitAsync(ct);
            var command = issued.GetProperty("command").GetString()!;
            Assert.Contains($"'{savedAddress}'", command);
            Assert.DoesNotContain("'https://sli.example.test/'", command);
            Assert.Contains(Convert.ToHexStringLower(SHA256.HashData(root.RawData)), command);
            Assert.Contains(Convert.ToHexStringLower(SHA256.HashData("synthetic package bytes"u8)), command);
            return (issued.GetProperty("id").GetGuid(), CommandToken(command));
        }
        static string CommandToken(string command)
        {
            var token = System.Text.RegularExpressions.Regex.Match(command, "'(?<key>[A-Za-z0-9_-]{43})'").Groups["key"].Value;
            Assert.Equal(43, token.Length);
            return token;
        }
        static string Csr(Guid host, ECDsa key) => new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256).CreateSigningRequestPem();
        async Task<JsonObject> Enroll(string token, string csr, string hostName = "fixture.example.test", string role = "workstation")
        {
            await using var tx = await db.BeginTransactionAsync(ct);
            var enrolled = await service.EnrollAsync(db, tx,
                new JsonObject { ["token"] = token, ["csr_pem"] = csr, ["reported_hostname"] = hostName, ["machine_role"] = role }, ct);
            await tx.CommitAsync(ct);
            return enrolled;
        }
        async Task Reject(string token, string csr, string hostName = "fixture.example.test", string role = "workstation") =>
            Assert.Equal("enrollment_token_rejected", (await Assert.ThrowsAsync<AgentCertificateException>(() => Enroll(token, csr, hostName, role))).Code);
        async Task<JsonObject> CheckIn(JsonObject enrolled)
        {
            await using var query = new NpgsqlCommand("select to_jsonb(a) from sli_agents a where id=@id", db);
            query.Parameters.AddWithValue("id", Guid.Parse((string)enrolled["agent_id"]!));
            return AgentClientPolicy.CheckIn(JsonNode.Parse((string)(await query.ExecuteScalarAsync(ct))!)!.AsObject(), false);
        }

        using var key1 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var key2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var key3 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var host1 = Guid.NewGuid();
        var host2 = Guid.NewGuid();
        string csr1 = Csr(host1, key1), csr2 = Csr(host2, key2), csr3 = Csr(Guid.NewGuid(), key3);
        var single = await Issue(1, address: savedAddress.TrimEnd('/'));
        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            var error = await Assert.ThrowsAsync<AgentControlException>(() => management.CreateConsoleTokenAsync(
                db, tx, JsonSerializer.SerializeToElement(new { host_limit = 1, server_url = "https://outside.example.test" }),
                "synthetic", context, ct));
            Assert.Equal("invalid_agent_console_server_url", error.Message);
            Assert.Contains("192.0.2.40", error.AllowedHosts!);
            var settings = await management.ReadConsoleSettingsAsync(db, tx, ct);
            Assert.Equal(savedAddress, settings.GetProperty("server_url").GetString());
        }
        var first = await Enroll(single.Token, csr1, "fixture.example.test", "domain_controller");
        Assert.NotNull(first["certificate_pem"]);
        var automatic = (await CheckIn(first))["collection_policy"]!.AsObject();
        Assert.True((bool)automatic["manage_windows_audit"]!);
        Assert.False((bool)automatic["audit_process_command_line"]!);
        Assert.Null(automatic["manage_domain_root_sacl"]);
        await Reject(single.Token, csr1);
        await Reject(single.Token, csr2);

        using var cliOutput = new StringWriter();
        using var cliError = new StringWriter();
        Assert.Equal(0, await AgentCommandConsole.RunAsync(["--count", "2", "--no-audit"], true,
            cliOutput, cliError, configuration));
        Assert.Empty(cliError.ToString());
        var batchToken = CommandToken(cliOutput.ToString());
        var expectedPackage = await AgentConsolePackage.ReadAsync(configuration, savedAddress, ct);
        Assert.Equal(expectedPackage.Command(batchToken) + cliOutput.NewLine, cliOutput.ToString());
        var second = await Enroll(batchToken, csr2, "FIXTURE", "domain_controller");
        var optedOut = await CheckIn(second);
        Assert.Null(optedOut["collection_policy"]!["manage_windows_audit"]);
        await Reject(batchToken, Csr(Guid.NewGuid(), key2), "other.example.test");
        await Reject(batchToken, Csr(host2, key3), "other.example.test");
        await Reject(batchToken, csr3, "fixture.example.test", "domain_controller");
        var workstation = await Enroll(batchToken, csr3, "other.example.test");
        Assert.True((bool)(await CheckIn(workstation))["collection_policy"]!["manage_windows_audit"]!);
        await Reject(batchToken, Csr(Guid.NewGuid(), key3));

        var oldId = Guid.Parse((string)first["agent_id"]!);
        var newId = Guid.Parse((string)second["agent_id"]!);
        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            await new AgentPolicyService(new AgentControlAudit()).UpdateControlAsync(db, tx, JsonSerializer.SerializeToElement(new
            {
                agent_id = newId,
                expected_revision = optedOut["policy_revision"]!.GetValue<long>(),
                collection_policy = new { manage_windows_audit = true },
            }), "synthetic", ct);
            await tx.CommitAsync(ct);
        }
        Assert.True((bool)(await CheckIn(second))["collection_policy"]!["manage_windows_audit"]!);
        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            var inventory = await management.ListAgentsAsync(db, tx, null, "synthetic", ct);
            var row = Assert.Single(inventory.GetProperty("items").EnumerateArray(), agent =>
                agent.GetProperty("host_name").GetString() != "other.example.test");
            Assert.Equal(newId, row.GetProperty("id").GetGuid());
            Assert.Equal("active", row.GetProperty("status").GetString());
            using var oldCertificate = X509Certificate2.CreateFromPem((string)first["certificate_pem"]!);
            await Assert.ThrowsAsync<AgentCertificateException>(() => new AgentIdentityService(ca).AuthenticateAsync(db, tx, oldCertificate, false, ct));
            await tx.CommitAsync(ct);
        }
        await using (var history = new NpgsqlCommand("""
            select a.status, d.details->>'replaced_by', exists(select 1 from sli_agent_certificates c where c.agent_id=a.id)
            from sli_agents a join sli_agent_audit d on d.target=a.id::text and d.action='disable'
            where a.id=@id and d.details->>'reason'='registration_replaced'
            """, db))
        {
            history.Parameters.AddWithValue("id", oldId);
            await using var row = await history.ExecuteReaderAsync(ct);
            Assert.True(await row.ReadAsync(ct));
            Assert.Equal("disabled", row.GetString(0));
            Assert.Equal(newId.ToString(), row.GetString(1));
            Assert.True(row.GetBoolean(2));
        }

        using var approvedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var approvedHost = Guid.NewGuid();
        const string approvedName = "approved.example.test";
        string approvedToken;
        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            var issued = await management.CreateTokenAsync(db, tx, JsonSerializer.SerializeToElement(new
            {
                host_id = approvedHost.ToString(), registration_host_name = approvedName,
                key_fingerprint = Convert.ToHexStringLower(SHA256.HashData(approvedKey.ExportSubjectPublicKeyInfo())),
            }), "synthetic", ct);
            approvedToken = issued.GetProperty("token").GetString()!;
            await tx.CommitAsync(ct);
        }
        var approved = await Enroll(approvedToken, Csr(approvedHost, approvedKey), approvedName);
        var unscoped = await Issue(1);
        using var freshKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var freshCsr = Csr(Guid.NewGuid(), freshKey);
        var conflict = await Assert.ThrowsAsync<AgentCertificateException>(() => Enroll(unscoped.Token, freshCsr, approvedName));
        Assert.Equal("agent_console_replacement_requires_approval", conflict.Code);
        await Enroll(unscoped.Token, freshCsr, "fresh.example.test");
        await using (var status = new NpgsqlCommand("select status from sli_agents where id=@id", db))
        {
            status.Parameters.AddWithValue("id", Guid.Parse((string)approved["agent_id"]!));
            Assert.Equal("active", await status.ExecuteScalarAsync(ct));
        }

        var expired = await Issue(1);
        await using (var admin = new NpgsqlConnection(fixture.Pg.ConnectionString))
        {
            await admin.OpenAsync(ct);
            await using var expire = new NpgsqlCommand("""
                update sli_agent_console_tokens set created_at=created_at-interval '2 hours',expires_at=expires_at-interval '2 hours' where id=@id
                """, admin);
            expire.Parameters.AddWithValue("id", expired.Id);
            await expire.ExecuteNonQueryAsync(ct);
        }
        await Reject(expired.Token, csr3);
        var revoked = await Issue(2);
        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            await management.RevokeConsoleTokenAsync(db, tx, JsonSerializer.SerializeToElement(new { id = revoked.Id }), "synthetic", ct);
            await tx.CommitAsync(ct);
        }
        await Reject(revoked.Token, csr3);
        await using var audit = new NpgsqlCommand("""
            select a.actor, a.details->>'host_limit', a.details::text, t.expires_at-t.created_at
            from sli_agent_console_tokens t join sli_agent_audit a on a.target=t.id::text
            where a.action='token_create' and t.token_hash=@hash
            """, db);
        audit.Parameters.AddWithValue("hash", Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(batchToken))));
        await using var issuance = await audit.ExecuteReaderAsync(ct);
        Assert.True(await issuance.ReadAsync(ct));
        Assert.Equal("host_admin:root", issuance.GetString(0));
        Assert.Equal("2", issuance.GetString(1));
        Assert.DoesNotContain(batchToken, issuance.GetString(2));
        Assert.Equal(TimeSpan.FromHours(1), issuance.GetTimeSpan(3));
    }

    [Fact]
    public async Task Authentication_and_renewal_share_transaction_and_rollback()
    {

        Assert.SkipWhen(Environment.GetEnvironmentVariable("SLI_T2_RUN_ID") is null, "Owned PostgreSQL binding required");
        await using var db = await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(), TestContext.Current.CancellationToken);
        await using var connection = await db.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using (var grants = new NpgsqlCommand("select current_user, has_table_privilege(current_user,'sli_agents','SELECT'), has_table_privilege(current_user,'sli_agents','INSERT'), has_table_privilege(current_user,'sli_agent_certificates','SELECT'), has_table_privilege(current_user,'sli_agent_certificates','INSERT'), has_table_privilege(current_user,'sli_agent_audit','SELECT'), has_table_privilege(current_user,'sli_agent_audit','INSERT'), has_column_privilege(current_user,'sli_agents','last_seen','UPDATE'), has_column_privilege(current_user,'sli_agent_certificates','revoked_at','UPDATE'), has_table_privilege(current_user,'sli_agent_group_members','SELECT'), has_table_privilege(current_user,'sli_agent_group_members','INSERT')", connection))
        await using (var grantReader = await grants.ExecuteReaderAsync(TestContext.Current.CancellationToken))
        {
            Assert.True(await grantReader.ReadAsync(TestContext.Current.CancellationToken));
            Assert.Equal("adlog_user", grantReader.GetString(0));
            for (int i = 1; i < grantReader.FieldCount; i++) Assert.True(grantReader.GetBoolean(i));
        }
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root = CaRequest("CN=test root", rootKey, 1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var issuerPublic = CaRequest("CN=test issuer", issuerKey, 0).Create(root, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(16));
        using var issuer = issuerPublic.CopyWithPrivateKey(issuerKey);
        var ca = new AgentIssuingCa(root, issuer);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var id = Guid.NewGuid();
        var host = Guid.NewGuid();
        var csr = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256);
        using var certificate = ca.Issue(AgentCertificateAuthority.ParseCsr(csr.CreateSigningRequestPem(), host), id, host);
        var serial = Serial(certificate);
        var certFp = Convert.ToHexStringLower(SHA256.HashData(certificate.RawData));
        var keyFp = Convert.ToHexStringLower(SHA256.HashData(csr.PublicKey.ExportSubjectPublicKeyInfo()));
        await using (var tx = await connection.BeginTransactionAsync(TestContext.Current.CancellationToken))
        {
            await using var insert = new NpgsqlCommand("insert into sli_agents(id,host_id,key_fingerprint) values(@id,@host,@key); insert into sli_agent_certificates(agent_id,serial,fingerprint,not_before,not_after) values(@id,@serial,@fingerprint,@before,@after)", connection, tx);
            insert.Parameters.AddWithValue("id", id); insert.Parameters.AddWithValue("host", host); insert.Parameters.AddWithValue("key", keyFp);
            insert.Parameters.AddWithValue("serial", serial); insert.Parameters.AddWithValue("fingerprint", certFp);
            insert.Parameters.AddWithValue("before", certificate.NotBefore.ToUniversalTime()); insert.Parameters.AddWithValue("after", certificate.NotAfter.ToUniversalTime());
            await insert.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
            var service = new AgentIdentityService(ca);
            var authenticated = await service.AuthenticateAsync(connection, tx, certificate, false, TestContext.Current.CancellationToken);
            Assert.Equal(id, authenticated.Id);
            var renew = new AgentEnrollmentService(ca, service);
            var result = await renew.RenewAsync(connection, tx, certificate, new JsonObject { ["csr_pem"] = csr.CreateSigningRequestPem() }, TestContext.Current.CancellationToken);
            Assert.Equal(id.ToString(), result["agent_id"]!.GetValue<string>());
            await using var count = new NpgsqlCommand("select count(*) from sli_agent_certificates where agent_id=@id", connection, tx);
            count.Parameters.AddWithValue("id", id);
            Assert.Equal(2L, await count.ExecuteScalarAsync(TestContext.Current.CancellationToken));
            await using (var revoke = new NpgsqlCommand("update sli_agent_certificates set revoked_at=clock_timestamp() where agent_id=@id and serial=@serial", connection, tx))
            { revoke.Parameters.AddWithValue("id", id); revoke.Parameters.AddWithValue("serial", serial); await revoke.ExecuteNonQueryAsync(TestContext.Current.CancellationToken); }
            var rejection = await Assert.ThrowsAsync<AgentCertificateException>(() => service.AuthenticateAsync(connection, tx, certificate, false, TestContext.Current.CancellationToken));
            Assert.Equal("agent_certificate_rejected", rejection.Code);
            await tx.RollbackAsync(TestContext.Current.CancellationToken);
        }
        await using var check = new NpgsqlCommand("select count(*) from sli_agents where id=@id", connection);
        check.Parameters.AddWithValue("id", id);
        Assert.Equal(0L, await check.ExecuteScalarAsync(TestContext.Current.CancellationToken));
        await using var auditCheck = new NpgsqlCommand("select count(*) from sli_agent_audit where target=@id and action='renew'", connection);
        auditCheck.Parameters.AddWithValue("id", id.ToString());
        Assert.Equal(0L, await auditCheck.ExecuteScalarAsync(TestContext.Current.CancellationToken));
    }
    [Theory]
    [InlineData("full", "workstation", "sli.workstations")]
    [InlineData("full", "domain_controller", "sli.windows.ad-dc")]
    [InlineData("beta", "workstation", null)]
    [InlineData("beta", "domain_controller", "sli.windows.ad-dc")]
    public async Task Enrollment_consumes_token_and_installs_default_policy_in_transaction(string profile, string role, string? module)
    {
        Assert.SkipWhen(Environment.GetEnvironmentVariable("SLI_T2_RUN_ID") is null, "Owned PostgreSQL binding required");
        var ct = TestContext.Current.CancellationToken;
        await using var db = await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(), ct);
        await using var connection = await db.OpenConnectionAsync(ct);
        await using (var grants = new NpgsqlCommand("select current_user, has_table_privilege(current_user,'sli_agents','SELECT'), has_table_privilege(current_user,'sli_agents','INSERT'), has_table_privilege(current_user,'sli_agent_certificates','SELECT'), has_table_privilege(current_user,'sli_agent_certificates','INSERT'), has_table_privilege(current_user,'sli_agent_audit','SELECT'), has_table_privilege(current_user,'sli_agent_audit','INSERT'), has_column_privilege(current_user,'sli_agents','last_seen','UPDATE'), has_column_privilege(current_user,'sli_agent_certificates','revoked_at','UPDATE'), has_table_privilege(current_user,'sli_agent_group_members','SELECT'), has_table_privilege(current_user,'sli_agent_group_members','INSERT')", connection))
        await using (var grantReader = await grants.ExecuteReaderAsync(TestContext.Current.CancellationToken))
        {
            Assert.True(await grantReader.ReadAsync(TestContext.Current.CancellationToken));
            Assert.Equal("adlog_user", grantReader.GetString(0));
            for (int i = 1; i < grantReader.FieldCount; i++) Assert.True(grantReader.GetBoolean(i));
        }
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root = CaRequest("CN=test root", rootKey, 1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var publicIssuer = CaRequest("CN=test issuer", issuerKey, 0).Create(root, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddYears(1), RandomNumberGenerator.GetBytes(16));
        using var issuer = publicIssuer.CopyWithPrivateKey(issuerKey);
        var ca = new AgentIssuingCa(root, issuer);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var host = Guid.NewGuid();
        var csr = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256);
        var keyFp = Convert.ToHexStringLower(SHA256.HashData(csr.PublicKey.ExportSubjectPublicKeyInfo()));
        var rawToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var digest = Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(rawToken)));
        await using var tx = await connection.BeginTransactionAsync(ct);
        var enrollmentToken=Guid.NewGuid();
        await using var insert = new NpgsqlCommand("insert into sli_agent_enrollment_tokens(id,token_hash,host_id,key_fingerprint,created_at,expires_at) values(@id,@hash,@host,@key,clock_timestamp(),clock_timestamp()+interval '15 minutes')", connection, tx);
        insert.Parameters.AddWithValue("id", enrollmentToken); insert.Parameters.AddWithValue("hash", digest); insert.Parameters.AddWithValue("host", host); insert.Parameters.AddWithValue("key", keyFp);
        await insert.ExecuteNonQueryAsync(ct);
        if(profile=="beta" && role=="domain_controller")
        {
            await using var seed=new NpgsqlCommand("""
                with forest as (insert into forests(name) values(@forest) returning id),
                domain as (insert into domains(forest_id,fqdn,domain_sid)
                    select id,'example.test','S-1-5-21-100000001-200000002-300000003' from forest returning id)
                insert into servers(domain_id,hostname,role) select id,'fixture.example.test','domain_controller' from domain;
                insert into sli_agent_audit(action,actor,target,details)
                values('token_create','session:1',@token,'{"registration_host_name":"fixture.example.test"}'::jsonb)
                """,connection,tx);
            seed.Parameters.AddWithValue("forest","fixture-"+host);
            seed.Parameters.AddWithValue("token",enrollmentToken.ToString());
            await seed.ExecuteNonQueryAsync(ct);
        }
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:CollectionProfile"]=profile }).Build();
        var service = new AgentEnrollmentService(ca, new AgentIdentityService(ca),config);
        var invalidName = await Assert.ThrowsAsync<AgentCertificateException>(() => service.EnrollAsync(connection, tx, new JsonObject { ["token"] = rawToken, ["instance_name"] = "bad\n", ["csr_pem"] = csr.CreateSigningRequestPem() }, ct));
        Assert.Equal("invalid_agent_instance_name", invalidName.Code);
        var result = await service.EnrollAsync(connection, tx, new JsonObject { ["token"] = rawToken, ["csr_pem"] = csr.CreateSigningRequestPem(), ["machine_role"] = role, ["reported_hostname"] = "fixture.example.test" }, ct);
        var agent = Guid.Parse(result["agent_id"]!.GetValue<string>());
        await using var query = new NpgsqlCommand("select e.used_at is not null, a.policy_revision, a.assigned_modules from sli_agent_enrollment_tokens e join sli_agents a on a.id=e.enrolled_agent_id where e.token_hash=@hash", connection, tx);
        query.Parameters.AddWithValue("hash", digest);
        await using (var reader = await query.ExecuteReaderAsync(ct))
        {
            Assert.True(await reader.ReadAsync(ct)); Assert.True(reader.GetBoolean(0)); Assert.Equal(module is null?1:2, reader.GetInt32(1));
            var assignments=JsonNode.Parse(reader.GetString(2))!.AsArray();
            if(module is null) Assert.Empty(assignments);
            else Assert.Contains(assignments.OfType<JsonObject>(),m=>m["module_id"]!.GetValue<string>()==module);
            if(profile=="beta" && role=="domain_controller")
                foreach(var snapshot in new[] { "sli.ad-snapshot","sli.gpo-snapshot" })
                    Assert.Contains(assignments.OfType<JsonObject>(),m=>m["module_id"]!.GetValue<string>()==snapshot && m["config"]!["domain_dns"]!.GetValue<string>()=="example.test");
        }
        await using (var audit = new NpgsqlCommand("select details->>'policy_sha256' from sli_agent_audit where target=@id and action='module_assign' and details->>'module_id'=@module", connection, tx))
        {
            audit.Parameters.AddWithValue("id", agent.ToString());
            audit.Parameters.AddWithValue("module",module??"sli.workstations");
            var expectedHash = role == "workstation" ? "8a09c7a41b0050e53b31cfa9b2a568108ba462206807efe734355f2f9f43f321" : "7edb1a39fb2ad5dffeb06cac8f65b4ec162e40fb6b661afd3b55dea3c18ee629";
            var hash=await audit.ExecuteScalarAsync(ct);
            if(profile=="full") Assert.Equal(expectedHash,hash);
            else if(module is null) Assert.Null(hash);
            else Assert.Matches("^[0-9a-f]{64}$",Assert.IsType<string>(hash));
        }
        if(role=="workstation")
        {
            var assigned=await new AgentModuleAssignmentService(new AgentControlAudit()).AssignAsync(connection,tx,
                JsonSerializer.SerializeToElement(new { agent_id=agent,module_id="sli.workstations",enabled=true,config=new JsonObject(),expected_revision=module is null?1:2 }),"session:1",ct);
            Assert.Contains(assigned.GetProperty("assigned_modules").EnumerateArray(),m=>m.GetProperty("module_id").GetString()=="sli.workstations" && m.GetProperty("enabled").GetBoolean());
        }
        var error = await Assert.ThrowsAsync<AgentCertificateException>(() => service.EnrollAsync(connection, tx, new JsonObject { ["token"] = rawToken, ["csr_pem"] = csr.CreateSigningRequestPem() }, ct));
        Assert.Equal("enrollment_token_rejected", error.Code);
        await tx.RollbackAsync(ct);
        await using var check = new NpgsqlCommand("select count(*) from sli_agents where id=@id", connection);
        check.Parameters.AddWithValue("id", agent);
        Assert.Equal(0L, await check.ExecuteScalarAsync(ct));
    }
    [Fact]
    public async Task Concurrent_enrollment_consumes_token_exactly_once()
    {
        Assert.SkipWhen(Environment.GetEnvironmentVariable("SLI_T2_RUN_ID") is null, "Owned PostgreSQL binding required");
        var ct=TestContext.Current.CancellationToken;
        await using var db=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        await using var seed=await db.OpenConnectionAsync(ct);
        await using var first=await db.OpenConnectionAsync(ct);
        await using var second=await db.OpenConnectionAsync(ct);
        using var rootKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root=CaRequest("CN=test root",rootKey,1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddYears(2));
        using var issuerKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var publicIssuer=CaRequest("CN=test issuer",issuerKey,0).Create(root,DateTimeOffset.UtcNow.AddHours(-1),DateTimeOffset.UtcNow.AddYears(1),RandomNumberGenerator.GetBytes(16));
        using var issuer=publicIssuer.CopyWithPrivateKey(issuerKey);
        var ca=new AgentIssuingCa(root,issuer);
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var host=Guid.NewGuid(); var csr=new CertificateRequest($"CN={host}",key,HashAlgorithmName.SHA256);
        var keyFp=Convert.ToHexStringLower(SHA256.HashData(csr.PublicKey.ExportSubjectPublicKeyInfo()));
        var token=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+','-').Replace('/','_');
        var digest=Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(token)));
        await using (var q=new NpgsqlCommand("insert into sli_agent_enrollment_tokens(id,token_hash,host_id,key_fingerprint,created_at,expires_at) values(@id,@hash,@host,@key,clock_timestamp(),clock_timestamp()+interval '15 minutes')",seed))
        { q.Parameters.AddWithValue("id",Guid.NewGuid()); q.Parameters.AddWithValue("hash",digest); q.Parameters.AddWithValue("host",host); q.Parameters.AddWithValue("key",keyFp); await q.ExecuteNonQueryAsync(ct); }
        var pem=csr.CreateSigningRequestPem();
        async Task<string> Attempt(NpgsqlConnection c)
        {
            await using var tx=await c.BeginTransactionAsync(ct);
            try
            {
                var result=await new AgentEnrollmentService(ca,new AgentIdentityService(ca)).EnrollAsync(c,tx,new JsonObject { ["token"]=token,["csr_pem"]=pem },ct);
                await tx.CommitAsync(ct); return result["agent_id"]!.GetValue<string>();
            }
            catch (AgentCertificateException ex) { await tx.RollbackAsync(ct); return ex.Code; }
        }
        await using var firstTx=await first.BeginTransactionAsync(ct);
        var firstResult=await new AgentEnrollmentService(ca,new AgentIdentityService(ca)).EnrollAsync(first,firstTx,new JsonObject { ["token"]=token,["csr_pem"]=pem },ct);
        var secondAttempt=Attempt(second);
        Assert.NotSame(secondAttempt,await Task.WhenAny(secondAttempt,Task.Delay(200,ct)));
        await firstTx.CommitAsync(ct);
        Assert.True(Guid.TryParse(firstResult["agent_id"]!.GetValue<string>(),out _));
        Assert.Equal("enrollment_token_rejected",await secondAttempt);
        await using var check=new NpgsqlCommand("select count(*) from sli_agents where host_id=@host",seed);
        check.Parameters.AddWithValue("host",host); Assert.Equal(1L,await check.ExecuteScalarAsync(ct));
    }
    [Theory]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public async Task Group_approved_enrollment_enforces_scope_and_copies_template(bool withinScope, bool injectFailure)
    {
        Assert.SkipWhen(Environment.GetEnvironmentVariable("SLI_T2_RUN_ID") is null, "Owned PostgreSQL binding required");
        Assert.SkipWhen(injectFailure && Environment.GetEnvironmentVariable("SLI_T2_AUDIT_FAILURE_FIXTURE") != "1", "Owned audit-failure fixture required");
        var ct=TestContext.Current.CancellationToken;
        await using var db=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        await using var c=await db.OpenConnectionAsync(ct);
        using var rootKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root=CaRequest("CN=test root",rootKey,1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddYears(2));
        using var issuerKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var pub=CaRequest("CN=test issuer",issuerKey,0).Create(root,DateTimeOffset.UtcNow.AddHours(-1),DateTimeOffset.UtcNow.AddYears(1),RandomNumberGenerator.GetBytes(16));
        using var issuer=pub.CopyWithPrivateKey(issuerKey);
        var ca=new AgentIssuingCa(root,issuer);
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var host=Guid.NewGuid(); var csr=new CertificateRequest($"CN={host}",key,HashAlgorithmName.SHA256);
        var keyFp=Convert.ToHexStringLower(SHA256.HashData(csr.PublicKey.ExportSubjectPublicKeyInfo()));
        var raw=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+','-').Replace('/','_');
        var hash=Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(raw)));
        var group=Guid.NewGuid(); var groupToken=Guid.NewGuid(); var token=Guid.NewGuid(); var request=Guid.NewGuid(); var template=Guid.NewGuid();
        await using var tx=await c.BeginTransactionAsync(ct);
        await using (var seed=new NpgsqlCommand("""
            insert into sli_agent_enrollment_groups(id,domain_id,ou_entity_ids) values(@group,101,array[2147000002]::bigint[]);
            insert into sli_agent_group_tokens(id,token_hash,created_at,expires_at,max_uses,domain_id,ou_entity_ids,group_id,computer_entity_ids) values(@gt,repeat('a',64),clock_timestamp(),clock_timestamp()+interval '1 hour',1,101,array[2147000002]::bigint[],@group,@selected);
            insert into sli_agent_enrollment_tokens(id,token_hash,host_id,key_fingerprint,created_at,expires_at) values(@token,@hash,@host,@key,clock_timestamp(),clock_timestamp()+interval '15 minutes');
            insert into sli_agent_group_requests(id,token_id,host_id,key_fingerprint,computer_entity_id,computer_version_id,status) select @request,@gt,@host,@key,2147000001,id,'approved' from ad_context_entity_versions where entity_id=2147000001 and source_section='directory_accounts';
            insert into sli_agent_policy_templates(id,version,assigned_modules,collection_policy,policy_sha256) values(@template,1,'[]'::jsonb,'{"state":"paused"}'::jsonb,repeat('b',64));
            insert into sli_agent_onboarding_copies(enrollment_token_id,request_id,template_id,template_version) values(@token,@request,@template,1);
            """,c,tx))
        {
            seed.Parameters.AddWithValue("group",group); seed.Parameters.AddWithValue("gt",groupToken); seed.Parameters.AddWithValue("token",token); seed.Parameters.AddWithValue("hash",hash);
            seed.Parameters.AddWithValue("host",host); seed.Parameters.AddWithValue("key",keyFp); seed.Parameters.AddWithValue("request",request); seed.Parameters.AddWithValue("template",template); seed.Parameters.AddWithValue("selected",new long[] { withinScope ? 2147000001L : 2147000002L }); await seed.ExecuteNonQueryAsync(ct);
        }
        await using (var revoke=new NpgsqlCommand("update sli_agent_group_tokens set revoked_at=clock_timestamp() where id=@id",c,tx))
        { revoke.Parameters.AddWithValue("id",groupToken); await revoke.ExecuteNonQueryAsync(ct); }
        var enrollment=new AgentEnrollmentService(ca,new AgentIdentityService(ca));
        var rejected=await Assert.ThrowsAsync<AgentCertificateException>(() => enrollment.EnrollAsync(c,tx,new JsonObject { ["token"]=raw,["csr_pem"]=csr.CreateSigningRequestPem() },ct));
        Assert.Equal("enrollment_token_rejected",rejected.Code);
        await using (var restore=new NpgsqlCommand("update sli_agent_group_tokens set revoked_at=null where id=@id",c,tx))
        { restore.Parameters.AddWithValue("id",groupToken); await restore.ExecuteNonQueryAsync(ct); }
        if (!withinScope)
        {
            var denied=await Assert.ThrowsAsync<AgentCertificateException>(() => enrollment.EnrollAsync(c,tx,new JsonObject { ["token"]=raw,["csr_pem"]=csr.CreateSigningRequestPem() },ct));
            Assert.Equal("invalid_group_enrollment_scope",denied.Code);
            await tx.RollbackAsync(ct);
            return;
        }
        if (injectFailure)
        {
            await using (var inject=new NpgsqlCommand("select set_config('sli.test.ca_audit_fail','on',true)",c,tx)) await inject.ExecuteNonQueryAsync(ct);
            var failure=await Assert.ThrowsAsync<PostgresException>(()=>enrollment.EnrollAsync(c,tx,new JsonObject { ["token"]=raw,["csr_pem"]=csr.CreateSigningRequestPem() },ct));
            Assert.Equal("P0001",failure.SqlState);
            await tx.RollbackAsync(ct);
            await using var rolledBack=new NpgsqlCommand("select (select count(*) from sli_agents where host_id=@host), (select count(*) from sli_agent_audit where actor='enrollment:' || @token::text), (select count(*) from sli_agent_group_members where group_id=@group)",c);
            rolledBack.Parameters.AddWithValue("host",host); rolledBack.Parameters.AddWithValue("token",token); rolledBack.Parameters.AddWithValue("group",group);
            await using var check=await rolledBack.ExecuteReaderAsync(ct); Assert.True(await check.ReadAsync(ct));
            Assert.Equal(0L,check.GetInt64(0)); Assert.Equal(0L,check.GetInt64(1)); Assert.Equal(0L,check.GetInt64(2));
            return;
        }
        var result=await enrollment.EnrollAsync(c,tx,new JsonObject { ["token"]=raw,["csr_pem"]=csr.CreateSigningRequestPem() },ct);
        var id=Guid.Parse(result["agent_id"]!.GetValue<string>());
        await using (var check=new NpgsqlCommand("select a.template_id,a.policy_revision,a.collection_policy->>'state',m.group_id from sli_agents a join sli_agent_group_members m on m.agent_id=a.id where a.id=@id",c,tx))
        {
            check.Parameters.AddWithValue("id",id); await using var r=await check.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct));
            Assert.Equal(template,r.GetGuid(0)); Assert.Equal(1L,r.GetInt64(1)); Assert.Equal("paused",r.GetString(2)); Assert.Equal(group,r.GetGuid(3));
        }
        await tx.RollbackAsync(ct);
    }
    [Fact]
    public async Task Approved_registration_replacement_preserves_old_certificate_in_same_transaction()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var c=new NpgsqlConnection(fixture.Dsn("adlog_user")); await c.OpenAsync(ct);
        using var rootKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root=CaRequest("CN=test root",rootKey,1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddYears(2));
        using var issuerKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var pub=CaRequest("CN=test issuer",issuerKey,0).Create(root,DateTimeOffset.UtcNow.AddHours(-1),DateTimeOffset.UtcNow.AddYears(1),RandomNumberGenerator.GetBytes(16));
        using var issuer=pub.CopyWithPrivateKey(issuerKey);
        var ca=new AgentIssuingCa(root,issuer); var service=new AgentEnrollmentService(ca,new AgentIdentityService(ca));
        await using var tx=await c.BeginTransactionAsync(ct);
        async Task<Guid> Enroll()
        {
            using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256); var host=Guid.NewGuid();
            var csr=new CertificateRequest($"CN={host}",key,HashAlgorithmName.SHA256);
            var fingerprint=Convert.ToHexStringLower(SHA256.HashData(csr.PublicKey.ExportSubjectPublicKeyInfo()));
            var raw=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+','-').Replace('/','_');
            var digest=Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(raw))); var token=Guid.NewGuid();
            await using var seed=new NpgsqlCommand("insert into sli_agent_enrollment_tokens(id,token_hash,host_id,key_fingerprint,created_at,expires_at) values(@id,@hash,@host,@key,clock_timestamp(),clock_timestamp()+interval '15 minutes'); insert into sli_agent_audit(action,actor,target,details) values('token_create','synthetic',@target,'{\"registration_host_name\":\"fixture.example.test\"}'::jsonb)",c,tx);
            seed.Parameters.AddWithValue("id",token); seed.Parameters.AddWithValue("hash",digest); seed.Parameters.AddWithValue("host",host); seed.Parameters.AddWithValue("key",fingerprint); seed.Parameters.AddWithValue("target",token.ToString()); await seed.ExecuteNonQueryAsync(ct);
            var mismatch=await Assert.ThrowsAsync<AgentCertificateException>(()=>service.EnrollAsync(c,tx,new JsonObject { ["token"]=raw,["csr_pem"]=csr.CreateSigningRequestPem(),["reported_hostname"]="other.example.test" },ct));
            Assert.Equal("agent_registration_name_mismatch",mismatch.Code);
            var result=await service.EnrollAsync(c,tx,new JsonObject { ["token"]=raw,["csr_pem"]=csr.CreateSigningRequestPem(),["reported_hostname"]="fixture.example.test" },ct);
            return Guid.Parse(result["agent_id"]!.GetValue<string>());
        }
        var oldId=await Enroll(); var newId=await Enroll();
        await using (var q=new NpgsqlCommand("select status,(select count(*) from sli_agent_certificates where agent_id=@old and revoked_at is not null),(select count(*) from sli_agent_audit where target=@target and action='disable' and details->>'reason'='registration_replaced') from sli_agents where id=@old",c,tx))
        {
            q.Parameters.AddWithValue("old",oldId); q.Parameters.AddWithValue("target",oldId.ToString()); await using var r=await q.ExecuteReaderAsync(ct);
            Assert.True(await r.ReadAsync(ct)); Assert.Equal("disabled",r.GetString(0)); Assert.Equal(0L,r.GetInt64(1)); Assert.Equal(1L,r.GetInt64(2));
        }
        Assert.NotEqual(oldId,newId);
        await tx.RollbackAsync(ct);
    }
    [Fact]
    public async Task Issue_audit_failure_rolls_back_token_certificate_policy_and_agent()
    {
        Assert.SkipWhen(Environment.GetEnvironmentVariable("SLI_T2_RUN_ID") is null, "Owned PostgreSQL binding required");
        Assert.SkipWhen(Environment.GetEnvironmentVariable("SLI_T2_AUDIT_FAILURE_FIXTURE") != "1", "Owned audit-failure fixture required");
        var ct=TestContext.Current.CancellationToken;
        await using var db=await SyntheticDatabase.BorrowAsync(OwnedDatabaseBinding.FromEnvironment(),ct);
        await using var c=await db.OpenConnectionAsync(ct);
        using var rootKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root=CaRequest("CN=test root",rootKey,1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddYears(2));
        using var issuerKey=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var pub=CaRequest("CN=test issuer",issuerKey,0).Create(root,DateTimeOffset.UtcNow.AddHours(-1),DateTimeOffset.UtcNow.AddYears(1),RandomNumberGenerator.GetBytes(16));
        using var issuer=pub.CopyWithPrivateKey(issuerKey); var ca=new AgentIssuingCa(root,issuer);
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256); var host=Guid.NewGuid(); var id=Guid.NewGuid();
        var csr=new CertificateRequest($"CN={host}",key,HashAlgorithmName.SHA256);
        var fingerprint=Convert.ToHexStringLower(SHA256.HashData(csr.PublicKey.ExportSubjectPublicKeyInfo()));
        var raw=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+','-').Replace('/','_');
        var digest=Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(raw)));
        await using (var seed=new NpgsqlCommand("insert into sli_agent_enrollment_tokens(id,token_hash,host_id,key_fingerprint,created_at,expires_at) values(@id,@hash,@host,@key,clock_timestamp(),clock_timestamp()+interval '15 minutes')",c))
        { seed.Parameters.AddWithValue("id",id); seed.Parameters.AddWithValue("hash",digest); seed.Parameters.AddWithValue("host",host); seed.Parameters.AddWithValue("key",fingerprint); await seed.ExecuteNonQueryAsync(ct); }
        await using (var tx=await c.BeginTransactionAsync(ct))
        {
            await using (var injection=new NpgsqlCommand("select set_config('sli.test.ca_audit_fail','on',true)",c,tx)) await injection.ExecuteNonQueryAsync(ct);
            var service=new AgentEnrollmentService(ca,new AgentIdentityService(ca));
            var failure=await Assert.ThrowsAsync<PostgresException>(()=>service.EnrollAsync(c,tx,new JsonObject { ["token"]=raw,["csr_pem"]=csr.CreateSigningRequestPem() },ct));
            Assert.Equal("P0001",failure.SqlState);
            await tx.RollbackAsync(ct);
        }
        await using var check=new NpgsqlCommand("select used_at is null, enrolled_agent_id is null, (select count(*) from sli_agents where host_id=@host), (select count(*) from sli_agent_audit where actor='enrollment:' || @id::text) from sli_agent_enrollment_tokens where id=@id",c);
        check.Parameters.AddWithValue("id",id); check.Parameters.AddWithValue("host",host);
        await using var r=await check.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct));
        Assert.True(r.GetBoolean(0)); Assert.True(r.GetBoolean(1)); Assert.Equal(0L,r.GetInt64(2)); Assert.Equal(0L,r.GetInt64(3));
    }
    private static string Serial(X509Certificate2 certificate)
    {
        var bytes = certificate.GetSerialNumber(); Array.Reverse(bytes);
        return Convert.ToHexStringLower(bytes).TrimStart('0');
    }
    private static CertificateRequest CaRequest(string name, ECDsa key, int pathLength)
    {
        var r = new CertificateRequest(name, key, HashAlgorithmName.SHA256);
        r.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, pathLength, true));
        r.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        r.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, false));
        return r;
    }
}
