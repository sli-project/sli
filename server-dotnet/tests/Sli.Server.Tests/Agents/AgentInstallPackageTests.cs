using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Agents.Certificates;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Registry;
using Sli.Server.Infrastructure;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentInstallPackageTests
{
    [Fact]
    public async Task Personalizes_a_verified_msi_and_refuses_a_different_source_digest()
    {
        RequireMsiTools();
        var ct = TestContext.Current.CancellationToken;
        var temp = Directory.CreateTempSubdirectory("sli-installer-test-");
        try
        {
            var source = Path.Combine(temp.FullName, "release.msi");
            await StageSourceAsync(source, "1.2.3", ct);
            var digest = await AgentInstallPackage.DigestAsync(source, ct);
            var origin = new Uri("https://agents.example.test/");
            var input = new AgentConsolePackage(origin, "test-public-ca", new string('a', 64), digest, "1.2.3");
            var output = Path.Combine(temp.FullName, "site.msi");
            var token = new string('b', 43);
            await AgentInstallPackage.BuildAsync(source, output, input, token, ct);
            var properties = await AgentInstallPackage.ExportPropertiesAsync(output, ct);
            Assert.Equal(origin.AbsoluteUri, properties["SERVER_URL"]);
            Assert.Equal(input.Pin, properties["CA_FINGERPRINT"]);
            Assert.Equal(input.Root, properties["SERVER_CA"]);
            Assert.Equal(token, properties["ENROLL_TOKEN"]);
            Assert.Equal("Test Agent (agents.example.test)", properties["ProductName"]);
            Assert.Equal(digest, await AgentInstallPackage.DigestAsync(source, ct));
            await Assert.ThrowsAsync<InvalidDataException>(() => AgentInstallPackage.BuildAsync(source,
                Path.Combine(temp.FullName, "unverified.msi"), input with { Digest = new string('0', 64) }, token, ct));
        }
        finally { temp.Delete(recursive: true); }
    }

    [Fact]
    public async Task Native_startup_prepares_install_and_upgrade_and_revocation_replaces_the_key()
    {
        RequireMsiTools();
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);

        string release = Path.Combine(fixture.Pg.Root, "release.msi");
        string updated = Path.Combine(fixture.Pg.Root, "updated.msi");
        string data = Path.Combine(fixture.Pg.Root, "site");
        string caPath = Path.Combine(fixture.Pg.Root, "fixture-ca.crt");
        string certificatePath = Path.Combine(fixture.Pg.Root, "fixture-server.crt");
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootRequest = new CertificateRequest("CN=Test CA", rootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        using var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(2));
        var issuerRequest = new CertificateRequest("CN=Test issuer", issuerKey, HashAlgorithmName.SHA256);
        issuerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        issuerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        using var issuer = issuerRequest.Create(root, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(1), RandomNumberGenerator.GetBytes(16));
        var serverRequest = new CertificateRequest("CN=agents.example.test", serverKey, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddDnsName("agents.example.test");
        serverRequest.CertificateExtensions.Add(san.Build());
        using var server = serverRequest.Create(root, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(1), RandomNumberGenerator.GetBytes(16));
        await File.WriteAllTextAsync(caPath, root.ExportCertificatePem(), ct);
        await File.WriteAllTextAsync(certificatePath, server.ExportCertificatePem(), ct);
        await StageSourceAsync(release, "1.2.3", ct);
        await StageSourceAsync(updated, "1.2.4", ct);
        using var configuration = new ConfigurationManager();
        configuration.AddInMemoryCollection(new Dictionary<string, string?> {
            ["SLI_DEPLOYMENT_MODE"] = "native", ["SLI_AGENT_CA_ROOT_CERT_FILE"] = caPath,
            ["Sli:AgentServerCaFile"] = caPath, ["Sli:AgentInstallerPath"] = release, ["Sli:DataDirectory"] = data,
            ["Kestrel:Certificates:Default:Path"] = certificatePath, ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user"),
        });
        var audit = new AgentControlAudit();
        var packages = new AgentInstallPackages(configuration, audit);
        var factory = new PostgresConnectionFactory(configuration);
        string CurrentMsi() => Assert.Single(Directory.GetFiles(data, "*.msi", SearchOption.AllDirectories));

        await packages.PrepareOnStartupAsync(factory, ct);
        string first = CurrentMsi();
        Assert.Equal("SLI-Agent-agents.example.test-1.2.3.msi", Path.GetFileName(first));
        var before = await AgentInstallPackage.ExportPropertiesAsync(first, ct);
        Assert.Equal("https://agents.example.test/", before["SERVER_URL"]);

        configuration["Sli:AgentInstallerPath"] = updated;
        await packages.PrepareOnStartupAsync(factory, ct);
        string next = CurrentMsi();
        Assert.Equal("SLI-Agent-agents.example.test-1.2.4.msi", Path.GetFileName(next));
        Assert.False(File.Exists(first));
        Assert.True(before["ENROLL_TOKEN"] == (await AgentInstallPackage.ExportPropertiesAsync(next, ct))["ENROLL_TOKEN"]);
        File.Delete(next);
        await packages.PrepareOnStartupAsync(factory, ct);
        next = CurrentMsi();
        Assert.True(before["ENROLL_TOKEN"] == (await AgentInstallPackage.ExportPropertiesAsync(next, ct))["ENROLL_TOKEN"]);

        await using var db = await factory.OpenAsync(ct);
        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            var keys = await new AgentManagementService(audit).ListConsoleTokensAsync(db, tx, "synthetic", ct);
            var id = Assert.Single(keys.GetProperty("items").EnumerateArray()).GetProperty("id").GetGuid();
            var prepared = await packages.PrepareAsync(db, tx, default, id, "synthetic", ct);
            await tx.CommitAsync(ct);
            AgentInstallPackages.DeleteRetiredFiles(prepared.RetiredMsi, prepared.RetiredKey);
        }
        Assert.False(File.Exists(next));
        var after = await AgentInstallPackage.ExportPropertiesAsync(CurrentMsi(), ct);
        Assert.False(before["ENROLL_TOKEN"] == after["ENROLL_TOKEN"]);

        using var ca = new AgentIssuingCa(new X509Certificate2(root), issuer.CopyWithPrivateKey(issuerKey));
        var enrollment = new AgentEnrollmentService(ca, new AgentIdentityService(ca));
        using var hostKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new JsonObject {
            ["token"] = before["ENROLL_TOKEN"], ["reported_hostname"] = "new.example.test", ["machine_role"] = "file_server",
            ["csr_pem"] = new CertificateRequest($"CN={Guid.NewGuid()}", hostKey, HashAlgorithmName.SHA256).CreateSigningRequestPem(),
        };
        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            var error = await Assert.ThrowsAsync<AgentCertificateException>(() => enrollment.EnrollAsync(db, tx, request, ct));
            Assert.Equal("enrollment_token_rejected", error.Code);
            await tx.RollbackAsync(ct);
        }
        await using (var tx = await db.BeginTransactionAsync(ct))
        {
            await AgentEnrollmentService.RecordRejectionAsync(db, tx, request, "enrollment_token_rejected", IPAddress.Parse("192.0.2.40"), ct);
            var inventory = await new AgentManagementService(audit).ListAgentsAsync(db, tx, null, "synthetic", ct);
            Assert.Equal("enrollment_token_revoked", Assert.Single(inventory.GetProperty("rejected_enrollments").EnumerateArray()).GetProperty("reason").GetString());
            request["token"] = after["ENROLL_TOKEN"];
            Assert.NotNull((await enrollment.EnrollAsync(db, tx, request, ct))["agent_id"]);
            await tx.CommitAsync(ct);
        }
    }

    [Fact]
    public async Task Installer_migration_applies_after_the_predecessor_and_rolls_back()
    {
        var ct = TestContext.Current.CancellationToken;
        var migrations = MigrationDirectory.Read();
        var installer = Assert.Single(migrations, m => m.Version == 446);
        int predecessor = migrations.Where(m => m.Version < installer.Version).Max(m => m.Version);
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: predecessor);
        await fixture.Pg.ApplyFileAsync(installer.Path, null, ct);
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(installer.Path, ".rollback.sql"), null, ct);
        await fixture.Pg.ApplyFileAsync(installer.Path, null, ct);
        await using var app = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await app.OpenAsync(ct);
        await using var check = new NpgsqlCommand("""
            select has_column_privilege(current_user, 'sli_agent_console_tokens', 'installer', 'UPDATE')
                and has_column_privilege(current_user, 'sli_agents', 'machine_role', 'UPDATE')
            """, app);
        Assert.True(Assert.IsType<bool>(await check.ExecuteScalarAsync(ct)));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    private static void RequireMsiTools() => Assert.SkipUnless(
        OperatingSystem.IsLinux() && File.Exists("/usr/bin/msibuild") && File.Exists("/usr/bin/msiinfo"), "Requires Debian msitools");

    internal static async Task StageSourceAsync(string path, string version, CancellationToken ct)
    {
        string table = Path.Combine(Path.GetDirectoryName(path)!, "Property.idt");
        await File.WriteAllTextAsync(table, "Property\tValue\r\ns72\tl0\r\nProperty\tProperty\r\n"
            + $"ProductName\tTest Agent\r\nProductVersion\t{version}\r\n", ct);
        try
        {
            using var process = Process.Start(new ProcessStartInfo("/usr/bin/msibuild") {
                ArgumentList = { path, "-i", table },
            })!;
            await process.WaitForExitAsync(ct);
            Assert.Equal(0, process.ExitCode);
        }
        finally { File.Delete(table); }
        string digest = await AgentInstallPackage.DigestAsync(path, ct);
        await File.WriteAllTextAsync(path + ".json", JsonSerializer.Serialize(new { product_version = version, sha256 = digest }), ct);
    }
}
