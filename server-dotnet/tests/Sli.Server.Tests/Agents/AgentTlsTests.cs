using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Security;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sli.Server.Hosting;
using Xunit;

namespace Sli.Server.Tests.Agents;

[Collection("Agent CA environment")]
public sealed class AgentTlsTests
{
    [Fact]
    public async Task OptionalClientCertificateAcceptsLeafOnlyFromTrustedIssuerAndRejectsForeignBeforeDispatch()
    {
        var ct = TestContext.Current.CancellationToken;
        using var rootKey = RSA.Create(2048);
        using var otherKey = RSA.Create(2048);
        using var secondKey = RSA.Create(2048);
        using var issuerKey = RSA.Create(2048);
        using var foreignIssuerKey = RSA.Create(2048);
        using var serverKey = RSA.Create(2048);
        using var clientKey = RSA.Create(2048);
        using var foreignKey = RSA.Create(2048);
        using var secondClientKey = RSA.Create(2048);
        using var root = Root(rootKey, "CN=Owned listener root");
        using var foreignRoot = Root(otherKey, "CN=Foreign listener root");
        using var secondRoot = Root(secondKey, "CN=Second listener root");
        using var issuer = Issuer(root, issuerKey);
        using var foreignIssuer = Issuer(foreignRoot, foreignIssuerKey);
        using var server = Leaf(root, serverKey, "CN=localhost", server: true);
        using var valid = Leaf(issuer, clientKey, "CN=valid client", server: false);
        using var invalid = Leaf(foreignIssuer, foreignKey, "CN=foreign client", server: false);
        using var validSecond = Leaf(secondRoot, secondClientKey, "CN=second client", server: false);
        string temp = Path.Combine(Path.GetTempPath(), "sli-agent-listener-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        string path = Path.Combine(temp, "listener-ca.pem");
        string issuerPath = Path.Combine(temp, "issuer.pem");
        await File.WriteAllTextAsync(path, root.ExportCertificatePem() + "\n" + secondRoot.ExportCertificatePem(), ct);
        await File.WriteAllTextAsync(issuerPath, issuer.ExportCertificatePem(), ct);
        await File.WriteAllTextAsync(Path.Combine(temp, "login.html"), "<html>synthetic login</html>", ct);
        string? priorCa = Environment.GetEnvironmentVariable("SLI_AGENT_MTLS_CA_FILE");
        string? priorIssuer = Environment.GetEnvironmentVariable("SLI_AGENT_CA_ISSUER_CERT_FILE");
        try
        {
            Environment.SetEnvironmentVariable("SLI_AGENT_MTLS_CA_FILE", path);
            Environment.SetEnvironmentVariable("SLI_AGENT_CA_ISSUER_CERT_FILE", issuerPath);
            using var host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
                builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Sli:AgentMtlsCaFile"] = path, ["Sli:WebRoot"] = temp, ["urls"] = "http://127.0.0.1:0", ["Sli:TrustedProxies"] = "",
                    ["Sli:AuthRequired"] = "1", ["Sli:OwnerSetup"] = "0", ["ConnectionStrings:Sli"] = ""
                }))).WithWebHostBuilder(b => b.ConfigureLogging(logging => logging.ClearProviders()).ConfigureServices(services => {
            foreach (var worker in services.Where(d => d.ServiceType == typeof(Microsoft.Extensions.Hosting.IHostedService)
                && (d.ImplementationType == typeof(Sli.Server.Workspace.DashboardWarmupService)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyJobWorker)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyScheduler)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyPostCollectionHostedService))).ToArray())
                services.Remove(worker);
        }));
            host.UseKestrel(options => options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(server)));
            host.StartServer();
            string address = Assert.Single(host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
            using var noCert = Client(address, null);
            Assert.Contains("synthetic login", await noCert.GetStringAsync("/login", ct));
            using var enrollmentBody = new StringContent("{}", Encoding.UTF8, "application/json");
            using var enrollment = await noCert.PostAsync("/api/v1/agent/enroll", enrollmentBody, ct);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, enrollment.StatusCode);
            using var noIdentity = await noCert.GetAsync("/api/v1/agent/identity", ct);
            Assert.Equal(HttpStatusCode.Unauthorized, noIdentity.StatusCode);
            using var trusted = Client(address, valid);
            using var identity = await trusted.GetAsync("/api/v1/agent/identity", ct);
            // The peer certificate reached the endpoint. This fixture has no PostgreSQL connection.
            Assert.Equal(HttpStatusCode.ServiceUnavailable, identity.StatusCode);
            using var trustedSecond = Client(address, validSecond);
            Assert.Equal(HttpStatusCode.OK, (await trustedSecond.GetAsync("/login", ct)).StatusCode);
            using var untrusted = Client(address, invalid);
            await Assert.ThrowsAsync<HttpRequestException>(() => untrusted.GetAsync("/login", ct));
            using var invalidBody = new StringContent("{}", Encoding.UTF8, "application/json");
            await Assert.ThrowsAsync<HttpRequestException>(() => untrusted.PostAsync("/api/v1/agent/enroll", invalidBody, ct));
        }
        finally
        {
            Environment.SetEnvironmentVariable("SLI_AGENT_CA_ISSUER_CERT_FILE", priorIssuer);
            Environment.SetEnvironmentVariable("SLI_AGENT_MTLS_CA_FILE", priorCa);
            Directory.Delete(temp, recursive: true);
        }
    }

    [Fact]
    public void ListenerPolicyBuildsTheLeafChainAndStartupRefusesAnUntrustedIssuer()
    {
        using var rootKey = RSA.Create(2048);
        using var foreignRootKey = RSA.Create(2048);
        using var issuerKey = RSA.Create(2048);
        using var foreignIssuerKey = RSA.Create(2048);
        using var leafKey = RSA.Create(2048);
        using var foreignLeafKey = RSA.Create(2048);
        using var root = Root(rootKey, "CN=Owned listener root");
        using var foreignRoot = Root(foreignRootKey, "CN=Foreign listener root");
        using var issuer = Issuer(root, issuerKey);
        using var foreignIssuer = Issuer(foreignRoot, foreignIssuerKey);
        using var leaf = Leaf(issuer, leafKey, "CN=valid client", server: false);
        using var foreignLeaf = Leaf(foreignIssuer, foreignLeafKey, "CN=foreign client", server: false);
        var temp = Directory.CreateTempSubdirectory("sli-agent-listener-");
        try
        {
            string rootPath = Path.Combine(temp.FullName, "root.pem");
            string issuerPath = Path.Combine(temp.FullName, "issuer.pem");
            File.WriteAllText(rootPath, root.ExportCertificatePem());
            File.WriteAllText(issuerPath, issuer.ExportCertificatePem());
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sli:AgentMtlsCaFile"] = rootPath,
                ["SLI_AGENT_CA_ISSUER_CERT_FILE"] = issuerPath
            }).Build();
            Assert.True(AgentTlsTrust.TryLoad(config, out var trust));
            Assert.NotNull(trust);
            using (trust)
            {
                var https = new HttpsConnectionAdapterOptions();
                var ssl = new SslServerAuthenticationOptions();
                trust.Configure(https);
                https.OnAuthenticate!(null!, ssl);
                using var chain = new X509Chain { ChainPolicy = ssl.CertificateChainPolicy! };
                Assert.True(chain.Build(leaf));
                Assert.False(chain.Build(foreignLeaf));
            }

            File.WriteAllText(issuerPath, foreignIssuer.ExportCertificatePem());
            Assert.False(AgentTlsTrust.TryLoad(config, out var rejected));
            Assert.Null(rejected);
        }
        finally { temp.Delete(recursive: true); }
    }

    private static HttpClient Client(string address, X509Certificate2? cert)
    {
        var handler = new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => true };
        if (cert is not null) handler.ClientCertificates.Add(cert);
        return new HttpClient(handler) { BaseAddress = new Uri(address) };
    }

    private static X509Certificate2 Root(RSA key, string name)
    {
        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(2));
    }

    private static X509Certificate2 Issuer(X509Certificate2 root, RSA key)
    {
        var request = new CertificateRequest("CN=Test agent issuer", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        using var issuer = request.Create(root, DateTimeOffset.UtcNow.AddMinutes(-3), DateTimeOffset.UtcNow.AddDays(1.5), RandomNumberGenerator.GetBytes(16));
        return issuer.CopyWithPrivateKey(key);
    }

    private static X509Certificate2 Leaf(X509Certificate2 issuer, RSA key, string name, bool server)
    {
        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var purposes = new OidCollection { new Oid(server ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(purposes, true));
        if (server) { var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("localhost"); request.CertificateExtensions.Add(san.Build()); }
        using var leaf = request.Create(issuer, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1), RandomNumberGenerator.GetBytes(16));
        return leaf.CopyWithPrivateKey(key);
    }
}
