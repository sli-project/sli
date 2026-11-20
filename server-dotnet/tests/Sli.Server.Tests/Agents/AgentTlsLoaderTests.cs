using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Sli.Server.Hosting;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentTlsLoaderTests
{
    [Fact]
    public void InvalidListenerBundleReturnsSafeFailureAndValidBundleLoadsOnlyOnce()
    {
        string temp = Path.Combine(Path.GetTempPath(), "sli-tls-loader-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            IConfiguration Config(string path) => new ConfigurationBuilder().AddInMemoryCollection(
                new Dictionary<string, string?> { ["Sli:AgentMtlsCaFile"] = path }).Build();
            Assert.True(AgentTlsTrust.TryLoad(Config(""), out var disabled));
            Assert.Null(disabled);
            Assert.False(AgentTlsTrust.TryLoad(Config(Path.Combine(temp, "missing.pem")), out var missing));
            Assert.Null(missing);
            Assert.False(AgentTlsTrust.TryLoad(Config(temp), out var directory));
            Assert.Null(directory);
            string file = Path.Combine(temp, "ca.pem");
            File.WriteAllText(file, "not a certificate");
            Assert.False(AgentTlsTrust.TryLoad(Config(file), out var malformed));
            Assert.Null(malformed);
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=synthetic root", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
            using var root = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
            File.WriteAllText(file, root.ExportCertificatePem());
            var config = Config(file);
            Assert.True(AgentTlsTrust.TryLoad(config, out var loaded));
            Assert.NotNull(loaded);
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddSliIngress(config, loaded);
            File.Delete(file);
            using var provider = services.BuildServiceProvider();
            Assert.NotNull(provider.GetRequiredService<IOptions<KestrelServerOptions>>().Value);
            Assert.Same(loaded, provider.GetRequiredService<AgentTlsTrust>());
        }
        finally { Directory.Delete(temp, recursive: true); }
    }
}
