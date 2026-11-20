using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Auth;
using Xunit;

namespace Sli.Server.Tests.Domains;

public sealed class HstsTransportTests
{
    // Real TCP/TLS through Program's middleware. DomainHttpTests separately
    // exercises in-memory scheme decisions; setting Request.Scheme is not TLS evidence.
    [Theory]
    [InlineData("", null, false)]
    [InlineData("", "https", false)]
    [InlineData("127.0.0.1/32", null, false)]
    [InlineData("127.0.0.1/32", "https", true)]
    [InlineData("127.0.0.1/32", "http", false)]
    [InlineData("127.0.0.1/32", "duplicate", false)]
    [InlineData("127.0.0.1/32", "duplicate-https", false)]
    [InlineData("127.0.0.1/32", "https, http", false)]
    [InlineData("127.0.0.1/32", "invalid", false)]
    [InlineData("127.0.0.1/32", " HTTPS ", true)]
    [InlineData("192.0.2.0/24", "https", false)]
    public Task NativeHttpUsesOneEffectiveSchemeForAdmissionAndHsts(string proxies, string? forwarded, bool secure) =>
        VerifyNativeAsync(false, proxies, forwarded, secure);

    [Theory]
    [InlineData("", null, true)]
    [InlineData("", "http", true)]
    [InlineData("127.0.0.1/32", null, true)]
    [InlineData("127.0.0.1/32", "https", true)]
    [InlineData("127.0.0.1/32", "http", false)]
    [InlineData("127.0.0.1/32", "duplicate", true)]
    [InlineData("127.0.0.1/32", "duplicate-https", true)]
    [InlineData("127.0.0.1/32", "https, http", true)]
    [InlineData("127.0.0.1/32", "invalid", true)]
    [InlineData("192.0.2.0/24", "http", true)]
    [InlineData("192.0.2.0/24", "duplicate", true)]
    public Task NativeTlsUsesOneEffectiveSchemeForAdmissionAndHsts(string proxies, string? forwarded, bool secure) =>
        VerifyNativeAsync(true, proxies, forwarded, secure);

    private static async Task VerifyNativeAsync(bool tls, string proxies, string? forwarded, bool secure)
    {
        using var key = RSA.Create(2048);
        var certificateRequest = new CertificateRequest("CN=example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(IPAddress.Loopback);
        certificateRequest.CertificateExtensions.Add(san.Build());
        using var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        var authenticator = new DeniedAuthenticator();
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(Sli.Server.Tests.Domains.SafeTestEnvironment.ConfigureApiHost).WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sli:AuthRequired"] = "1", ["Sli:AuthAllowInsecureHttp"] = "1", ["Sli:TrustedProxies"] = proxies
            }));
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IPrincipalAuthenticator>();
                services.AddSingleton<IPrincipalAuthenticator>(authenticator);
            });
        });
        factory.UseKestrel(options => options.Listen(IPAddress.Loopback, 0, listener =>
        {
            if (tls) listener.UseHttps(certificate);
        }));
        var addresses = factory.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!;
        var address = new Uri(Assert.Single(addresses.Addresses));
        Assert.Equal(tls ? "https" : "http", address.Scheme);
        var ct = TestContext.Current.CancellationToken;

        bool admitted = secure || proxies.Length == 0;
        string response = await SendAsync(address, certificate, "/api/auth/me", forwarded, ct);
        Assert.StartsWith(admitted ? "HTTP/1.1 401 " : "HTTP/1.1 403 ", response);
        Assert.Contains(admitted ? "authentication_required" : "secure_transport_required", response);
        Assert.Equal(admitted ? 1 : 0, authenticator.Calls);
        AssertHsts(response, secure);

        // Anonymous redirects use the same header policy, including when an API
        // request on the very same physical transport would have been rejected.
        string redirect = await SendAsync(address, certificate, "/app/", forwarded, ct);
        Assert.StartsWith("HTTP/1.1 302 ", redirect);
        Assert.Contains("Location: /login?next=", redirect, StringComparison.OrdinalIgnoreCase);
        AssertHsts(redirect, secure);
    }

    private static void AssertHsts(string response, bool secure)
    {
        string[] headers = response.Split("\r\n\r\n", 2)[0].Split("\r\n");
        var hsts = headers.Where(line => line.StartsWith("Strict-Transport-Security:", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (secure)
            Assert.Equal("max-age=15552000; includeSubDomains", Assert.Single(hsts).Split(':', 2)[1].Trim());
        else
            Assert.Empty(hsts);
    }

    private static async Task<string> SendAsync(Uri address, X509Certificate2 certificate, string path, string? forwarded, CancellationToken ct)
    {
        using var socket = new TcpClient();
        await socket.ConnectAsync(IPAddress.Loopback, address.Port, ct);
        await using var network = socket.GetStream();
        using var tls = address.Scheme == "https" ? new SslStream(network, leaveInnerStreamOpen: true,
            (_, peer, _, errors) => peer is not null
                && (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) == SslPolicyErrors.None
                && peer.GetRawCertData().AsSpan().SequenceEqual(certificate.RawData)) : null;
        if (tls is not null)
        {
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = address.Host }, ct);
            Assert.True(tls.IsAuthenticated && tls.IsEncrypted);
        }
        Stream stream = tls is null ? network : tls;
        // Raw HTTP preserves two actual header lines instead of allowing an HTTP
        // client to combine duplicate XFP into a single comma-separated value.
        string proto = forwarded switch
        {
            null => "",
            "duplicate" => "X-Forwarded-Proto: https\r\nX-Forwarded-Proto: http\r\n",
            "duplicate-https" => "X-Forwarded-Proto: https\r\nX-Forwarded-Proto: https\r\n",
            _ => "X-Forwarded-Proto: " + forwarded + "\r\n"
        };
        byte[] request = Encoding.ASCII.GetBytes($"GET {path} HTTP/1.1\r\nHost: {address.Authority}\r\n{proto}Connection: close\r\n\r\n");
        await stream.WriteAsync(request, ct);
        using var reader = new StreamReader(stream, leaveOpen: true);
        return await reader.ReadToEndAsync(ct);
    }

    private sealed class DeniedAuthenticator : IPrincipalAuthenticator
    {
        public int Calls { get; private set; }
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct)
        {
            Calls++;
            return ValueTask.FromResult(AuthenticationResult.Denied(401, "authentication_required"));
        }
    }
}
