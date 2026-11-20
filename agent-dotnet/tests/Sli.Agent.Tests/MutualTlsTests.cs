using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

/// <summary>
/// A loopback server with its own CA: the agent must trust only the configured CA, check the server name and present
/// its client certificate (the server derives the agent's identity and the signature key from it).
/// </summary>
public sealed class MutualTlsTests : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly List<IDisposable> _disposables = [];
    private readonly CancellationTokenSource _stop = new();

    public MutualTlsTests() => _listener.Start();

    public void Dispose()
    {
        _stop.Cancel();
        _listener.Stop();
        foreach (var item in Enumerable.Reverse(_disposables)) item.Dispose();
        _stop.Dispose();
    }

    private int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    private X509Certificate2 Own(X509Certificate2 value)
    {
        _disposables.Add(value);
        return value;
    }

    private X509Certificate2 NewCa(string name = "Test CA")
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _disposables.Add(key);
        var request = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        return Own(request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30)));
    }

    private X509Certificate2 Issue(X509Certificate2 ca, string subject, string usage, string? dns)
    {
        ECDsa key;
        if (OperatingSystem.IsWindows() && usage == "1.3.6.1.5.5.7.3.1")
        {
            // Keep the synthetic server certificate only in memory. Schannel still requires
            // a named OS key; create/delete a test-only machine CNG container, without PFX
            // import, X509Store writes or a user profile.
            var container = CngKey.Create(CngAlgorithm.ECDsaP256, "sli-mtls-test-" + Guid.NewGuid().ToString("N"),
                new CngKeyCreationParameters { KeyCreationOptions = CngKeyCreationOptions.MachineKey });
            _disposables.Add(new TemporaryServerKey(container));
            key = new ECDsaCng(container);
        }
        else key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _disposables.Add(key);
        var request = new CertificateRequest("CN=" + subject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(usage)], true));
        if (dns is not null)
        {
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName(dns);
            request.CertificateExtensions.Add(names.Build());
        }
        var serial = new byte[8];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7F;
        using var signed = request.Create(ca, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(7), serial);
        return Own(signed.CopyWithPrivateKey(key));
    }

    [SupportedOSPlatform("windows")]
    private sealed class TemporaryServerKey(CngKey key) : IDisposable
    {
        public void Dispose()
        {
            try { key.Delete(); }
            finally { key.Dispose(); }
        }
    }

    /// <summary>Serves one request; only an explicitly expected TLS rejection may return null.</summary>
    private async Task<(string? ClientThumbprint, string Body)?> ServeOnce(X509Certificate2 server, X509Certificate2 clientTrust,
        bool expectRejection = false)
    {
        var stage = "TCP accept";
        var validationFailure = "client certificate not validated";
        try
        {
            using var tcp = await _listener.AcceptTcpClientAsync(_stop.Token);
            using var ssl = new SslStream(tcp.GetStream());
            string? thumbprint = null;
            stage = "TLS handshake";
            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = server,
                ClientCertificateRequired = true,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                {
                    if (certificate is null)
                    {
                        validationFailure = "client certificate missing";
                        return false;
                    }
                    using var chain = new X509Chain();
                    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    chain.ChainPolicy.CustomTrustStore.Add(clientTrust);
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.DisableCertificateDownloads = true;
                    chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
                    using var leaf = new X509Certificate2(certificate);
                    thumbprint = leaf.Thumbprint;
                    var trusted = chain.Build(leaf);
                    validationFailure = trusted ? "client certificate validated"
                        : string.Join(", ", chain.ChainStatus.Select(status => status.Status));
                    return trusted;
                },
            }, _stop.Token);
            stage = "HTTP request/response";
            var buffer = new MemoryStream();
            var chunk = new byte[4096];
            int headerEnd;
            string text;
            do
            {
                var read = await ssl.ReadAsync(chunk, _stop.Token);
                if (read == 0) throw new IOException("Client closed before the HTTP headers.");
                buffer.Write(chunk, 0, read);
                text = Encoding.ASCII.GetString(buffer.ToArray());
                headerEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            }
            while (headerEnd < 0);
            var contentLength = System.Text.RegularExpressions.Regex.Match(text, @"(?i)content-length:\s*(\d+)");
            var length = contentLength.Success ? int.Parse(contentLength.Groups[1].Value) : 0;
            while (buffer.Length < headerEnd + 4 + length)
            {
                var read = await ssl.ReadAsync(chunk, _stop.Token);
                if (read == 0) throw new IOException("Client closed before the HTTP body.");
                buffer.Write(chunk, 0, read);
            }
            var body = Encoding.ASCII.GetString(buffer.ToArray())[(headerEnd + 4)..];
            var answer = Encoding.ASCII.GetBytes("{\"status\":\"committed\"}");
            await ssl.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {answer.Length}\r\nConnection: close\r\n\r\n"), _stop.Token);
            await ssl.WriteAsync(answer, _stop.Token);
            await ssl.FlushAsync(_stop.Token);
            return (thumbprint, body);
        }
        catch (Exception exception) when (exception is AuthenticationException or IOException or OperationCanceledException or SocketException)
        {
            if (expectRejection && exception is (AuthenticationException or IOException)) return null;
            throw new InvalidOperationException($"mTLS test server failed during {stage}: {validationFailure}.", exception);
        }
        finally
        {
            // A one-shot server is dead after this exchange. In particular, a GET retry after
            // a TLS 1.3 rejection must not connect to an unserviced listener backlog.
            _listener.Stop();
        }
    }

    private async Task<JsonObject> Exchange(Task<JsonObject> request, Task<(string? ClientThumbprint, string Body)?> served)
    {
        try
        {
            await Task.WhenAny(request, served);
            if (served.IsFaulted) await served;
            var answer = await request;
            await served;
            return answer;
        }
        finally
        {
            // Observe the server's failure immediately and stop/observe the other operation.
            // There is no test deadline; the production AgentHttp.Timeout remains unchanged.
            _stop.Cancel();
            try { await Task.WhenAll(request, served); }
            catch (Exception) { /* Preserve the original failure from the exchange. */ }
        }
    }

    private AgentHttpClient Client(X509Certificate2? client, params X509Certificate2[] roots) =>
        new(AgentHttp.Create(new Uri($"https://localhost:{Port}/"), client, [.. roots]));

    [Fact]
    public async Task ATrustedServerAndAPresentedClientCertificateExchangeJson()
    {
        var ca = NewCa();
        var server = Issue(ca, "localhost", "1.3.6.1.5.5.7.3.1", "localhost");
        var client = Issue(ca, "agent", "1.3.6.1.5.5.7.3.2", null);
        var served = ServeOnce(server, ca);
        using var http = Client(client, ca);
        var answer = await Exchange(http.PostAsync("/api/v1/agent/packets", new JsonObject { ["hello"] = "world" }, _stop.Token), served);
        Assert.Equal("committed", answer["status"]!.GetValue<string>());
        var seen = await served;
        Assert.Equal(client.Thumbprint, seen!.Value.ClientThumbprint);
        Assert.Equal("{\"hello\":\"world\"}", seen.Value.Body);
    }

    [Fact]
    public async Task AServerFromAnotherCaIsNotTrusted()
    {
        var ca = NewCa();
        var rogue = NewCa("Rogue CA");
        var server = Issue(rogue, "localhost", "1.3.6.1.5.5.7.3.1", "localhost");
        var client = Issue(ca, "agent", "1.3.6.1.5.5.7.3.2", null);
        var served = ServeOnce(server, ca, expectRejection: true);
        using var http = Client(client, ca);
        var error = await Assert.ThrowsAsync<TransportException>(() => http.PostAsync("/x", new JsonObject(), _stop.Token));
        Assert.Equal("agent_tls_server_untrusted", error.Code);
        await served;
    }

    [Fact]
    public async Task AServerCertificateForAnotherNameIsRefusedEvenFromTheRightCa()
    {
        var ca = NewCa();
        var server = Issue(ca, "other.example.test", "1.3.6.1.5.5.7.3.1", "other.example.test");
        var client = Issue(ca, "agent", "1.3.6.1.5.5.7.3.2", null);
        var served = ServeOnce(server, ca, expectRejection: true);
        using var http = Client(client, ca);
        var error = await Assert.ThrowsAsync<TransportException>(() => http.PostAsync("/x", new JsonObject(), _stop.Token));
        Assert.Equal("agent_tls_name_mismatch", error.Code);
        await served;
    }

    [Fact]
    public async Task WithoutAClientCertificateTheServerDoesNotAnswer()
    {
        var ca = NewCa();
        var server = Issue(ca, "localhost", "1.3.6.1.5.5.7.3.1", "localhost");
        var served = ServeOnce(server, ca, expectRejection: true);
        using var http = Client(null, ca);
        await Assert.ThrowsAsync<TransportException>(() => http.PostAsync("/x", new JsonObject(), _stop.Token));
        Assert.Null(await served);
    }

    [Fact]
    public async Task AClientCertificateFromAnUntrustedCaIsRefusedByTheServer()
    {
        var ca = NewCa();
        var rogue = NewCa("Rogue CA");
        var server = Issue(ca, "localhost", "1.3.6.1.5.5.7.3.1", "localhost");
        var client = Issue(rogue, "agent", "1.3.6.1.5.5.7.3.2", null);
        var served = ServeOnce(server, ca, expectRejection: true);
        using var http = Client(client, ca);
        await Assert.ThrowsAsync<TransportException>(() => http.PostAsync("/x", new JsonObject(), _stop.Token));
        Assert.Null(await served);
    }

    [Fact]
    public async Task AnIdentityReloadedAfterEnrollmentCanUseMutualTls()
    {
        var directory = Helpers.TempDirectory();
        try
        {
            // HostIdentityStore accepts a supplied clock; SslStream/OpenSSL uses wall time.
            // Keep deterministic enrollment fixtures elsewhere, but issue live TLS certificates now.
            var now = DateTimeOffset.UtcNow;
            using var authority = new TestAuthority(now);
            var store = new HostIdentityStore(directory, new PhysicalDurableFiles(), new RestrictedFileKeyProtector());
            store.Prepare();
            using (store.Accept(authority.Issue(store), now)) { }
            using var identity = store.Load()!;
            var server = Issue(authority.Root, "localhost", "1.3.6.1.5.5.7.3.1", "localhost");
            var served = ServeOnce(server, authority.Root);
            using var http = Client(identity.Certificate, authority.Root);
            await Exchange(http.GetAsync("/api/v1/agent/identity", _stop.Token), served);
            Assert.Equal(identity.Certificate.Thumbprint, (await served)!.Value.ClientThumbprint);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Theory]
    [InlineData(2026)]
    [InlineData(2036)]
    public void AReloadedIdentityIsValidAtItsIssuingClockAndExpiresAfterThirtyDays(int year)
    {
        var now = new DateTimeOffset(year, 10, 7, 12, 0, 0, TimeSpan.Zero);
        var directory = Helpers.TempDirectory();
        try
        {
            using var authority = new TestAuthority(now);
            var store = new HostIdentityStore(directory, new PhysicalDurableFiles(), new RestrictedFileKeyProtector());
            store.Prepare();
            using (store.Accept(authority.Issue(store), now)) { }
            using var identity = store.Load()!;
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(authority.Root);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
            chain.ChainPolicy.VerificationTime = now.UtcDateTime;
            Assert.True(chain.Build(identity.Certificate));
            Assert.Equal(now.AddDays(30).UtcDateTime, identity.Certificate.NotAfter.ToUniversalTime());
            // Reproduces the 7 Nov rejection of the certificate issued at Helpers.Now (7 Oct).
            chain.ChainPolicy.VerificationTime = now.AddDays(31).UtcDateTime;
            Assert.False(chain.Build(identity.Certificate));
            Assert.Contains(chain.ChainStatus, status => status.Status == X509ChainStatusFlags.NotTimeValid);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public async Task AServerFailureCancelsThePendingRequestAndReportsTheCause()
    {
        var pending = new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var registration = _stop.Token.Register(() => pending.TrySetCanceled(_stop.Token));
        var failure = new InvalidOperationException("mTLS test server failed during TLS handshake: NotTimeValid.");
        var served = new TaskCompletionSource<(string? ClientThumbprint, string Body)?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var exchange = Exchange(pending.Task, served.Task);
        Assert.False(exchange.IsCompleted);
        served.SetException(failure);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => exchange);
        Assert.Same(failure, error);
        Assert.True(pending.Task.IsCanceled);
    }
}
