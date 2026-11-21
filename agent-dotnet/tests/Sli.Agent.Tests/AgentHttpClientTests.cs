using System.Net;
using System.Net.Sockets;
using System.ComponentModel;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public class AgentHttpClientTests
{
    private sealed class StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        public List<(HttpMethod Method, string Path, string? ContentType, string Body)> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
            Requests.Add((request.Method, request.RequestUri!.AbsolutePath, request.Content?.Headers.ContentType?.ToString(), body));
            return await respond(request, cancellationToken);
        }
    }

    private static AgentHttpClient Client(StubHandler handler, bool clientCertificateConfigured = false) =>
        new(new HttpClient(handler) { BaseAddress = new Uri("https://core.example.test/") }, clientCertificateConfigured);

    private static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    [Fact]
    public async Task PostsThePacketInCanonicalFormToTheAgentEndpoint()
    {
        using var key = Helpers.NewKey();
        var packet = Packets.Make(Helpers.Signer(key), Helpers.AgentId, 1, Helpers.Sample("", "1"), Helpers.Now);
        var handler = new StubHandler((_, _) => Task.FromResult(Json("{\"status\":\"committed\"}")));
        using var client = Client(handler);
        var answer = await client.PostPacketAsync(packet, CancellationToken.None);
        Assert.Equal("committed", answer!["status"]!.GetValue<string>());
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("/api/v1/agent/packets", request.Path);
        Assert.Equal("application/json", request.ContentType);
        Assert.Equal(packet.ToCanonical(), request.Body);
    }

    [Fact]
    public async Task GetsTheCheckInWithoutABody()
    {
        var handler = new StubHandler((_, _) => Task.FromResult(Json("{\"agent_id\":\"x\"}")));
        using var client = Client(handler);
        Assert.Equal("x", (await client.GetAsync("/api/v1/agent/identity", CancellationToken.None))["agent_id"]!.GetValue<string>());
        Assert.Equal(HttpMethod.Get, handler.Requests[0].Method);
        Assert.Equal(string.Empty, handler.Requests[0].Body);
    }

    [Theory]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.Created)]
    public async Task UnknownServerErrorsExposeOnlyTheStatus(HttpStatusCode status)
    {
        using var client = Client(new StubHandler((_, _) => Task.FromResult(Json("{\"error\":\"agent_authentication_failed\"}", status))));
        var exception = await Assert.ThrowsAsync<TransportException>(() => client.PostAsync("/x", new JsonObject(), CancellationToken.None));
        Assert.Equal($"agent_server_rejected_{(int)status}", exception.Code);
        Assert.Equal($"Server returned HTTP {(int)status}.", exception.Detail);
        Assert.DoesNotContain("authentication", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("{\"error\":\"agent_instance_name_mismatch\"}", "agent_instance_name_mismatch")]
    [InlineData("{\"error\":\"agent_csr_key_mismatch\"}", "agent_csr_key_mismatch")]
    [InlineData("{\"error\":\"private host token\"}", "agent_server_rejected_400")]
    [InlineData("{\"error\":{\"secret\":true}}", "agent_server_rejected_400")]
    [InlineData("not json", "agent_server_rejected_400")]
    [InlineData("{\"error\":\"private\",\"error\":\"secret\"}", "agent_server_rejected_400")]
    public async Task ServerErrorsUseAFiniteAllowlist(string body, string expected)
    {
        using var client = Client(new StubHandler((_, _) => Task.FromResult(Json(body, HttpStatusCode.BadRequest))));
        var error = await Assert.ThrowsAsync<TransportException>(() => client.PostAsync("/api/v1/agent/enroll", new JsonObject(), CancellationToken.None));
        Assert.Equal(expected, error.Code);
        Assert.Equal(expected, error.Message);
        Assert.Equal("Server returned HTTP 400.", error.Detail);
        Assert.Null(error.InnerException);
    }

    [Fact]
    public async Task OversizedServerErrorExposesOnlyTheStatus()
    {
        using var client = Client(new StubHandler((_, _) => Task.FromResult(Json(new string('x', AgentHttpClient.MaxResponseBytes + 1), HttpStatusCode.BadRequest))));
        var error = await Assert.ThrowsAsync<TransportException>(() => client.GetAsync("/x", CancellationToken.None));
        Assert.Equal("agent_server_rejected_400", error.Code);
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("\"text\"")]
    [InlineData("not json")]
    [InlineData("")]
    public async Task OnlyAJsonObjectIsAnAnswer(string body)
    {
        using var client = Client(new StubHandler((_, _) => Task.FromResult(Json(body))));
        await Assert.ThrowsAsync<TransportException>(() => client.PostAsync("/x", new JsonObject(), CancellationToken.None));
    }

    [Fact]
    public async Task AnAnswerOverSixtyKilobytesIsRefused()
    {
        var big = "{\"filler\":\"" + new string('x', AgentHttpClient.MaxResponseBytes) + "\"}";
        using var client = Client(new StubHandler((_, _) => Task.FromResult(Json(big))));
        await Assert.ThrowsAsync<TransportException>(() => client.PostAsync("/x", new JsonObject(), CancellationToken.None));
    }

    [Fact]
    public async Task NetworkFailuresBecomeTheSameCode()
    {
        using var client = Client(new StubHandler((_, _) => throw new HttpRequestException("secret host details")));
        var exception = await Assert.ThrowsAsync<TransportException>(() => client.PostAsync("/x", new JsonObject(), CancellationToken.None));
        Assert.DoesNotContain("secret", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(unchecked((int)0x8009030E), "agent_tls_client_key_unusable")]
    [InlineData(unchecked((int)0x8009030D), "agent_tls_client_key_unusable")]
    [InlineData(unchecked((int)0x80090016), "agent_tls_client_key_unusable")]
    [InlineData(unchecked((int)0x8009000B), "agent_tls_client_key_unusable")]
    [InlineData(unchecked((int)0x80090325), "agent_tls_server_untrusted")]
    [InlineData(unchecked((int)0x800B0109), "agent_tls_server_untrusted")]
    [InlineData(unchecked((int)0x80090328), "agent_tls_server_expired")]
    [InlineData(unchecked((int)0x800B0101), "agent_tls_server_expired")]
    [InlineData(unchecked((int)0x80090327), "agent_tls_client_rejected")]
    [InlineData(unchecked((int)0x80090322), "agent_tls_name_mismatch")]
    [InlineData(unchecked((int)0x800B010F), "agent_tls_name_mismatch")]
    [InlineData(unchecked((int)0x80090326), "agent_transport_failed")]
    public async Task NestedNativeTlsErrorsBecomeSafeCodes(int nativeCode, string expected)
    {
        var failure = new HttpRequestException("secret URL and token",
            new AuthenticationException("private certificate details", new Win32Exception(nativeCode, "private key path")));
        using var client = Client(new StubHandler((_, _) => throw failure));
        var error = await Assert.ThrowsAsync<TransportException>(() => client.GetAsync("/x", CancellationToken.None));
        Assert.Equal(expected, error.Code);
        Assert.Equal(expected, error.Message);
        Assert.Null(error.InnerException);
    }

    [Theory]
    [InlineData(unchecked((int)0x80090325))]
    [InlineData(unchecked((int)0x80090328))]
    [InlineData(unchecked((int)0x80092010))]
    public async Task NativePeerTrustAlertsIdentifyTheClientCertificateOnMutualTls(int nativeCode)
    {
        var failure = new HttpRequestException(HttpRequestError.SecureConnectionError, "secret URL",
            new AuthenticationException("private TLS details", new Win32Exception(nativeCode)));
        using var client = Client(new StubHandler((_, _) => throw failure), clientCertificateConfigured: true);
        var error = await Assert.ThrowsAsync<TransportException>(() => client.GetAsync("/x", CancellationToken.None));
        Assert.Equal("agent_tls_client_rejected", error.Code);
        Assert.Equal("The server rejected the agent certificate during TLS.", error.Detail);
    }

    [Theory]
    [InlineData(SocketError.HostNotFound, "agent_dns_failed", "Could not resolve the server name.")]
    [InlineData(SocketError.ConnectionRefused, "agent_tcp_refused", "The server refused the TCP connection.")]
    [InlineData(SocketError.TimedOut, "agent_http_timeout", "The connection or response from the server timed out.")]
    public async Task SocketFailuresHaveSafeDetails(SocketError socketError, string code, string detail)
    {
        using var client = Client(new StubHandler((_, _) => throw new HttpRequestException("secret URL", new SocketException((int)socketError))));
        var error = await Assert.ThrowsAsync<TransportException>(() => client.GetAsync("/x", CancellationToken.None));
        Assert.Equal(code, error.Code);
        Assert.Equal(detail, error.Detail);
        Assert.Null(error.InnerException);
    }

    [Theory]
    [InlineData("Authentication failed because the remote party sent a TLS alert: 'BadCertificate'.", "agent_tls_client_rejected")]
    [InlineData("SSL routines:tlsv1 alert unknown ca", "agent_tls_client_rejected")]
    [InlineData("SSL routines:tlsv13 alert certificate required", "agent_tls_client_rejected")]
    [InlineData("Authentication failed because the remote party sent a TLS alert: 'HandshakeFailure'.", "agent_tls_handshake_failed")]
    public async Task OnlyExplicitPeerCertificateAlertsIdentifyClientCertificateRejection(string alert, string expected)
    {
        using var client = Client(new StubHandler((_, _) => throw new HttpRequestException(HttpRequestError.SecureConnectionError,
            "secret URL", new AuthenticationException("TLS failed", new CryptographicException(alert + " private certificate data")))));
        var error = await Assert.ThrowsAsync<TransportException>(() => client.GetAsync("/x", CancellationToken.None));
        Assert.Equal(expected, error.Code);
        Assert.DoesNotContain("private", error.Detail, StringComparison.Ordinal);
        Assert.Null(error.InnerException);
    }

    [Fact]
    public async Task NestedTimeoutHasItsOwnCode()
    {
        using var client = Client(new StubHandler((_, _) => throw new HttpRequestException("secret", new TimeoutException("private"))));
        var error = await Assert.ThrowsAsync<TransportException>(() => client.GetAsync("/x", CancellationToken.None));
        Assert.Equal("agent_http_timeout", error.Code);
        Assert.Null(error.InnerException);
    }

    [Theory]
    [InlineData("agent_tls_client_key_unusable", "agent_tls_client_key_unusable")]
    [InlineData("agent_tls_server_untrusted", "agent_tls_server_untrusted")]
    [InlineData("agent_tls_name_mismatch", "agent_tls_name_mismatch")]
    [InlineData("agent_tls_server_expired", "agent_tls_server_expired")]
    [InlineData("private certificate details", "agent_transport_failed")]
    public async Task ValidationCallbackDiagnosticsAreAllowlisted(string innerCode, string expected)
    {
        var failure = new HttpRequestException("secret", new AuthenticationException("private", new TransportException(innerCode)));
        using var client = Client(new StubHandler((_, _) => throw failure), clientCertificateConfigured: true);
        var error = await Assert.ThrowsAsync<TransportException>(() => client.GetAsync("/x", CancellationToken.None));
        Assert.Equal(expected, error.Message);
        Assert.Null(error.InnerException);
    }

    [Fact]
    public void AClientCertificateWithoutItsKeyHasAnActionableCode()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=synthetic", key, HashAlgorithmName.SHA256);
        using var original = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        using var certificate = X509CertificateLoader.LoadCertificate(original.RawData);
        Assert.Equal("agent_tls_client_key_unusable", Assert.Throws<TransportException>(() =>
            AgentHttp.Create(new Uri("https://localhost/"), certificate, [])).Code);
    }

    [Fact]
    public async Task ATimeoutIsAFailureButCancellationIsNot()
    {
        using var timeout = Client(new StubHandler((_, _) => throw new TaskCanceledException()));
        var error = await Assert.ThrowsAsync<TransportException>(() => timeout.PostAsync("/x", new JsonObject(), CancellationToken.None));
        Assert.Equal("agent_http_timeout", error.Code);
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        using var client = Client(new StubHandler((_, token) => Task.FromCanceled<HttpResponseMessage>(token)));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.PostAsync("/x", new JsonObject(), cancelled.Token));
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Conflict)]
    public async Task RejectedOrAlreadyUsedEnrollmentDoesNotLookLikeANetworkFailure(HttpStatusCode status)
    {
        using var client = Client(new StubHandler((_, _) => Task.FromResult(Json("private server response", status))));
        var error = await Assert.ThrowsAsync<TransportException>(() => client.PostAsync("/api/v1/agent/enroll", new JsonObject(), CancellationToken.None));
        Assert.Equal("agent_bootstrap_rejected", error.Code);
        Assert.Equal($"Server returned HTTP {(int)status}.", error.Detail);
        Assert.DoesNotContain("private", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/api/v1/agent/enroll")]
    [InlineData("/api/v1/agent/group-enroll")]
    [InlineData("/api/v1/agent/renew")]
    [InlineData("/api/v1/agent/identity")]
    [InlineData("/api/v1/agent/policy-report")]
    [InlineData("/api/v1/agent/packets")]
    [InlineData("/api/v1/agent/windows-audit-report")]
    public async Task EveryHttpCallTimesOutWhileWaitingForHeaders(string path)
    {
        var handler = new StubHandler(async (_, token) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return Json("{}");
        });
        using var client = new AgentHttpClient(new HttpClient(handler) { BaseAddress = new Uri("https://core.example.test/"), Timeout = TimeSpan.FromMilliseconds(50) });
        var call = path.EndsWith("/identity", StringComparison.Ordinal)
            ? client.GetAsync(path, CancellationToken.None) : client.PostAsync(path, new JsonObject(), CancellationToken.None);
        var error = await Assert.ThrowsAsync<TransportException>(() => call.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal("agent_http_timeout", error.Code);
    }

    [Fact]
    public async Task TheDeadlineIncludesReadingTheBodyAfterHeaders()
    {
        var handler = new StubHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new StreamContent(new StalledStream()) }));
        using var client = new AgentHttpClient(new HttpClient(handler) { BaseAddress = new Uri("https://core.example.test/"), Timeout = TimeSpan.FromMilliseconds(50) });
        var error = await Assert.ThrowsAsync<TransportException>(() =>
            client.GetAsync("/api/v1/agent/identity", CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal("agent_http_timeout", error.Code);
    }

    private sealed class StalledStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    [Theory]
    [InlineData("http://core.example.test/")]
    [InlineData("https://user:pw@core.example.test/")]
    [InlineData("https://core.example.test/path")]
    [InlineData("https://core.example.test/?q=1")]
    [InlineData("https://core.example.test/#f")]
    public void OnlyABareHttpsOriginIsAccepted(string url) =>
        Assert.Equal("agent_config_invalid", Assert.Throws<AgentException>(() => AgentHttp.Create(new Uri(url), null, [])).Code);

    [Fact]
    public void ABareHttpsOriginIsAccepted()
    {
        using var client = AgentHttp.Create(new Uri("https://core.example.test:8443/"), null, []);
        Assert.Equal(8443, client.BaseAddress!.Port);
        Assert.Equal(TimeSpan.FromSeconds(30), client.Timeout);
    }
}
