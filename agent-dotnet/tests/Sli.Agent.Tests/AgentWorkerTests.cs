using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sli.Agent.Service;
using Sli.Agent.Core;
using System.ComponentModel;
using System.Security.Authentication;
using System.Text.Json.Nodes;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class AgentWorkerTests
{
    private sealed class CertificateHandler(JsonObject response, System.Net.HttpStatusCode status = System.Net.HttpStatusCode.OK) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(response.ToJsonString()) });
    }

    [Theory]
    [InlineData("shape", "agent_certificate_invalid_shape")]
    [InlineData("key", "agent_certificate_invalid_key_mismatch")]
    [InlineData("ca", "agent_certificate_invalid_ca_flag")]
    [InlineData("key_usage", "agent_certificate_invalid_key_usage")]
    [InlineData("missing_eku", "agent_certificate_invalid_eku")]
    [InlineData("reversed_san", "agent_certificate_invalid_san")]
    [InlineData("signature", "agent_certificate_invalid_issuer_chain")]
    [InlineData("future", "agent_certificate_invalid_validity")]
    [InlineData("chain_build", "agent_certificate_invalid_chain_build")]
    public async Task CertificateDiagnosticsReachWarningAndLastCycleWithoutSecrets(string defect, string expected)
    {
        var directory = Helpers.TempDirectory();
        try
        {
            var options = new AgentOptions { ServerUrl = "https://synthetic.example.test/", StateDir = Path.Combine(directory, "state"), TokenFile = Path.Combine(directory, "token") };
            File.WriteAllText(options.TokenFile, new string('t', 43));
            File.SetLastWriteTimeUtc(options.TokenFile, Helpers.Now.UtcDateTime);
            var store = AgentRuntime.CreateIdentityStore(options);
            store.Prepare();
            var keyBefore = File.ReadAllBytes(Path.Combine(options.StateDir, "identity-key.json"));
            using var server = new ServerAuthority(defect);
            var response = server.Issue(store, defect);
            if (defect == "shape") response["agent_id"] = "private invalid subject";
            if (defect == "key")
            {
                var other = new HostIdentityStore(Path.Combine(directory, "other"), new PhysicalDurableFiles(), new RestrictedFileKeyProtector());
                other.Prepare(store.ReadHostId());
                response = server.Issue(other);
            }
            using var runtime = new AgentRuntime(Options.Create(options), new TestClock(), _ =>
                new AgentHttpClient(new HttpClient(new CertificateHandler(response)) { BaseAddress = new Uri(options.ServerUrl) }));
            var logger = new RecordingLogger();
            using var worker = new AgentWorker(runtime, logger);
            await worker.StartAsync(CancellationToken.None);
            var logged = await logger.Entry.Task.WaitAsync(TimeSpan.FromSeconds(5));
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await worker.StopAsync(stop.Token);
            Assert.Equal(LogLevel.Warning, logged.Level);
            Assert.Contains(expected, logged.Message, StringComparison.Ordinal);
            Assert.Null(logged.Exception);
            var raw = File.ReadAllText(Path.Combine(options.StateDir, "last-cycle.json"));
            Assert.Equal(expected, JsonNode.Parse(raw)!["error_code"]!.GetValue<string>());
            Assert.False(JsonNode.Parse(raw)!["collection_active"]!.GetValue<bool>());
            Assert.False(File.Exists(Path.Combine(options.StateDir, "identity.json")));
            Assert.Equal(keyBefore, File.ReadAllBytes(Path.Combine(options.StateDir, "identity-key.json")));
            foreach (var secret in new[] { "private", "CERTIFICATE", directory, store.ReadHostId(), Helpers.AgentId, "synthetic.example.test", new string('t', 43) })
            {
                Assert.DoesNotContain(secret, logged.Message, StringComparison.Ordinal);
                Assert.DoesNotContain(secret, raw, StringComparison.Ordinal);
            }
        }
        finally { Directory.Delete(directory, true); }
    }

    [Theory]
    [InlineData("invalid_agent_registration_name", true)]
    [InlineData("synthetic_private_response", false)]
    public async Task EnrollmentWarningIncludesOnlyRecognizedServerReasons(string reason, bool recognized)
    {
        var directory = Helpers.TempDirectory();
        try
        {
            var options = new AgentOptions { ServerUrl = "https://synthetic.example.test/", StateDir = Path.Combine(directory, "state"), TokenFile = Path.Combine(directory, "token") };
            var token = new string('t', 43);
            File.WriteAllText(options.TokenFile, token);
            File.SetLastWriteTimeUtc(options.TokenFile, Helpers.Now.UtcDateTime);
            var response = new JsonObject { ["error"] = reason, ["token"] = token };
            using var runtime = new AgentRuntime(Options.Create(options), new TestClock(), _ =>
                new AgentHttpClient(new HttpClient(new CertificateHandler(response, System.Net.HttpStatusCode.BadRequest))
                    { BaseAddress = new Uri(options.ServerUrl) }));
            var logger = new RecordingLogger();
            using var worker = new AgentWorker(runtime, logger);
            await worker.StartAsync(CancellationToken.None);
            var logged = await logger.Entry.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await worker.StopAsync(CancellationToken.None);
            Assert.Equal(LogLevel.Warning, logged.Level);
            Assert.Contains("agent_server_rejected_400", logged.Message, StringComparison.Ordinal);
            if (recognized)
                Assert.Contains("agent_server_rejected_400 " + reason, logged.Message, StringComparison.Ordinal);
            else
                Assert.DoesNotContain(reason, logged.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(token, logged.Message, StringComparison.Ordinal);
            Assert.Null(logged.Exception);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public async Task LogsOnlyWhenTheTransportReasonChanges()
    {
        var directory = Helpers.TempDirectory();
        try
        {
            var options = new AgentOptions { ServerUrl = "https://synthetic.example.test/", StateDir = Path.Combine(directory, "state"), TokenFile = Path.Combine(directory, "token") };
            File.WriteAllText(options.TokenFile, new string('t', 43));
            File.SetLastWriteTimeUtc(options.TokenFile, Helpers.Now.UtcDateTime);
            using var handler = new ChangingFailureHandler();
            using var runtime = new AgentRuntime(Options.Create(options), new TestClock(), _ =>
                new AgentHttpClient(new HttpClient(handler, disposeHandler: false) { BaseAddress = new Uri(options.ServerUrl) }));
            var logger = new RecordingLogger();
            using var worker = new AgentWorker(runtime, logger);
            await worker.StartAsync(CancellationToken.None);
            var first = await logger.Entry.Task.WaitAsync(TimeSpan.FromSeconds(5));
            var second = await logger.SecondEntry.Task.WaitAsync(TimeSpan.FromSeconds(12));
            await worker.StopAsync(CancellationToken.None);
            Assert.Contains("agent_dns_failed", first.Message, StringComparison.Ordinal);
            Assert.Contains("agent_tcp_refused", second.Message, StringComparison.Ordinal);
            Assert.Equal("The server refused the TCP connection.", JsonNode.Parse(File.ReadAllText(
                Path.Combine(options.StateDir, "status.json")))!["error_detail"]!.GetValue<string>());
        }
        finally { Directory.Delete(directory, true); }
    }

    private sealed class ChangingFailureHandler : HttpMessageHandler
    {
        private int attempts;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var code = ++attempts <= 2 ? System.Net.Sockets.SocketError.HostNotFound : System.Net.Sockets.SocketError.ConnectionRefused;
            throw new HttpRequestException("synthetic", new System.Net.Sockets.SocketException((int)code));
        }
    }

    private sealed class FailingHandler(Exception failure) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => throw failure;
    }

    [Theory]
    [InlineData(unchecked((int)0x8009030E), "agent_tls_client_key_unusable")]
    [InlineData(unchecked((int)0x80090325), "agent_tls_server_untrusted")]
    [InlineData(unchecked((int)0x80090322), "agent_tls_name_mismatch")]
    [InlineData(-1, "agent_http_timeout")]
    [InlineData(0, "agent_transport_failed")]
    public async Task TransportDiagnosticsReachWarningAndStatusWithoutSecrets(int nativeCode, string expected)
    {
        var directory = Helpers.TempDirectory();
        try
        {
            var options = new AgentOptions { ServerUrl = "https://synthetic.example.test/", StateDir = Path.Combine(directory, "state"), TokenFile = Path.Combine(directory, "token") };
            File.WriteAllText(options.TokenFile, new string('t', 43));
            File.SetLastWriteTimeUtc(options.TokenFile, Helpers.Now.UtcDateTime);
            Exception inner = nativeCode == -1 ? new TimeoutException("private timeout details")
                : new AuthenticationException("private certificate", new Win32Exception(nativeCode, "private key path"));
            using var runtime = new AgentRuntime(Options.Create(options), new TestClock(), _ =>
                new AgentHttpClient(new HttpClient(new FailingHandler(new HttpRequestException("secret URL and token", inner))) { BaseAddress = new Uri(options.ServerUrl) }));
            var logger = new RecordingLogger();
            using var worker = new AgentWorker(runtime, logger);
            await worker.StartAsync(CancellationToken.None);
            var logged = await logger.Entry.Task.WaitAsync(TimeSpan.FromSeconds(5));
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await worker.StopAsync(stop.Token);
            Assert.Equal(LogLevel.Warning, logged.Level);
            Assert.Contains(expected, logged.Message, StringComparison.Ordinal);
            Assert.Null(logged.Exception);
            var raw = File.ReadAllText(Path.Combine(options.StateDir, "status.json"));
            var status = JsonNode.Parse(raw)!;
            Assert.Equal(expected, status["error_code"]!.GetValue<string>());
            Assert.Contains(status["error_detail"]!.GetValue<string>(), logged.Message, StringComparison.Ordinal);
            foreach (var secret in new[] { "private certificate", "private key path", "secret", directory, "synthetic.example.test", new string('t', 43) })
            {
                Assert.DoesNotContain(secret, logged.Message, StringComparison.Ordinal);
                Assert.DoesNotContain(secret, raw, StringComparison.Ordinal);
            }
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public async Task EachFailedCycleIsLoggedAsWarningWithoutExceptionText()
    {
        var directory = Helpers.TempDirectory();
        try
        {
            using var runtime = new AgentRuntime(Options.Create(new AgentOptions { StateDir = directory }), TimeProvider.System);
            var logger = new RecordingLogger();
            using var worker = new AgentWorker(runtime, logger);
            await worker.StartAsync(CancellationToken.None);
            var logged = await logger.Entry.Task.WaitAsync(TimeSpan.FromSeconds(5));
            var repeated = await logger.SecondEntry.Task.WaitAsync(TimeSpan.FromSeconds(5));
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await worker.StopAsync(stop.Token);
            Assert.Equal(LogLevel.Warning, logged.Level);
            Assert.Equal(LogLevel.Warning, repeated.Level);
            Assert.Contains("agent_config_invalid", logged.Message, StringComparison.Ordinal);
            Assert.Null(logged.Exception);
            Assert.DoesNotContain(directory, logged.Message, StringComparison.Ordinal);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public async Task WorkerStartsAndCancelsWithoutScmRegistration()
    {
        var directory = Helpers.TempDirectory();
        try
        {
            using var runtime = new AgentRuntime(Options.Create(new AgentOptions { StateDir = directory }), TimeProvider.System);
            using var worker = new AgentWorker(runtime, NullLogger<AgentWorker>.Instance);
            await worker.StartAsync(CancellationToken.None);
            var deadline = System.Diagnostics.Stopwatch.StartNew();
            while (!File.Exists(Path.Combine(directory, "status.json")) && deadline.Elapsed < TimeSpan.FromSeconds(5)) await Task.Delay(10);
            Assert.True(File.Exists(Path.Combine(directory, "status.json")));
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await worker.StopAsync(stop.Token);
            Assert.True(worker.ExecuteTask!.IsCompleted);
        }
        finally { Directory.Delete(directory, true); }
    }
}
