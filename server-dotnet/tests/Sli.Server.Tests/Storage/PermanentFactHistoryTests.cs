using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Storage.Archive;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Behavioral vectors from tests/storage/test_permanent_fact_history.py.
public sealed class PermanentFactHistoryTests
{
    static CancellationToken Token => TestContext.Current.CancellationToken;
    sealed class ClickHouse : HttpMessageHandler
    {
        internal HttpStatusCode Status = HttpStatusCode.OK;
        internal bool Refused, BrokenBody;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Assert.Contains("max_execution_time=0", request.RequestUri!.Query);
            if (Refused) throw new HttpRequestException("private endpoint", new SocketException((int)SocketError.ConnectionRefused));
            return Task.FromResult(new HttpResponseMessage(Status) { Content = BrokenBody
                ? new StreamContent(new BrokenStream()) : new StringContent("sensitive_event_payload private endpoint") });
        }
    }
    sealed class BrokenStream : MemoryStream
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.FromException<int>(new IOException("sensitive_event_payload private endpoint"));
    }
    static LifecycleClickHouse Transport(HttpClient client) => new(client, new Uri("http://192.0.2.1:8123/"));

    static Task Request(LifecycleClickHouse ch, string operation) => operation switch {
        "query" => ch.RowsAsync("SELECT sensitive_event_payload", Token),
        "insert" => ch.InsertAsync(FileAuditHistory.Table, [new JsonObject { ["payload"] = "sensitive_event_payload" }], Token),
        _ => ch.ExecuteAsync("SELECT sensitive_event_payload", Token)
    };
    [Theory]
    [InlineData("query", false)] [InlineData("insert", false)] [InlineData("execute", false)]
    [InlineData("query", true)] [InlineData("insert", true)] [InlineData("execute", true)]
    public async Task Transport_outage_including_body_reads_has_a_safe_retryable_reason(string operation, bool body)
    {
        using var handler = new ClickHouse { Refused = !body, BrokenBody = body }; using var client = new HttpClient(handler);
        var error = await Assert.ThrowsAsync<LifecycleBlocked>(() => Request(Transport(client), operation));
        Assert.Equal("history_clickhouse_unavailable", error.Message); Assert.Null(error.InnerException);
    }

    [Theory]
    [InlineData(429, true)] [InlineData(502, true)] [InlineData(503, true)] [InlineData(504, true)]
    [InlineData(401, false)] [InlineData(403, false)] [InlineData(500, false)]
    public async Task Http_errors_hide_payloads_and_only_availability_failures_are_retryable(int status, bool retryable)
    {
        using var handler = new ClickHouse { Status = (HttpStatusCode)status }; using var client = new HttpClient(handler);
        foreach (string operation in new[] { "query", "insert", "execute" }) {
            var error = await Assert.ThrowsAsync<LifecycleBlocked>(() => Request(Transport(client), operation));
            Assert.Equal(retryable ? "history_clickhouse_unavailable" : $"ClickHouse HTTP {status}:request_failed", error.Message);
            Assert.Null(error.InnerException);
        }
    }

    [Fact]
    public async Task Caller_cancellation_is_not_reported_as_a_transport_outage()
    {
        using var handler = new ClickHouse(); using var client = new HttpClient(handler);
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Transport(client).RowsAsync("SELECT 1", cancelled.Token));
    }

}
