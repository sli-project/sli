using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Consumer;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Hosting;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Storage.History;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class StorageLifecycleIoTests
{
    sealed class Settings : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "sli-io-" + Guid.NewGuid().ToString("N"));
        internal Dictionary<string, string?> Values { get; } = new();
        internal string Password => Path.Combine(Root, "warm-password");
        internal Settings()
        {
            Directory.CreateDirectory(Root);
            Values["Sli__Storage__ShortEventReads"] = "false";
            File.WriteAllText(Password, "synthetic-password\n");
            Values["ADLOG_WARM_CLICKHOUSE_HOST"] = "warm-tier";
            Values["ADLOG_WARM_CLICKHOUSE_PASSWORD_FILE"] = Password;
        }
        public void Dispose() => Directory.Delete(Root, true);
    }

    [Theory]
    [InlineData(null, "127.0.0.1")]
    [InlineData("clickhouse", "clickhouse")]
    public async Task Warm_settings_do_not_redirect_history_queries_inserts_or_streams(string? host, string expected)
    {
        using var settings = new Settings(); using var handler = new Http(); using var client = new HttpClient(handler);
        var ct = TestContext.Current.CancellationToken;
        settings.Values["ADLOG_HISTORY_CLICKHOUSE_HOST"] = host;
        settings.Values["ADLOG_HISTORY_CLICKHOUSE_PORT"] = "57847";
        settings.Values["ADLOG_HISTORY_CLICKHOUSE_USER"] = "history_reader";
        settings.Values["ADLOG_HISTORY_CLICKHOUSE_PASSWORD"] = "synthetic-history-password";
        var configuration = HistoryConfiguration.Load(null, settings.Values.GetValueOrDefault);
        using var configured = configuration.CreateClient();
        var ch = new LifecycleClickHouse(client, configuration.Endpoint, configured.DefaultRequestHeaders.Authorization);
        Assert.Equal(1, Assert.Single(await ch.RowsAsync("SELECT 1 value", ct))["value"]!.GetValue<int>());
        await ch.InsertAsync(FileAuditHistory.Table, [new() { ["event_db_id"] = 41 }], ct);
        await foreach (var row in ch.StreamRowsAsync("SELECT 1 value", ct)) Assert.Equal(1, row["value"]!.GetValue<int>());
        Assert.Equal(3, handler.Calls.Count);
        Assert.All(handler.Calls, call => {
            Assert.Equal(expected, call.Uri.Host); Assert.Equal(57847, call.Uri.Port);
            Assert.Equal("Basic aGlzdG9yeV9yZWFkZXI6c3ludGhldGljLWhpc3RvcnktcGFzc3dvcmQ=", call.Auth);
        });
        Assert.All(handler.Responses, content => Assert.True(content.Closed));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Explicit_endpoint_overrides_both_warm_and_history_settings(bool stream)
    {
        using var settings = new Settings(); using var handler = new Http(); using var client = new HttpClient(handler);
        var ct = TestContext.Current.CancellationToken;
        settings.Values["ADLOG_HISTORY_CLICKHOUSE_HOST"] = "clickhouse";
        var ch = new LifecycleClickHouse(client, new Uri("http://explicit-tier:18123/"),
            new AuthenticationHeaderValue("Basic", "ZXhwbGljaXRfcmVhZGVyOnN5bnRoZXRpYy1leHBsaWNpdC1wYXNzd29yZA=="));
        if (stream) {
            await foreach (var row in ch.StreamRowsAsync("SELECT 1 value FORMAT JSONEachRow", ct)) Assert.Equal(1, row["value"]!.GetValue<int>());
        } else Assert.Equal("{\"value\":1}\n", await ch.ExecuteAsync("SELECT 1 value FORMAT JSONEachRow", ct));
        var call = Assert.Single(handler.Calls);
        Assert.Equal("explicit-tier", call.Uri.Host); Assert.Equal(18123, call.Uri.Port);
        Assert.Equal("explicit_reader:synthetic-explicit-password", Encoding.UTF8.GetString(Convert.FromBase64String(call.Auth![6..])));
        Assert.True(Assert.Single(handler.Responses).Closed);
    }

    [Fact]
    public async Task Stopping_a_stream_early_closes_the_response()
    {
        using var handler = new Http(); using var client = new HttpClient(handler);
        var ch = new LifecycleClickHouse(client, new Uri("http://explicit-tier:18123/"));
        await foreach (var row in ch.StreamRowsAsync("SELECT 1 value", TestContext.Current.CancellationToken)) {
            Assert.Equal(1, row["value"]!.GetValue<int>()); break;
        }
        Assert.True(Assert.Single(handler.Responses).Closed);
    }

    sealed class Http : HttpMessageHandler
    {
        internal List<(Uri Uri, string Body, string? Auth, string? ContentType)> Calls = [];
        internal List<TrackedContent> Responses = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Calls.Add((request.RequestUri!, await request.Content!.ReadAsStringAsync(ct), request.Headers.Authorization?.ToString(), request.Content.Headers.ContentType?.ToString()));
            var content = new TrackedContent(Calls[^1].Body.StartsWith("SELECT count()", StringComparison.Ordinal) ? "1\n" : "{\"value\":1}\n"); Responses.Add(content);
            return new(HttpStatusCode.OK) { Content = content };
        }
    }
    sealed class TrackedContent(string content) : StringContent(content, Encoding.UTF8)
    {
        internal bool Closed;
        protected override void Dispose(bool disposing) { Closed = true; base.Dispose(disposing); }
    }

    [Fact]
    public async Task Empty_insert_does_not_open_http_connection()
    {
        using var handler = new Http(); using var client = new HttpClient(handler);
        await new LifecycleClickHouse(client, new Uri("http://explicit-tier:18123/")).InsertAsync(FileAuditHistory.Table, [], TestContext.Current.CancellationToken);
        Assert.Empty(handler.Calls);
    }

    [Fact]
    public async Task Json_query_strips_semicolon_and_sends_readonly_without_execution_deadline()
    {
        using var handler = new Http(); using var client = new HttpClient(handler);
        var rows = await new LifecycleClickHouse(client, new Uri("http://explicit-tier:18123/")).RowsAsync("SELECT 1 value;", TestContext.Current.CancellationToken);
        Assert.Equal(1, Assert.Single(rows)["value"]!.GetValue<int>());
        var call = Assert.Single(handler.Calls);
        Assert.Equal("SELECT 1 value FORMAT JSONEachRow", call.Body);
        Assert.Equal("?max_execution_time=0&readonly=1", call.Uri.Query);
        Assert.Equal("text/plain; charset=utf-8", call.ContentType);
        Assert.True(Assert.Single(handler.Responses).Closed);
    }
}
