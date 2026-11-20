using System.Net;
using Microsoft.AspNetCore.Http.Timeouts;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Npgsql;
using Sli.Server.Ad;
using Sli.Server.Gpo;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Ad;
using Sli.Server.Tests.Gpo;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class HistoryDeadlineTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    // The host signals its existing deadline. No timer or independent read limit.
    sealed class Deadline(CancellationToken token) : IHttpRequestTimeoutFeature
    {
        public CancellationToken RequestTimeoutToken => token;
        public void DisableTimeout() { }
    }
    sealed class Metadata : IPostgresConnectionFactory
    {
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Stopped = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        {
            Entered.SetResult();
            try { await Task.Delay(Timeout.InfiniteTimeSpan, ct); }
            finally { Stopped.SetResult(); }
            throw new InvalidOperationException("unreachable");
        }
    }
    static Task<IHost> Host(string family, Metadata metadata, CancellationToken deadline)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>
        {
            ["Sli:Storage:HistoryReadMode"] = "primary",
            ["Sli:Storage:HistoryClickHouseHost"] = "192.0.2.1",
            ["Sli:Storage:HistoryClickHousePort"] = "8123",
            ["Sli:Storage:HistoryClickHouseUser"] = "synthetic-history",
            ["Sli:Storage:HistoryClickHousePassword"] = "synthetic-test-only"
        }).Build();
        var feature = new Deadline(deadline);
        return family == "gpo"
            ? GpoEndpointTests.Host(new GpoReadStore(metadata, config), deadline: feature)
            : AdV2Tests.Host(new AdV2Store(metadata, config), deadline: feature);
    }
    static string Path(string family) => "/api/v2/reports/" + (family == "gpo" ? "ad.gpo.v2" : "ad.infrastructure") + "/data?tab=changes";

    [Theory] [InlineData("gpo")] [InlineData("ad")]
    public async Task Host_deadline_cancels_metadata_before_any_clickhouse_read(string family)
    {
        using var deadline = new CancellationTokenSource();
        var metadata = new Metadata();
        using var host = await Host(family, metadata, deadline.Token);
        using var client = host.GetTestClient();
        var pending = client.GetAsync(Path(family), Ct);
        try
        {
            await metadata.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10), Ct);
            deadline.Cancel();
            // A test watchdog only; production uses the host token without new limits.
            await metadata.Stopped.Task.WaitAsync(TimeSpan.FromSeconds(10), Ct);
            using var response = await pending.WaitAsync(TimeSpan.FromSeconds(10), Ct);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            string body = await response.Content.ReadAsStringAsync(Ct);
            Assert.Contains("report_read_timeout", body);
            Assert.Contains("unavailable", body);
            Assert.DoesNotContain("synthetic-test-only", body);
        }
        finally { client.CancelPendingRequests(); }
    }

    [Theory] [InlineData("gpo")] [InlineData("ad")]
    public async Task Caller_abort_still_cancels_metadata_without_expiring_host_deadline(string family)
    {
        using var deadline = new CancellationTokenSource();
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var metadata = new Metadata();
        using var host = await Host(family, metadata, deadline.Token);
        using var client = host.GetTestClient();
        var pending = client.GetAsync(Path(family), caller.Token);
        try
        {
            await metadata.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10), Ct);
            caller.Cancel();
            await metadata.Stopped.Task.WaitAsync(TimeSpan.FromSeconds(10), Ct);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
            Assert.False(deadline.IsCancellationRequested);
        }
        finally { caller.Cancel(); }
    }
}
