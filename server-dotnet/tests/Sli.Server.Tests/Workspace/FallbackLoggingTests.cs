using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sli.Server.Compatibility;
using Sli.Server.Legacy;
using Sli.Server.Operations;
using Sli.Server.Workspace;
using Xunit;

namespace Sli.Server.Tests.Workspace;

public sealed class FallbackLoggingTests
{
    private sealed class UnusedReads : ILegacyRows, ILegacyHttpReader
    {
        public Task<JsonArray> QueryAsync(string sql, IReadOnlyList<object> parameters, int timeoutMs, CancellationToken ct) => throw new InvalidOperationException("unexpected read");
        public Task<JsonArray> HistoryAsync(string sql, IReadOnlyDictionary<string, string> parameters, CancellationToken ct) => throw new InvalidOperationException("unexpected read");
        public Task<Dictionary<long, JsonObject>> HistoryEventsAsync(long[] ids, CancellationToken ct) => throw new InvalidOperationException("unexpected read");
        public Task<JsonObject> ReadAsync(string path, LegacyQuery query, CancellationToken ct) => throw new InvalidOperationException("unexpected read");
    }
    private sealed class Logs : ILoggerProvider
    {
        internal readonly ConcurrentQueue<(LogLevel Level, string Message, Exception? Error)> Entries = new();
        public ILogger CreateLogger(string categoryName) => new Capture(this);
        public void Dispose() { }
        private sealed class Capture(Logs owner) : ILogger
        {
            public bool IsEnabled(LogLevel level) => true;
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public void Log<TState>(LogLevel level, EventId id, TState state, Exception? error, Func<TState, Exception?, string> format)
                => owner.Entries.Enqueue((level, format(state, error), error));
        }
    }

    private sealed class FailedSections : IOperationsQueries
    {
        internal readonly List<string> Failed = [];
        public Task<JsonArray> ReadAsync(string sql, CancellationToken ct, params (string Name, object? Value)[] parameters)
        {
            if (sql.Contains("post_collection_jobs") || sql == OperationsSql.ChannelCycles || sql == OperationsSql.Outbox)
            {
                Failed.Add(sql);
                throw new InvalidOperationException("private-source-fixture");
            }
            return Task.FromResult(new JsonArray());
        }
    }

    [Fact]
    public async Task CollectorFallbacksRemainAvailableAndLogThreeTypedWarningsWithoutPrivateData()
    {
        using var logs = new Logs();
        var services = new ServiceCollection();
        services.AddLogging(b => b.ClearProviders().AddProvider(logs));
        using var provider = services.BuildServiceProvider();
        var config = new ConfigurationBuilder().Build();
        var queries = new FailedSections();
        var service = ActivatorUtilities.CreateInstance<OperationsService>(provider, queries, new OperationsFiles(config), new OperationsCatalog(), new OperationsJobs(), TimeProvider.System);

        var result = await service.ReadAsync("/api/collector/health", new(), TestContext.Current.CancellationToken);

        foreach (string section in new[] { "post_collection", "runtime_history", "storage_v2_outbox" })
            Assert.Equal("unavailable", result[section]!["status"]!.ToString());
        Assert.Equal(3, queries.Failed.Count);
        Assert.Equal(3, logs.Entries.Count);
        Assert.All(logs.Entries, entry => {
            Assert.Equal(LogLevel.Warning, entry.Level);
            Assert.Null(entry.Error);
            Assert.Contains("InvalidOperationException", entry.Message);
            Assert.DoesNotContain("private-source-fixture", entry.Message);
        });
        Assert.Contains(logs.Entries, e => e.Message.Contains("post_collection_overview_unavailable"));
        Assert.Contains(logs.Entries, e => e.Message.Contains("runtime_collection_history_unavailable"));
        Assert.Contains(logs.Entries, e => e.Message.Contains("storage_v2_outbox_unavailable"));
        Assert.DoesNotContain("private-source-fixture", result.ToJsonString());
    }

    [Fact]
    public async Task FailedDashboardRefreshLogsWarningRetainsCacheAndAllowsAnotherRefresh()
    {
        using var logs = new Logs();
        var services = new ServiceCollection();
        services.AddLogging(b => b.ClearProviders().AddProvider(logs));
        services.AddScoped<DashboardSnapshotReader>(_ => throw new InvalidOperationException("private-source-fixture"));
        services.AddSingleton<ILegacyRows>(new UnusedReads());
        services.AddSingleton<ILegacyHttpReader>(new UnusedReads());
        await using var provider = services.BuildServiceProvider();
        var config = new ConfigurationBuilder().Build();
        var operations = ActivatorUtilities.CreateInstance<OperationsService>(provider, new FailedSections(), new OperationsFiles(config), new OperationsCatalog(), new OperationsJobs(), TimeProvider.System);
        var cache = new DashboardSnapshotCache { Payload = new JsonObject { ["status"] = "ok", ["fixture"] = "last-good-snapshot", ["diagnostics"] = new JsonObject() } };
        var reader = ActivatorUtilities.CreateInstance<DashboardSnapshotReader>(provider, operations, new LegacyJobStore(), new LegacySettings(config), cache, provider.GetRequiredService<IServiceScopeFactory>());

        Task? previous = null;
        for (int attempt = 1; attempt <= 2; attempt++)
        {
            var result = await reader.ReadAsync(false, TestContext.Current.CancellationToken);
            Assert.Equal("last-good-snapshot", result["fixture"]!.ToString());
            Task refresh = cache.Refresh!;
            Assert.NotSame(previous, refresh);
            await refresh.WaitAsync(TestContext.Current.CancellationToken);
            Assert.True(refresh.IsCompletedSuccessfully);
            Assert.Equal("InvalidOperationException", cache.LastError);
            Assert.Equal("last-good-snapshot", cache.Payload!["fixture"]!.ToString());
            Assert.Equal(attempt, logs.Entries.Count);
            previous = refresh;
        }
        Assert.All(logs.Entries, entry => {
            Assert.Equal(LogLevel.Warning, entry.Level);
            Assert.Contains("snapshot_refresh_failed", entry.Message);
            Assert.Contains("InvalidOperationException", entry.Message);
            Assert.DoesNotContain("private-source-fixture", entry.Message);
            Assert.Null(entry.Error);
        });
    }
}
