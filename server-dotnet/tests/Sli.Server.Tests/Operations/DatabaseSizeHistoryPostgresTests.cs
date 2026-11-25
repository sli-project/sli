using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Operations;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Operations;

public sealed class DatabaseSizeHistoryPostgresTests
{
    [Fact]
    public async Task Default_storage_api_limit_keeps_more_than_seven_days_of_native_points()
    {
        using var state = new Sli.Server.Tests.Storage.StorageLifecycleTests.State();
        var start = new DateTime(2026, 11, 5, 0, 0, 0, DateTimeKind.Utc);
        for (int slot = 0; slot < 50; slot++)
            DatabaseSizeHistory.Record(state.Files, start.AddHours(6 * slot), 1024L + slot);

        using var app = await OperationsEndpointTests.Start(settings: new() { ["Sli:DataDirectory"] = state.Path });
        using var response = await app.Client.GetAsync("/api/storage/lifecycle", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();
        var body = await OperationsEndpointTests.Body(response);
        Assert.Equal(2000L, body["latest_snapshot"]!["database_bytes"]!.GetValue<long>());

        var history = body["postgres_size_history"]!.AsObject();
        var samples = history["samples"]!.AsArray();
        Assert.Equal(48, samples.Count);
        var first = DateTimeOffset.Parse(samples[^1]!["captured_at"]!.GetValue<string>());
        var last = DateTimeOffset.Parse(samples[0]!["captured_at"]!.GetValue<string>());
        Assert.Equal(start.AddHours(12), first.UtcDateTime);
        Assert.Equal(TimeSpan.FromHours(282), last - first);
    }

    [Fact]
    public async Task Native_worker_publishes_two_real_database_sizes_to_the_storage_api()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        var files = new LifecycleFiles(Path.Combine(fixture.Pg.Root, "storage-metrics"));
        var start = new DateTime(2026, 11, 5, 0, 0, 0, DateTimeKind.Utc);
        var workerSettings = new Dictionary<string, string>
        {
            ["ADLOG_PG_DSN"] = fixture.Dsn("sli_storage_lifecycle_login"),
            ["ADLOG_STORAGE_LIFECYCLE_DELETE_DSN"] = fixture.Dsn("sli_storage_lifecycle_delete_login"),
        };

        async Task<long> Capture(DateTime at)
        {
            await using var runtime = new LifecycleRuntime(key => workerSettings.GetValueOrDefault(key), files);
            var worker = new StorageLifecycleWorker(runtime, files, () => at);
            Assert.Equal(0, await worker.RunAsync(new(Once: true), _ => { }, ct));
            return files.Read(StorageLifecycleWorker.DatabaseUsageFile)!["database_bytes"]!.GetValue<long>();
        }

        long firstSize = await Capture(start);
        await using (var db = new NpgsqlConnection(fixture.Pg.ConnectionString))
        {
            await db.OpenAsync(ct);
            await PostCollectionPostgres.Sql(db, """
                create table synthetic_size_growth as
                select n, md5(n::text) as payload from generate_series(1, 100000) as source(n)
                """, ct);
        }
        DateTime secondAt = start.AddHours(6);
        long secondSize = await Capture(secondAt);
        Assert.True(firstSize > 0 && secondSize > firstSize);
        Assert.Equal(secondSize, await Capture(secondAt.AddMinutes(1)));

        var settings = new Dictionary<string, string?>
        {
            ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user"),
            ["Sli:DataDirectory"] = files.Root,
        };
        var config = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        var queries = new OperationsQueries(new PostgresConnectionFactory(config));
        using var app = await OperationsEndpointTests.Start(settings: settings, postgresQueries: queries);
        using var response = await app.Client.GetAsync("/api/storage/lifecycle", ct);
        response.EnsureSuccessStatusCode();
        var body = await OperationsEndpointTests.Body(response);

        // A clean installation has no legacy composite snapshot. The history
        // of measured database sizes must be available independently.
        Assert.Null(body["latest_snapshot"]);
        var history = body["postgres_size_history"]!.AsObject();
        var samples = history["samples"]!.AsArray();
        Assert.Collection(samples,
            recent =>
            {
                Assert.Equal(secondAt, DateTimeOffset.Parse(recent!["captured_at"]!.GetValue<string>()).UtcDateTime);
                Assert.Equal(secondSize, recent["database_bytes"]!.GetValue<long>());
                Assert.Equal(2, recent.AsObject().Count);
            },
            earlier =>
            {
                Assert.Equal(start, DateTimeOffset.Parse(earlier!["captured_at"]!.GetValue<string>()).UtcDateTime);
                Assert.Equal(firstSize, earlier["database_bytes"]!.GetValue<long>());
            });
        Assert.True(System.Text.Json.Nodes.JsonNode.DeepEquals(samples[0], history["latest_snapshot"]));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
