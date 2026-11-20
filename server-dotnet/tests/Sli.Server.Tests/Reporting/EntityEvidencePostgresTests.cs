using System.Reflection;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;
using Sli.Server.Entities;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class EntityEvidencePostgresTests
{
    [Fact]
    public async Task Id_only_preflight_prepares_on_postgresql_without_exposing_sort_time()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        var store = new QueryCapture();
        using var host = new HostBuilder().Build();
        var reader = new EntityReader(store, new EntityDirectoryReader(store, host.Services.GetRequiredService<IHostEnvironment>()), host.Services);
        // Exercise the exact query used before evidence authorization/hydration,
        // just as the Python reference captures its private id-only reader.
        var candidates = typeof(EntityReader).GetMethod("EvidenceCandidates", BindingFlags.Instance | BindingFlags.NonPublic)!
            .CreateDelegate<Func<int, EntityReadOptions, int, CancellationToken, Task<JsonArray>>>(reader);
        await candidates(1, new EntityReadOptions(), 31, ct);
        var query = Assert.Single(store.Queries);

        // Only our disposable, fully migrated cluster; never an inherited DSN.
        await using var db = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await db.OpenAsync(ct);
        await using var command = new NpgsqlCommand(query.Sql, db);
        foreach (var (key, value) in query.Parameters) command.Parameters.AddWithValue(key, value);
        // PostgreSQL rejects DISTINCT with an unselected ORDER BY expression.
        await command.PrepareAsync(ct);
        await using (var explain = new NpgsqlCommand("explain " + query.Sql, db))
        {
            foreach (var (key, value) in query.Parameters) explain.Parameters.AddWithValue(key, value);
            await using var plan = await explain.ExecuteReaderAsync(ct);
            Assert.True(await plan.ReadAsync(ct));
        }
        await using (var rows = await command.ExecuteReaderAsync(ct))
        {
            Assert.Equal(new[] { "event_db_id", "server_id", "domain_id", "channel", "summary_key" },
                Enumerable.Range(0, rows.FieldCount).Select(rows.GetName));
            Assert.False(await rows.ReadAsync(ct));
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    private sealed class QueryCapture : IEntityReadStore
    {
        internal readonly List<(string Sql, IReadOnlyDictionary<string, object> Parameters)> Queries = [];
        public Task<JsonArray> ReadAsync(string sql, IReadOnlyDictionary<string, object> parameters, int timeoutSeconds, CancellationToken ct)
        {
            Queries.Add((sql, new Dictionary<string, object>(parameters)));
            return Task.FromResult(new JsonArray());
        }
    }
}
