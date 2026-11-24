using System.Globalization;
using System.Text.Json.Nodes;
using Sli.Server.Infrastructure;
using Sli.Server.Reporting;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class JournalPagePostgresTests(ITestOutputHelper output)
{
    private sealed class Connections(SqlPostgresFixture fixture) : IPostgresConnectionFactory
    {
        public Task<Npgsql.NpgsqlConnection> OpenAsync(CancellationToken ct) => fixture.Pg.OpenAsync(ct, "adlog_user");
    }
    private sealed class MeasuredSession(IReportSession db, ITestOutputHelper output) : IReportSession
    {
        private bool measured;
        public async Task<IReadOnlyList<JsonObject>> QueryAsync(string sql, IReadOnlyList<object?> values, CancellationToken ct)
        {
            if (!measured && sql.StartsWith("with short_events", StringComparison.Ordinal))
            {
                measured = true;
                var result = await db.QueryAsync("explain (analyze, serialize text, format json) " + sql, values, ct);
                var plan = result.Single()["QUERY PLAN"]![0]!;
                double planning = plan["Planning Time"]!.GetValue<double>();
                double execution = plan["Execution Time"]!.GetValue<double>();
                double statement = planning + execution;
                output.WriteLine($"PostgreSQL journal query with output serialization: {statement:F1} ms");
                if (statement >= 1000)
                    output.WriteLine(plan.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
                Assert.True(statement < 1000, $"Journal PostgreSQL query exceeded one second: {statement:F1} ms");
            }
            return await db.QueryAsync(sql, values, ct);
        }

        public Task CommitAsync(CancellationToken ct) => db.CommitAsync(ct);
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    [Fact]
    public async Task Counts_groups_pages_and_finds_earlier_events_in_the_granted_slice()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using (var seed = await fixture.Pg.OpenAsync(ct))
            await PostCollectionPostgres.Sql(seed, """
                insert into servers(id,domain_id,hostname,fqdn,role)
                    select 900001,id,'dc01','dc01.example.test','domain_controller' from domains where fqdn='example.test';
                select create_event_storage_partitions(current_date-1,current_date);
                insert into event_hot(event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields)
                select n,statement_timestamp()-interval '90 minutes'+n*interval '1 second',
                    case when n <= 4966 then 4625 when n=4967 then 4728 when n=4968 then 1102 else 4624 end,
                    1,'EXAMPLE\synthetic-'||(n%2),null,'192.0.2.10','dc01.example.test',
                    '{"$server_id":900001,"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing"}',
                    '{"Status":"0xc000006d"}',
                    case when n=4966 then '{"LogonType":"9"}'::jsonb
                         when n=5000 then '{"LogonType":null}'::jsonb else '{}'::jsonb end
                from generate_series(1,5000) n;
                """, ct);

        DateTimeOffset to = DateTimeOffset.UtcNow;
        DateTimeOffset from = to.AddHours(-2);
        DateTimeOffset boundary = new(DateTime.UtcNow.Date.AddDays(-14), TimeSpan.Zero);
        await using var db = await new ReportDatabase(new Connections(fixture)).OpenAsync(false, ct);
        var measured = new MeasuredSession(db, output);
        Task<JsonObject> Read(JournalOptions options, int limit = 25, string? cursor = null, string? search = null, long domain = 1)
        {
            var sql = new ReportQuery();
            string scope = " where event.domain_id=" + sql.Parameter(domain);
            var query = new Dictionary<string, string>
            {
                ["time_from"] = from.ToString("O", CultureInfo.InvariantCulture),
                ["time_to"] = to.ToString("O", CultureInfo.InvariantCulture)
            };
            if (cursor is not null) query["cursor"] = cursor;
            if (search is not null) query["q"] = search;
            return JournalPage.ReadAsync(measured, sql, scope, new JsonObject(), ["id", "event_id", "time_created_utc", "channel",
                "subject_user_name", "target_user_name"], query, options, limit, boundary, ct);
        }

        var options = new JournalOptions(true, null, null, "all", "", "", null);
        var first = await Read(options);
        Assert.Equal(5000L, first["journal_event_count"]!.GetValue<long>());
        Assert.Equal(35L, first["filtered_count"]!.GetValue<long>());
        Assert.Equal(4998L, first["journal_counts"]!["authentication"]!.GetValue<long>());
        Assert.Equal(1L, first["journal_counts"]!["groups"]!.GetValue<long>());
        Assert.Equal(1L, first["journal_counts"]!["audit"]!.GetValue<long>());
        Assert.Equal(25, first["items"]!.AsArray().Count);
        Assert.All(first["items"]!.AsArray().Take(2), row => {
            Assert.True(row!.AsObject().ContainsKey("logon_type"));
            Assert.Null(row["logon_type"]);
        });

        var second = await Read(options, cursor: first["next_cursor"]!.GetValue<string>());
        Assert.Equal(10, second["items"]!.AsArray().Count);
        var group = Assert.Single(second["items"]!.AsArray(), row => row!["journal_expandable"]!.GetValue<bool>())!;
        Assert.Equal(4966L, group["event_count"]!.GetValue<long>());
        Assert.Null(group["actor"]);
        Assert.Equal("192.0.2.10", group["ip_address"]!.GetValue<string>());
        Assert.Equal("9", group["logon_type"]!.GetValue<string>());
        Assert.NotEqual(group["first_seen_utc"]!.ToString(), group["last_seen_utc"]!.ToString());

        var repeats = await Read(options with { Expand = group["id"]!.GetValue<long>() });
        Assert.Equal(25, repeats["items"]!.AsArray().Count);
        Assert.True(repeats["has_more"]!.GetValue<bool>());
        var bucket = Assert.IsType<JsonObject>(repeats["items"]!.AsArray().First(row => row!["journal_expandable"]!.GetValue<bool>()));
        var members = await Read(options with { Expand = group["id"]!.GetValue<long>(), Member = bucket["id"]!.GetValue<long>() }, 50);
        Assert.Equal(bucket["event_count"]!.GetValue<long>(), members["items"]!.AsArray().Count);
        Assert.All(members["items"]!.AsArray(), row =>
        {
            Assert.Equal(1L, row!["event_count"]!.GetValue<long>());
            Assert.Equal(bucket["actor"]!.GetValue<string>(), row["actor"]!.GetValue<string>());
        });
        Assert.Empty((await Read(options with { Expand = group["id"]!.GetValue<long>() }, domain: 2))["items"]!.AsArray());

        var failures = await Read(options with { Result = "failure", Pivot = "address" }, search: "192.0.2.10");
        Assert.Equal(4966L, failures["journal_counts"]!["all"]!.GetValue<long>());
        Assert.Equal(4966L, (await Read(options with { Collapse = false, Result = "failure" }))["filtered_count"]!.GetValue<long>());
        var audit = await Read(options with { View = "audit" });
        Assert.Equal(1102L, Assert.Single(audit["items"]!.AsArray())!["event_id"]!.GetValue<long>());

        var before = await Read(options with { Before = 5000 }, 5);
        Assert.Equal(new long[] { 4998, 4996, 4994, 4992, 4990 }, before["items"]!.AsArray().Select(row => row!["id"]!.GetValue<long>()));
        Assert.Empty((await Read(options with { Before = 5000 }, domain: 2))["items"]!.AsArray());
    }
}
