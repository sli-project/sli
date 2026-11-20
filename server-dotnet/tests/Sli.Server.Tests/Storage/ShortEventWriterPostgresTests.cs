using System.Text.Json.Nodes;
using System.Xml.Linq;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class ShortEventWriterPostgresTests(ITestOutputHelper output)
{
    private static ShortEventRow? Row(long id, int kind, Dictionary<string,string>? data = null, long domain = 1)
    {
        XNamespace ns = EventXml.Namespace;
        var xml = new XElement(ns + "Event", new XElement(ns + "System",
            new XElement(ns + "Provider", new XAttribute("Name", "Microsoft-Windows-Security-Auditing")),
            new XElement(ns + "EventID", kind), new XElement(ns + "EventRecordID", id),
            new XElement(ns + "TimeCreated", new XAttribute("SystemTime", "2026-11-15T01:02:03Z")),
            new XElement(ns + "Channel", "Security"), new XElement(ns + "Computer", "dc01.example.test")),
            new XElement(ns + "EventData", (data ?? []).Select(f => new XElement(ns + "Data", new XAttribute("Name", f.Key), f.Value))));
        var row = EventXml.Parse(xml.ToString(), "dc01.example.test", "dc01.example.test", "Security");
        return ShortEventRow.Create(id, domain, row, Direct4624Projection.Create(row));
    }

    private static async Task Write(NpgsqlDataSource worker, IReadOnlyList<ShortEventRow> rows, CancellationToken ct)
    {
        await using var db = await worker.OpenConnectionAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        await PostCollectionPostgres.Sql(db, "set local role adlog_storage_worker", ct);
        await ShortEventWriter.WriteAsync(db, tx, rows, ct); await tx.CommitAsync(ct);
    }

    [Fact]
    public async Task Concurrent_replays_count_once_and_keep_nulls_and_domains_separate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, "select create_event_storage_partitions('2026-11-15','2026-11-15')", ct);
        await using var worker = NpgsqlDataSource.Create(fixture.Dsn("sli_storage_login"));
        ShortEventRow[] rows = [Row(1,4625)!,Row(2,4625)!,Row(3,4625,domain:2)!];
        await Task.WhenAll(Enumerable.Range(0,4).Select(_ => Write(worker, rows, ct)));
        // A later packet adds to the same day's existing group.
        await Write(worker, [Row(4,4625)!], ct);
        await using var query = new NpgsqlCommand("select domain_id,event_count,actor,source from event_cold_daily order by domain_id", db);
        await using (var r = await query.ExecuteReaderAsync(ct)) {
            Assert.True(await r.ReadAsync(ct)); Assert.Equal(1, r.GetInt64(0)); Assert.Equal(3, r.GetInt64(1));
            Assert.True(r.IsDBNull(2)); Assert.True(r.IsDBNull(3));
            Assert.True(await r.ReadAsync(ct)); Assert.Equal(2, r.GetInt64(0)); Assert.Equal(1, r.GetInt64(1));
            Assert.False(await r.ReadAsync(ct));
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Replication_filter_and_bounded_unicode_values_reach_both_layers_as_data()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        await using var worker = NpgsqlDataSource.Create(fixture.Dsn("sli_storage_login"));
        string longValue = string.Concat(Enumerable.Repeat("🙂",1100));
        ShortEventRow?[] rows = [
            Row(1,4662,new() { ["Properties"]="{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}" }),
            Row(2,4662,new() { ["Properties"]="synthetic-unrelated-right" }),
            Row(3,4634),
            Row(4,4688,new() { ["SubjectUserName"]=longValue,["NewProcessName"]=longValue,["CommandLine"]=longValue,
                ["IpAddress"]=longValue,["LogonType"]=longValue,["Status"]=longValue })
        ];
        await Write(worker, rows.OfType<ShortEventRow>().ToArray(), ct);
        await Write(worker, rows.OfType<ShortEventRow>().ToArray(), ct);
        await using (var query = new NpgsqlCommand("""
            select (select count(*) from event_hot),(select count(*) from event_cold_facts),
                   (select sum(event_count)::bigint from event_cold_daily);
            select char_length(actor),char_length(fields->>'CommandLine'),method->>'LogonType'
            from event_hot where event_kind=4688;
            select min(pg_column_size(h)),avg(pg_column_size(h)),max(pg_column_size(h)) from event_hot h;
            """, db)) {
            await using var r = await query.ExecuteReaderAsync(ct); Assert.True(await r.ReadAsync(ct));
            Assert.Equal(2,r.GetInt64(0)); Assert.Equal(1,r.GetInt64(1)); Assert.Equal(1,r.GetInt64(2));
            Assert.True(await r.NextResultAsync(ct)); Assert.True(await r.ReadAsync(ct));
            Assert.Equal(256,r.GetInt32(0)); Assert.Equal(1024,r.GetInt32(1));
            Assert.Equal(string.Concat(Enumerable.Repeat("🙂",64)),r.GetString(2));
            Assert.True(await r.NextResultAsync(ct)); Assert.True(await r.ReadAsync(ct));
            output.WriteLine($"Hot row pg_column_size min/mean/max: {r.GetInt32(0)}/{r.GetDecimal(1):F1}/{r.GetInt32(2)} bytes (synthetic replication/long Unicode)");
        }
        await fixture.AssertNoSqlErrorsAsync(ct);

        // Even a corrupt stored digest cannot merge unrelated dimensions.
        await PostCollectionPostgres.Sql(db,"update event_cold_daily set actor='synthetic-collision'",ct);
        var conflict = await Assert.ThrowsAsync<InvalidOperationException>(() => Write(worker,[Row(5,4688,new() {
            ["SubjectUserName"]=longValue,["NewProcessName"]=longValue,["CommandLine"]=longValue,
            ["IpAddress"]=longValue,["LogonType"]=longValue,["Status"]=longValue })!],ct));
        Assert.Equal("short_event_summary_conflict",conflict.Message);
        await using var count = new NpgsqlCommand("select count(*) from event_hot",db);
        Assert.Equal(2L,await count.ExecuteScalarAsync(ct));
    }
}
