using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Ad;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Xunit;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Tests.Ad;

// Vectors from tests/reports/test_computers_v6_comparison_batch.py.
public sealed class AdComputerComparisonBatchTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static JsonObject Snapshot(long domain, long id, string scope = "a", string state = "available", bool enabled = true)
    {
        var row = Obj(new { snapshot_id = id, domain_id = domain, scope_sha256 = scope, contract_id = AdComputerComparison.Contract,
            schema_version = 1, captured_at_utc = "2026-01-01T00:00:00Z", bucket_start_utc = (string?)null,
            source_observed_at_utc = (string?)null, source_state = state, object_count = 1,
            payload_json = new { contract_id = AdComputerComparison.Contract, state,
                items = new[] { new { object_guid = $"synthetic-{domain}", entity_id = domain, enabled } } } });
        row["payload_sha256"] = AdJobPlugin.Digest(row["payload_json"]!.AsObject());
        return row;
    }

    sealed class Recorder(JsonObject[]? input = null, long[]? catalog = null)
    {
        internal readonly List<(string Sql, long[]? Scope)> Calls = [];
        internal Task<List<JsonObject>> Read(string sql, long[]? scope)
        {
            Calls.Add((sql, scope));
            if (sql == AdComputerComparison.CatalogSql)
                return Task.FromResult((catalog ?? []).Select(id => Obj(new { id })).ToList());
            Assert.Equal(AdComputerComparison.PairSql, sql);
            var result = new List<JsonObject>();
            foreach (long domain in scope!.Distinct())
            {
                var history = (input ?? []).Where(r => r.Int("domain_id") == domain)
                    .OrderByDescending(r => r.Time("captured_at_utc")).ThenByDescending(r => r.Int("snapshot_id")).ToArray();
                if (history.Length == 0) continue;
                foreach (var row in history.Where(r => new[] { "scope_sha256", "contract_id", "schema_version" }
                    .All(k => JsonNode.DeepEquals(r[k], history[0][k]))).Take(2))
                {
                    var copy = row.DeepClone().AsObject(); copy["domain_snapshot_count"] = history.Length; result.Add(copy);
                }
            }
            return Task.FromResult(result);
        }
    }

    [Theory]
    [InlineData(0, 0)][InlineData(1, 1)][InlineData(2, 1)][InlineData(10, 1)]
    public async Task Explicit_scope_uses_one_comparison_read_and_empty_scope_reads_nothing(int count, int budget)
    {
        long[] scope = Enumerable.Range(1, count).Select(n => (long)n).ToArray();
        var recorder = new Recorder(); var result = await AdComputerComparison.LoadAsync(scope, recorder.Read);
        Assert.Equal(budget, recorder.Calls.Count); Assert.False(result["deletion_claim_allowed"]!.GetValue<bool>());
        if (count > 0) Assert.Equal(scope, recorder.Calls[0].Scope);
        if (count == 0) { Assert.Equal("not_collected", result.Text("state")); Assert.Empty(result["items"]!.AsArray()); }
    }

    [Theory]
    [InlineData(0, 1)][InlineData(1, 2)][InlineData(2, 2)][InlineData(10, 2)]
    public async Task Null_scope_adds_only_one_catalog_read(int count, int budget)
    {
        long[] catalog = Enumerable.Range(1, count).Select(n => (long)n).ToArray();
        var recorder = new Recorder(catalog: catalog);
        await AdComputerComparison.LoadAsync(null, recorder.Read);
        Assert.Equal(budget, recorder.Calls.Count); Assert.Equal(AdComputerComparison.CatalogSql, recorder.Calls[0].Sql);
        Assert.Null(recorder.Calls[0].Scope);
        if (count > 0) Assert.Equal(catalog, recorder.Calls[1].Scope);
    }

    static async Task<JsonArray> Singles(JsonObject[] rows, long[] scope)
    {
        var expected = new JsonArray();
        foreach (long domain in scope)
        {
            var result = await AdComputerComparison.LoadAsync([domain], new Recorder(rows).Read);
            result["domain_id"] = domain; expected.Add(result);
        }
        return expected;
    }

    [Fact]
    public async Task Batch_preserves_single_results_order_duplicates_unknowns_and_qualifications()
    {
        JsonObject[] rows = [Snapshot(1, 10, enabled: false), Snapshot(1, 11), Snapshot(2, 20), Snapshot(2, 21, scope: "incompatible"),
            Snapshot(3, 30), Snapshot(4, 40), Snapshot(4, 41, state: "partial")];
        long[] scope = [4, 2, 1, 3, 5, 1];
        var expected = await Singles(rows, scope); var recorder = new Recorder(rows);
        var actual = await AdComputerComparison.LoadAsync(scope, recorder.Read);
        using var reference = typeof(AdComputerComparisonBatchTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Ad.computer-comparison-batch-reference.json")!;
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(reference), actual), actual.ToJsonString());
        Assert.True(JsonNode.DeepEquals(expected, actual["domains"])); Assert.Single(recorder.Calls);
        Assert.True(JsonNode.DeepEquals(Array(expected.SelectMany(d => d!["items"]!.AsArray())), actual["items"]));
        Assert.Equal("partial", actual.Text("state")); Assert.Equal(actual["items"]!.AsArray().Count, actual.Int("change_count"));
        Assert.False(actual["deletion_claim_allowed"]!.GetValue<bool>());
        Assert.Equal("incompatible_snapshot_pair_not_compared", actual["domains"]![1].Text("reason"));
        Assert.Equal("previous_compatible_snapshot_not_collected", actual["domains"]![3].Text("reason"));
        Assert.Equal("snapshot_history_not_collected", actual["domains"]![4].Text("reason"));
        var change = actual["items"]![0]!;
        Assert.Equal("enabled_changed", change.Text("change_type")); Assert.Equal("False", change.Text("before")); Assert.Equal("True", change.Text("after"));
        Assert.Equal("enabled_changed:1", change.Text("row_id")); Assert.Equal(1, change.Int("domain_id"));
        Assert.Equal(11, actual["domains"]![2]!["current"].Int("snapshot_id"));
        Assert.Equal(10, actual["domains"]![2]!["previous"].Int("snapshot_id"));
        Assert.All(actual["domains"]!.AsArray(), d => Assert.False(d!["deletion_claim_allowed"]!.GetValue<bool>()));
    }

    [Fact]
    public async Task Complete_pairs_remain_available_and_payload_contract_errors_propagate()
    {
        JsonObject[] rows = [Snapshot(1, 10), Snapshot(1, 11), Snapshot(2, 20), Snapshot(2, 21)];
        var result = await AdComputerComparison.LoadAsync([2, 1], new Recorder(rows).Read);
        Assert.Equal("available", result.Text("state")); Assert.Empty(result["items"]!.AsArray());
        foreach (int index in new[] { 2, 3 })
        {
            rows[index]["payload_json"]!["contract_id"] = "synthetic.invalid";
            rows[index]["payload_sha256"] = AdJobPlugin.Digest(rows[index]["payload_json"]!.AsObject());
            var error = await Assert.ThrowsAsync<InvalidDataException>(() => AdComputerComparison.LoadAsync([1, 2], new Recorder(rows).Read));
            Assert.Equal("incompatible_computers_v6_snapshots", error.Message);
            rows[index]["payload_json"]!["contract_id"] = AdComputerComparison.Contract;
            rows[index]["payload_sha256"] = AdJobPlugin.Digest(rows[index]["payload_json"]!.AsObject());
        }
    }

    [Theory][InlineData(false)][InlineData(true)]
    public async Task Comparison_keeps_snapshot_hash_verification_even_without_a_pair(bool pair)
    {
        var latest = Snapshot(1, 11); latest["payload_json"]!["items"]![0]!["enabled"] = false;
        JsonObject[] rows = pair ? [Snapshot(1, 10), latest] : [latest];
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => AdComputerComparison.LoadAsync([1], new Recorder(rows).Read));
        Assert.Equal("ad_snapshot_hash_mismatch", error.Message);
    }

    [Theory][InlineData(false)][InlineData(true)]
    public async Task Query_failure_propagates_for_comparison_and_catalog(bool catalog)
    {
        var failure = new InvalidOperationException("synthetic read failure");
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => AdComputerComparison.LoadAsync(catalog ? null : [1, 2], (_, _) => throw failure));
        Assert.Same(failure, error);
    }

    sealed class Connections(string dsn) : IPostgresConnectionFactory
    {
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        { var db = new NpgsqlConnection(dsn); await db.OpenAsync(ct); return db; }
    }

    [Fact]
    public async Task Postgres_selects_latest_compatible_pair_per_authorized_domain_and_report_uses_it()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = new NpgsqlConnection(pg.ConnectionString); await db.OpenAsync(Ct);
        // Production SQL against the same minimal relations as the frozen Python vector.
        await PostCollectionPostgres.Sql(db, """
            create table domains(id bigint primary key);
            create table computers_report_v6_snapshots (
                snapshot_id bigint,domain_id bigint,scope_sha256 text,contract_id text,schema_version integer,
                captured_at_utc timestamptz,bucket_start_utc timestamptz,source_observed_at_utc timestamptz,
                source_state text,object_count integer,payload_json jsonb,payload_sha256 bytea);
            insert into domains values (1),(2),(3),(4),(5),(99);
            """, Ct);
        JsonObject[] rows = [Snapshot(1, 10), Snapshot(1, 11, scope: "other"), Snapshot(1, 12, enabled: false),
            Snapshot(2, 20), Snapshot(2, 21), Snapshot(2, 22), Snapshot(3, 30), Snapshot(4, 40), Snapshot(4, 41, scope: "other"),
            Snapshot(99, 990), Snapshot(99, 991), Snapshot(1, 8), Snapshot(1, 9), Snapshot(1, 13)];
        rows[11]["schema_version"] = 2; rows[12]["contract_id"] = "synthetic.other";
        var offsets = new Dictionary<long, int> { [10] = 20, [11] = 25, [12] = 30, [13] = 10, [8] = 28, [9] = 29, [20] = 30, [21] = 30, [22] = 20 };
        foreach (var row in rows)
        {
            var at = DateTimeOffset.Parse("2026-01-01T00:00:00Z").AddHours(offsets.GetValueOrDefault(row.Int("snapshot_id")));
            row["captured_at_utc"] = Iso(at);
            await using var insert = new NpgsqlCommand("""
                insert into computers_report_v6_snapshots values($1,$2,$3,$4,$5,$6,null,null,$7,$8,$9,$10)
                """, db);
            foreach (object value in new object[] { row.Int("snapshot_id"), row.Int("domain_id"), row.Text("scope_sha256")!, row.Text("contract_id")!,
                (int)row.Int("schema_version"), at, row.Text("source_state")!, (int)row.Int("object_count") }) insert.Parameters.Add(new() { Value = value });
            insert.Parameters.Add(new() { NpgsqlDbType = NpgsqlDbType.Jsonb, Value = row["payload_json"]!.ToJsonString() });
            insert.Parameters.Add(new() { Value = Convert.FromHexString(row.Text("payload_sha256")!) });
            await insert.ExecuteNonQueryAsync(Ct);
        }
        long[] scope = [4, 1, 5, 2, 3, 1]; var expected = await Singles(rows, scope);
        var calls = new List<string>();
        Task<List<JsonObject>> Read(string sql, long[]? ids)
        { calls.Add(sql); return ids is null ? AdJson.ReadAsync(db, sql, Ct) : AdJson.ReadAsync(db, sql, Ct, (object)ids); }
        var actual = await AdComputerComparison.LoadAsync(scope, Read);
        Assert.True(JsonNode.DeepEquals(expected, actual["domains"])); Assert.Single(calls);
        Assert.DoesNotContain(actual["domains"]!.AsArray(), d => d.Int("domain_id") == 99);
        Assert.Equal(12, actual["domains"]![1]!["current"].Int("snapshot_id")); Assert.Equal(10, actual["domains"]![1]!["previous"].Int("snapshot_id"));
        Assert.Equal(21, actual["domains"]![3]!["current"].Int("snapshot_id")); Assert.Equal(20, actual["domains"]![3]!["previous"].Int("snapshot_id"));
        calls.Clear(); Assert.Equal("not_collected", (await AdComputerComparison.LoadAsync([], Read)).Text("state")); Assert.Empty(calls);
        calls.Clear(); var all = await AdComputerComparison.LoadAsync(null, Read);
        Assert.Equal(new long[] { 1, 2, 3, 4, 5, 99 }, all["domains"]!.AsArray().Select(d => d.Int("domain_id"))); Assert.Equal(2, calls.Count);

        // The retained projection adapter is tested independently of the native AD report route.
        var request = new AdV2Request("ad.computers.v6", "view", null, scope, new(), "changes", null, false, 100, null, "UTC");
        var report = AdComputerComparison.Report(actual, request);
        Assert.True(JsonNode.DeepEquals(actual, report["snapshot_comparison"]));
        Assert.True(JsonNode.DeepEquals(report["items"], report["collections"]!["changes"]));
        Assert.Equal("partial", report.Text("state")); Assert.Equal(2, report.Int("filtered_count"));
        Assert.Equal("2026-01-02T06:00:00Z", report["items"]![0].Text("observed_at_utc")); Assert.Null(report["items"]![0]!["actor"]);
        var filtered = AdComputerComparison.Report(actual, request with { Params = new() { ["q"] = "Зафиксировано" }, Limit = 1 });
        Assert.Single(filtered["items"]!.AsArray()); Assert.True(filtered["has_more"]!.GetValue<bool>()); Assert.Equal(2, filtered.Int("filtered_count"));
        Assert.Null(filtered["next_cursor"]);
        Assert.Empty(AdComputerComparison.Report(actual, request with { Params = new() { ["reason_code"] = "ou_changed" } })["items"]!.AsArray());
        Assert.Equal("changes_view_does_not_accept_cursor", Assert.Throws<AdInputException>(() => AdComputerComparison.Report(actual, request with { Cursor = "synthetic" })).Message);
    }
}
