using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Ad;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Ad;

public sealed class AdComputersSnapshotWorkerTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static readonly DateTimeOffset Captured = new(2026, 8, 30, 12, 0, 0, TimeSpan.Zero);
    static JsonObject Report() => JsonNode.Parse("""
        {"contract_id":"sli.computers-report.v6","report_key":"ad.computers.v6","state":"available",
         "threshold":{"selected_days":90,"allowed_days":[30,60,90,180]},
         "coverage":{"domains":[],"latest_observed_at_utc":null},"summary":{"total_computers":1},
         "semantic":{},"items":[{"entity_id":1,"display_name":"WS-01"}]}
        """)!.AsObject();

    static async Task Schema(NpgsqlConnection db)
    {
        await PostCollectionPostgres.Sql(db, """
            create table domains(id bigint primary key);
            insert into domains values(1);
            create table ad_context_runs(run_id uuid primary key);
            """, Ct);
        string sql = await File.ReadAllTextAsync(Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/113_computers_report_v6.sql"), Ct);
        string table = Regex.Match(sql, @"create table if not exists computers_report_v6_snapshots\s*\([\s\S]*?\r?\n\);").Value;
        Assert.NotEmpty(table);
        await PostCollectionPostgres.Sql(db, table, Ct);
    }

    [Fact]
    public async Task Snapshot_identity_includes_activity_threshold_and_preserves_payload()
    {
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(Ct);
        await using var db = await pg.OpenAsync(Ct); await Schema(db);
        var report = Report(); string original = report.ToJsonString();
        var result = await AdComputersReportSnapshot.PersistAsync(db, report, 1, Captured, Ct);
        Assert.Equal("captured", result["status"]!.ToString());
        Assert.Equal(1, result["object_count"]!.GetValue<int>());
        Assert.Equal(original, report.ToJsonString());
        await using (var read = new NpgsqlCommand("select scope_json::text,payload_json::text,encode(scope_sha256,'hex'),encode(payload_sha256,'hex'),bucket_start_utc from computers_report_v6_snapshots", db))
        await using (var reader = await read.ExecuteReaderAsync(Ct))
        {
            Assert.True(await reader.ReadAsync(Ct));
            var scope = JsonNode.Parse(reader.GetString(0))!; var payload = JsonNode.Parse(reader.GetString(1))!;
            Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"domain_ids":[1],"report_key":"ad.computers.v6","threshold_days":90}"""), scope));
            Assert.True(JsonNode.DeepEquals(report["threshold"], payload["threshold"]));
            Assert.True(JsonNode.DeepEquals(report["items"], payload["items"]));
            Assert.Equal("2026-08-30T12:00:00+00:00", payload["captured_at_utc"]!.ToString());
            // Independently computed with Python json.dumps(sort_keys=True, separators=(",", ":")).
            Assert.Equal("6b2fd1c1bbdbbb5ca6f516b0b5e9038bb603ec8e422c878864fc5860ec707446", reader.GetString(2));
            Assert.Equal(AdJobPlugin.Digest(payload), reader.GetString(3));
            Assert.Equal(Captured.UtcDateTime, reader.GetDateTime(4));
        }
        Assert.Equal("already_captured", (await AdComputersReportSnapshot.PersistAsync(db, report, 1, Captured.AddHours(1), Ct))["status"]!.ToString());
        report["threshold"]!["selected_days"] = 60;
        Assert.Equal("captured", (await AdComputersReportSnapshot.PersistAsync(db, report, 1, Captured, Ct))["status"]!.ToString());
        report.Remove("threshold");
        Assert.Equal("already_captured", (await AdComputersReportSnapshot.PersistAsync(db, report, 1, Captured, Ct))["status"]!.ToString());
        await using var count = new NpgsqlCommand("select count(*) from computers_report_v6_snapshots", db);
        Assert.Equal(2L, await count.ExecuteScalarAsync(Ct));
        Assert.DoesNotMatch(@"(?m)\b(?:ERROR|FATAL|PANIC):", await pg.DiagnosticsAsync(Ct));
    }

    [Fact]
    public void Computers_exact_projection_matches_active_output_hash_and_is_an_independent_copy()
    {
        var active = JsonNode.Parse("""{"contract_id":"sli.computers-report.v6","report_key":"ad.computers.v6","items":[{"entity_id":1,"display_name":"WS-01"}],"threshold":{"selected_days":60}}""")!.AsObject();
        var manifest = JsonNode.Parse("""{"manifest_id":"00000000-0000-0000-0000-000000000001","manifest_sha256":"abc","members":[{"family":"computers_v6","source_id":"1","payload_sha256":"def"}]}""")!.AsObject();
        var result = AdJobPlugin.Project(manifest, "ad.computers.v6", "computers_v6", active, out var shadow);
        Assert.NotSame(active, shadow);
        Assert.True(JsonNode.DeepEquals(active, shadow));
        const string pythonHash = "330aed1906e55d4fd10a6b35e93c64076982b88e34c69e122e819e0fe19ee87f";
        Assert.Equal(pythonHash, AdJobPlugin.Digest(active));
        Assert.Equal(pythonHash, AdJobPlugin.Digest(shadow));
        Assert.Equal(pythonHash, result["output_sha256"]!.ToString());
        shadow["items"]![0]!["display_name"] = "changed";
        shadow["threshold"]!["selected_days"] = 90;
        Assert.Equal("WS-01", active["items"]![0]!["display_name"]!.ToString());
        Assert.Equal(60, active["threshold"]!["selected_days"]!.GetValue<int>());
    }

    [Theory]
    [InlineData("state", "failed", "snapshot_source_not_usable")]
    [InlineData("contract_id", "other", "snapshot_contract_mismatch")]
    public async Task Invalid_report_is_rejected_before_database_access(string field, string value, string code)
    {
        var report = Report(); report[field] = value;
        await using var db = new NpgsqlConnection();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => AdComputersReportSnapshot.PersistAsync(db, report, 1, Captured, Ct));
        Assert.Equal(code, error.Message);
    }
}
