using System.IO.Compression;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Compatibility;
using Sli.Server.Operations;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class StabilizationRuntimeSecurityAiTests
{
    // Source: tests/storage/test_stabilization_runtime_security_ai.py.
    sealed class RawTree : IDisposable
    {
        public string Root { get; } = Path.Combine(Path.GetTempPath(), "sli-stabilization-" + Guid.NewGuid().ToString("N"));
        public OperationsFiles Files { get; }
        public string Old { get; }
        public string Recent { get; }
        public RawTree()
        {
            string raw = Path.Combine(Root, "data", "raw", "pilot"); Directory.CreateDirectory(raw);
            Old = Path.Combine(raw, "old.jsonl"); Recent = Path.Combine(raw, "recent.jsonl");
            File.WriteAllText(Old, "{}\n"); File.WriteAllText(Recent, "{\"recent\":true}\n");
            File.SetLastWriteTimeUtc(Old, DateTime.UtcNow.AddDays(-10));
            Files = new(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
                ["Sli:ProjectRoot"] = Root, ["Sli:DataDirectory"] = Path.Combine(Root, "data") }).Build());
        }
        public void Dispose() => Directory.Delete(Root, true);
    }

    [Fact]
    public void Raw_cleanup_is_a_dry_run_until_applied_and_preserves_the_relative_path()
    {
        using var tree = new RawTree();
        var plan = tree.Files.BuildRawCleanupPlan(olderThanDays: 7);
        Assert.Equal(1, (int)plan["total_candidates"]!);
        var dry = tree.Files.ApplyRawCleanupPlan(plan);
        Assert.Equal("dry-run", (string?)dry["mode"]); Assert.True(File.Exists(tree.Old));
        Assert.False(Directory.Exists(Path.Combine(tree.Root, "data", "raw_archive")));
        var result = tree.Files.ApplyRawCleanupPlan(plan, apply: true);
        Assert.Empty(result["errors"]!.AsArray()); Assert.Single(result["moved"]!.AsArray());
        Assert.False(File.Exists(tree.Old)); Assert.True(File.Exists(tree.Recent));
        Assert.Equal("{}\n", File.ReadAllText(Path.Combine(tree.Root, "data", "raw_archive", "pilot", "old.jsonl")));
        var summary = tree.Files.RuntimeStorage(true, DateTimeOffset.UtcNow);
        Assert.NotNull(summary["sizes"]); Assert.NotNull(summary["disk"]);
    }

    [Fact]
    public void Zip_cleanup_explains_recent_exclusions_and_persists_the_last_cleanup()
    {
        using var tree = new RawTree();
        var plan = tree.Files.BuildRawCleanupPlan(olderThanDays: 7, archiveMode: "zip");
        Assert.Equal("zip", (string?)plan["archive_mode"]);
        Assert.Equal(1, (int)plan["total_candidates"]!);
        Assert.Equal(1L, (long)plan["exclusion_summary"]!["recent_file"]!);
        var result = tree.Files.ApplyRawCleanupPlan(plan, apply: true);
        Assert.Empty(result["errors"]!.AsArray()); Assert.False(File.Exists(tree.Old)); Assert.True(File.Exists(tree.Recent));
        Assert.Equal("pilot/old.jsonl", (string?)Assert.Single(result["archived"]!.AsArray())!["archive_name"]);
        using var zip = ZipFile.OpenRead((string)result["zip_path"]!);
        using var reader = new StreamReader(Assert.Single(zip.Entries).Open()); Assert.Equal("{}\n", reader.ReadToEnd());
        var summary = tree.Files.RuntimeStorage(true, DateTimeOffset.UtcNow);
        Assert.Equal("zip", (string?)summary["last_raw_cleanup"]!["archive_mode"]);
        Assert.Equal(1, (int)summary["last_raw_cleanup"]!["archived_count"]!);
    }

    [Theory]
    [InlineData("move")]
    [InlineData("zip")]
    public void Changed_sources_are_kept_after_a_plan_was_built(string mode)
    {
        using var tree = new RawTree(); var plan = tree.Files.BuildRawCleanupPlan(archiveMode: mode);
        File.WriteAllText(tree.Old, "{\"changed\":true}\n");
        var result = tree.Files.ApplyRawCleanupPlan(plan, apply: true);
        Assert.NotEmpty(result["errors"]!.AsArray()); Assert.True(File.Exists(tree.Old));
        Assert.Empty(result["moved"]!.AsArray()); Assert.Empty(result["archived"]!.AsArray());
    }

    [Theory]
    [InlineData("path")]
    [InlineData("target")]
    public void A_modified_plan_cannot_escape_the_raw_and_archive_directories(string field)
    {
        using var tree = new RawTree(); var plan = tree.Files.BuildRawCleanupPlan();
        string outside = Path.Combine(tree.Root, "outside.jsonl"); File.WriteAllText(outside, "keep");
        plan["candidates"]![0]![field] = outside;
        var result = tree.Files.ApplyRawCleanupPlan(plan, apply: true);
        Assert.NotEmpty(result["errors"]!.AsArray()); Assert.Equal("keep", File.ReadAllText(outside)); Assert.True(File.Exists(tree.Old));
    }

    [Fact]
    public void Strict_leak_check_blocks_original_identity_and_ip_but_accepts_tokens_and_clock_time()
    {
        var blocked = AiPreviewRedaction.Leaks(new JsonObject { ["user"] = "example\\fixture", ["ip"] = "192.0.2.7" }, "strict");
        Assert.True((bool)blocked["blocked"]!); Assert.Equal("blocked", (string?)blocked["status"]);
        Assert.Contains(blocked["items"]!.AsArray(), i => (string?)i!["type"] == "domain_user" && (string?)i["path"] == "$.user");
        Assert.Contains(blocked["items"]!.AsArray(), i => (string?)i!["type"] == "ipv4" && (string?)i["path"] == "$.ip");
        var safe = AiPreviewRedaction.Leaks(new JsonObject { ["user"] = "account_001", ["ip"] = "ip_001", ["time"] = "08:00:00" }, "strict");
        Assert.Equal("ok", (string?)safe["status"]); Assert.False((bool)safe["blocked"]!); Assert.Equal(0, (int)safe["leaks_found"]!);
    }

    [Fact]
    public async Task Collector_history_persists_query_import_and_speed_metrics_in_PostgreSQL()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new PostCollectionPostgres(canonicalSchema: true); await fixture.StartAsync(ct);
        await using var db = await fixture.OpenAsync(ct);
        string schema = File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(), "config", "postgres_schema.sql"));
        await PostCollectionPostgres.Sql(db, Regex.Match(schema, @"create table if not exists collector_channel_runs \([\s\S]*?\n\);").Value, ct);
        var summary = JsonNode.Parse("""{"channels":[{"channel":"Security","status":"completed","count":3,"started_at":"2026-07-07T08:00:00Z","finished_at":"2026-07-07T08:00:05Z","duration_seconds":5,"max_events":500,"timeout_seconds":900}]}""")!.AsObject();
        var stats = JsonNode.Parse("""{"Security":{"inserted":3,"skipped":0}}""")!.AsObject();
        await CollectorChannelHistory.RecordAsync(db, "dc.example.test", summary, stats, importDurationMs: 200, ct: ct);
        await using (var command = new NpgsqlCommand("select server,channel,query_duration_ms,import_duration_ms,events_per_second,total_duration_ms,inserted,skipped from collector_channel_runs", db))
        await using (var row = await command.ExecuteReaderAsync(ct)) {
            Assert.True(await row.ReadAsync(ct)); Assert.Equal("dc.example.test", row.GetString(0)); Assert.Equal("Security", row.GetString(1));
            Assert.Equal(5000, row.GetInt32(2)); Assert.Equal(200, row.GetInt32(3)); Assert.Equal(0.6, row.GetDouble(4)); Assert.Equal(5200, row.GetInt32(5));
            Assert.Equal(3, row.GetInt64(6)); Assert.Equal(0, row.GetInt64(7)); Assert.False(await row.ReadAsync(ct));
        }
        // Missing channels produce no rows; zero query duration is not an invented speed.
        await CollectorChannelHistory.RecordAsync(db, "dc.example.test", new JsonObject(), new JsonObject(), ct: ct);
        summary["channels"]![0]!["duration_seconds"] = 0;
        await CollectorChannelHistory.RecordAsync(db, "dc.example.test", summary, stats, ct: ct);
        await using var zero = new NpgsqlCommand("select count(*),count(events_per_second) from collector_channel_runs", db);
        await using var counts = await zero.ExecuteReaderAsync(ct); Assert.True(await counts.ReadAsync(ct));
        Assert.Equal(2, counts.GetInt64(0)); Assert.Equal(1, counts.GetInt64(1));
    }
}
