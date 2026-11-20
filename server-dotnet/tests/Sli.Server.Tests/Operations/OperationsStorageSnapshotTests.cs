using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Sli.Server.Operations;
using Xunit;

namespace Sli.Server.Tests.Operations;

public sealed class OperationsStorageSnapshotTests : IDisposable
{
    readonly string root = Path.Combine(Path.GetTempPath(), "sli-storage-snapshot-" + Guid.NewGuid().ToString("N"));
    static readonly DateTimeOffset Now = new(2026, 9, 2, 10, 0, 0, TimeSpan.Zero);
    OperationsFiles Files() => new(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["Sli:ProjectRoot"] = root, ["Sli:DataDirectory"] = Path.Combine(root, "data"),
        ["Sli:Operations:ADLOG_OPERATIONS_STORAGE_MAX_AGE_SECONDS"] = "3600",
        ["Sli:Operations:SLI_BACKUP_SUMMARY_PATH"] = Path.Combine(root, "missing-backup.json")
    }).Build());
    string Write(string relative, int bytes)
    {
        string path = Path.Combine(root, relative); Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, new byte[bytes]); return path;
    }
    void Snapshot(JsonObject data)
    {
        string path = Write("artifacts/operations/project-storage-latest.json", 0);
        File.WriteAllText(path, data.ToJsonString());
    }
    static JsonObject ValidSnapshot() => JsonNode.Parse("""
        {"schema":"sli.operations-storage-footprint.v1","status":"ok","generated_at_utc":"2026-09-02T09:59:50+00:00",
         "components":[{"key":"project_root","bytes":10}],"totals":{"accounted_bytes":10},"warnings":[],
         "raw_spool":{"status":"ok","bytes":10,"batch_count":1,"oldest_batch_at_utc":"2026-08-30T10:00:00+00:00",
         "oldest_batch_age_seconds":10,"scan":{"complete":true,"errors":0},
         "thresholds":{"bytes_warning":1,"bytes_critical":2,"batch_count_warning":1,"oldest_age_warning_seconds":1}}}
        """)!.AsObject();

    [Fact]
    public void RuntimeInventoryMeasuresOnlyDirectBatchesAndTheirOldestTimestamp()
    {
        Write("data/raw/pilot/batch-old/Security.jsonl", 7); Write("data/raw/pilot/batch-new/System.jsonl", 5);
        Directory.CreateDirectory(Path.Combine(root, "data/raw/pilot/batch-new/nested"));
        Directory.SetLastWriteTimeUtc(Path.Combine(root, "data/raw/pilot/batch-old"), new DateTime(2026, 8, 30, 10, 0, 0, DateTimeKind.Utc));
        Directory.SetLastWriteTimeUtc(Path.Combine(root, "data/raw/pilot/batch-new"), new DateTime(2026, 8, 31, 10, 0, 0, DateTimeKind.Utc));
        var spool = Files().RuntimeStorage(true, Now)["raw_spool"];
        Assert.NotNull(spool); Assert.Equal("ok", (string?)spool["status"]);
        Assert.Equal(12, (long)spool["bytes"]!); Assert.Equal(2, (long)spool["batch_count"]!);
        Assert.Equal("2026-08-30T10:00:00+00:00", (string?)spool["oldest_batch_at_utc"]);
        Assert.True((bool)spool["scan"]!["complete"]!); Assert.Equal(524288000, (int)spool["thresholds"]!["bytes_warning"]!);
    }

    [Fact]
    public void MissingRawSpoolIsUnknownRatherThanMeasuredZero()
    {
        Directory.CreateDirectory(root);
        var spool = Files().RuntimeStorage(true, Now)["raw_spool"];
        Assert.NotNull(spool); Assert.Equal("unavailable", (string?)spool["status"]);
        Assert.Null(spool["bytes"]); Assert.Null(spool["batch_count"]); Assert.Null(spool["oldest_batch_at_utc"]);
        Assert.False((bool)spool["scan"]!["complete"]!);
    }

    [Fact]
    public void ReaderRejectsWrongSchemaWithoutStartingMeasurement()
    {
        Snapshot(new JsonObject { ["schema"] = "wrong", ["components"] = new JsonArray() });
        var result = Files().Footprint(Now);
        Assert.Equal("unavailable", (string?)result["status"]); Assert.Empty(result["components"]!.AsArray());
        Assert.False((bool)result["snapshot"]!["available"]!); Assert.False(Directory.Exists(Path.Combine(root, "data")));
    }

    [Fact]
    public void ReaderAddsFreshnessToValidSnapshot()
    {
        Snapshot(ValidSnapshot()); var result = Files().Footprint(Now);
        Assert.Equal("ok", (string?)result["status"]); Assert.True((bool)result["snapshot"]!["available"]!);
        Assert.False((bool)result["snapshot"]!["stale"]!); Assert.Equal(10, (double)result["snapshot"]!["age_seconds"]!);
    }

    [Fact]
    public void ReaderRejectsUnavailableSpoolWithInventedZeroMeasurements()
    {
        var data = ValidSnapshot(); data["raw_spool"]!["status"] = "unavailable";
        data["raw_spool"]!["bytes"] = 0; data["raw_spool"]!["batch_count"] = 0; Snapshot(data);
        var result = Files().Footprint(Now);
        Assert.Equal("unavailable", (string?)result["status"]); Assert.Null(result["raw_spool"]!["bytes"]);
    }

    [Fact]
    public void ReaderKeepsOtherFootprintWhenSpoolIsHonestlyUnavailable()
    {
        var data = ValidSnapshot(); data["status"] = "partial";
        var spool = data["raw_spool"]!; spool["status"] = "unavailable";
        foreach (string key in new[] { "bytes", "human", "batch_count", "oldest_batch_at_utc", "oldest_batch_age_seconds" }) spool[key] = null;
        spool["scan"] = new JsonObject { ["complete"] = false, ["errors"] = 1 }; Snapshot(data);
        var result = Files().Footprint(Now);
        Assert.Equal("partial", (string?)result["status"]); Assert.Equal(10, (int)result["totals"]!["accounted_bytes"]!);
        Assert.Equal("unavailable", (string?)result["raw_spool"]!["status"]); Assert.Null(result["raw_spool"]!["bytes"]);
    }

    sealed class ProjectFiles(IConfiguration config, JsonObject project) : OperationsFiles(config)
    {
        public override JsonObject RuntimeStorage(bool force, DateTimeOffset now) => project.DeepClone().AsObject();
    }
    static JsonObject Project(bool partial = false) => JsonNode.Parse(partial ? """
        {"sizes":{"project":{"bytes":1000},"data":{"bytes":500},"storage_v2_archives":{"bytes":300},
         "backups":{"bytes":100},"artifacts":{"bytes":50},"venv":{"bytes":200},"frontend_node_modules":{"bytes":150}},
         "scan":{"complete_project_tree":true},"raw_spool":{"status":"partial","bytes":12,"batch_count":2,
         "oldest_batch_at_utc":"2026-08-30T10:00:00+00:00","scan":{"complete":false,"errors":1},
         "thresholds":{"bytes_warning":10,"bytes_critical":20,"batch_count_warning":1000,"oldest_age_warning_seconds":172800}}}
        """ : """
        {"sizes":{"project":{"bytes":100}},"scan":{"complete_project_tree":true},
         "raw_spool":{"status":"ok","bytes":0,"batch_count":0,"scan":{"complete":true},
         "thresholds":{"bytes_warning":100,"bytes_critical":200,"batch_count_warning":100}}}
        """)!.AsObject();
    OperationsStorageSnapshot Producer(JsonObject project, long pgBytes, Func<string[], CancellationToken, Task<string>> docker) =>
        new(new ProjectFiles(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["Sli:ProjectRoot"] = root, ["Sli:DataDirectory"] = Path.Combine(root, "data") }).Build(), project),
            _ => Task.FromResult(new JsonObject { ["available"] = true, ["status"] = "ok",
                ["database"] = new JsonObject { ["database_bytes"] = pgBytes, ["checked_at"] = Now } }));
    static Task<string> Docker(string[] args, CancellationToken ct) => Task.FromResult(args[0] switch
    {
        "inspect" => """[{"State":{"Running":true},"Mounts":[]}]""",
        "image" => "700",
        _ => args.Contains("du") ? "600 /var/lib/clickhouse" : """{"database":"synthetic","bytes":450}"""
    });
    StorageSnapshotOptions Options() => new() { ExternalArchive = Path.Combine(root, "external"), EvidenceRoot = Path.Combine(root, "evidence") };
    static Dictionary<string, JsonObject> Components(JsonObject result) => result["components"]!.AsArray().OfType<JsonObject>().ToDictionary(c => (string)c["key"]!);

    [Fact]
    public async Task ProducerExcludesNestedRowsAndSharedImagesFromTotals()
    {
        Write("external/archive.bin", 200); Write("evidence/raw.bin", 300);
        var result = await Producer(Project(true), 400, Docker).BuildAsync(Options(), Now, TestContext.Current.CancellationToken);
        Assert.Equal(1900, (long)result["totals"]!["accounted_bytes"]!);
        Assert.Equal(1500, (long)result["totals"]!["known_physical_bytes"]!);
        Assert.Null(result["docker_images"]);
        var components = Components(result);
        Assert.Equal(new[] { "evidence_root", "external_archive", "postgres_database", "project_root" },
            components.Values.Where(c => (bool)c["included_in_accounted_total"]!).Select(c => (string)c["key"]!).Order().ToArray());
        Assert.DoesNotContain(components.Keys, k => k.StartsWith("docker_image:",StringComparison.Ordinal));
        Assert.Equal("partial", (string?)result["raw_spool"]!["status"]);
        Assert.Equal(259200, (long)result["raw_spool"]!["oldest_batch_age_seconds"]!);
        Assert.Contains(result["warnings"]!.AsArray(), w => w!.ToString().Contains("RAW spool scan is incomplete"));
    }

    [Fact]
    public void WriterSerializesPostgresUtcDatetimeAndReplacesSnapshotAtomically()
    {
        string path = Write("latest.json", 100);
        OperationsStorageSnapshot.WriteAtomic(path, new { checked_at = new DateTime(2026, 8, 2, 1, 2, 3, DateTimeKind.Utc) });
        Assert.Equal("2026-08-02T01:02:03+00:00", (string?)JsonNode.Parse(File.ReadAllText(path))!["checked_at"]);
        Assert.False(File.Exists(path + ".tmp"));
    }

    [Fact]
    public async Task PhysicalPostgresAndPlatformDependenciesAreCountedOnce()
    {
        Write("external/archive.bin", 200); Write("evidence/raw.bin", 300); Write("deps/docker-data/ext4.vhdx", 5000);
        Write("pg-data/base.bin", 3000); Write("pg-bin/postgres.exe", 1500); Write("sli-data/runtime/state.bin", 250); Write("pnpm-store/pkg.tar", 800);
        var project = Project(); project["sizes"]!["project"]!["bytes"] = 1000;
        var options = Options() with { PlatformDependencies = Path.Combine(root, "deps"), PostgresData = Path.Combine(root, "pg-data"),
            PostgresBin = Path.Combine(root, "pg-bin"), SliData = Path.Combine(root, "sli-data"), PnpmStore = Path.Combine(root, "pnpm-store"), HistoryContainer = "sli-history" };
        var result = await Producer(project, 400, Docker).BuildAsync(options, Now, TestContext.Current.CancellationToken);
        var components = Components(result);
        Assert.Equal(new[] { "evidence_root", "external_archive", "platform_dependencies", "pnpm_store", "postgres_physical_cluster", "postgres_server_install", "project_root", "sli_data_root" },
            components.Values.Where(c => (bool)c["included_in_accounted_total"]!).Select(c => (string)c["key"]!).Order().ToArray());
        foreach (var (child, parent) in new[] { ("postgres_database", "postgres_physical_cluster"), ("sli_data_runtime", "sli_data_root") })
        {
            Assert.False((bool)components[child]["included_in_accounted_total"]!); Assert.Equal(parent, (string?)components[child]["parent"]);
        }
        Assert.Equal(12050, (long)result["totals"]!["accounted_bytes"]!);
        Assert.Equal("measured", (string?)result["totals"]!["accounting_quality"]); Assert.False((bool)result["totals"]!["postgres_proxy_included"]!);
    }

    async Task<(JsonObject Result, List<string[]> Calls)> History(string? failure = null, bool deps = false, string? history = "sli-history", bool docker = true)
    {
        Write("pg/data", 10); if (deps) Directory.CreateDirectory(Path.Combine(root, "deps"));
        var calls = new List<string[]>();
        Task<string> Probe(string[] args, CancellationToken ct)
        {
            calls.Add(args);
            if (args[1] == "sli-history" && (failure == "inspect" && args[0] == "inspect" || failure == "du" && args.Contains("du") || failure == "query" && args.Contains("--query")))
                throw new InvalidOperationException("credential=do-not-expose");
            return args[0] == "image" ? Task.FromResult("0") : Docker(args, ct);
        }
        var result = await Producer(Project(), 10, Probe).BuildAsync(Options() with { PostgresData = Path.Combine(root, "pg"),
            PlatformDependencies = deps ? Path.Combine(root, "deps") : null, HistoryContainer = history, IncludeDocker = docker }, Now, TestContext.Current.CancellationToken);
        return (result, calls);
    }

    [Theory]
    [InlineData("inspect", false)] [InlineData("du", false)] [InlineData("query", false)]
    [InlineData("inspect", true)] [InlineData("du", true)] [InlineData("query", true)]
    public async Task StorageDoesNotProbeClickHouseOrExposeItsCredentials(string failure, bool deps)
    {
        var (result, calls) = await History(failure, deps);
        Assert.Empty(calls);
        Assert.DoesNotContain(Components(result).Keys, k => k.Contains("clickhouse",StringComparison.Ordinal));
        Assert.Equal("ok", (string?)result["status"]); Assert.Equal("measured", (string?)result["totals"]!["accounting_quality"]);
        Assert.Equal(110, (long)result["totals"]!["accounted_bytes"]!);
        Assert.DoesNotContain("do-not-expose", result.ToJsonString());
    }

    [Theory]
    [InlineData(null, true)] [InlineData("", true)] [InlineData("sli-warm-tier-step1", true)] [InlineData("sli-history", false)]
    public async Task UnconfiguredSharedOrSkippedHistoryIsNotAnAccountingFailure(string? history, bool docker)
    {
        var (result, calls) = await History(history: history, docker: docker);
        Assert.Equal("ok", (string?)result["status"]); Assert.Equal("measured", (string?)result["totals"]!["accounting_quality"]);
        Assert.DoesNotContain("clickhouse_volume_history", Components(result).Keys);
        Assert.DoesNotContain(calls, args => args.Contains("sli-history"));
        if (!docker) Assert.Empty(calls);
    }

    [Fact]
    public async Task LegacyContainerOptionsDoNotChangePostgresAccounting()
    {
        var (result, calls) = await History();
        Assert.Empty(calls); Assert.DoesNotContain("clickhouse_volume_history",Components(result).Keys);
        Assert.Equal("ok", (string?)result["status"]); Assert.Equal("measured", (string?)result["totals"]!["accounting_quality"]);
        Assert.Equal(110, (long)result["totals"]!["accounted_bytes"]!);
    }

    [Fact]
    public async Task CommandProducesAReadableSnapshotWithExplicitOfflineOptions()
    {
        string path = Path.Combine(root, "artifacts/operations/project-storage-latest.json");
        using var output = new StringWriter(); using var error = new StringWriter();
        int code = await OperationsStorageSnapshotCommand.RunCoreAsync(["--output", path, "--skip-docker", "--clickhouse-history-container", "sli-history", "--postgres-data", Path.Combine(root, "pg"),
            "--external-archive", Path.Combine(root, "missing-external"), "--evidence-root", Path.Combine(root, "missing-evidence"),
            "--platform-deps", Path.Combine(root, "missing-deps"), "--postgres-bin", Path.Combine(root, "missing-bin"),
            "--sli-data", Path.Combine(root, "missing-data"), "--pnpm-store", Path.Combine(root, "missing-store")],
            (options, ct) => Producer(Project(), 10, (_, _) => throw new InvalidOperationException("Docker must be skipped")).BuildAsync(options, Now, ct), output, error, TestContext.Current.CancellationToken);
        Assert.Equal(0, code); Assert.Equal("", error.ToString()); Assert.True(File.Exists(path)); Assert.False(File.Exists(path + ".tmp"));
        Assert.Equal("ok", (string?)Files().Footprint(Now)["status"]);
        Assert.DoesNotContain("clickhouse_volume_history", Components(JsonNode.Parse(File.ReadAllText(path))!.AsObject()).Keys);
    }

    [Fact]
    public async Task CommandRejectsUnknownArgumentsWithoutStartingMeasurement()
    {
        using var output = new StringWriter(); using var error = new StringWriter(); bool invoked = false;
        int code = await OperationsStorageSnapshotCommand.RunCoreAsync(["--not-an-option"], (_, _) => { invoked = true; throw new InvalidOperationException(); }, output, error, TestContext.Current.CancellationToken);
        Assert.NotEqual(0, code); Assert.False(invoked);
    }

    public void Dispose() { if (Directory.Exists(root)) Directory.Delete(root, true); }
}
