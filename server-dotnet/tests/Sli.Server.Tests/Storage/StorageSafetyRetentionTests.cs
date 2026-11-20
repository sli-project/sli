using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Sli.Server.Operations;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Behavioral vectors from tests/storage/test_storage_safety_retention.py.
public sealed class StorageSafetyRetentionTests
{
    static readonly DateTimeOffset Now = new(2026, 11, 9, 12, 0, 0, TimeSpan.Zero);
    const long GiB = 1024L * 1024 * 1024;
    const string OldName = "full-20260729-120000-1234-abcdef12";
    sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }
    sealed class Files(IConfiguration config) : OperationsFiles(config)
    {
        public long Free = 50 * GiB, Total = 200 * GiB;
        public string? Linked;
        protected override (long Free, long Total) ReadDiskSpace() => (Free, Total);
        internal override bool CleanupLinkLike(string path) => path == Linked || base.CleanupLinkLike(path);
    }
    sealed class Queries : IOperationsQueries
    {
        public bool FailImport; public HashSet<string> Imported = [];
        public Task<JsonArray> ReadAsync(string sql, CancellationToken ct, params (string Name, object? Value)[] parameters)
        {
            if (sql.Contains("from raw_batch_lifecycle", StringComparison.Ordinal))
            {
                if (FailImport) throw new IOException("fixture unavailable");
                return Task.FromResult(new JsonArray(Imported.Select(p => (JsonNode)new JsonObject { ["file_path"] = p }).ToArray()));
            }
            if (sql.Contains("as database_name")) return Task.FromResult(new JsonArray(new JsonObject { ["database_bytes"] = 0 }));
            return Task.FromResult(new JsonArray());
        }
    }
    sealed class Scope : IDisposable
    {
        public string Root = Path.Combine(Path.GetTempPath(), "sli-storage-retention-" + Guid.NewGuid().ToString("N"));
        public Files Files; public Queries Queries = new(); public OperationsService Service;
        public Scope(params (string Key, string Value)[] settings)
        {
            Directory.CreateDirectory(Root);
            var values = new Dictionary<string, string?> { ["Sli:ProjectRoot"] = Root, ["Sli:DataDirectory"] = Path.Combine(Root, "data"),
                ["Sli:Operations:SLI_BACKUP_SUMMARY_PATH"] = Path.Combine(Root, "missing-backup-summary.json"), ["Sli:Operations:ADLOG_RAW_RETENTION_DAYS"] = "2" };
            foreach (var (key, value) in settings) values["Sli:Operations:" + key] = value;
            Files = new(new ConfigurationBuilder().AddInMemoryCollection(values).Build());
            Service = new(Queries, Files, new OperationsCatalog(), new OperationsJobs(), new Clock());
        }
        public string FileAt(string relative, double hours)
        {
            string path = Path.GetFullPath(Path.Combine(Root, relative)); Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, "{}\n"); File.SetLastWriteTimeUtc(path, Now.AddHours(-hours).UtcDateTime); return path;
        }
        public string Run(string name, double hours)
        {
            string path = FileAt(Path.Combine("data", "tmp", "pytest-runs", name, "fixture.bin"), hours);
            string directory = Path.GetDirectoryName(path)!; Directory.SetLastWriteTimeUtc(directory, Now.AddHours(-hours).UtcDateTime); return directory;
        }
        public void Dispose() { if (Directory.Exists(Root)) Directory.Delete(Root, true); }
    }
    [Theory]
    [InlineData(6L, 100L, 10L, "blocked", false, "free_bytes_and_percent_below_stop")]
    [InlineData(49241799720L, 536870912000L, 10737418240L, "blocked", false, "free_percent_below_stop")]
    [InlineData(9663676416L, 85899345920L, 10737418240L, "blocked", false, "free_bytes_below_stop")]
    [InlineData(12884901888L, 107374182400L, 10737418240L, "warn", true, "warning_only")]
    [InlineData(53687091200L, 214748364800L, 10737418240L, "ok", true, "none")]
    [InlineData(10L, 100L, 10L, "warn", true, "warning_only")]
    [InlineData(15L, 100L, 10L, "ok", true, "none")]
    [InlineData(4L, 100L, 10L, "blocked", false, "free_bytes_and_percent_below_stop")]
    public void DiskPressureMatchesCollectionGuard(long free, long total, long minimum, string status, bool allowed, string condition)
    {
        using var s = new Scope(("ADLOG_STOP_COLLECTION_IF_FREE_DISK_BYTES_BELOW", minimum.ToString()));
        s.Files.Free = free; s.Files.Total = total; var result = s.Files.DiskPressure();
        Assert.Equal(status, (string?)result["status"]); Assert.Equal(allowed, (bool)result["collection_allowed"]!);
        Assert.Equal("free_bytes_or_percent", (string?)result["blocking_threshold"]?["mode"]);
        Assert.Equal(condition, (string?)result["blocking_threshold"]?["condition"]);
        Assert.Equal(minimum, (long)result["blocking_threshold"]!["free_bytes"]!);
    }
    [Theory]
    [InlineData(false, 5, "полный обход проекта неполон: ошибок чтения 5")]
    [InlineData(true, 0, null)]
    [InlineData(true, 1, "полный обход проекта неполон: ошибок чтения 1")]
    public void IncompleteProjectScanIsNeverClean(bool complete, int errors, string? expected)
    {
        var overview = new JsonObject { ["scan"] = new JsonObject { ["complete_project_tree"] = complete, ["errors"] = errors } };
        Assert.Equal(expected, OperationsStorage.ProjectScanWarning(overview));
    }
    [Theory]
    [InlineData(false, "not_confirmed_imported")]
    [InlineData(true, "import_confirmation_unavailable")]
    public async Task DryRunPreservesOldRawWithoutImportProof(bool unavailable, string exclusion)
    {
        using var s = new Scope(); string raw = s.FileAt("data/raw/old.jsonl", 120); s.Queries.FailImport = unavailable;
        var plan = await s.Service.CleanupPreviewAsync(TestContext.Current.CancellationToken);
        var result = await s.Service.ApplyStorageCleanupPlanAsync(plan, ct: TestContext.Current.CancellationToken);
        Assert.Equal("dry-run", (string?)result["mode"]); Assert.True(File.Exists(raw));
        Assert.Equal(0, (int)result["total_candidates"]!); Assert.Equal(1, (long)result["scan"]!["raw"]!["excluded"]![exclusion]!);
        Assert.True((bool)result["safety"]!["raw_requires_confirmed_postgres_import"]!);
    }
    [Fact]
    public async Task FailedAndEvidenceRawRemainProtectedEvenWhenImported()
    {
        using var s = new Scope();
        foreach (string name in new[] { "failed_job.jsonl", "evidence_candidate.jsonl" }) s.Queries.Imported.Add(s.FileAt("data/raw/" + name, 120));
        var plan = await s.Service.CleanupPreviewAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, (int)plan["total_candidates"]!); Assert.Equal(2, (long)plan["scan"]!["raw"]!["excluded"]!["protected"]!);
        Assert.All(s.Queries.Imported, p => Assert.True(File.Exists(p)));
    }
    [Fact]
    public async Task StorageApplyRequiresConfirmationAndWritesOnlyConfiguredReceipt()
    {
        using var s = new Scope(); string raw = s.FileAt("data/raw/old.jsonl", 120); s.Queries.Imported.Add(raw);
        string other = s.FileAt("other-data/maintenance/storage_cleanup_last.json", 0); byte[] before = File.ReadAllBytes(other);
        var plan = await s.Service.CleanupPreviewAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1, (int)plan["total_candidates"]!);
        var result = await s.Service.ApplyStorageCleanupPlanAsync(plan, apply: true, ct: TestContext.Current.CancellationToken);
        Assert.Equal("failed", (string?)result["status"]); Assert.True(File.Exists(raw));
        Assert.True(File.Exists(Path.Combine(s.Root, "data/maintenance/storage_cleanup_last.json"))); Assert.Equal(before, File.ReadAllBytes(other));
    }
    [Fact]
    public async Task StorageHealthIncludesConfiguredPolicyCapacityAndPressure()
    {
        using var s = new Scope(); var result = await s.Service.ReadAsync("/api/storage/health", new(), TestContext.Current.CancellationToken);
        Assert.Equal(2, (long)result["policy"]!["raw_retention_days"]!); Assert.NotNull(result["capacity_plan"]); Assert.NotNull(result["disk_pressure"]);
    }
    [Fact]
    public void GeneratedRunPlanIsExactAndPreservesRecentAndInvalidNames()
    {
        using var s = new Scope(); string old = s.Run(OldName, 30), recent = s.Run("quick-20260730-090000-5678-1234abcd", 2), invalid = s.Run("manual-folder", 50);
        var plan = s.Files.BuildPytestRunCleanupPlan(Now);
        Assert.Equal(s.Files.PytestRunsRoot, (string?)plan["root"]); Assert.Equal(1, (int)plan["total_candidates"]!);
        Assert.Equal(old, (string?)plan["actions"]?[0]?["path"]);
        Assert.Equal(2, plan["scan"]!["excluded"]!.AsObject().Count);
        Assert.Equal(1, (long)plan["scan"]!["excluded"]!["recent"]!); Assert.Equal(1, (long)plan["scan"]!["excluded"]!["invalid_name"]!);
        Assert.True(Directory.Exists(recent)); Assert.True(Directory.Exists(invalid));
    }
    [Fact]
    public void ActiveRunMarkerIsPreserved()
    {
        using var s = new Scope(); string active = s.Run(OldName, 30); string marker = Path.Combine(s.Files.PytestRunsRoot, ".active-" + OldName + ".json"); File.WriteAllText(marker, "{\"pid\":1234}");
        var plan = s.Files.BuildPytestRunCleanupPlan(Now);
        Assert.Equal(0, (int)plan["total_candidates"]!); Assert.Equal(1, (long)plan["scan"]!["excluded"]!["active_marker"]!);
        Assert.True(Directory.Exists(active)); Assert.True(File.Exists(marker));
    }
    [Fact]
    public void TopLevelLinkLikeRunIsExcluded()
    {
        using var s = new Scope(); string linked = s.Run(OldName, 30); s.Files.Linked = linked;
        var plan = s.Files.BuildPytestRunCleanupPlan(Now);
        Assert.Equal(0, (int)plan["total_candidates"]!); Assert.Equal(1, (long)plan["scan"]!["excluded"]!["top_level_link"]!); Assert.True(Directory.Exists(linked));
    }
    [Fact]
    public void RunApplyRequiresConfirmationAndDeletesOnlyPlannedChild()
    {
        using var s = new Scope(); string old = s.Run(OldName, 30), sibling = s.FileAt("data/tmp/keep.txt", 50);
        var plan = s.Files.BuildPytestRunCleanupPlan(Now);
        var dry = s.Files.ApplyPytestRunCleanupPlan(plan, Now); Assert.Equal("dry-run", (string?)dry["mode"]); Assert.True(Directory.Exists(old));
        var refused = s.Files.ApplyPytestRunCleanupPlan(plan, Now, apply: true);
        Assert.Equal("failed", (string?)refused["status"]); Assert.True(Directory.Exists(old));
        var applied = s.Files.ApplyPytestRunCleanupPlan(plan, Now, apply: true, confirmApply: true);
        Assert.Equal("ok", (string?)applied["status"]); Assert.Equal(1, (int)applied["applied_count"]!); Assert.False(Directory.Exists(old)); Assert.Equal("{}\n", File.ReadAllText(sibling));
    }
    [Theory]
    [InlineData("root")]
    [InlineData("outside")]
    [InlineData("active")]
    [InlineData("recent")]
    public void RunApplyRevalidatesPlanBeforeDeletion(string change)
    {
        using var s = new Scope(); string old = s.Run(OldName, 30); var plan = s.Files.BuildPytestRunCleanupPlan(Now);
        if (change == "root") plan["root"] = s.Root;
        if (change == "outside") plan["actions"]![0]!["path"] = s.Root;
        if (change == "active") File.WriteAllText(Path.Combine(s.Files.PytestRunsRoot, ".active-" + OldName + ".json"), "{}");
        if (change == "recent") File.SetLastWriteTimeUtc(Path.Combine(old, "fixture.bin"), Now.UtcDateTime);
        var result = s.Files.ApplyPytestRunCleanupPlan(plan, Now, apply: true, confirmApply: true);
        Assert.NotEqual("ok", (string?)result["status"]); Assert.Equal(0, (int)result["applied_count"]!); Assert.True(Directory.Exists(old));
    }
    [Theory]
    [InlineData(true, true)]
    [InlineData(true, false)]
    [InlineData(false, false)]
    public async Task ConfirmedStorageApplyExecutesRealPlan(bool archive, bool compress)
    {
        using var s = new Scope(("ADLOG_RAW_ARCHIVE_ENABLED", archive ? "1" : "0"), ("ADLOG_RAW_ARCHIVE_COMPRESS", compress ? "1" : "0"));
        string raw = s.FileAt("data/raw/old.jsonl", 120); s.Queries.Imported.Add(raw);
        var plan = await s.Service.CleanupPreviewAsync(TestContext.Current.CancellationToken);
        var result = await s.Service.ApplyStorageCleanupPlanAsync(plan, true, true, TestContext.Current.CancellationToken);
        Assert.Equal("ok", (string?)result["status"]); Assert.False(File.Exists(raw)); Assert.Single(result["applied"]!.AsArray());
        if (archive) Assert.Single(Directory.GetFiles(Path.Combine(s.Root, "data/raw_archive")));
    }
    [Fact]
    public async Task StorageApplyRevalidatesImportProof()
    {
        using var s = new Scope(); string raw = s.FileAt("data/raw/old.jsonl", 120); s.Queries.Imported.Add(raw);
        var plan = await s.Service.CleanupPreviewAsync(TestContext.Current.CancellationToken); s.Queries.Imported.Clear();
        var result = await s.Service.ApplyStorageCleanupPlanAsync(plan, true, true, TestContext.Current.CancellationToken);
        Assert.Equal("warn", (string?)result["status"]); Assert.True(File.Exists(raw)); Assert.Empty(result["applied"]!.AsArray());
    }
}
