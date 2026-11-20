using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Operations;
using Sli.Server.Storage.Lifecycle;
using Sli.Server.Tests.Operations;
using Sli.Server.Workstations;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Behavioral vectors from tests/storage/test_purge_audit.py.
public sealed class PurgeAuditTests
{
    static OperationsFiles Reader(StorageLifecycleTests.State state) => new(new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:ProjectRoot"] = state.Path, ["Sli:DataDirectory"] = state.Path }).Build());

    [Fact]
    public void Interrupted_run_remains_running_after_reopening_receipts()
    {
        using var state = new StorageLifecycleTests.State();
        state.Files.StartPurge("agent_inbox");

        var row = Assert.Single(Reader(state).PurgeRuns()["runs"]!.AsArray())!.AsObject();
        Assert.Equal("running", row["status"]?.ToString());
        Assert.Equal("agent_inbox", row["lane"]?.ToString());
        Assert.Equal("sli.purge-run.v1", row["contract"]?.ToString());
        Assert.Equal(0L, row["duration_ms"]?.GetValue<long>());
        Assert.Equal(0L, row["bytes_reclaimed"]?.GetValue<long>());
        Assert.Equal(0L, row["logical_bytes_deleted"]?.GetValue<long>());
        Assert.False(row["physical_reclaim_performed"]!.GetValue<bool>());
        Assert.Null(row["finished_at_utc"]);
        Assert.Equal(new[] { "sli_agent_packet_inbox" }, row["tables"]!.AsObject().Select(p => p.Key).Order());
        foreach (var table in row["tables"]!.AsObject()) {
            Assert.Equal(0L, table.Value!["selected_count"]!.GetValue<long>());
            Assert.Equal(0L, table.Value["deleted_count"]!.GetValue<long>());
            Assert.Empty(table.Value["partitions"]!.AsArray());
        }
    }

    [Fact]
    public void Finished_runs_prune_disk_and_visible_history_to_latest_receipts()
    {
        using var state = new StorageLifecycleTests.State();
        state.Files.StartPurge("agent_inbox"); // An interrupted run is pruned with old completed runs.
        for (int i = 0; i < 55; i++) {
            var run = state.Files.StartPurge("agent_inbox");
            state.Files.PurgeReceipt(run, new JsonObject { ["status"] = "complete", ["last_scanned_id"] = (long)i });
        }

        var result = Reader(state).PurgeRuns();
        Assert.Equal("ok", result["status"]?.ToString());
        Assert.Equal(50, result["limit"]!.GetValue<int>());
        var rows = result["runs"]!.AsArray();
        Assert.Equal(50, rows.Count);
        Assert.Equal(50, Directory.GetFiles(Path.Combine(state.Path, "runtime", "purge-runs"), "*.json").Length);
        Assert.Equal(Enumerable.Range(5, 50).Reverse().Select(i => (long)i), rows.Select(r => r!["last_scanned_id"]!.GetValue<long>()));
        foreach (var row in rows) {
            Assert.Equal("complete", row!["status"]?.ToString());
            Assert.NotNull(row["duration_ms"]);
            Assert.True(row["duration_ms"]!.GetValue<double>() >= 0);
            Assert.Equal(0L, row["bytes_reclaimed"]!.GetValue<long>());
            Assert.True(DateTimeOffset.Parse(row["finished_at_utc"]!.ToString()) >= DateTimeOffset.Parse(row["started_at_utc"]!.ToString()));
        }
    }

    [Fact]
    public async Task Initial_receipt_write_failure_prevents_database_work()
    {
        using var state = new StorageLifecycleTests.State();
        Directory.CreateDirectory(Path.Combine(state.Path, "runtime"));
        // A file in place of the audit directory deterministically rejects writes on Windows and Linux.
        File.WriteAllText(Path.Combine(state.Path, "runtime", "purge-runs"), "fixture write failure");
        var database = NpgsqlDataSource.Create("Host=192.0.2.1;Database=synthetic;Username=synthetic");
        await database.DisposeAsync(); // Any attempt to open it fails locally, without network access.
        var retention = new InboxRetention(database, state.Files);
        await Assert.ThrowsAnyAsync<IOException>(() => retention.RunAsync(new DateTime(2026, 9, 20, 0, 0, 0, DateTimeKind.Utc), Guid.Empty, 1000, TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("57014", "purge_statement_timeout")]
    [InlineData("55P03", "purge_lock_unavailable")]
    [InlineData("42501", "purge_permission_denied")]
    [InlineData("23503", "purge_dependency_changed")]
    public void Database_failure_uses_sqlstate_instead_of_private_exception_text(string sqlstate, string reason)
    {
        var error = new PostgresException("fixture private query text", "ERROR", "ERROR", sqlstate);
        Assert.Equal(reason, LifecycleJson.Failure(error));
        Assert.Equal(reason, WorkstationPurgeRun.Reason(error));
    }

    [Fact]
    public async Task Storage_health_exposes_purge_runs_when_database_metrics_are_unavailable()
    {
        using var state = new StorageLifecycleTests.State();
        var run = state.Files.StartPurge("agent_inbox");
        state.Files.PurgeReceipt(run, new JsonObject { ["status"] = "blocked", ["reason"] = "history_retention_delete_mismatch" });
        var queries = new OperationsEndpointTests.Queries { Fail = true };
        var service = new OperationsService(queries, Reader(state), new OperationsCatalog(), new OperationsJobs(), TimeProvider.System);

        var result = await service.ReadAsync("/api/storage/health", new(), TestContext.Current.CancellationToken);
        Assert.Equal("unavailable", result["storage_lifecycle"]?["status"]?.ToString());
        Assert.False(result["postgres_operations"]!["available"]!.GetValue<bool>());
        var row = Assert.Single(result["purge_runs"]!["runs"]!.AsArray());
        Assert.Equal("blocked", row!["status"]?.ToString());
        Assert.Equal("history_retention_delete_mismatch", row["reason"]?.ToString());
        Assert.DoesNotContain("private-db-password-and-AD-data", result.ToJsonString());
    }
}
