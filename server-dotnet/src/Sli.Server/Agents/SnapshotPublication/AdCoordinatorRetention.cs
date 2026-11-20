using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Storage.Lifecycle;

namespace Sli.Server.Agents.SnapshotPublication;

internal static class AdCoordinatorRetention
{
    internal static async Task<JsonObject> RunAsync(NpgsqlConnection db, Guid manifest, Func<string, string?> get, CancellationToken ct)
    {
        // The coordinator keeps its application identity. History uses the
        // existing dedicated writer identity, never the deletion identity.
        NpgsqlConnection? writer = null;
        if (GpoWorkerConfiguration.TryCreateNamed(get, LifecycleRuntime.ReadSecret,
            "ADLOG_SNAPSHOT_HISTORY_DSN", "ADLOG_SNAPSHOT_HISTORY_PASSWORD", "sli_snapshot_history", 0, out string? dsn)) {
            writer = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(dsn!) {
                CommandTimeout = 0, Options = "-c role=adlog_storage_lifecycle_worker -c statement_timeout=0 -c lock_timeout=0"
            }.ConnectionString);
            await writer.OpenAsync(ct);
        }
        await using var lifetime = writer;
        var connection = writer ?? db;
        await using var source = NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder(connection.ConnectionString) { CommandTimeout = 0 }.ConnectionString);
        var history = new SnapshotHistory(source, get, () => source);
        await using var tx = await connection.BeginTransactionAsync(ct);
        await using var gate = new NpgsqlCommand("select pg_advisory_xact_lock(hashtext('sli_ad_snapshot_change_history_v1'))", connection, tx);
        await gate.ExecuteNonQueryAsync(ct);
        long records = await history.PublishManifest(connection, tx, manifest, ct);
        await tx.CommitAsync(ct);
        return new() { ["status"] = "executed", ["records_published"] = records, ["manifest_id"] = manifest.ToString("D") };
    }
}
