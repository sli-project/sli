using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;

namespace Sli.Server.Legacy;

public sealed record LegacyCollectionRequest(string Server, string[] Channels, string CollectionMode, string CollectMessage)
{
    internal static LegacyCollectionRequest Create(string server, string[] channels, bool recovery, LegacySettings settings)
    {
        string forced = (settings.Get("ADLOG_COLLECTION_MODE") ?? "auto").Trim().ToLowerInvariant();
        string mode = forced is "current" or "backfill" or "recovery" ? forced : recovery ? "recovery" : "current";
        return new(server, channels.ToArray(), mode, settings.Get("ADLOG_COLLECT_MESSAGE") ?? "false");
    }
}

// Channel history is supplied by acquisition only after import. Preserve the
// effective and requested modes separately, including empty channel results.
public sealed record LegacyCollectorRun(string Server, JsonObject Summary, JsonObject ImportStats)
{
    internal IEnumerable<NpgsqlCommand> Commands(long jobId, NpgsqlConnection? db = null, NpgsqlTransaction? tx = null)
    {
        foreach (var item in (Summary["channels"] as JsonArray ?? []).OfType<JsonObject>()) {
            string channel = item["channel"]?.ToString() ?? "";
            if (channel.Length == 0) continue;
            var stats = ImportStats[channel] as JsonObject;
            var command = new NpgsqlCommand("""
                insert into collector_channel_runs(
                    job_id,server,channel,started_utc,finished_utc,status,inserted,skipped,count,partial_count,
                    timeout_seconds,limit_used,collection_mode,requested_collection_mode,cursor_strategy,cursor_fallback_reason,
                    collector_backend,backend_reason,partial_kind,failure_stage,cursor_commit_allowed)
                values(@job_id,@server,@channel,@started_utc,@finished_utc,@status,@inserted,@skipped,@count,@partial_count,
                    @timeout_seconds,@limit_used,@collection_mode,@requested_collection_mode,@cursor_strategy,@cursor_fallback_reason,
                    @collector_backend,@backend_reason,@partial_kind,@failure_stage,@cursor_commit_allowed)
                """, db, tx) { CommandTimeout = 0 };
            void Add(string key, NpgsqlDbType type, object? value) => command.Parameters.AddWithValue(key, type, value ?? DBNull.Value);
            long Number(JsonNode? node) => long.TryParse(node?.ToString(), out long value) ? value : 0;
            Add("job_id", NpgsqlDbType.Bigint, jobId); Add("server", NpgsqlDbType.Text, Server); Add("channel", NpgsqlDbType.Text, channel);
            Add("started_utc", NpgsqlDbType.Text, item["started_at"]?.ToString());
            Add("finished_utc", NpgsqlDbType.Text, (item["finished_at"] ?? Summary["finished_at"])?.ToString());
            string status = item["status"]?.ToString() ?? "unknown";
            Add("status", NpgsqlDbType.Text, status);
            foreach (string key in new[] { "inserted", "skipped" }) Add(key, NpgsqlDbType.Bigint, Number(stats?[key]));
            Add("count", NpgsqlDbType.Bigint, Number(item["count"]));
            Add("partial_count", NpgsqlDbType.Bigint, Number(item[status == "partial_timeout" ? "count" : "partial_count"]));
            foreach (var (column, value) in new[] { ("timeout_seconds", item["timeout_seconds"]), ("limit_used", item["max_events"] ?? item["limit"] ?? item["limit_used"]) })
                Add(column, NpgsqlDbType.Integer, value is null ? null : checked((int)Number(value)));
            foreach (string key in new[] { "collection_mode", "requested_collection_mode" }) Add(key, NpgsqlDbType.Text, Summary[key]?.ToString());
            foreach (string key in new[] { "cursor_strategy", "cursor_fallback_reason", "partial_kind", "failure_stage" }) Add(key, NpgsqlDbType.Text, item[key]?.ToString());
            foreach (string key in new[] { "collector_backend", "backend_reason" }) Add(key, NpgsqlDbType.Text, (item[key] ?? Summary[key])?.ToString());
            Add("cursor_commit_allowed", NpgsqlDbType.Boolean, item["cursor_commit_allowed"]?.GetValue<bool>());
            yield return command;
        }
    }

    internal async Task RecordAsync(long jobId, NpgsqlConnection db, CancellationToken ct)
    {
        await using var tx = await db.BeginTransactionAsync(ct);
        foreach (var command in Commands(jobId, db, tx)) {
            await using (command) await command.ExecuteNonQueryAsync(ct);
        }
        await tx.CommitAsync(ct);
    }
}
