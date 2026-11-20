using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Operations;

// Collector history writer. Uses an already authorized caller-owned connection;
// it neither changes adaptive policy nor commits collection cursors.
public static class CollectorChannelHistory
{
    public static async Task RecordAsync(NpgsqlConnection db, string server, JsonObject summary, JsonObject importStats,
        int? importDurationMs = null, CancellationToken ct = default)
    {
        foreach (var item in (summary["channels"] as JsonArray ?? []).OfType<JsonObject>()) {
            string channel = S(item["channel"]); if (channel.Length == 0) continue;
            var stats = importStats[channel] as JsonObject;
            int? duration = Milliseconds(item["duration_seconds"]) ?? Milliseconds(item["query_duration_seconds"]);
            if (duration is null or 0 && int.TryParse(S(item["query_duration_ms"]), out int fallback)) duration = fallback;
            long count = N(item["count"]); string status = S(item["status"], "unknown");
            await using var command = new NpgsqlCommand("""
                insert into collector_channel_runs(server,channel,started_utc,finished_utc,status,inserted,skipped,count,partial_count,
                    query_duration_ms,import_duration_ms,total_duration_ms,events_per_second)
                values(@server,@channel,@started,@finished,@status,@inserted,@skipped,@count,@partial,
                    @query_ms,@import_ms,@total_ms,@speed)
                """, db) { CommandTimeout = 0 };
            command.Parameters.AddWithValue("server", server); command.Parameters.AddWithValue("channel", channel);
            command.Parameters.AddWithValue("started", NpgsqlDbType.Text, (object?)SOrNull(item["started_at"]) ?? DBNull.Value);
            command.Parameters.AddWithValue("finished", NpgsqlDbType.Text, (object?)(SOrNull(item["finished_at"]) ?? SOrNull(summary["finished_at"])) ?? DBNull.Value);
            command.Parameters.AddWithValue("status", status); command.Parameters.AddWithValue("inserted", N(stats?["inserted"]));
            command.Parameters.AddWithValue("skipped", N(stats?["skipped"])); command.Parameters.AddWithValue("count", count);
            command.Parameters.AddWithValue("partial", status == "partial_timeout" ? count : N(item["partial_count"]));
            command.Parameters.AddWithValue("query_ms", NpgsqlDbType.Integer, (object?)duration ?? DBNull.Value);
            command.Parameters.AddWithValue("import_ms", NpgsqlDbType.Integer, (object?)importDurationMs ?? DBNull.Value);
            command.Parameters.AddWithValue("total_ms", checked((duration ?? 0) + (importDurationMs ?? 0)));
            command.Parameters.AddWithValue("speed", NpgsqlDbType.Double, duration > 0 ? Math.Round(count / (duration.Value / 1000.0), 3, MidpointRounding.ToEven) : DBNull.Value);
            await command.ExecuteNonQueryAsync(ct);
        }
    }
    static string? SOrNull(JsonNode? node) => node is null ? null : S(node);
    static int? Milliseconds(JsonNode? node) => double.TryParse(S(node), NumberStyles.Float, CultureInfo.InvariantCulture, out double seconds) &&
        double.IsFinite(seconds) && seconds * 1000 is >= int.MinValue and <= int.MaxValue ? (int)(seconds * 1000) : null;
}
