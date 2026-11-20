using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;
using static Sli.Server.Sources.CollectorAdaptive;

namespace Sli.Server.Sources;

internal delegate Task<JsonArray> CollectorAdaptiveQuery(string sql, CancellationToken ct, params object?[] args);

// PostgreSQL-only port of postgres_runtime_pipeline planning and channel history.
// State and history commit together; there is no source I/O or cursor advancement here.
public sealed class CollectorAdaptiveStore(IPostgresConnectionFactory connections,
    CollectorAdaptiveOptions? options = null, TimeProvider? timeProvider = null)
{
    private readonly CollectorAdaptiveOptions settings = options ?? CollectorAdaptiveOptions.FromEnvironment();
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public async Task<CollectorAdaptivePlan> GetPlanAsync(string server, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct);
        return await GetPlanAsync(Query(db, null), server, ct);
    }

    public async Task RecordRunsAsync(string server, JsonObject summary, JsonObject importStats,
        long? jobId, CancellationToken ct, string adaptiveStateMode = "update")
    {
        string mode = NormalizeMode(adaptiveStateMode);
        await using var db = await connections.OpenAsync(ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        await RecordRunsAsync(Query(db, tx), server, summary, importStats, jobId, ct, mode);
        await tx.CommitAsync(ct);
    }

    private static CollectorAdaptiveQuery Query(NpgsqlConnection db, NpgsqlTransaction? tx) => async (sql, ct, args) => {
        SqlArguments.Validate(args);
        await using var command = new NpgsqlCommand(sql, db, tx) { CommandTimeout = 0 };
        for (int i = 0; i < args.Length; i++) {
            if (args[i] is null) command.Parameters.AddWithValue("p" + i, NpgsqlDbType.Unknown, DBNull.Value);
            else command.Parameters.AddWithValue("p" + i, args[i]!);
        }
        var rows = new JsonArray();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) {
            var row = new JsonObject();
            for (int i = 0; i < reader.FieldCount; i++)
                row[reader.GetName(i)] = reader.IsDBNull(i) ? null : JsonSerializer.SerializeToNode(reader.GetValue(i));
            rows.Add(row);
        }
        return rows;
    };

    internal async Task<CollectorAdaptivePlan> GetPlanAsync(CollectorAdaptiveQuery query, string server, CancellationToken ct)
    {
        var cursor = (await query("select last_event_time_utc from collection_channel_state where server_hostname=@p0 and channel=@p1", ct, server, "Security")).FirstOrDefault();
        var marker = cursor?["last_event_time_utc"];
        if (marker is null) marker = (await query(LatestSql, ct, server, "Security")).FirstOrDefault()?["time_created_utc"];
        int? lag = Lag(marker);
        var states = (await query("select * from collector_adaptive_state where server=@p0", ct, server))
            .OfType<JsonObject>().ToDictionary(s => S(s["channel"]));
        var fairness = new List<string>();
        if (settings.FairnessEnabled)
            foreach (string channel in DefaultChannels.Where(c => c != "Security")) {
                var row = (await query("select last_successful_collection_utc, last_event_time_utc, updated_at from collection_channel_state where server_hostname=@p0 and channel=@p1", ct, server, channel)).FirstOrDefault();
                if (row is null) continue;
                var stamp = row["last_successful_collection_utc"] ?? row["updated_at"] ?? row["last_event_time_utc"];
                if (Time(stamp) is not { } time || Math.Floor((clock.GetUtcNow() - time).TotalMinutes) >= Math.Max(1, settings.FairnessStale)) fairness.Add(channel);
            }
        return new CollectorAdaptive(settings, clock).BuildPlan(server, lag, states.GetValueOrDefault("Security"), fairness.ToArray(), states);
    }

    internal async Task RecordRunsAsync(CollectorAdaptiveQuery query, string server, JsonObject summary, JsonObject importStats,
        long? jobId, CancellationToken ct, string adaptiveStateMode = "update")
    {
        string mode = NormalizeMode(adaptiveStateMode);
        var adaptive = new CollectorAdaptive(settings, clock);
        foreach (var item in (summary["channels"] as JsonArray ?? []).OfType<JsonObject>()) {
            string channel = S(item["channel"]);
            if (channel.Length == 0) continue;
            var stats = importStats[channel];
            int inserted = N(stats?["inserted"]), skipped = N(stats?["skipped"]), count = N(item["count"]);
            string status = S(item["status"]); if (status.Length == 0) status = "unknown";
            int partial = status == "partial_timeout" ? count : N(item["partial_count"]);
            var latest = (await query(LatestSql, ct, server, channel)).FirstOrDefault();
            long? recordId = Long(latest?["event_record_id"]) ?? Long(item["latest_event_record_id"]) ?? Long(item["latest_record_id"]);
            int? lag = Lag(latest?["time_created_utc"] ?? item["latest_event_time_utc"]);
            int? size = Nonzero(item["max_events"]) ?? Nonzero(item["limit"]) ?? Nonzero(item["limit_used"]);
            int? duration = Milliseconds(item["duration_seconds"]) ?? Milliseconds(item["query_duration_seconds"]) ?? Int(item["query_duration_ms"]);
            var previous = (await query("select latest_event_record_id,lag_minutes from collector_channel_runs where server=@p0 and channel=@p1 order by id desc limit 1", ct, server, channel)).FirstOrDefault();
            string? action = null;
            if (mode == "update") {
                var state = (await query("select * from collector_adaptive_state where server=@p0 and channel=@p1", ct, server, channel)).FirstOrDefault() as JsonObject;
                var transition = channel == "Security"
                    ? adaptive.SecurityTransition(state, status, inserted, skipped, lag, size, S(item["partial_kind"]))
                    : adaptive.NonSecurityTransition(state, status, size, item["continuity"] is JsonObject continuity && B(continuity["truncated"]), S(item["partial_kind"]));
                action = S(transition["last_action"]);
                await query(UpsertSql, ct, server, channel, N(transition["current_limit"]), N(transition["consecutive_completed"]),
                    B(transition["recovery_mode"]), status, Int(transition["last_lag_minutes"]), action, Time(transition["updated_at"])!.Value.UtcDateTime);
            }
            else if (channel == "Security") action = "observe_only:state_unchanged";
            await query(InsertRunSql, ct, jobId, server, channel, Optional(item["started_at"]),
                Optional(item["finished_at"] ?? summary["finished_at"]), status, inserted, skipped, count, partial,
                recordId, lag, Int(item["timeout_seconds"]), size, action, Optional(item["error"]), duration,
                duration ?? 0, count > 0 && duration > 0 ? Math.Round(count / (duration.Value / 1000.0), 2, MidpointRounding.ToEven) : null,
                recordId - Long(previous?["latest_event_record_id"]), lag - Int(previous?["lag_minutes"]),
                Optional(summary["collection_mode"]), Optional(summary["requested_collection_mode"]), Optional(item["cursor_strategy"]), Optional(item["cursor_fallback_reason"]),
                Optional(item["collector_backend"] ?? summary["collector_backend"]), Optional(item["backend_reason"] ?? summary["backend_reason"]),
                Optional(item["partial_kind"]), Optional(item["failure_stage"]), item["cursor_commit_allowed"] is null ? null : B(item["cursor_commit_allowed"]));
        }
    }

    private static string NormalizeMode(string? mode) {
        string clean = string.IsNullOrEmpty(mode) ? "update" : mode.Trim().ToLowerInvariant();
        return clean is "update" or "observe" ? clean : throw new ArgumentException("Unsupported adaptive state mode", nameof(mode));
    }
    private static string? Optional(JsonNode? n) => n is null ? null : S(n);
    private static long? Long(JsonNode? n) => long.TryParse(S(n), out long value) ? value : null;
    private static int? Int(JsonNode? n) => int.TryParse(S(n), out int value) ? value : null;
    private static int? Nonzero(JsonNode? n) => Int(n) is { } i && i != 0 ? i : null;
    private static int? Milliseconds(JsonNode? n) => double.TryParse(S(n), CultureInfo.InvariantCulture, out double value) && value != 0 ? (int)(value * 1000) : null;
    private static DateTimeOffset? Time(JsonNode? n) => DateTimeOffset.TryParse(S(n), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var t) ? t.ToUniversalTime() : null;
    private int? Lag(JsonNode? n) => Time(n) is { } t ? Math.Max(0, (int)Math.Floor((clock.GetUtcNow() - t).TotalMinutes)) : null;

    internal const string LatestSql = """
        select last_event_time_utc as time_created_utc,last_event_record_id as event_record_id
        from collection_channel_state where server_hostname=@p0 and channel=@p1
          and last_event_time_utc is not null order by last_event_time_utc desc,last_event_record_id desc limit 1
        """;
    internal const string UpsertSql = """
        insert into collector_adaptive_state(server,channel,current_limit,consecutive_completed,recovery_mode,last_status,last_lag_minutes,last_action,updated_at)
        values(@p0,@p1,@p2,@p3,@p4,@p5,@p6,@p7,@p8)
        on conflict(server,channel) do update set current_limit=excluded.current_limit,consecutive_completed=excluded.consecutive_completed,
        recovery_mode=excluded.recovery_mode,last_status=excluded.last_status,last_lag_minutes=excluded.last_lag_minutes,last_action=excluded.last_action,updated_at=excluded.updated_at
        """;
    internal const string InsertRunSql = """
        insert into collector_channel_runs(job_id,server,channel,started_utc,finished_utc,status,inserted,skipped,count,partial_count,
        latest_event_record_id,lag_minutes,timeout_seconds,limit_used,adaptive_action,error,query_duration_ms,total_duration_ms,events_per_second,
        last_record_id_delta,lag_delta_minutes,collection_mode,requested_collection_mode,cursor_strategy,cursor_fallback_reason,
        collector_backend,backend_reason,partial_kind,failure_stage,cursor_commit_allowed)
        values(@p0,@p1,@p2,@p3,@p4,@p5,@p6,@p7,@p8,@p9,@p10,@p11,@p12,@p13,@p14,@p15,@p16,@p17,@p18,@p19,@p20,@p21,@p22,@p23,@p24,@p25,@p26,@p27,@p28,@p29)
        """;
}
