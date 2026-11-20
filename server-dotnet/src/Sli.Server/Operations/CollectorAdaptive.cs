using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Operations;

// Security batch sizing from collector_adaptive.py. These are batch sizes, not
// process deadlines: a saved backoff must survive the next recovery plan.
internal static class CollectorAdaptive
{
    internal static JsonObject Plan(JsonObject? state, long? lag)
    {
        long limit = Math.Clamp(N(state?["current_limit"], 20000), 100, 50000);
        bool previous = B(state?["recovery_mode"]), recovery = previous;
        if (lag > 60) recovery = true;
        else if (lag < 15) recovery = false;
        if (recovery && !previous) limit = Math.Max(20000, limit);
        return new() { ["security_limit"] = limit, ["channel_limits"] = new JsonObject { ["Security"] = limit }, ["recovery_mode"] = recovery };
    }

    internal static JsonObject Transition(JsonObject? state, string status, long? previousLimit, long? lag, DateTimeOffset now, string? partialKind = null)
    {
        long previous = Math.Clamp(previousLimit is null or 0 ? N(state?["current_limit"], 20000) : previousLimit.Value, 100, 50000);
        long limit = previous, consecutive = N(state?["consecutive_completed"]);
        bool recovery = B(state?["recovery_mode"]);
        string action = "keep", reason = "stable";
        if (status == "partial_timeout" && partialKind == "failure") { consecutive = 0; reason = "functional_partial_failure"; }
        else if (status is "timeout" or "partial_timeout")
        {
            limit = Math.Max(100, previous / 2); consecutive = 0; recovery = true;
            action = "decrease_limit"; reason = status;
        }
        else if (status == "completed")
        {
            consecutive = 0;
            limit = Math.Min(50000, lag is null or > 60 ? Math.Max(previous * 2, previous + 10000) : previous + 10000);
            reason = lag is null or > 60 ? "completed_fast_recovery" : "completed_streak";
            if (limit != previous) action = "increase_limit";
        }
        else if (status == "failed") { consecutive = 0; reason = "functional_failure"; }
        if (lag > 60) recovery = true;
        else if (status == "completed" && lag < 15) recovery = false;
        return new() { ["previous_limit"] = previous, ["current_limit"] = limit, ["consecutive_completed"] = consecutive,
            ["recovery_mode"] = recovery, ["last_status"] = status, ["last_lag_minutes"] = lag,
            ["last_action"] = $"{action}:{reason}; {previous}->{limit}; recovery={(recovery ? "on" : "off")}",
            ["action"] = action, ["reason"] = reason, ["updated_at"] = Stamp(now) };
    }

    internal static NpgsqlCommand StateCommand(string server, JsonObject transition, NpgsqlConnection? db = null, NpgsqlTransaction? tx = null)
    {
        var command = new NpgsqlCommand("""
            insert into collector_adaptive_state(server,channel,current_limit,consecutive_completed,recovery_mode,last_status,last_lag_minutes,last_action,updated_at)
            values (@server,'Security',@current_limit,@consecutive_completed,@recovery_mode,@last_status,@last_lag_minutes,@last_action,@updated_at)
            on conflict(server,channel) do update set current_limit=excluded.current_limit,consecutive_completed=excluded.consecutive_completed,
                recovery_mode=excluded.recovery_mode,last_status=excluded.last_status,last_lag_minutes=excluded.last_lag_minutes,
                last_action=excluded.last_action,updated_at=excluded.updated_at
            """, db, tx) { CommandTimeout = 0 };
        command.Parameters.AddWithValue("server", server);
        foreach (string field in new[] { "current_limit", "consecutive_completed" }) command.Parameters.AddWithValue(field, checked((int)N(transition[field])));
        command.Parameters.AddWithValue("recovery_mode", B(transition["recovery_mode"]));
        foreach (string field in new[] { "last_status", "last_action" }) command.Parameters.AddWithValue(field, S(transition[field]));
        command.Parameters.AddWithValue("updated_at", NpgsqlDbType.TimestampTz, Time(transition["updated_at"])!.Value);
        command.Parameters.AddWithValue("last_lag_minutes", NpgsqlDbType.Integer, transition["last_lag_minutes"] is null ? DBNull.Value : checked((int)N(transition["last_lag_minutes"])));
        return command;
    }

    internal static async Task<JsonObject> RecordAsync(NpgsqlConnection db, NpgsqlTransaction tx, string server, string status, long? limitUsed, long? lag, DateTimeOffset now, CancellationToken ct, string? partialKind = null)
    {
        JsonObject? state = null;
        await using (var read = new NpgsqlCommand("select current_limit,consecutive_completed,recovery_mode from collector_adaptive_state where server=@server and channel='Security' for update", db, tx) { CommandTimeout = 0 })
        {
            read.Parameters.AddWithValue("server", server);
            await using var reader = await read.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct)) state = new() { ["current_limit"] = reader.GetInt32(0), ["consecutive_completed"] = reader.GetInt32(1), ["recovery_mode"] = reader.GetBoolean(2) };
        }
        var transition = Transition(state, status, limitUsed, lag, now, partialKind);
        await using var save = StateCommand(server, transition, db, tx);
        await save.ExecuteNonQueryAsync(ct);
        return transition;
    }
}
