using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;

namespace Sli.Server.Legacy;

internal static class LegacyCollectionHistory
{
    internal static string[] UniqueTexts(IEnumerable<string>? values) =>
        (values ?? []).Where(value => value.Length > 0).Distinct(StringComparer.Ordinal).ToArray();

    internal static async Task StartAsync(NpgsqlConnection db, string run, string worker, LegacyJobInput input, CancellationToken ct)
    {
        // Existing schema (restored by migration 133); workers never create runtime schema.
        await using var command = new NpgsqlCommand("""
            insert into runtime_collection_runs(run_id,worker_id,status,phase,servers_json,hours,max_events_per_channel,
                created_at,started_at,updated_at)
            values(@run,@worker,'running','starting','[]'::jsonb,@hours,@events,now(),now(),now())
            """, db);
        command.Parameters.AddWithValue("run", run); command.Parameters.AddWithValue("worker", worker);
        command.Parameters.AddWithValue("hours", input.Hours); command.Parameters.AddWithValue("events", input.MaxEvents);
        await command.ExecuteNonQueryAsync(ct);
    }

    internal static async Task UpdateAsync(NpgsqlConnection db, string run, JsonObject job, CancellationToken ct)
    {
        string status = job["status"]?.GetValue<string>() ?? "failed";
        string[] errors = UniqueTexts(job["errors"]?.AsArray().Select(value => value?.ToString() ?? ""));
        await using var command = new NpgsqlCommand("""
            update runtime_collection_runs set status=@status,phase=@phase,job_id=coalesce(@job,job_id),
                servers_json=@servers,duration_ms=coalesce(@duration,duration_ms),errors_json=@errors,
                finished_at=case when @terminal then now() else finished_at end,updated_at=now()
            where run_id=@run
            """, db);
        command.Parameters.AddWithValue("run", run); command.Parameters.AddWithValue("status", status);
        command.Parameters.AddWithValue("phase", job["phase"]?.GetValue<string>() ?? "done");
        command.Parameters.AddWithValue("job", NpgsqlDbType.Bigint, (object?)job["id"]?.GetValue<int>() ?? DBNull.Value);
        command.Parameters.AddWithValue("duration", NpgsqlDbType.Bigint, (object?)job["duration_ms"]?.GetValue<long>() ?? DBNull.Value);
        command.Parameters.AddWithValue("servers", NpgsqlDbType.Jsonb, job["servers"]?.ToJsonString() ?? "[]");
        command.Parameters.AddWithValue("errors", NpgsqlDbType.Jsonb, System.Text.Json.JsonSerializer.Serialize(errors));
        command.Parameters.AddWithValue("terminal", status is "completed" or "partial" or "failed" or "skipped" or "blocked");
        await command.ExecuteNonQueryAsync(ct);
    }
}
