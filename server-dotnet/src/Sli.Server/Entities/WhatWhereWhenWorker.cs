using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;

namespace Sli.Server.Entities;

internal sealed class WhatWhereWhenDatabase(NpgsqlConnection connection, NpgsqlTransaction transaction) : IWhatWhereWhenTransaction
{
    public async Task<JsonArray> Query(string sql, Dictionary<string, object> args, CancellationToken ct)
    {
        await using var command = Command(sql, args); var result = new JsonArray();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var row = new JsonObject();
            for (int i = 0; i < reader.FieldCount; i++)
            {
                object? value = reader.IsDBNull(i) ? null : reader.GetValue(i);
                row[reader.GetName(i)] = value switch
                {
                    null => null,
                    byte[] bytes => JsonValue.Create(Convert.ToHexString(bytes).ToLowerInvariant()),
                    DateTime time => JsonValue.Create(time.ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFF'Z'", CultureInfo.InvariantCulture)),
                    string json when reader.GetDataTypeName(i) is "json" or "jsonb" => JsonNode.Parse(json),
                    _ => System.Text.Json.JsonSerializer.SerializeToNode(value)
                };
            }
            result.Add(row);
        }
        return result;
    }
    public async Task<int> Execute(string sql, Dictionary<string, object> args, CancellationToken ct)
    { await using var command = Command(sql, args); return await command.ExecuteNonQueryAsync(ct); }
    NpgsqlCommand Command(string sql, Dictionary<string, object> args)
    {
        var command = new NpgsqlCommand(sql, connection, transaction);
        foreach (var (key, value) in args) command.Parameters.AddWithValue(key, value);
        return command;
    }
}

internal sealed class WhatWhereWhenWorker(NpgsqlDataSource source, Microsoft.Extensions.Configuration.IConfiguration? configuration = null)
{
    internal async Task<int> Run(bool once, int batch, int retention, Action<JsonObject> output, CancellationToken ct)
    {
        await using var connection = await source.OpenConnectionAsync(ct);
        await using (var command = new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_what_where_when_projection'))", connection))
            if (await command.ExecuteScalarAsync(ct) is not true) { output(new() { ["status"] = "skipped", ["reason"] = "worker_lock_held" }); return 0; }
        string worker = $"{Environment.MachineName}:{Environment.ProcessId}:{Guid.NewGuid()}"; var started = DateTime.UtcNow;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Heartbeat(connection, worker, started, "running", "projection", new(), ct);
                try
                {
                    JsonObject result;
                    await using (var transaction = await connection.BeginTransactionAsync(ct))
                    {
                        result = await WhatWhereWhenCycle.Run(new WhatWhereWhenDatabase(connection, transaction), batch, retention, ct, configuration);
                        await transaction.CommitAsync(ct);
                    }
                    output(result);
                    await Heartbeat(connection, worker, started, "idle", "sleep", new() { ["last_result"] = result.DeepClone() }, ct);
                    if (once) return 0;
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (NpgsqlException error) when (error is not PostgresException) { throw; }
                catch (Exception error)
                {
                    // The transaction was disposed/rolled back before reporting a
                    // failed cycle. Never print exception text containing source data.
                    var failure = new JsonObject { ["status"] = "failed", ["error_type"] = error.GetType().Name };
                    output(failure); await Heartbeat(connection, worker, started, "failed", "sleep", failure, ct);
                    if (once) return 1;
                }
                await Task.Delay(TimeSpan.FromSeconds(30), ct);
            }
            return 0;
        }
        finally
        {
            if (connection.State == System.Data.ConnectionState.Open)
            {
                await using var unlock = new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_what_where_when_projection'))", connection);
                await unlock.ExecuteScalarAsync(CancellationToken.None);
            }
        }
    }
    static async Task Heartbeat(NpgsqlConnection connection, string worker, DateTime started, string status, string phase, JsonObject details, CancellationToken ct)
    {
        try
        {
            await using var command = new NpgsqlCommand("""
                insert into runtime_worker_heartbeats(worker_name,worker_id,process_pid,status,phase,expected_interval_seconds,details_json,started_at,heartbeat_at,updated_at)
                values('what_where_when_projection',@worker,@pid,@status,@phase,30,@details,@started,now(),now())
                on conflict(worker_name) do update set worker_id=excluded.worker_id,process_pid=excluded.process_pid,status=excluded.status,phase=excluded.phase,
                  expected_interval_seconds=excluded.expected_interval_seconds,details_json=excluded.details_json,
                  started_at=case when runtime_worker_heartbeats.worker_id=excluded.worker_id then runtime_worker_heartbeats.started_at else excluded.started_at end,heartbeat_at=now(),updated_at=now()
                """, connection);
            command.Parameters.AddWithValue("worker", worker); command.Parameters.AddWithValue("pid", Environment.ProcessId); command.Parameters.AddWithValue("status", status); command.Parameters.AddWithValue("phase", phase);
            command.Parameters.AddWithValue("details", NpgsqlDbType.Jsonb, details.ToJsonString()); command.Parameters.AddWithValue("started", started);
            await command.ExecuteNonQueryAsync(ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (NpgsqlException error) when (error is not PostgresException) { throw; }
        catch (Exception) { if (connection.State != System.Data.ConnectionState.Open) throw; }
    }
}
