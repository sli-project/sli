using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;

namespace Sli.Server.Operations;

public interface IOperationsQueries
{
    Task<JsonArray> ReadAsync(string sql, CancellationToken ct, params (string Name, object? Value)[] parameters);
    Task<JsonArray> ReadReadinessAsync(string sql, CancellationToken ct) => ReadAsync(sql, ct);
}

// Each section owns a short read-only transaction. An optional failed metric must
// not abort subsequent sections, and request cancellation must still propagate.
public sealed class OperationsQueries(IPostgresConnectionFactory connections) : IOperationsQueries
{
    public async Task<JsonArray> ReadAsync(string sql, CancellationToken ct, params (string Name, object? Value)[] parameters)
        => await ExecuteAsync(sql, ct, true, parameters);

    public Task<JsonArray> ReadReadinessAsync(string sql, CancellationToken ct) => ExecuteAsync(sql, ct, false, []);

    private async Task<JsonArray> ExecuteAsync(string sql, CancellationToken ct, bool bounded, (string Name, object? Value)[] parameters)
    {
        await using var db = await connections.OpenAsync(ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        await using (var bounds = new NpgsqlCommand(bounded ? "set transaction read only; set local statement_timeout='3000ms'; set local lock_timeout='1000ms'; set local jit=off" : "set transaction read only", db, tx))
        {
            if (!bounded) bounds.CommandTimeout = 0;
            await bounds.ExecuteNonQueryAsync(ct);
        }
        await using var command = new NpgsqlCommand(sql, db, tx) { CommandTimeout = bounded ? 4 : 0 };
        foreach (var (name, value) in parameters)
        {
            if (value is null) command.Parameters.AddWithValue(name, NpgsqlDbType.Unknown, DBNull.Value);
            else command.Parameters.AddWithValue(name, value);
        }
        await using var reader = await command.ExecuteReaderAsync(ct);
        var rows = new JsonArray();
        while (await reader.ReadAsync(ct))
        {
            var row = new JsonObject();
            for (int i = 0; i < reader.FieldCount; i++)
            {
                if (reader.IsDBNull(i)) { row[reader.GetName(i)] = null; continue; }
                object value = reader.GetValue(i);
                row[reader.GetName(i)] = reader.GetDataTypeName(i) is "json" or "jsonb"
                    ? JsonNode.Parse((string)value) : System.Text.Json.JsonSerializer.SerializeToNode(value);
            }
            rows.Add(row);
        }
        return rows;
    }
}

internal static class OpsJson
{
    internal static string S(JsonNode? node, string fallback = "") => node is JsonValue v && v.TryGetValue<string>(out var s) ? s : node?.ToJsonString() ?? fallback;
    internal static long N(JsonNode? node, long fallback = 0) => long.TryParse(S(node), out var n) ? n : fallback;
    internal static bool B(JsonNode? node) => node is JsonValue v && v.TryGetValue<bool>(out bool b) && b;
    internal static JsonNode? Copy(JsonNode? node) => node?.DeepClone();
    internal static JsonArray A(IEnumerable<JsonNode?> nodes) => new(nodes.Select(Copy).ToArray());
    internal static DateTimeOffset? Time(JsonNode? node) => DateTimeOffset.TryParse(S(node), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var t) ? t.ToUniversalTime() : null;
    internal static string Stamp(DateTimeOffset t) => t.ToUniversalTime().ToString(t.Ticks % TimeSpan.TicksPerSecond == 0 ? "yyyy-MM-dd'T'HH:mm:sszzz" : "yyyy-MM-dd'T'HH:mm:ss.ffffffzzz", System.Globalization.CultureInfo.InvariantCulture);
    internal static JsonObject Unavailable(Exception error) => new() { ["status"] = "unavailable", ["error_type"] = error.GetType().Name };
    internal static string Human(long bytes)
    {
        double size = bytes;
        foreach (string unit in new[] { "B", "KB", "MB", "GB", "TB" })
        { if (size < 1024 || unit == "TB") return unit == "B" ? $"{bytes} B" : size.ToString("F1", System.Globalization.CultureInfo.InvariantCulture) + " " + unit; size /= 1024; }
        return "";
    }
}
