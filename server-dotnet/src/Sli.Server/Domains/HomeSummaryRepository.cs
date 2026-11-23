using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;

namespace Sli.Server.Domains;

public interface IHomeSummaryRepository
{
    Task<IReadOnlyList<JsonObject>> ReadAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct);
    Task<IReadOnlyList<JsonObject>> ReadActivityAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct) =>
        ReadAsync(sql, parameters, ct);
}

/// <summary>Parameterized reads following the caller's cancellation token.</summary>
public sealed class HomeSummaryRepository(IPostgresConnectionFactory connections) : IHomeSummaryRepository
{
    public Task<IReadOnlyList<JsonObject>> ReadAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct) =>
        ReadAsync(sql, parameters, preferHashAggregate: false, ct);

    public Task<IReadOnlyList<JsonObject>> ReadActivityAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct) =>
        ReadAsync(sql, parameters, preferHashAggregate: true, ct);

    private async Task<IReadOnlyList<JsonObject>> ReadAsync(string sql, IReadOnlyDictionary<string, object?> parameters,
        bool preferHashAggregate, CancellationToken ct)
    {
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        const string readOnly = "set transaction read only; set local jit=off";
        // Activity groups a large event stream into a bounded set of hourly buckets.
        // Discourage sorting every event when the hourly groups fit in memory.
        var setup = preferHashAggregate ? readOnly + "; set local enable_sort=off" : readOnly;
        await using (var limits = new NpgsqlCommand(setup, connection, transaction) { CommandTimeout = 0 })
        {
            await limits.ExecuteNonQueryAsync(ct);
        }
        await using var command = new NpgsqlCommand("select to_jsonb(home_row) from (" + sql + ") home_row", connection, transaction) { CommandTimeout = 0 };
        foreach (var (key, value) in parameters)
        {
            var type = value switch
            {
                long[] => NpgsqlDbType.Array | NpgsqlDbType.Bigint, long => NpgsqlDbType.Bigint,
                string[] => NpgsqlDbType.Array | NpgsqlDbType.Text,
                DateTimeOffset => NpgsqlDbType.TimestampTz, bool => NpgsqlDbType.Boolean,
                _ => key is "since" or "from" or "to" ? NpgsqlDbType.TimestampTz : NpgsqlDbType.Text
            };
            command.Parameters.Add(new NpgsqlParameter(key, type) { Value = value ?? DBNull.Value });
        }
        var rows = new List<JsonObject>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) rows.Add(JsonNode.Parse(reader.GetString(0))!.AsObject());
        await reader.DisposeAsync();
        await Problems.ProblemRepository.AttachKerberosFacts(transaction, rows, ct);
        return rows;
    }
}

internal static class HomeJson
{
    public static string? Text(this JsonNode? node, string key) => node?[key]?.GetValueKind() == System.Text.Json.JsonValueKind.String ? node[key]!.GetValue<string>() : null;
    public static long Number(this JsonNode? node, string key) => long.TryParse(node?[key]?.ToString(), out var n) ? n : 0;
    public static bool? Boolean(this JsonNode? node, string key) => bool.TryParse(node?[key]?.ToString(), out var b) ? b : null;
    public static DateTimeOffset? Stamp(this JsonNode? node, string key) => DateTimeOffset.TryParse(node.Text(key), System.Globalization.CultureInfo.InvariantCulture,
        System.Globalization.DateTimeStyles.AssumeUniversal, out var t) ? t.ToUniversalTime() : null;
    public static JsonNode? Copy(this JsonNode? node) => node?.DeepClone();
    public static JsonObject Object(object value) => System.Text.Json.JsonSerializer.SerializeToNode(value)!.AsObject();
    public static JsonArray Array<T>(IEnumerable<T> values) => System.Text.Json.JsonSerializer.SerializeToNode(values)!.AsArray();
}
