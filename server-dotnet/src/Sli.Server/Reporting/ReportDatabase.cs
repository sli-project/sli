using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;

namespace Sli.Server.Reporting;

public interface IReportDatabase
{
    Task<IReportSession> OpenAsync(bool write, CancellationToken ct);
}

public interface IReportSession : IAsyncDisposable
{
    Task<IReadOnlyList<JsonObject>> QueryAsync(string sql, IReadOnlyList<object?> values, CancellationToken ct);
    Task CommitAsync(CancellationToken ct);
}

public sealed class ReportDatabase(IPostgresConnectionFactory connections) : IReportDatabase
{
    public async Task<IReportSession> OpenAsync(bool write, CancellationToken ct)
    {
        var connection = await connections.OpenAsync(ct);
        try
        {
            var transaction = await connection.BeginTransactionAsync(ct);
            await using var setup = new NpgsqlCommand((write ? "" : "set transaction read only; ") +
                "set local statement_timeout=0; set local lock_timeout=0", connection, transaction) { CommandTimeout = 0 };
            await setup.ExecuteNonQueryAsync(ct);
            return new Session(connection, transaction);
        }
        catch { await connection.DisposeAsync(); throw; }
    }

    private sealed class Session(NpgsqlConnection connection, NpgsqlTransaction transaction) : IReportSession
    {
        public async Task<IReadOnlyList<JsonObject>> QueryAsync(string sql, IReadOnlyList<object?> values, CancellationToken ct)
        {
            await using var command = new NpgsqlCommand(sql, connection, transaction) { CommandTimeout = 0 };
            for (int i = 0; i < values.Count; i++)
            {
                var value = values[i];
                command.Parameters.Add(value is null
                    ? new NpgsqlParameter("p" + i, NpgsqlDbType.Text) { Value = DBNull.Value }
                    : new NpgsqlParameter("p" + i, value));
            }
            var result = new List<JsonObject>();
            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var row = new JsonObject();
                for (int i = 0; i < reader.FieldCount; i++)
                {
                    object? value = await reader.IsDBNullAsync(i, ct) ? null : reader.GetValue(i);
                    row[reader.GetName(i)] = value switch
                    {
                        string json when reader.GetDataTypeName(i) is "json" or "jsonb" => JsonNode.Parse(json),
                        // A PostgreSQL date is a calendar day, not midnight in
                        // the application host's timezone.
                        DateTime day when reader.GetDataTypeName(i) == "date" => JsonValue.Create(day.ToString("yyyy-MM-dd",System.Globalization.CultureInfo.InvariantCulture)),
                        DateTime time => JsonValue.Create(Sli.Server.Access.Administration.AssignmentAudit.Stamp(new DateTimeOffset(time))),
                        DateTimeOffset time => JsonValue.Create(Sli.Server.Access.Administration.AssignmentAudit.Stamp(time)),
                        _ => System.Text.Json.JsonSerializer.SerializeToNode(value)
                    };
                }
                result.Add(row);
            }
            return result;
        }
        public Task CommitAsync(CancellationToken ct) => transaction.CommitAsync(ct);
        public async ValueTask DisposeAsync() { await transaction.DisposeAsync(); await connection.DisposeAsync(); }
    }
}

public sealed class ReportException(string code, int status = 400) : Exception(code)
{
    public int Status { get; } = status;
}

internal static class ReportJson
{
    internal static string Text(this JsonNode? node, string key, string fallback = "") => node?[key]?.ToString() ?? fallback;
    internal static long Number(this JsonNode? node, string key, long fallback = 0) => long.TryParse(node?[key]?.ToString(), out long n) ? n : fallback;
    internal static bool Flag(this JsonNode? node, string key) => node?[key] is JsonValue v && v.TryGetValue<bool>(out bool b) && b;
    internal static JsonArray Array(this JsonNode? node, string key) => node?[key] as JsonArray ?? [];
    internal static string[] Strings(this JsonNode? node, string key) => node.Array(key).Select(v => v?.ToString() ?? "").ToArray();
    internal static JsonArray Nodes<T>(IEnumerable<T> values) => System.Text.Json.JsonSerializer.SerializeToNode(values)!.AsArray();
    internal static JsonObject Copy(this JsonObject value) => (JsonObject)value.DeepClone();
    internal static string[] Sorted(IEnumerable<string> values) => values.Distinct().Order(StringComparer.Ordinal).ToArray();
    internal static System.Numerics.BigInteger Integer(string value)
    {
        if (Sli.Server.Access.Administration.AccessReadEndpoints.TryPythonInteger(value, out var number, out int digits)) return number;
        throw new ReportException(digits > 4300 ? $"Exceeds the limit (4300 digits) for integer string conversion: value has {digits} digits; use sys.set_int_max_str_digits() to increase the limit"
            : "invalid literal for int() with base 10: " + Sli.Server.Access.Administration.AccessReadEndpoints.PythonRepr(value));
    }
    internal static void Require([System.Diagnostics.CodeAnalysis.DoesNotReturnIf(false)] bool condition, string code, int status = 400) { if (!condition) throw new ReportException(code, status); }
}
