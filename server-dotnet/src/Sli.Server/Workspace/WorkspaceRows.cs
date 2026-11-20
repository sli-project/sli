using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;

namespace Sli.Server.Workspace;

// Rows are public projections only. SQL and parameter names are server-owned.
public interface IWorkspaceRows
{
    Task<IReadOnlyList<JsonElement>> ReadAsync(string sql, CancellationToken ct, params NpgsqlParameter[] parameters);
}

public sealed class PostgresWorkspaceRows(IPostgresConnectionFactory connections) : IWorkspaceRows
{
    public async Task<IReadOnlyList<JsonElement>> ReadAsync(string sql, CancellationToken ct, params NpgsqlParameter[] parameters)
    {
        await using var connection = await connections.OpenAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        await using (var limits = new NpgsqlCommand("set transaction read only; set local statement_timeout=3000; set local jit=off", connection, transaction))
            await limits.ExecuteNonQueryAsync(ct);
        await using var command = new NpgsqlCommand("select to_jsonb(r) from (" + sql + ") r", connection, transaction);
        command.Parameters.AddRange(parameters);
        var rows = new List<JsonElement>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            using var json = JsonDocument.Parse(reader.GetString(0));
            rows.Add(json.RootElement.Clone());
        }
        return rows;
    }
}

internal static class WorkspaceJson
{
    internal static readonly JsonElement Declarations = JsonDocument.Parse(ReadResource("declarations.json")).RootElement.Clone();
    internal static string ReadResource(string name)
    {
        using var stream = typeof(WorkspaceJson).Assembly.GetManifestResourceStream("Sli.Server.Workspace." + name)
            ?? throw new InvalidOperationException("Workspace declaration missing: " + name);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Trim();
    }
    internal static DateTimeOffset? Time(JsonElement row, string key) => row.ValueKind == JsonValueKind.Object && row.TryGetProperty(key, out var value)
        && value.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(value.GetString(), System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal, out var parsed) ? parsed.ToUniversalTime() : null;
    internal static string? Iso(DateTimeOffset? value) => value?.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'+00:00'");
    internal static long? Age(DateTimeOffset? value, DateTimeOffset now) => value is null ? null : Math.Max(0, (long)(now - value.Value).TotalSeconds);
    internal static NpgsqlParameter JsonParameter(string name, object value) => new(name, NpgsqlDbType.Jsonb) { Value = JsonSerializer.Serialize(value) };
}
