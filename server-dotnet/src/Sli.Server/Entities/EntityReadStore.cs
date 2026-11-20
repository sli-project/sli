using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;

namespace Sli.Server.Entities;

public interface IEntityReadStore
{
    Task<JsonArray> ReadAsync(string sql, IReadOnlyDictionary<string, object> parameters, int timeoutSeconds, CancellationToken ct);
}

// Application identity only; query values are always Npgsql parameters.
public sealed class EntityReadStore(IPostgresConnectionFactory connections) : IEntityReadStore, IAsyncDisposable
{
    public EntityReadStore(IPostgresConnectionFactory connections, IConfiguration? configuration) : this(connections) { }

    NpgsqlConnection? connection;
    NpgsqlTransaction? transaction;
    public async Task<JsonArray> ReadAsync(string sql, IReadOnlyDictionary<string, object> parameters, int timeoutSeconds, CancellationToken ct)
    {
        if (connection is null)
        {
            connection = await connections.OpenAsync(ct);
            transaction = await connection.BeginTransactionAsync(System.Data.IsolationLevel.RepeatableRead, ct);
            await using var mode = new NpgsqlCommand("set transaction read only", connection, transaction);
            await mode.ExecuteNonQueryAsync(ct);
        }
        var db = connection; var tx = transaction!;
        await tx.SaveAsync("entity_read", ct);
        try
        {
            await using (var setup = new NpgsqlCommand("set local statement_timeout = 0", db, tx) { CommandTimeout = 0 })
                await setup.ExecuteNonQueryAsync(ct);
            await using var command = new NpgsqlCommand(sql, db, tx) { CommandTimeout = 0 };
            foreach (var (key, value) in parameters)
                if (value is JsonNode node) command.Parameters.AddWithValue(key, NpgsqlDbType.Jsonb, node.ToJsonString());
                else command.Parameters.AddWithValue(key, value);
            var result = new JsonArray();
            await using (var reader = await command.ExecuteReaderAsync(ct))
                while (await reader.ReadAsync(ct))
                {
                    var row = new JsonObject();
                    for (int i = 0; i < reader.FieldCount; i++)
                    {
                        object? value = reader.IsDBNull(i) ? null : reader.GetValue(i);
                        row[reader.GetName(i)] = value switch
                        {
                            null => null,
                            DateTime time => JsonValue.Create(time.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFF'Z'", CultureInfo.InvariantCulture)),
                            DateTimeOffset time => JsonValue.Create(time.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFF'Z'", CultureInfo.InvariantCulture)),
                            string json when reader.GetDataTypeName(i) is "json" or "jsonb" => JsonNode.Parse(json),
                            _ => System.Text.Json.JsonSerializer.SerializeToNode(value)
                        };
                    }
                    result.Add(row);
                }
            await tx.ReleaseAsync("entity_read", ct);
            return result;
        }
        catch
        {
            if (db.State == System.Data.ConnectionState.Open && !ct.IsCancellationRequested) { await tx.RollbackAsync("entity_read", ct); await tx.ReleaseAsync("entity_read", ct); }
            throw;
        }
    }
    public async ValueTask DisposeAsync()
    {
        if (transaction is not null) await transaction.DisposeAsync();
        if (connection is not null) await connection.DisposeAsync();
    }
}

public sealed class EntityInputException(string code, JsonArray? unknownTypes = null) : Exception(code)
{
    public JsonArray? UnknownTypes { get; } = unknownTypes;
}

public sealed record EntityReadOptions(int Limit = 50, string? BeforeTime = null, long? BeforeId = null,
    string? From = null, string? To = null, string Timezone = "UTC", string? BeforeSummaryKey = null);
