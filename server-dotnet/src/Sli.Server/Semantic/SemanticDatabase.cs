using System.Data;
using System.Text.Json.Nodes;
using System.Text.Json;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;

namespace Sli.Server.Semantic;

// A request owns a single snapshot. Mutations and their audit records commit together.
public interface ISemanticDatabase
{
    Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct);
}
public interface ISemanticSession : IAsyncDisposable
{
    Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values);
    Task CommitAsync(CancellationToken ct);
}
internal interface ISemanticStreamingSession : ISemanticSession
{
    IAsyncEnumerable<JsonObject> StreamAsync(string sql, CancellationToken ct, params object?[] values);
}
public sealed class SemanticDatabase(IPostgresConnectionFactory connections, IConfiguration? configuration = null) : ISemanticDatabase
{
    public async Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct)
    {
        var db = await connections.OpenAsync(ct);
        try
        {
            var tx = await db.BeginTransactionAsync(write ? IsolationLevel.ReadCommitted : IsolationLevel.RepeatableRead, ct);
            var session = new SemanticSession(db, tx, ownsConnection: true, configuration: configuration);
            await session.ExecuteAsync(write ? "set local statement_timeout=0; set local jit=off" :
                "set transaction read only; set local statement_timeout=0; set local jit=off", ct);
            return session;
        }
        catch { await db.DisposeAsync(); throw; }
    }
}
internal sealed class SemanticSession(NpgsqlConnection db, NpgsqlTransaction tx, bool ownsConnection = false, DetectionDiagnostics? diagnostics = null, IConfiguration? configuration = null) : ISemanticStreamingSession
{
    internal static void Parameters(NpgsqlCommand command, object?[] values)
    {
        SqlArguments.Validate(values);
        foreach (object? value in values)
        {
            var parameter = new NpgsqlParameter { Value = value ?? DBNull.Value };
            if (value is JsonNode json) { parameter.NpgsqlDbType = NpgsqlDbType.Jsonb; parameter.Value = json.ToJsonString(); }
            else if (value is null) parameter.NpgsqlDbType = NpgsqlDbType.Unknown;
            command.Parameters.Add(parameter);
        }
    }
    public async Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
    {
        var rows = new JsonArray();
        await foreach (var row in StreamAsync(sql, ct, values)) rows.Add(row);
        return rows;
    }
    public async IAsyncEnumerable<JsonObject> StreamAsync(string sql, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct, params object?[] values)
    {
        (sql, values) = SemanticHistorySession.RewriteEvents(sql, values, configuration);
        diagnostics?.Query(sql);
        SemanticWork.Query(db, sql);
        await using var command = new NpgsqlCommand(sql, db, tx) { CommandTimeout = 0 };
        Parameters(command, values);
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var row = new JsonObject();
            for (int i = 0; i < reader.FieldCount; i++)
            {
                object? value = await reader.IsDBNullAsync(i, ct) ? null : reader.GetValue(i);
                row[reader.GetName(i)] = value switch
                {
                    null => null,
                    byte[] bytes => JsonValue.Create(Convert.ToHexStringLower(bytes)),
                    Guid id => JsonValue.Create(id.ToString()),
                    string json when reader.GetDataTypeName(i) is "jsonb" or "json" => JsonNode.Parse(json),
                    DateTime date => JsonValue.Create(SemanticJson.Stamp(new DateTimeOffset(DateTime.SpecifyKind(date, DateTimeKind.Utc)))),
                    _ => JsonSerializer.SerializeToNode(value)
                };
            }
            yield return row;
        }
    }
    internal async Task<int> ExecuteAsync(string sql, CancellationToken ct, params object?[] values)
    {
        diagnostics?.Query(sql);
        SemanticWork.Query(db, sql);
        await using var command = new NpgsqlCommand(sql, db, tx) { CommandTimeout = 0 }; Parameters(command, values);
        return await command.ExecuteNonQueryAsync(ct);
    }
    public Task CommitAsync(CancellationToken ct) => tx.CommitAsync(ct);
    public async ValueTask DisposeAsync() { await tx.DisposeAsync(); if (ownsConnection) await db.DisposeAsync(); }
}

public sealed class SemanticInputException(string code, int status = 400) : Exception(code)
{
    public int Status { get; } = status;
}
