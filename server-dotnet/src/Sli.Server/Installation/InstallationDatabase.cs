using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;

namespace Sli.Server.InstallationSetup;

public sealed class InstallationException(string code, int status = 400) : Exception(code)
{
    public int Status { get; } = status;
}

// Every mutation and its audit use the same connection and transaction.
public interface IInstallationSession
{
    Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] args);
}
public interface IInstallationDatabase
{
    Task<T> ReadAsync<T>(Func<IInstallationSession, Task<T>> read, CancellationToken ct);
    Task<T> WriteAsync<T>(Func<IInstallationSession, Task<T>> write, CancellationToken ct);
}
public sealed class InstallationDatabase(IPostgresConnectionFactory connections) : IInstallationDatabase
{
    public async Task<T> ReadAsync<T>(Func<IInstallationSession, Task<T>> read, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct);
        return await read(new Session(db, null));
    }
    public async Task<T> WriteAsync<T>(Func<IInstallationSession, Task<T>> write, CancellationToken ct)
    {
        await using var db = await connections.OpenAsync(ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        var result = await write(new Session(db, tx));
        await tx.CommitAsync(ct);
        return result;
    }
    private sealed class Session(NpgsqlConnection db, NpgsqlTransaction? tx) : IInstallationSession
    {
        public async Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] args)
        {
            SqlArguments.Validate(args);
            // Follow request cancellation; elapsed time alone does not make SQL dead.
            await using var cmd = new NpgsqlCommand(sql, db, tx) { CommandTimeout = 0 };
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] is null) cmd.Parameters.AddWithValue("p" + i, NpgsqlDbType.Text, DBNull.Value);
                else cmd.Parameters.AddWithValue("p" + i, args[i]!);
            }
            var result = new JsonArray();
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var row = new JsonObject();
                for (int i = 0; i < reader.FieldCount; i++)
                    row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetDataTypeName(i) is "json" or "jsonb"
                        ? JsonNode.Parse(reader.GetString(i)) : System.Text.Json.JsonSerializer.SerializeToNode(reader.GetValue(i));
                result.Add(row);
            }
            return result;
        }
    }
}
