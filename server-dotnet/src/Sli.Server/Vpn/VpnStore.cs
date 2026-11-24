using System.Data;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;

namespace Sli.Server.Vpn;

public interface IVpnReadSession : IAsyncDisposable
{
    Task<List<JsonObject>> ReadAsync(string sql,object?[] parameters,CancellationToken ct);
}
public interface IVpnStore
{
    bool AccountingConfigured => false;
    Task<IVpnReadSession?> OpenAccountingAsync(CancellationToken ct) => Task.FromResult<IVpnReadSession?>(null);
    Task<IVpnReadSession> OpenAsync(CancellationToken ct);
}
public sealed class PostgresVpnStore(IPostgresConnectionFactory connections) : IVpnStore
{
    public bool AccountingConfigured => Agents.Radius.RadiusAccountingMode.Effective() is not null;

    public Task<IVpnReadSession> OpenAsync(CancellationToken ct) =>
        Task.FromException<IVpnReadSession>(new InvalidOperationException("module_disabled"));

    public async Task<IVpnReadSession?> OpenAccountingAsync(CancellationToken ct)
    {
        if (Agents.Radius.RadiusAccountingMode.Effective() is not { } mode) return null;
        var db = await connections.OpenAsync(ct);
        try
        {
            // Readiness and domain history must observe the same read-only PostgreSQL snapshot.
            var tx = await db.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
            await using var readOnly = new NpgsqlCommand("set transaction read only", db, tx);
            await readOnly.ExecuteNonQueryAsync(ct);
            if (await mode.RegisteredAsync(db, tx, active: true, ct)) return new Session(db, tx);
        }
        catch
        {
            await db.DisposeAsync();
            throw;
        }
        await db.DisposeAsync();
        return null;
    }

    private sealed class Session(NpgsqlConnection db, NpgsqlTransaction tx) : IVpnReadSession
    {
        public Task<List<JsonObject>> ReadAsync(string sql, object?[] parameters, CancellationToken ct)
        {
            if (sql.StartsWith("module_disabled:", StringComparison.Ordinal))
                throw new InvalidOperationException("module_disabled");
            return RadiusJobs.Rows(db, tx, sql, ct, parameters);
        }

        public async ValueTask DisposeAsync()
        {
            try { await tx.DisposeAsync(); }
            finally { await db.DisposeAsync(); }
        }
    }
    internal static NpgsqlParameter Parameter(object? value)=>value switch
    {
        null=>new() {NpgsqlDbType=NpgsqlDbType.TimestampTz,Value=DBNull.Value},
        JsonNode json=>new() {NpgsqlDbType=NpgsqlDbType.Jsonb,Value=json.ToJsonString()},
        _=>new() {Value=value is DateTimeOffset at?at.UtcDateTime:value}
    };
}
