using System.Data;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Infrastructure;
using Sli.Server.Semantic;

namespace Sli.Server.Vpn;

public interface IVpnReadSession : IAsyncDisposable
{
    Task<List<JsonObject>> ReadAsync(string sql,object?[] parameters,CancellationToken ct);
}
public interface IVpnStore { Task<IVpnReadSession> OpenAsync(CancellationToken ct); }
public sealed class PostgresVpnStore : IVpnStore
{
    public PostgresVpnStore(IPostgresConnectionFactory connections, IConfiguration? configuration = null) { }

    public Task<IVpnReadSession> OpenAsync(CancellationToken ct)
    {
        throw new InvalidOperationException("module_disabled");
    }
    internal static NpgsqlParameter Parameter(object? value)=>value switch
    {
        null=>new() {NpgsqlDbType=NpgsqlDbType.TimestampTz,Value=DBNull.Value},
        JsonNode json=>new() {NpgsqlDbType=NpgsqlDbType.Jsonb,Value=json.ToJsonString()},
        _=>new() {Value=value is DateTimeOffset at?at.UtcDateTime:value}
    };
}
