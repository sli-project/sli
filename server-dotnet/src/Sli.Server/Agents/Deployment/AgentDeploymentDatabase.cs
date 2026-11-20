using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Groups;
using Sli.Server.Infrastructure;

namespace Sli.Server.Agents.Deployment;

// One caller-owned transaction includes grant locks, state changes and audit.
internal interface IAgentDeploymentDatabase : IAsyncDisposable
{
    Task OpenAsync(CancellationToken ct);
    Task<List<JsonObject>> Rows(string sql, CancellationToken ct, params (string, object?)[] args);
    Task<int> Execute(string sql, CancellationToken ct, params (string, object?)[] args);
    Task CommitAsync(CancellationToken ct);
}

internal sealed class AgentDeploymentDatabase(IPostgresConnectionFactory connections) : IAgentDeploymentDatabase
{
    private NpgsqlConnection? connection;
    private NpgsqlTransaction? transaction;
    public async Task OpenAsync(CancellationToken ct)
    {
        connection = await connections.OpenAsync(ct);
        transaction = await connection.BeginTransactionAsync(ct);
    }
    public async Task<List<JsonObject>> Rows(string sql, CancellationToken ct, params (string, object?)[] args)
    {
        // PostgreSQL permits data-modifying statements in a CTE, not a FROM
        // subquery. Keep RETURNING and SELECT results on the same JSON reader.
        string query = sql.StartsWith("select ", StringComparison.OrdinalIgnoreCase)
            ? "select row_to_json(r)::text from (" + sql + ") r"
            : "with r as (" + sql + ") select row_to_json(r)::text from r";
        await using var command = AgentGroupStore.Query(connection!, transaction!, query, args);
        await using var reader = await command.ExecuteReaderAsync(ct);
        var rows = new List<JsonObject>();
        while (await reader.ReadAsync(ct)) rows.Add(JsonNode.Parse(reader.GetString(0))!.AsObject());
        return rows;
    }
    public Task<int> Execute(string sql, CancellationToken ct, params (string, object?)[] args)
        => AgentGroupStore.Execute(connection!, transaction!, sql, ct, args);
    public Task CommitAsync(CancellationToken ct) => transaction!.CommitAsync(ct);
    public async ValueTask DisposeAsync()
    {
        if (transaction is not null) await transaction.DisposeAsync();
        if (connection is not null) await connection.DisposeAsync();
    }
}

internal sealed class AgentDeploymentRejection(string code, int status = 403) : Exception(code)
{
    internal int Status { get; } = status;
}
