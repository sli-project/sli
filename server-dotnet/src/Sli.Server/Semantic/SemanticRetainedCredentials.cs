using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Infrastructure;

namespace Sli.Server.Semantic;

public static partial class SemanticRetainedCommand
{
    // Same transaction/ACL pattern as RadiusObservationHost.WithConsumerLogin.
    // The temporary login can SET ROLE only to the existing semantic worker.
    private static async Task<JsonObject> WithWorkerLogin(IPostgresConnectionFactory factory, Func<string, CancellationToken, Task<JsonObject>> run, CancellationToken ct)
    {
        string role = "adlog_semantic_runtime_" + Guid.NewGuid().ToString("N")[..16];
        string password = Convert.ToHexString(RandomNumberGenerator.GetBytes(36));
        await using var admin = await factory.OpenAsync(ct); using var quote = new NpgsqlCommandBuilder();
        string id = quote.QuoteIdentifier(role), database = quote.QuoteIdentifier(admin.Database);
        async Task Execute(string sql, CancellationToken token) { await using var command = new NpgsqlCommand(sql, admin) { CommandTimeout = 0 }; await command.ExecuteNonQueryAsync(token); }
        async Task LockAcl(CancellationToken token) { await using var command = new NpgsqlCommand("select pg_advisory_xact_lock(hashtextextended($1,0))", admin) { CommandTimeout = 0 }; command.Parameters.AddWithValue("sli.semantic.ephemeral_database_connect_acl.v1"); await command.ExecuteScalarAsync(token); }
        await using (var tx = await admin.BeginTransactionAsync(ct)) {
            await LockAcl(ct);
            // Password is generated hexadecimal only, never input from a host or a caller.
            await Execute($"create role {id} login noinherit nosuperuser nocreatedb nocreaterole nobypassrls noreplication password '{password}'; grant adlog_semantic_worker to {id}; grant connect on database {database} to {id}", ct);
            await tx.CommitAsync(ct);
        }
        try {
            var builder = new NpgsqlConnectionStringBuilder(admin.ConnectionString) { Username = role, Password = password, Pooling = false, Multiplexing = false, CommandTimeout = 0, IncludeErrorDetail = false };
            return await run(builder.ConnectionString, ct);
        }
        finally {
            await using var tx = await admin.BeginTransactionAsync(CancellationToken.None); await LockAcl(CancellationToken.None);
            await Execute($"revoke connect on database {database} from {id}; revoke adlog_semantic_worker from {id}; drop role {id}", CancellationToken.None);
            await tx.CommitAsync(CancellationToken.None);
        }
    }
}
