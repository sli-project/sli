using Npgsql;

namespace Sli.Server.Storage.Direct;

internal static class DirectDictionaries
{
    internal static async Task<IReadOnlyDictionary<(string Kind,string Value),int>> ResolveAsync(
        DirectRuntimeAuthorization authorization, NpgsqlDataSource workerDataSource,
        IReadOnlyCollection<(string Kind,string Value)> values, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        await using var db = await workerDataSource.OpenConnectionAsync(ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        await using (var role = new NpgsqlCommand("set local role adlog_storage_worker", db, tx)) await role.ExecuteNonQueryAsync(ct);
        await using (var roleCheck = new NpgsqlCommand("select current_user", db, tx))
            if ((string?)await roleCheck.ExecuteScalarAsync(ct) != "adlog_storage_worker") throw new InvalidOperationException("storage_v2_worker_role_required");
        var resolved = new Dictionary<(string,string),int>();
        foreach (var group in values.Distinct().OrderBy(v => v.Kind, StringComparer.Ordinal).ThenBy(v => v.Value, StringComparer.Ordinal).GroupBy(v=>v.Kind))
        {
            await Sli.Server.Storage.Backfill.StorageV2Postgres.ResolveDictionaryAsync(group.Key,group.Select(x=>x.Value).ToArray(),resolved,
                (sql,wanted)=>Sli.Server.Storage.Backfill.StorageV2Postgres.Query(db,tx,sql,ct,("values",wanted)));
        }
        await tx.CommitAsync(ct);
        return resolved;
    }
}
