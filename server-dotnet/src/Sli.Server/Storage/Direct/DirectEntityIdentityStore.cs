using Npgsql;

namespace Sli.Server.Storage.Direct;

internal static class DirectEntityIdentityStore
{
    internal static async Task<IReadOnlyDictionary<(int TypeId,string NaturalKey),int>> ReserveAsync(
        DirectRuntimeAuthorization authorization, NpgsqlDataSource workerDataSource,
        IReadOnlyCollection<(int TypeId,string NaturalKey)> entities, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        await using var db = await workerDataSource.OpenConnectionAsync(ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        await using (var role = new NpgsqlCommand("set local role adlog_storage_worker", db, tx)) await role.ExecuteNonQueryAsync(ct);
        await using (var roleCheck = new NpgsqlCommand("select current_user", db, tx))
            if ((string?)await roleCheck.ExecuteScalarAsync(ct) != "adlog_storage_worker") throw new InvalidOperationException("storage_v2_worker_role_required");
        var wanted = entities.Distinct().OrderBy(e => e.TypeId).ThenBy(e => e.NaturalKey, StringComparer.Ordinal).ToArray();
        var result = new Dictionary<(int,string),int>();
        if(wanted.Length>0)
        {
            await using (var insert = new NpgsqlCommand("""
                insert into storage_v2_entity_identity_allocations(entity_type_id,natural_key)
                select * from unnest(@types,@keys) w(type,key) order by type,key collate "C"
                on conflict(entity_type_id,natural_key) do nothing
                """, db, tx))
            {
                insert.Parameters.AddWithValue("types", wanted.Select(x=>x.TypeId).ToArray()); insert.Parameters.AddWithValue("keys", wanted.Select(x=>x.NaturalKey).ToArray());
                await insert.ExecuteNonQueryAsync(ct);
            }
            await using var lookup = new NpgsqlCommand("select a.entity_type_id,a.natural_key,a.id from unnest(@types,@keys) w(type,key) join storage_v2_entity_identity_allocations a on a.entity_type_id=w.type and a.natural_key=w.key", db, tx);
            lookup.Parameters.AddWithValue("types", wanted.Select(x=>x.TypeId).ToArray()); lookup.Parameters.AddWithValue("keys", wanted.Select(x=>x.NaturalKey).ToArray());
            await using var reader=await lookup.ExecuteReaderAsync(ct);
            while(await reader.ReadAsync(ct)) {
                if(reader.GetInt32(2)<=0)throw new InvalidOperationException("storage_v2_entity_identity_unresolved");
                result.Add((reader.GetInt32(0),reader.GetString(1)),reader.GetInt32(2));
            }
            if(result.Count!=wanted.Length)throw new InvalidOperationException("storage_v2_entity_identity_unresolved");
        }
        await tx.CommitAsync(ct);
        return result;
    }
}
