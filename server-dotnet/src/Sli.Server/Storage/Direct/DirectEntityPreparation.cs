using Npgsql;

namespace Sli.Server.Storage.Direct;

internal sealed record DirectPreparedEntity(DirectEntityModel Model, int EffectiveId);
internal sealed record DirectEntityRequest(int Id,int TypeId,DirectEntity Source,DateTime First,DateTime Last);

internal static class DirectEntityPreparation
{
    internal static async Task<IReadOnlyDictionary<int,DirectPreparedEntity>> PrepareBatchAsync(NpgsqlConnection db,NpgsqlTransaction tx,
        IReadOnlyList<DirectEntityRequest> inputs,long domainId,long serverId,CancellationToken ct)
    {
        var ids=inputs.Select(x=>x.Id).ToArray();
        var stored=new Dictionary<int,(long? Domain,long? Server,DateTime? First,DateTime? Last)>();
        await using (var lookup = new NpgsqlCommand("select id,domain_id,server_id,first_seen_utc,last_seen_utc from entities_v2 where id=any(@ids)", db, tx))
        {
            lookup.Parameters.AddWithValue("ids", ids);
            await using var reader = await lookup.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct)) stored.Add(reader.GetInt32(0),(
                reader.IsDBNull(1)?null:reader.GetInt64(1),reader.IsDBNull(2)?null:reader.GetInt64(2),
                reader.IsDBNull(3)?null:reader.GetDateTime(3),reader.IsDBNull(4)?null:reader.GetDateTime(4)));
        }
        var resolved=ids.ToDictionary(x=>x,x=>x);
        await using (var present = new NpgsqlCommand("select to_regprocedure('resolve_entity_identity_v2(integer)') is not null", db, tx))
            if (await present.ExecuteScalarAsync(ct) is true)
            {
                await using var resolve = new NpgsqlCommand("select id,resolve_entity_identity_v2(id) from unnest(@ids) w(id)", db, tx);
                resolve.Parameters.AddWithValue("ids",ids);
                await using var reader=await resolve.ExecuteReaderAsync(ct);
                int count=0;
                while(await reader.ReadAsync(ct)) {
                    if(reader.IsDBNull(1) || reader.GetInt32(1)<=0)throw new InvalidOperationException("storage_v2_entity_resolution_failed");
                    resolved[reader.GetInt32(0)]=reader.GetInt32(1);count++;
                }
                if(count!=ids.Length)throw new InvalidOperationException("storage_v2_entity_resolution_failed");
            }
        return inputs.ToDictionary(x=>x.Id,x=> {
            stored.TryGetValue(x.Id,out var old);
            var first=old.First is {} f && f<x.First?f:x.First;
            var last=old.Last is {} l && l>x.Last?l:x.Last;
            return new DirectPreparedEntity(DirectEntityModel.Create(x.Id,x.TypeId,x.Source,
                old.Domain ?? (x.Source.DomainScoped?domainId:null),old.Server ?? (x.Source.ServerScoped?serverId:null),first,last),resolved[x.Id]);
        });
    }
}
