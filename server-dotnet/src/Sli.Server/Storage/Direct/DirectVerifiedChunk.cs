using Npgsql;

namespace Sli.Server.Storage.Direct;

internal sealed record DirectChunkEvent(long EventId, byte[] EventHash, IReadOnlyList<DirectPreparedEntity> Entities);

internal static class DirectVerifiedChunk
{
    internal static async Task VerifyBatchAsync(NpgsqlConnection db,NpgsqlTransaction tx,
        IReadOnlyList<DirectChunkEvent> batch,CancellationToken ct)
    {
        if(batch.Count==0)return;
        var events=new Dictionary<long,byte[]>();
        await using(var command=new NpgsqlCommand("""
            select a.id,a.normalized_hash from storage_v2_event_identity_allocations a
            join event_source_representations_v2 r on r.event_id=a.id and r.normalized_hash=a.normalized_hash
            where a.id=any(@ids)
            """,db,tx)) {
            command.Parameters.AddWithValue("ids",batch.Select(x=>x.EventId).ToArray());
            await using var reader=await command.ExecuteReaderAsync(ct);
            while(await reader.ReadAsync(ct))events.Add(reader.GetInt64(0),reader.GetFieldValue<byte[]>(1));
        }
        var entities=new Dictionary<int,(byte[] Core,byte[]? Details)>();
        await using(var command=new NpgsqlCommand("""
            select e.id,e.source_core_sha256,d.source_details_sha256 from entities_v2 e
            left join entity_details_v2 d on d.entity_id=e.id where e.id=any(@ids)
            """,db,tx)) {
            command.Parameters.AddWithValue("ids",batch.SelectMany(x=>x.Entities).Select(x=>x.Model.Id).Distinct().ToArray());
            await using var reader=await command.ExecuteReaderAsync(ct);
            while(await reader.ReadAsync(ct))entities.Add(reader.GetInt32(0),(reader.GetFieldValue<byte[]>(1),reader.IsDBNull(2)?null:reader.GetFieldValue<byte[]>(2)));
        }
        foreach(var item in batch) {
            if(!events.TryGetValue(item.EventId,out var hash))throw new InvalidOperationException("storage_v2_event_readback_missing");
            if(!hash.AsSpan().SequenceEqual(item.EventHash))throw new InvalidOperationException("storage_v2_chunk_hash_mismatch");
            foreach(var entity in item.Entities) {
                if(!entities.TryGetValue(entity.Model.Id,out var stored) || stored.Details is null)
                    throw new InvalidOperationException("storage_v2_entity_readback_missing");
                if(!stored.Core.AsSpan().SequenceEqual(entity.Model.CoreHash) || !stored.Details.AsSpan().SequenceEqual(entity.Model.DetailsHash))
                    throw new InvalidOperationException("storage_v2_chunk_hash_mismatch");
            }
        }
    }
}
