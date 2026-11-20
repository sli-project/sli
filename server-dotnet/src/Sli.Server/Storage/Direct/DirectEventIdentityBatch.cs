using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol.Compatibility;

namespace Sli.Server.Storage.Direct;

internal sealed record DirectEventRequest(int ChannelId,long RecordId,DateTime TimeUtc,JsonObject Row,string IdentityHash);

internal static partial class DirectEventIdentityStore
{
    internal const string AllocationBatchSql="""
        insert into storage_v2_event_identity_allocations(id,server_id,channel_id,event_record_id,time_created_utc,normalized_hash)
        with allocated as materialized (
            select nextval('storage_v2_event_id_seq') as id,w.*
            from unnest(@channels,@records,@times,@hashes) with ordinality w(channel_id,event_record_id,time_created_utc,normalized_hash,ordinal)
            order by w.ordinal
        )
        select id,@server,channel_id,event_record_id,time_created_utc,normalized_hash from allocated
        order by channel_id,event_record_id,time_created_utc
        on conflict(server_id,channel_id,event_record_id,time_created_utc) do nothing
        """;

    internal static async Task<IReadOnlyList<DirectEventReservation>> ReserveBatchAsync(DirectRuntimeAuthorization authorization,
        NpgsqlDataSource workerDataSource,long serverId,IReadOnlyList<DirectEventRequest> inputs,CancellationToken ct,bool localSourceAliases=false)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        if(inputs.Count==0)return [];
        var hashes=inputs.Select(x=>Convert.FromHexString(x.IdentityHash)).ToArray();
        if(hashes.Any(x=>x.Length!=32) || inputs.Any(x=>x.TimeUtc.Kind!=DateTimeKind.Utc || x.RecordId<=0))
            throw new InvalidDataException("storage_v2_event_identity_invalid");
        await using var db=await workerDataSource.OpenConnectionAsync(ct);
        await using var tx=await db.BeginTransactionAsync(ct);
        await using(var role=new NpgsqlCommand("set local role adlog_storage_worker",db,tx))await role.ExecuteNonQueryAsync(ct);
        await using(var check=new NpgsqlCommand("select current_user",db,tx))
            if((string?)await check.ExecuteScalarAsync(ct)!="adlog_storage_worker")throw new InvalidOperationException("storage_v2_worker_role_required");
        void Wanted(NpgsqlCommand command) {
            command.Parameters.AddWithValue("server",serverId);
            command.Parameters.AddWithValue("channels",inputs.Select(x=>x.ChannelId).ToArray());
            command.Parameters.AddWithValue("records",inputs.Select(x=>x.RecordId).ToArray());
            command.Parameters.AddWithValue("times",inputs.Select(x=>x.TimeUtc).ToArray());
            command.Parameters.AddWithValue("hashes",NpgsqlDbType.Array|NpgsqlDbType.Bytea,hashes);
        }
        await using(var insert=new NpgsqlCommand(AllocationBatchSql,db,tx)) {
            Wanted(insert);await insert.ExecuteNonQueryAsync(ct);
        }
        var result=new DirectEventReservation[inputs.Count];
        await using(var lookup=new NpgsqlCommand("""
            select w.ordinal,allocation.id,allocation.normalized_hash,allocation.normalized_hash,
                exists(select 1 from public.event_hot h where h.event_id=allocation.id and h.time_created_utc=w.time_created_utc and h.event_record_id is not null),
                allocation.normalized_hash
            from unnest(@channels,@records,@times,@hashes) with ordinality w(channel_id,event_record_id,time_created_utc,normalized_hash,ordinal)
            left join storage_v2_event_identity_allocations allocation on allocation.server_id=@server and allocation.channel_id=w.channel_id
                and allocation.event_record_id=w.event_record_id and allocation.time_created_utc=w.time_created_utc
            order by w.ordinal
            """,db,tx)) {
            Wanted(lookup);await using var reader=await lookup.ExecuteReaderAsync(ct);
            while(await reader.ReadAsync(ct)) {
                int ordinal=checked((int)reader.GetInt64(0)-1);
                if(reader.IsDBNull(1))throw new InvalidOperationException("storage_v2_identity_unresolved");
                byte[] retained=reader.GetFieldValue<byte[]>(2);bool published=reader.GetBoolean(4);
                if((!reader.IsDBNull(3) && !reader.GetFieldValue<byte[]>(3).AsSpan().SequenceEqual(retained)) ||
                    (published && !reader.GetFieldValue<byte[]>(5).AsSpan().SequenceEqual(retained)))throw new DirectSourceConflict(published,ordinal);
                result[ordinal]=new(reader.GetInt64(1),retained,published);
            }
        }
        if(result.Any(x=>x is null))throw new InvalidOperationException("storage_v2_identity_unresolved");
        var ids=result.Select(x=>x.Id).ToArray();
        await using(var insert=new NpgsqlCommand("""
            insert into event_source_representations_v2(event_id,normalized_hash,identity_version,canonical_hash,representation,representation_sha256)
            select w.id,w.retained,2,w.canonical,w.representation,w.digest
            from unnest(@ids,@retained,@canonical,@representations,@digests,@allowed) w(id,retained,canonical,representation,digest,allowed)
            where w.allowed on conflict(event_id) do nothing
            """,db,tx)) {
            insert.Parameters.AddWithValue("ids",ids);
            insert.Parameters.AddWithValue("retained",NpgsqlDbType.Array|NpgsqlDbType.Bytea,result.Select(x=>x.NormalizedHash).ToArray());
            insert.Parameters.AddWithValue("canonical",NpgsqlDbType.Array|NpgsqlDbType.Bytea,hashes);
            insert.Parameters.AddWithValue("representations",NpgsqlDbType.Array|NpgsqlDbType.Jsonb,inputs.Select(x=>SourceJson.Serialize(x.Row)).ToArray());
            insert.Parameters.AddWithValue("digests",NpgsqlDbType.Array|NpgsqlDbType.Bytea,inputs.Select(x=>Convert.FromHexString(RepresentationDigest(x.Row))).ToArray());
            insert.Parameters.AddWithValue("allowed",result.Select((x,i)=>!x.Published && x.NormalizedHash.AsSpan().SequenceEqual(hashes[i])).ToArray());
            await insert.ExecuteNonQueryAsync(ct);
        }
        var representations=new Dictionary<long,(byte[] Normalized,short Version,byte[] Canonical,JsonObject? Row,byte[] Digest)>();
        await using(var rep=new NpgsqlCommand("""
            select event_id,normalized_hash,identity_version,canonical_hash,representation::text,representation_sha256
            from event_source_representations_v2 where event_id=any(@ids) order by event_id for update
            """,db,tx)) {
            rep.Parameters.AddWithValue("ids",ids);await using var reader=await rep.ExecuteReaderAsync(ct);
            while(await reader.ReadAsync(ct))representations.Add(reader.GetInt64(0),(reader.GetFieldValue<byte[]>(1),reader.GetInt16(2),reader.GetFieldValue<byte[]>(3),JsonNode.Parse(reader.GetString(4)) as JsonObject,reader.GetFieldValue<byte[]>(5)));
        }
        for(int i=0;i<inputs.Count;i++) {
            var reservation=result[i];
            if(!representations.TryGetValue(reservation.Id,out var rep))throw new InvalidOperationException("event_retained_source_unavailable");
            var stored=rep.Row ?? throw new InvalidOperationException("event_retained_hash_differs");
            if(rep.Version!=2 || !rep.Normalized.AsSpan().SequenceEqual(reservation.NormalizedHash) ||
                !rep.Digest.AsSpan().SequenceEqual(Convert.FromHexString(RepresentationDigest(stored))))throw new DirectSourceConflict(reservation.Published,i);
            var storedCanonical=Convert.FromHexString(DirectEventIdentity.Hash(stored));
            if(!rep.Canonical.AsSpan().SequenceEqual(storedCanonical) || !storedCanonical.AsSpan().SequenceEqual(hashes[i]) ||
                DirectRepresentationConflict.IsProven(stored,inputs[i].Row))throw new DirectSourceConflict(reservation.Published,i);
            if(!JsonNode.DeepEquals(stored,inputs[i].Row))
            {
                // AD/DC resolves both transport names to this server before calling.
                // Retain the original proof; XML, identity hashes and event fields
                // still have to match in full, including on a retry after upgrade.
                var previous=(JsonObject)stored.DeepClone(); var incoming=(JsonObject)inputs[i].Row.DeepClone();
                foreach(string key in new[] { "computer_name","connect_address" }) { previous.Remove(key); incoming.Remove(key); }
                if(!localSourceAliases || !JsonNode.DeepEquals(previous,incoming))throw new InvalidOperationException("event_representation_pending");
            }
        }
        await tx.CommitAsync(ct);
        return result;
    }
}
