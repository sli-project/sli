using Npgsql;
using Sli.Server.Agents.Registry;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Consumer;

namespace Sli.Server.Storage.Direct;

internal sealed record DirectBatchProjection(DirectEventReservation Reservation, JsonObject Row,
    Direct4624Projection Projection, IReadOnlyList<DirectPreparedEntity> Entities);

// One source batch publishes under one independent Storage V2 worker transaction.
internal static class Direct4624Publication
{
    internal static async Task PublishBatchAsync(DirectRuntimeAuthorization authorization, NpgsqlDataSource workerDataSource,
        IReadOnlyList<DirectBatchProjection> batch,IReadOnlyDictionary<string,short> roleIds,CancellationToken ct,
        Action<AdDcProjectionStep>? reportStep=null)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        var publish=batch.Where(x=>!x.Reservation.Published).ToArray();
        if(publish.Length==0)return;
        if(publish.Any(x=>x.Entities.Count!=x.Projection.Entities.Count || x.Entities.Count<3 || x.Projection.Entities.Any(e=>!roleIds.ContainsKey(e.Role))))
            throw new InvalidDataException("storage_v2_projection_invalid");
        EnsureSupportedMode();
        reportStep?.Invoke(AdDcProjectionStep.HotWriteWait);
        await using var db=await workerDataSource.OpenConnectionAsync(ct);
        await using var tx=await db.BeginTransactionAsync(ct);
        await using(var role=new NpgsqlCommand("set local role adlog_storage_worker",db,tx)) await role.ExecuteNonQueryAsync(ct);
        await using(var check=new NpgsqlCommand("select current_user",db,tx))
            if((string?)await check.ExecuteScalarAsync(ct)!="adlog_storage_worker")throw new InvalidOperationException("storage_v2_worker_role_required");
        bool resolver;
        await using(var capability=new NpgsqlCommand("select to_regprocedure('resolve_entity_identity_v2(integer)') is not null",db,tx)) resolver=await capability.ExecuteScalarAsync(ct) is true;
        if(resolver) await using(var guard=new NpgsqlCommand("select pg_advisory_xact_lock(hashtext('entity_identity_merge_r7'))",db,tx)) await guard.ExecuteNonQueryAsync(ct);
        reportStep?.Invoke(AdDcProjectionStep.HotEntities);
        var entities=publish.SelectMany(x=>x.Entities).DistinctBy(x=>x.Model.Id).OrderBy(x=>x.Model.Id).ToArray();
        var entityWrites=entities.Select(x=>Direct4624Writes.EntityCommand(db,tx,x.Model)).ToArray();
        var detailWrites=entities.Select(x=>Direct4624Writes.EntityDetailsCommand(db,tx,x.Model)).ToArray();
        try {
            await Direct4624Writes.WriteBatchAsync(db,tx,entityWrites,"entities_v2",ct);
            await Direct4624Writes.WriteBatchAsync(db,tx,detailWrites,"entity_details_v2",ct);
        } finally {
            foreach(var command in entityWrites.Concat(detailWrites))await command.DisposeAsync();
        }
        reportStep?.Invoke(AdDcProjectionStep.HotEntityResolution);
        var resolved=new Dictionary<int,int>();
        if(resolver) {
            await using var resolve=new NpgsqlCommand("select id,resolve_entity_identity_v2(id) from unnest(@ids) w(id)",db,tx);
            resolve.Parameters.AddWithValue("ids",entities.Select(x=>x.Model.Id).ToArray());
            await using var reader=await resolve.ExecuteReaderAsync(ct);
            while(await reader.ReadAsync(ct)) {
                if(reader.IsDBNull(1) || reader.GetInt32(1)<=0)throw new InvalidOperationException("storage_v2_entity_resolution_failed");
                resolved.Add(reader.GetInt32(0),reader.GetInt32(1));
            }
            if(resolved.Count!=entities.Length)throw new InvalidOperationException("storage_v2_entity_resolution_failed");
        } else {
            foreach(var entity in entities)resolved[entity.Model.Id]=entity.Model.Id;
        }
        var verification = new List<DirectChunkEvent>();
        foreach(var item in publish)
            verification.Add(new(item.Reservation.Id,item.Reservation.NormalizedHash,item.Entities));
        reportStep?.Invoke(AdDcProjectionStep.HotVerification);
        await DirectVerifiedChunk.VerifyBatchAsync(db,tx,verification,ct);
        reportStep?.Invoke(AdDcProjectionStep.HotCommit);
        await tx.CommitAsync(ct);
    }
    internal static void EnsureSupportedMode() => _ = Sli.Server.Semantic.SemanticProducer.RuntimeMode();

    internal static void EnsureSupportedMode(string? enabledValue, string? modeValue)
    {
        _ = Sli.Server.Semantic.SemanticProducer.RuntimeMode(name => name switch {
            "ADLOG_SEMANTIC_PRODUCTION_ENABLED" => enabledValue,
            "ADLOG_SEMANTIC_RUNTIME_MODE" => modeValue,
            _ => Environment.GetEnvironmentVariable(name)
        });
    }
}
