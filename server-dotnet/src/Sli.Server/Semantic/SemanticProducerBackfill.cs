using System.Text.Json.Nodes;
using Npgsql;

namespace Sli.Server.Semantic;

internal static class SemanticProducerBackfill
{
    internal const int WindowSize=65536;
    // A recent allocation alone can be a historical import. Use both the
    // allocation and occurrence times to find fresh, attested short events.
    internal const string LiveSelectionSql="""
        select e.id from public.semantic_event_source355 e
        where e.time_created_utc between now()-interval '5 minutes' and now()
          and e.migrated_at>=now()-interval '5 minutes'
          and not (coalesce((select c.decided_ids from public.semantic_producer_coverage c
             where c.runtime_mode=$1 and c.processor_version=$2),'{}'::int8multirange) @> e.id)
        order by e.time_created_utc,e.id limit $3
        """;
    // Coverage is already durable per mode/version. Its complement supplies a
    // lower bound for each unresolved interval, without assuming commit order
    // or treating sequence gaps / reserved-but-unpublished IDs as decisions.
    internal const string SelectionSql="""
        select pending.id
        from unnest(int8multirange(int8range(1,null,'[)')) - coalesce(
            (select c.decided_ids from public.semantic_producer_coverage c
             where c.runtime_mode=$1 and c.processor_version=$2),'{}'::int8multirange)) span
        cross join lateral (
            select e.id from public.semantic_event_source355 e
            where e.id>=lower(span) and e.id<=coalesce(upper(span)-1,9223372036854775807)
            order by e.id limit $3
        ) pending
        order by pending.id limit $3
        """;
    internal static async Task<JsonObject> RunAsync(NpgsqlConnection db,string mode,int batch,CancellationToken ct)
    {
        if(batch is <1 or >WindowSize)throw new ArgumentOutOfRangeException(nameof(batch));
        ct.ThrowIfCancellationRequested();
        await using var tx=await db.BeginTransactionAsync(ct);
        var session=new SemanticSession(db,tx);
        async Task<(int Scanned,int Queued)> Produce(string sql,int take,bool live)
        {
            if(take==0) return (0,0);
            var rows=await session.QueryAsync(sql,ct,mode,SemanticEvent.Version,take);
            var ids=rows.Select(x=>x.Number("id")).ToArray();
            if(ids.Length==0) return (0,0);
            var selection=await SemanticProducer.ReadSelection(session,ids,mode,ct);
            int queued=await SemanticProducer.Enqueue(session,selection.Jobs,ct,live);
            await SemanticProducer.RecordDecisions(session,ids,mode,ct);
            return (ids.Length,queued);
        }
        int page=Math.Min(batch,SemanticProducer.EnqueueBatchSize);
        var live=await Produce(LiveSelectionSql,Math.Max(1,page-1),live:true);
        var history=await Produce(SelectionSql,page-live.Scanned,live:false);
        // A maximum is progress telemetry only. Discovery retains all
        // undecided IDs, including lower IDs committed by parallel importers.
        var progress=(await session.QueryAsync("""
            select coalesce((select upper(range_merge(c.decided_ids))-1 from public.semantic_producer_coverage c
                where c.runtime_mode=$1 and c.processor_version=$2),0) as cursor
            """,ct,mode,SemanticEvent.Version)).Single()!;
        await tx.CommitAsync(ct);
        return new JsonObject { ["status"]="short_events",["scanned"]=live.Scanned+history.Scanned,["queued"]=live.Queued+history.Queued,
            ["live_queued"]=live.Queued,["backfill_queued"]=history.Queued,
            ["cursor"]=progress.Number("cursor") };
    }
}
