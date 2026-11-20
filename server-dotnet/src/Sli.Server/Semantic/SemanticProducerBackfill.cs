using System.Text.Json.Nodes;
using Npgsql;

namespace Sli.Server.Semantic;

internal static class SemanticProducerBackfill
{
    internal const int WindowSize=65536;
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
        var rows=await session.QueryAsync(SelectionSql,ct,mode,SemanticEvent.Version,Math.Min(batch,SemanticProducer.MaxBatch));
        var ids=rows.Select(x=>x.Number("id")).ToArray();
        int queued=0;
        if(ids.Length>0) {
            var selection=await SemanticProducer.ReadSelection(session,ids,mode,ct);
            queued=await SemanticProducer.Enqueue(session,selection.Jobs,ct);
            await SemanticProducer.RecordDecisions(session,ids,mode,ct);
        }
        // A maximum is progress telemetry only. Discovery retains all
        // undecided IDs, including lower IDs committed by parallel importers.
        var progress=(await session.QueryAsync("""
            select coalesce(max(upper(span)-1),0) as cursor from public.semantic_producer_coverage c
            cross join lateral unnest(c.decided_ids) span
            where c.runtime_mode=$1 and c.processor_version=$2
            """,ct,mode,SemanticEvent.Version)).Single()!;
        await tx.CommitAsync(ct);
        return new JsonObject { ["status"]="short_events",["scanned"]=ids.Length,["queued"]=queued,
            ["cursor"]=progress.Number("cursor") };
    }
}
