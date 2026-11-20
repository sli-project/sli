using System.Text.Json.Nodes;

namespace Sli.Server.Storage.EventReports;
// Caller supplies per-event access and controller authorization. No anchor grant is transitive.
internal sealed class EventRelationsReader(Func<long,int,(decimal Delta,long Id)?,CancellationToken,Task<IReadOnlyList<RelationCandidate>>> query,Func<long,CancellationToken,Task<bool>> admitted)
{
    internal EventRelationsReader(EventRelationStore store,Func<long,CancellationToken,Task<bool>> admitted) : this(store.QueryAsync,admitted) { }
    internal async Task<JsonObject> ReadAsync(long anchor,int limit,string? cursor,TimeSpan budget,CancellationToken ct)
    {
        if(anchor<=0) throw new ArgumentOutOfRangeException(nameof(anchor));
        if(budget<=TimeSpan.Zero) throw new TimeoutException("event_relations_budget_exhausted");
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(budget); ct=deadline.Token;
        if(!await admitted(anchor,ct)) throw new UnauthorizedAccessException("not_found");
        var position=cursor is null ? ((decimal Delta,long Id)?)null : EventRelationCursor.Decode(anchor,cursor);
        int size=Math.Clamp(limit,1,200);
        var visible=new List<RelationCandidate>();
        var decisions=new Dictionary<long,bool>();
        while(visible.Count<=size)
        {
            ct.ThrowIfCancellationRequested();
            var rows=(await query(anchor,size+1,position,ct)).OrderBy(r=>r.Delta).ThenByDescending(r=>r.RelatedId)
                .Where(r=>position is null || r.Delta>position.Value.Delta || r.Delta==position.Value.Delta && r.RelatedId<position.Value.Id)
                .GroupBy(r=>r.RelatedId).Select(g=>g.First()).Take(size+1).ToArray();
            if(rows.Length==0) break;
            foreach(var row in rows)
            {
                ct.ThrowIfCancellationRequested();
                if(row.RelatedId<=0 || row.RelatedId==anchor) continue;
                if(!decisions.TryGetValue(row.RelatedId,out bool allowed)) decisions[row.RelatedId]=allowed=await admitted(row.RelatedId,ct);
                if(allowed) visible.Add(row);
                if(visible.Count>size) break;
            }
            position=(rows[^1].Delta,rows[^1].RelatedId);
            if(rows.Length<size+1) break;
        }
        // Build pagination only from admitted IDs: a base64 cursor is public
        // metadata too and must not expose a denied event identifier.
        return EventRelationContract.Build(anchor,visible,size);
    }
}
