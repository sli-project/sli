using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Storage.History;

namespace Sli.Server.Storage.EventReports;

// Caller supplies independently established event authorization and controller route.
internal sealed class EventDetailReportOwner(EventDetailOwner raw, NpgsqlDataSource source, Func<long,CancellationToken,Task<bool>> admitted, Func<JsonObject,CancellationToken,Task<JsonObject>> project)
{
    internal async Task<Dictionary<long,JsonObject>> ReadAsync(IEnumerable<long> requested,bool primary,DateTimeOffset cutoff,TimeSpan budget,CancellationToken ct)
    {
        long[] ids=requested.Where(id=>id>0).Distinct().ToArray();
        if(ids.Length>100) throw new ArgumentOutOfRangeException(nameof(requested));
        if(budget<=TimeSpan.Zero) throw new TimeoutException("event_detail_budget_exhausted");
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(budget); ct=deadline.Token; var clock=Stopwatch.StartNew();
        var rows=await EventReportAdmission.ReadAsync(ids,admitted,(permitted,token)=>
        {
            var remaining=budget-clock.Elapsed; if(remaining<=TimeSpan.Zero) throw new TimeoutException("event_detail_budget_exhausted");
            return raw.ReadAsync(permitted,primary,cutoff,remaining,token);
        },ct);
        await ApplyPrioritiesAsync(rows,ct);
        var output=new Dictionary<long,JsonObject>();
        foreach(var (id,row) in rows) { ct.ThrowIfCancellationRequested(); output.Add(id,await project(row,ct)); }
        return output;
    }
    async Task ApplyPrioritiesAsync(Dictionary<long,JsonObject> rows,CancellationToken ct)
    {
        var identities=new Dictionary<long,string>();
        foreach(var (id,row) in rows)
        {
            string hash=(row["normalized_hash"]?.ToString() ?? "").ToLowerInvariant();
            if(hash.StartsWith("\\x",StringComparison.Ordinal)) hash=hash[2..];
            if(hash.Length==64 && hash.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f')) identities[id]=hash;
        }
        if(identities.Count==0) return;
        await using var db=await source.OpenConnectionAsync(ct);
        await using var tx=await db.BeginTransactionAsync(ct);
        await using(var limits=new NpgsqlCommand("set local statement_timeout=3000; set local lock_timeout=1000",db,tx) { CommandTimeout=3 }) await limits.ExecuteNonQueryAsync(ct);
        await using var command=new NpgsqlCommand("select i.id,public.account_watch_event_priority(i.id,i.sha256) from unnest(@ids::bigint[],@sha::text[]) as i(id,sha256)",db,tx) { CommandTimeout=3 };
        command.Parameters.AddWithValue("ids",NpgsqlDbType.Array | NpgsqlDbType.Bigint,identities.Keys.ToArray());
        command.Parameters.AddWithValue("sha",NpgsqlDbType.Array | NpgsqlDbType.Text,identities.Values.ToArray());
        await using var reader=await command.ExecuteReaderAsync(ct); var priorities=new Dictionary<long,JsonNode?>();
        while(await reader.ReadAsync(ct)) priorities[reader.GetInt64(0)]=reader.IsDBNull(1) ? null : JsonNode.Parse(reader.GetString(1));
        await reader.DisposeAsync(); await tx.CommitAsync(ct);
        foreach(var (id,row) in rows) row["watch_priority"]=priorities.TryGetValue(id,out var priority) ? priority?.DeepClone() : null;
    }
}
