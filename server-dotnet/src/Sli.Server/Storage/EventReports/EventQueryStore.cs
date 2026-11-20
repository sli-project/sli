using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Entities;

namespace Sli.Server.Storage.EventReports;

internal sealed record SearchEvent(long Id,DateTimeOffset Stamp,string Fingerprint,string Store,JsonObject Fields);
internal interface IEventQueryStore
{
    Task<IReadOnlyList<SearchEvent>> CaptureAsync(EventSearchInput input,EventSearchPolicy policy,CancellationToken ct);
    Task<JsonObject> EntitiesAsync(long id,CancellationToken ct);
    Task<JsonObject> ListAsync(EventListInput input,CapabilityDecisionSet capabilities,CancellationToken ct);
    void AdmitSearch();
    DateTimeOffset RetentionBoundary { get; }
}

internal sealed partial class EventReadService
{
    public void AdmitSearch() { _=ShortBoundary(config); }
    public DateTimeOffset RetentionBoundary => ShortBoundary(config);
    public async Task<IReadOnlyList<SearchEvent>> CaptureAsync(EventSearchInput input,EventSearchPolicy policy,CancellationToken ct)
    {
        var hotCompiler=new EventSearchSql();
        string select=string.Join(",",policy.Fields.Select(f=>hotCompiler.Select(f)+" as \""+f+"\""));
        // Daily groups have no event identity. Exact captures use individual hot
        // events and retained cold facts, with a digest of the stored short row.
        string prefix="with short_events as ("+EntityShortSql.Source(hotCompiler.Value(ShortBoundary(config)),daily:false)+") ";
        string hotSql=prefix+"select "+select+",e.id as _id,e.time_created_utc as _stamp,encode(sha256(convert_to(to_jsonb(e)::text,'UTF8')),'hex') as _fingerprint "+
            ShortJoins+" where s.id is not null and e.id>0 and "+hotCompiler.Predicate(input,policy)+" order by e.time_created_utc,e.id limit 250001";
        var hot=await QueryPgAsync(hotSql,hotCompiler.Parameters,ct);
        if(hot.Count>250000) throw new EventSearchException("storage_limit_exceeded");
        var result=new Dictionary<long,SearchEvent>(); long bytes=0;
        void Add(SearchEvent row)
        {
            if(row.Id<=0 || row.Stamp<input.From || row.Stamp>=input.To || row.Fingerprint.Length!=64 || !row.Fingerprint.All(Uri.IsHexDigit)) throw new EventSearchException("storage_integrity_error");
            if(result.TryGetValue(row.Id,out var prev))
            { if(prev.Stamp!=row.Stamp || !prev.Fingerprint.Equals(row.Fingerprint,StringComparison.OrdinalIgnoreCase)) throw new EventSearchException("storage_integrity_error"); return; }
            bytes+=JsonSerializer.SerializeToUtf8Bytes(row.Fields).Length;
            if(bytes>16*1024*1024 || result.Count>=250000) throw new EventSearchException("storage_limit_exceeded");
            result.Add(row.Id,row);
        }
        foreach(var row in hot)
        {
            ct.ThrowIfCancellationRequested();
            long id=Long(row,"_id"); var stamp=Stamp(row["_stamp"]);
            var fields=new JsonObject();
            foreach(string f in policy.Fields) {
                var value=row[f];
                fields[f]=(f is "account" or "account_kind") && value is JsonValue v && v.TryGetValue<string>(out var json)
                    ? JsonNode.Parse(json) : value?.DeepClone();
            }
            if(fields.ContainsKey("title")) fields["title"]=EventListProjection.Title(fields);
            EventSearchProjection.Complete(fields);
            Add(new(id,stamp,row["_fingerprint"]!.ToString().ToUpperInvariant(),"postgres",fields));
        }
        return result.Values.ToArray();
    }
    internal async Task<List<JsonObject>> QueryPgAsync(string sql,IReadOnlyDictionary<string,object> parameters,CancellationToken ct)
    {
        await using var db=await connections.OpenAsync(ct);
        await using var tx=await db.BeginTransactionAsync(ct);
        await using(var limits=new NpgsqlCommand("set transaction read only; set local statement_timeout=0; set local lock_timeout=0",db,tx)) await limits.ExecuteNonQueryAsync(ct);
        await using var cmd=new NpgsqlCommand(sql,db,tx) { CommandTimeout=0 };
        foreach(var (name,value) in parameters) cmd.Parameters.AddWithValue(name,value);
        await using var r=await cmd.ExecuteReaderAsync(ct); var rows=new List<JsonObject>(); long bytes=0;
        while(await r.ReadAsync(ct))
        {
            var row=new JsonObject(); for(int i=0;i<r.FieldCount;i++) row[r.GetName(i)]=r.IsDBNull(i)?null:JsonSerializer.SerializeToNode(r.GetValue(i));
            rows.Add(row); bytes+=JsonSerializer.SerializeToUtf8Bytes(row).Length;
            if(rows.Count>250001 || bytes>16*1024*1024) throw new EventSearchException("storage_limit_exceeded");
        }
        return rows;
    }
    public Task<JsonObject> EntitiesAsync(long id,CancellationToken ct) => ShortEntitiesAsync(id,QueryPgAsync,ct);
    internal Task<JsonObject> EntitiesAsync(long id,Func<string,IReadOnlyDictionary<string,object>,CancellationToken,Task<List<JsonObject>>> query,CancellationToken ct) =>
        ShortEntitiesAsync(id,query,ct);
    internal static long Long(JsonObject row,string field) => long.TryParse(row[field]?.ToString(),NumberStyles.Integer,CultureInfo.InvariantCulture,out long id)?id:throw new EventSearchException("storage_integrity_error");
    internal static DateTimeOffset Stamp(JsonNode? n)
    {
        if(n is JsonValue v)
        {
            if(v.TryGetValue<DateTimeOffset>(out var offset)) return offset.ToUniversalTime();
            if(v.TryGetValue<DateTime>(out var date)) return new DateTimeOffset(DateTime.SpecifyKind(date,DateTimeKind.Utc));
        }
        return DateTimeOffset.Parse(EventSearchInput.String(n)??n?.ToString()??"",CultureInfo.InvariantCulture,DateTimeStyles.AssumeUniversal|DateTimeStyles.AdjustToUniversal);
    }
}
