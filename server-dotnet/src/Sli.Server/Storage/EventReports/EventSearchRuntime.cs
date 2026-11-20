using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sli.Server.Storage.EventReports;

// One bounded, process-local store. No database transaction survives a response.
internal sealed class EventSearchRuntime(TimeProvider clock)
{
    internal sealed record Execution(long Owner,string Binding,string QueryHash,EventSearchInput Input,DateTimeOffset AsOf,
        DateTimeOffset Expires,DateTimeOffset Boundary,JsonArray Groups,JsonArray Members,long Bytes);
    readonly Dictionary<string,Execution> entries=[];
    readonly SemaphoreSlim operation=new(1,1);
    readonly byte[] secret=RandomNumberGenerator.GetBytes(32);
    internal async Task<T> RunAsync<T>(Func<Task<T>> work)
    {
        if(!await operation.WaitAsync(0)) throw new EventSearchException("snapshot_limit_exceeded");
        try { return await work(); } finally { operation.Release(); }
    }
    internal Execution Get(string id,long owner)
    {
        foreach(string expired in entries.Where(p=>p.Value.Expires<=clock.GetUtcNow()).Select(p=>p.Key).ToArray()) entries.Remove(expired);
        if(!entries.TryGetValue(id,out var entry) || entry.Owner!=owner) throw new EventSearchException("snapshot_expired");
        return entry;
    }
    internal void Remove(string id) => entries.Remove(id);
    internal void Reauthorize(string id,Execution entry,EventSearchPolicy policy)
    { if(entry.Binding!=policy.Binding) { Remove(id); throw new EventSearchException("snapshot_invalidated"); } }
    internal string Start(long owner,EventSearchInput input,EventSearchPolicy policy,IReadOnlyList<SearchEvent> rows,DateTimeOffset boundary,CancellationToken ct=default)
    {
        _=GetOrPurge();
        if(rows.Count>250000 || rows.Select(r=>r.Id).Distinct().Count()!=rows.Count) throw new EventSearchException("storage_integrity_error");
        var groups=new Dictionary<string,JsonObject>(); var members=new JsonArray();
        foreach(var row in rows)
        {
            ct.ThrowIfCancellationRequested();
            if(row.Id<=0 || row.Stamp<input.From || row.Stamp>=input.To || row.Fields.Any(f=>!policy.Fields.Contains(f.Key))) throw new EventSearchException("storage_integrity_error");
            string key=EventSearchProjection.GroupKey(row);
            if(!groups.TryGetValue(key,out var group))
            {
                if(groups.Count>=10000) throw new EventSearchException("snapshot_limit_exceeded");
                groups[key]=group=new JsonObject { ["group_key"]=key,["count"]=0,["first_seen"]=row.Stamp,["last_seen"]=row.Stamp };
                if(policy.Fields.Contains("title")) { var projected=new JsonObject(); foreach(var (f,v) in row.Fields) if(f is not ("id" or "time_created_utc" or "source_payload_state")) projected[f]=v?.DeepClone(); group["fields"]=projected; }
            }
            group["count"]=group["count"]!.GetValue<int>()+1;
            if(EventReadService.Stamp(group["first_seen"])>row.Stamp) group["first_seen"]=row.Stamp;
            if(EventReadService.Stamp(group["last_seen"])<row.Stamp) group["last_seen"]=row.Stamp;
            members.Add(new JsonObject { ["group_key"]=key,["event_db_id"]=row.Id,["stamp"]=row.Stamp,["fields"]=row.Fields.DeepClone(),["source_store"]=row.Store });
        }
        var sorted=input.Sort=="count_desc"?groups.Values.OrderByDescending(g=>g["count"]!.GetValue<int>()).ThenByDescending(g=>EventReadService.Stamp(g["last_seen"])).ThenBy(g=>g["group_key"]!.ToString(),StringComparer.Ordinal):
            input.Sort=="time_asc"?groups.Values.OrderBy(g=>EventReadService.Stamp(g["last_seen"])).ThenBy(g=>g["group_key"]!.ToString(),StringComparer.Ordinal):groups.Values.OrderByDescending(g=>EventReadService.Stamp(g["last_seen"])).ThenBy(g=>g["group_key"]!.ToString(),StringComparer.Ordinal);
        var grouped=new JsonArray(sorted.Select(g=>(JsonNode)g).ToArray());
        long bytes=JsonSerializer.SerializeToUtf8Bytes(grouped).Length+JsonSerializer.SerializeToUtf8Bytes(members).Length+JsonSerializer.SerializeToUtf8Bytes(input.Request).Length;
        if(bytes>16*1024*1024) throw new EventSearchException("snapshot_limit_exceeded");
        while(entries.Count>=128 || entries.Values.Sum(e=>e.Bytes)+bytes>64*1024*1024) entries.Remove(entries.MinBy(e=>e.Value.AsOf).Key);
        string id=Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(24)); var now=clock.GetUtcNow();
        var query=(JsonObject)input.Request.DeepClone(); query.Remove("page_size"); query.Remove("entry_context");
        entries.Add(id,new(owner,policy.Binding,EventSearchPolicy.Hash(new JsonObject { ["query"]=query,["account_role"]=input.AccountRole,["question"]=Question(input.Question) }),input,now,now.AddSeconds(300),boundary,grouped,members,bytes));
        return id;
    }
    bool GetOrPurge() { foreach(string id in entries.Where(e=>e.Value.Expires<=clock.GetUtcNow()).Select(e=>e.Key).ToArray()) entries.Remove(id); return true; }
    internal JsonObject Page(string id,Execution entry,JsonObject request,bool members)
    {
        int size=EventSearchInput.Size(request,entry.Input.PageSize); string? group=EventSearchInput.String(request["group_key"]);
        IEnumerable<JsonNode?> all=entry.Groups;
        if(members)
        {
            if(group is null || !entry.Groups.Any(g=>g!["group_key"]!.ToString()==group)) throw new EventSearchException("invalid_request");
            all=entry.Members.Where(m=>m!["group_key"]!.ToString()==group).OrderBy(m=>EventReadService.Stamp(m!["stamp"])).ThenBy(m=>m!["event_db_id"]!.GetValue<long>());
        }
        var rows=all.ToArray(); string context=id+"|"+entry.Owner+"|"+(members?"members|"+group:"groups");
        int offset=0;
        if(request.ContainsKey("cursor"))
        {
            string after=Position(EventSearchInput.String(request["cursor"]),context);
            int index=Array.FindIndex(rows,r=>r![members?"event_db_id":"group_key"]!.ToString()==after);
            if(index<0) throw new EventSearchException("invalid_cursor"); offset=index+1;
        }
        var selected=rows.Skip(offset).Take(size).Select(r=>r!.DeepClone()).ToArray();
        bool more=offset+selected.Length<rows.Length;
        var result=Envelope(id,entry);
        result["items"]=new JsonArray(selected); result["has_more"]=more; result["next_cursor"]=more?Token(context,selected[^1][members?"event_db_id":"group_key"]!.ToString()):null;
        if(members)
        {
            result.Remove("query_hash"); result.Remove("as_of"); result.Remove("expires_at"); result.Remove("storage_coverage"); result.Remove("grouping_version");
            result["group_key"]=group;
            foreach(var row in result["items"]!.AsArray()) row!["source_payload_state"]=row["fields"]?["source_payload_state"]?.DeepClone()??JsonValue.Create("unknown");
        }
        return result;
    }
    internal JsonObject Summary(string id,Execution entry,JsonObject request,EventSearchPolicy policy,CancellationToken ct=default)
    {
        string[] blocks=request.ContainsKey("blocks") ? (request["blocks"] as JsonArray)?.Select(n=>EventSearchInput.String(n)??"").ToArray()??[]:["totals","facets"];
        if(blocks.Length is <1 or >4 || blocks.Distinct().Count()!=blocks.Length || blocks.Any(b=>!new[]{"totals","facets","histogram","coverage"}.Contains(b))) throw new EventSearchException("invalid_request");
        string? field=EventSearchInput.String(request["facet_field"]),query=EventSearchInput.String(request["facet_query"]);
        string[] facetFields=["event_id","channel","provider","outcome","action","reason","logon_type","source_station","related_object","account","server_id","domain_id","ip"];
        if(request.ContainsKey("facet_field") && (field is null || !facetFields.Contains(field) || !policy.Fields.Contains(field) || !blocks.Contains("facets")) || request.ContainsKey("facet_query") && (field is null || query is null || query.Length>256)) throw new EventSearchException("invalid_request");
        if(request.ContainsKey("cursor") && field is null) throw new EventSearchException("invalid_cursor");
        int size=EventSearchInput.Size(request),buckets=24;
        if(request.ContainsKey("histogram_buckets") && (!blocks.Contains("histogram") || request["histogram_buckets"] is not JsonValue bv || !bv.TryGetValue<int>(out buckets) || buckets is <1 or >120)) throw new EventSearchException("invalid_request");
        var result=Envelope(id,entry); var totals=new JsonObject(); var facets=new JsonObject();
        JsonObject Ready()=>new() { ["status"]="ready",["accuracy"]="exact",["scope"]="retained_matches" };
        if(blocks.Contains("totals")) foreach(var (name,count) in new[]{("events",entry.Members.Count),("groups",entry.Groups.Count)}) { var v=Ready(); v["value"]=count; totals[name]=v; }
        if(blocks.Contains("facets")) foreach(string name in field is null?facetFields.Where(policy.Fields.Contains):[field])
        {
            ct.ThrowIfCancellationRequested();
            var eventValues=entry.Members.Select(m=>Values(m!["fields"]![name],name)).ToArray();
            var counts=eventValues.SelectMany(v=>v).GroupBy(n=>n,StringComparer.Ordinal).ToDictionary(g=>g.Key,g=>g.Count(),StringComparer.Ordinal);
            var ordered=counts.Keys.Where(k=>query is null || (JsonNode.Parse(k)?.ToString()??"").Contains(query,StringComparison.OrdinalIgnoreCase)).OrderByDescending(k=>counts[k]).ThenBy(k=>JsonNode.Parse(k) is JsonValue v && v.TryGetValue<long>(out long n)?n:0).ThenBy(k=>JsonNode.Parse(k)!.ToString(),StringComparer.Ordinal).ToArray();
            string context=id+"|"+entry.Owner+"|facets|"+name+"|"+(query??"").ToLowerInvariant(); int offset=0;
            if(request.ContainsKey("cursor")) { string after=Position(EventSearchInput.String(request["cursor"]),context); int index=Array.IndexOf(ordered,after); if(index<0) throw new EventSearchException("invalid_cursor"); offset=index+1; }
            var selected=ordered.Skip(offset).Take(size).ToArray(); var set=selected.ToHashSet(); bool more=offset+selected.Length<ordered.Length;
            var facet=Ready(); facet["items"]=new JsonArray(selected.Select(k=>new JsonObject { ["value"]=JsonNode.Parse(k),["count"]=counts[k] } as JsonNode).ToArray());
            facet["other_values_count"]=counts.Count-selected.Length; facet["other_events_count"]=eventValues.Count(v=>v.Except(set).Any()); facet["unknown_events_count"]=eventValues.Count(v=>v.Count==0); facet["multi_valued"]=eventValues.Any(v=>v.Count>1); facet["has_more"]=more; facet["next_cursor"]=more?Token(context,selected[^1]):null; facets[name]=facet;
        }
        result["totals"]=totals; result["facets"]=facets; result["histogram"]=new JsonObject(); result["source_coverage"]=new JsonObject();
        if(blocks.Contains("histogram") || blocks.Contains("coverage")) result["source_coverage"]=Coverage(entry.Input);
        if(blocks.Contains("histogram"))
        {
            var histogram=Ready(); histogram["timezone"]=entry.Input.Zone; var items=new JsonArray(); long duration=(entry.Input.To-entry.Input.From).Ticks;
            int[] counts=new int[buckets];
            foreach(var member in entry.Members) { ct.ThrowIfCancellationRequested(); long ticks=(EventReadService.Stamp(member!["stamp"])-entry.Input.From).Ticks; int index=(int)Math.Min(buckets-1,(decimal)ticks*buckets/duration); counts[index]++; }
            for(int i=0;i<buckets;i++)
            {
                var from=entry.Input.From.AddTicks(duration*i/buckets); var to=entry.Input.From.AddTicks(duration*(i+1)/buckets);
                items.Add(new JsonObject { ["from"]=from,["to"]=to,["value"]=counts[i],["coverage"]="unknown" });
            }
            histogram["items"]=items; result["histogram"]=histogram;
        }
        return result;
    }
    static HashSet<string> Values(JsonNode? raw,string name)
    {
        var values=raw is JsonArray a?a.ToArray():[raw]; var result=new HashSet<string>(StringComparer.Ordinal);
        foreach(var n in values)
        {
            JsonNode? v=n; if(name=="account" && n is JsonObject obj) v=obj["entity_id"];
            if(v is null || v.ToString()=="") continue;
            result.Add(v.ToJsonString());
        }
        return result;
    }
    static JsonObject? Question(string? name)
    {
        if(name is null) return null;
        JsonObject Condition(string field,JsonArray values)=>new() { ["field"]=field,["operator"]="in",["values"]=values,["role"]=null };
        JsonArray Branch(int[] ids,string provider="Microsoft-Windows-Security-Auditing",string channel="Security")=>new(Condition("provider",new JsonArray(JsonValue.Create(provider))),Condition("channel",new JsonArray(JsonValue.Create(channel))),Condition("event_id",new JsonArray(ids.Select(id=>JsonValue.Create(id) as JsonNode).ToArray())));
        var branches=new JsonArray();
        if(name=="failed_logons") { branches.Add(Branch([4625,4771,6273])); var validation=Branch([4776]); validation.Add(Condition("outcome",new JsonArray(JsonValue.Create("failure")))); branches.Add(validation); }
        else { branches.Add(Branch(EventSearchInput.Questions[name])); if(name=="log_cleared") branches.Add(Branch([104],"Microsoft-Windows-Eventlog","System")); }
        return new() { ["question_id"]=name,["alternatives"]=branches,["account_role"]=name is "failed_logons" or "lockouts"?"target":"actor",["confirmed_privilege"]=false,["confirmed_grant"]=false,["version"]="evsearch.questions.v1" };
    }
    static JsonObject Coverage(EventSearchInput input)=>new() { ["status"]="unknown",["confirmed"]=new JsonArray(),["unconfirmed"]=new JsonArray(new JsonArray(JsonValue.Create(input.From),JsonValue.Create(input.To))) };
    static JsonObject Envelope(string id,Execution e)=>new() { ["execution_id"]=id,["query_hash"]=e.QueryHash,["as_of"]=e.AsOf,["expires_at"]=e.Expires,["contract_version"]="evsearch.v1",["grouping_version"]="evsearch.group.v1",["period"]=EventSearchInput.Period(e.Input.From,e.Input.To,e.Input.Zone),["retention_boundary"]=e.Boundary,["coverage"]="unknown",["storage_coverage"]=Coverage(e.Input) };
    string Token(string context,string after)
    {
        byte[] data=Encoding.UTF8.GetBytes(new JsonObject { ["context"]=context,["after"]=after }.ToJsonString());
        return Convert.ToBase64String(HMACSHA256.HashData(secret,data).Concat(data).ToArray()).TrimEnd('=').Replace('+','-').Replace('/','_');
    }
    string Position(string? token,string context)
    {
        try
        {
            if(token is null || token.Length is <1 or >2048) throw new FormatException();
            byte[] data=Convert.FromBase64String(token.Replace('-','+').Replace('_','/').PadRight((token.Length+3)/4*4,'='));
            if(data.Length<=32 || !CryptographicOperations.FixedTimeEquals(data.AsSpan(0,32),HMACSHA256.HashData(secret,data.AsSpan(32)))) throw new FormatException();
            var obj=JsonNode.Parse(data.AsSpan(32))!;
            if(obj["context"]?.ToString()!=context || EventSearchInput.String(obj["after"]) is not {} after) throw new FormatException();
            return after;
        }
        catch(Exception e) when(e is FormatException or JsonException or InvalidOperationException) { throw new EventSearchException("invalid_cursor"); }
    }
}
