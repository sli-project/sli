using System.Globalization;
using System.Text.Json.Nodes;

namespace Sli.Server.Storage.EventReports;

internal sealed record LegacySearchTranslation(JsonObject Request,string[] Notices,bool StartEmpty);

internal static class EventSearchLegacy
{
    static readonly string[] Keys=["q","view","category","server","servers","account","user","subject","initiator","target","object","event_id","event_ids","channel","provider","source","time_from","time_to","from","to","timezone","period","risk","tier","order","limit","cursor","offset","return_to"];
    static readonly string[] JournalKeys=["q","view","server","time_from","time_to","from","to","timezone","period","limit","cursor","offset","return_to","order"];

    // The caller supplies a server-owned resolver that checks access and exact
    // identity. Zero or multiple matches must never drop a legacy predicate.
    internal static LegacySearchTranslation Translate(IReadOnlyDictionary<string,string[]> query,string source="journal",Func<string,string,string?,long[]>? resolveIdentity=null)
    {
        if(source is not ("journal" or "search") || query.Keys.Except(Keys).Any() || source=="journal" && query.Keys.Except(JournalKeys).Any()) throw new EventSearchException("legacy_unsupported_filter");
        foreach(var (key,values) in query)
        {
            if(values is null || values.Length==0 || values.Any(v=>string.IsNullOrEmpty(v) || v.Trim()!=v)) throw new EventSearchException("legacy_unsupported_filter");
            if(key is not ("event_id" or "event_ids") && values.Length!=1) throw new EventSearchException("legacy_ambiguous_filter");
        }
        string? One(params string[] aliases)
        {
            var values=aliases.Where(query.ContainsKey).Select(k=>query[k][0]).Distinct().ToArray();
            if(values.Length>1) throw new EventSearchException("legacy_ambiguous_filter");
            return values.FirstOrDefault();
        }
        var conditions=new JsonArray();
        void Condition(string field,JsonNode value,string? role=null,string op="eq")
        {
            var c=new JsonObject { ["field"]=field,["operator"]=op,["value"]=value };
            if(role is not null) c["role"]=role;
            conditions.Add(c);
        }
        long Identity(string field,string value,string? role=null)
        {
            var matches=resolveIdentity?.Invoke(field,value,role);
            if(matches is null || matches.Length!=1 || matches[0]<=0) throw new EventSearchException("legacy_identity_unresolved");
            return matches[0];
        }
        string? view=One("view");
        if(view is not null and not ("all" or "attention" or "authentication" or "accounts" or "tasks")) throw new EventSearchException("legacy_unsupported_filter");
        if(view is not null and not "all")
        {
            if(source=="journal") Condition("legacy_journal_view",JsonValue.Create(view)!);
            else if(view=="attention") Condition("risk",JsonValue.Create("high")!);
            else Condition("category",JsonValue.Create(view=="authentication"?"authentication":view=="accounts"?"account_management":"service_task")!);
        }
        foreach(string key in new[]{"category","risk","tier"})
        {
            if(One(key) is not {} value) continue;
            if(source=="search") foreach(var c in conditions.Where(c=>EventSearchInput.String(c!["field"])==key).ToArray()) conditions.Remove(c);
            Condition(key,JsonValue.Create(value)!);
        }
        if(One("q") is {} q) Condition("legacy_"+source+"_q",JsonValue.Create(q)!);
        foreach(var (aliases,role) in new[]{(new[]{"account","user"},"any"),(new[]{"subject","initiator"},"actor"),(new[]{"target","object"},"target")})
            if(One(aliases) is {} value) Condition("account",JsonValue.Create(Identity("account",value,role))!,role);
        if(One("server","servers") is {} server)
        {
            var names=source=="search"?server.Split(','):[server];
            if(names.Any(string.IsNullOrWhiteSpace)) throw new EventSearchException("legacy_unsupported_filter");
            Condition("server_id",new JsonArray(names.Select(n=>(JsonNode?)JsonValue.Create(Identity("server_id",n.Trim()))).ToArray()),op:"in");
        }
        foreach(var (field,aliases) in new[]{("provider",new[]{"provider","source"}),("channel",new[]{"channel"})})
            if(One(aliases) is {} value) Condition(field,JsonValue.Create(value)!);
        if(query.ContainsKey("event_id") && query.ContainsKey("event_ids")) throw new EventSearchException("legacy_ambiguous_filter");
        var ids=query.GetValueOrDefault("event_id",query.GetValueOrDefault("event_ids",[]));
        if(ids.Length>0)
        {
            var values=ids.SelectMany(v=>v.Split(',')).ToArray();
            if(values.Any(v=>!Digits(v,10))) throw new EventSearchException("legacy_unsupported_filter");
            Condition("event_id",new JsonArray(values.Select(v=>(JsonNode?)JsonValue.Create(long.Parse(v,CultureInfo.InvariantCulture))).ToArray()),op:"in");
        }
        string? start=One("time_from","from"),end=One("time_to","to"),preset=One("period");
        if((start is null)!=(end is null) || start is not null && preset is not (null or "custom")) throw new EventSearchException("invalid_period");
        var period=new JsonObject { ["preset"]=start is not null?"custom":preset??"24h",["timezone"]=One("timezone")??"UTC" };
        if(start is not null) { period["from"]=start; period["to"]=end; }
        string order=One("order")??"desc";
        if(order is not ("asc" or "desc")) throw new EventSearchException("legacy_unsupported_filter");
        var request=new JsonObject { ["contract_version"]="evsearch.v1",["conditions"]=conditions,["period"]=period,["sort"]="time_"+order,["exclude_machine_system"]=false };
        if(One("limit") is {} limit)
        {
            if(!Digits(limit,3)) throw new EventSearchException("legacy_unsupported_filter");
            request["page_size"]=int.Parse(limit,CultureInfo.InvariantCulture);
        }
        if(One("return_to") is {} returnTo) request["entry_context"]=new JsonObject { ["kind"]="question",["return_to"]=returnTo };
        return new(EventSearchInput.Validate(request),query.ContainsKey("cursor") || query.ContainsKey("offset")?["evsearch.legacy_paging_reset"]:[],conditions.Count==0 && start is null);
    }
    static bool Digits(string value,int max)=>value.Length>0 && value.Length<=max && value.All(c=>c is >= '0' and <= '9');
}
