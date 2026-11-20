using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;

namespace Sli.Server.Storage.EventReports;

internal sealed record EventListInput(DateTimeOffset? From,DateTimeOffset? To,string Zone,int Limit,bool Asc,
    JsonObject? Cursor,string? Q,string? Account,string? Channel,string? Provider,string? Subject,string? Target,
    string[] Servers,int[] EventIds,string? Risk,string? Tier,string? Category)
{
    internal static EventListInput Parse(IQueryCollection query,DateTimeOffset now)
    {
        string? First(params string[] keys) { foreach(string key in keys) { string? v=query[key].FirstOrDefault(); if(!string.IsNullOrWhiteSpace(v)) return v.Trim(); } return null; }
        string zone=First("timezone")??"UTC"; DateTimeOffset? from=null,to=null;
        try
        {
            _=TimeZoneInfo.FindSystemTimeZoneById(zone);
            if(First("time_from") is {} start) from=EventSearchInput.Instant(start,zone,false);
            if(First("time_to") is {} end) to=EventSearchInput.Instant(end,zone,true);
        }
        catch(TimeZoneNotFoundException) { throw new EventSearchException("invalid_timezone",400); }
        catch(InvalidTimeZoneException) { throw new EventSearchException("invalid_timezone",400); }
        catch(FormatException e) { throw new EventSearchException(e.Message is "nonexistent_local_datetime" or "ambiguous_local_datetime_requires_offset"?e.Message:"invalid_datetime",400); }
        if(from>=to) throw new EventSearchException("empty_or_reversed_time_range",400);
        string? q=First("q"),account=First("account","user");
        if(from is null && to is null && q is null && account is null) from=now.AddHours(-24);
        int limit=int.TryParse(First("limit"),NumberStyles.Integer,CultureInfo.InvariantCulture,out int n)?Math.Clamp(n,1,1000):200;
        JsonObject? cursor=null;
        if(First("cursor") is {} raw && raw.Length<=2048)
        {
            try {
                raw=raw.Replace('-','+').Replace('_','/');
                var obj=JsonNode.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(raw.PadRight((raw.Length+3)/4*4,'=')))) as JsonObject;
                bool summary=obj?["short"]?.ToString()=="true" && obj["group"]?.ToString() is {Length:64} group && group.All(Uri.IsHexDigit);
                if(obj is not null && EventSearchInput.Integer(obj["id"],summary?0:1,long.MaxValue) && obj["time"] is not null && Record(obj["record"], out long record)) {
                    _=EventReadService.Stamp(obj["time"]); obj["record"]=record; cursor=obj;
                }
            }
            catch(Exception e) when(e is FormatException or System.Text.Json.JsonException or InvalidOperationException) { }
        }
        string? view=First("view")?.ToLowerInvariant();
        return new(from,to,zone,limit,First("order")?.ToLowerInvariant()=="asc",cursor,q,account,First("channel"),First("provider","source"),First("subject","initiator"),First("target","object"),
            (First("server","servers")??"").Split(',',StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries).Distinct().ToArray(),
            query["event_id"].SelectMany(v=>(v??"").Replace(';',',').Split(',')).Select(v=>int.TryParse(v,out int id)?id:-1).Where(id=>id>=0).Distinct().ToArray(),
            First("risk")?.ToLowerInvariant()??(view=="attention"?"high":null),First("tier")?.ToLowerInvariant(),First("category") is {} category?EventCardSemantics.Category(category,false):(view=="authentication"?"authentication":view=="accounts"?"account_management":view=="tasks"?"service_task":null));
    }
    private static bool Record(JsonNode? node, out long record)
    {
        record = -1;
        if (node is null) return true;
        if (node is not JsonValue value) return false;
        if (value.TryGetValue<long>(out record)) return true;
        if (value.TryGetValue<string>(out var text)) return long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out record);
        if (value.TryGetValue<bool>(out bool flag)) { record = flag ? 1 : 0; return true; }
        if (value.TryGetValue<decimal>(out decimal number) && number >= long.MinValue && number <= long.MaxValue)
        { record = (long)number; return true; }
        return false;
    }
    internal static string Encode(JsonObject row)
    {
        var obj=new JsonObject { ["time"]=row["time_created_utc"]?.DeepClone(),["record"]=row["event_record_id"]?.DeepClone()??JsonValue.Create(-1),["id"]=row["id"]?.DeepClone() };
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(obj.ToJsonString())).TrimEnd('=').Replace('+','-').Replace('/','_');
    }
}
