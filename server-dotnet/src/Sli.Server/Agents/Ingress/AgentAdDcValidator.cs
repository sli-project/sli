using System.Globalization;
using System.Numerics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Agents.Ingress;

// Frozen source: server/sli/plugins/ad/agent_policy.py dc_event_rows.
public static class AgentAdDcValidator
{
    public const string Live = "sli.windows.ad-dc", History = "sli.windows.ad-dc-history";
    private static readonly string[] Channels=DcCursor.Channels.ToArray();
    private static readonly EventCatalog Catalog=EventCatalog.Load();
    private static readonly HashSet<(string,string,int)> LegacyIdentities=LoadLegacyIdentities();

    // Payload compatibility is checked by the collection contract and full row/cursor
    // validation. A patch/minor release is not a different source identity.
    internal static bool SupportsVersion(string value) => Version.TryParse(value,out var version)
        && version.Major==1 && version.Build>=0 && version.Revision<0;

    public static JsonObject NormalizePolicy(JsonObject input,bool history)
    {
        // The source factory selects the policy by presence of the field, not module id.
        history=input.ContainsKey("history_before_utc");
        var config=(JsonObject)input.DeepClone(); string? before=null;
        if(history) {
            before=Text(config["history_before_utc"]); _=AgentAdDcUtc.Parse(before); config.Remove("history_before_utc");
            if(config.ContainsKey("initial_read_hours") && (config["initial_read_hours"] is null || Text(config["initial_read_hours"])!="all")) throw new ArgumentException();
            config["initial_read_hours"]="all";
        }
        foreach(string name in new[]{"source_name","connect_address","policy_revision"})
            if(config[name] is not null && UnicodeCaseFold.TrimAndFold(Text(config[name])).Length==0) throw new ArgumentException();
        if(config["channel_generations"] is JsonObject gens) foreach(var item in gens) if(UnicodeCaseFold.TrimAndFold(Text(item.Value)).Length==0) throw new ArgumentException();
        var result=AdDcConfig.Parse(config,EventCatalog.Load()).ToJson();
        if(history) { result["history_before_utc"]=before; result["batch_size"]=Math.Min(result["batch_size"]!.GetValue<int>(),4); }
        return result;
    }
    public static JsonArray Validate(Envelope envelope,JsonObject packet,JsonObject? policy,string sourceName,bool transportGap=false)
    {
        try { return ValidateCore(envelope,packet,policy,sourceName,transportGap); }
        catch(Exception x) when(x is ArgumentException or InvalidOperationException or NullReferenceException or FormatException or OverflowException or JsonException or AgentException or ProtocolException or KeyNotFoundException)
        { throw new ProtocolException("agent_collection_cursor_invalid"); }
    }
    private static JsonArray ValidateCore(Envelope e,JsonObject packet,JsonObject? policy,string sourceName,bool transportGap)
    {
        static void Require(bool v) { if(!v) throw new ArgumentException(); }
        var rows=AgentCollectionRows.ExtractEvents(packet); var before=State(e.CursorBefore); var after=State(e.CursorAfter);
        var old=before["channels"]!.AsObject(); var current=after["channels"]!.AsObject(); var context=packet["context"]!["ad_dc"]!.AsObject(); var header=packet["header"]!.AsObject();
        bool history=e.ModuleId==History; Require(history||e.ModuleId==Live);
        Require(context.ContainsKey("read_error"));
        var enabled=policy is not null ? policy["channels"]!.AsObject() : context.ContainsKey("channels") ? context["channels"]!.AsObject() : new JsonObject { ["Security"]=true,["System"]=true,["Directory Service"]=true };
        var generations=policy is not null ? policy["channel_generations"]!.AsObject() : context.ContainsKey("channel_generations") ? context["channel_generations"]!.AsObject() : new JsonObject();
        var reportedChannels=context["channels"] as JsonObject;
        bool legacyChannels=reportedChannels is not null && reportedChannels.Count==3 && Channels.Take(3).All(reportedChannels.ContainsKey);
        var channelOrder = legacyChannels || reportedChannels is null && enabled.Count==3 && Channels.Take(3).All(enabled.ContainsKey) ? Channels[..3] : Channels;
        Require(Integer(before["next"])<channelOrder.Length && Integer(after["next"])<channelOrder.Length
            && old.All(p=>channelOrder.Contains(p.Key)) && current.All(p=>channelOrder.Contains(p.Key)));
        var active=channelOrder.Where(ch=>enabled.ContainsKey(ch) && Truthy(enabled[ch]) && !(history && old[ch] is JsonObject p && p["complete"] is JsonValue complete && complete.GetValue<bool>() && Equal(p["generation"],generations.ContainsKey(ch)?generations[ch]:JsonValue.Create(e.SourceInstanceId)))).ToHashSet();
        Require(channelOrder.All(enabled.ContainsKey));
        Require(active.Count>0); int next=(int)Integer(before["next"]); int index=Enumerable.Range(0,channelOrder.Length).Select(i=>(next+i)%channelOrder.Length).First(i=>active.Contains(channelOrder[i]));
        int repeat=(next+channelOrder.Length-1)%channelOrder.Length;
        if(!history && Text(header["channel"])==channelOrder[repeat] && active.Contains(channelOrder[repeat]) && old.ContainsKey(channelOrder[repeat])) index=repeat;
        string channel=channelOrder[index]; var progress=current[channel]!.AsObject(); var previous=old[channel] as JsonObject;
        bool reset=previous is not null && Text(previous["generation"])!=Text(header["generation"]); BigInteger? start=previous is not null&&!reset?Id(previous["record_id"]):null; BigInteger? last=Id(progress["record_id"]);
        var others=(JsonObject)current.DeepClone(); others.Remove(channel); var oldOthers=(JsonObject)old.DeepClone(); oldOthers.Remove(channel);
        var bounds=Bounds(progress); var oldBounds=previous is not null&&!reset?Bounds(previous):new JsonObject(); bool failed=context["read_error"] is not null; bool recovered=context["bookmark_recovered"] is not null && Flag(context["bookmark_recovered"]);
        Require(!(history && (bounds.ContainsKey("since_utc") || !bounds.ContainsKey("before_utc"))) && !(!history && (bounds.ContainsKey("before_utc") || progress.ContainsKey("complete")))
            && (oldBounds.Count==0 || Equal(bounds,oldBounds)) && !(oldBounds.Count==0 && previous is not null && !reset && bounds.Count>0)
            && !(progress["complete"] is not null && (!history||rows.Count>0||e.FilteredCount>0||failed)));
        if(policy is not null) {
            // Older agents report only the original channels. Normalize their
            // missing defaults exactly as AdDcConfig does, then compare every
            // policy value. An explicit denial or generation still must match.
            var claimedChannels=reportedChannels?.DeepClone().AsObject();
            if(legacyChannels && enabled.Count==Channels.Length)
                foreach(string extra in Channels.Skip(3)) claimedChannels![extra]=true;
            Require((!context.ContainsKey("channels")||Equal(claimedChannels,policy["channels"])) && (!context.ContainsKey("channel_generations")||Equal(context["channel_generations"],policy["channel_generations"])));
            if(history) Require(Equal(bounds["before_utc"],policy["history_before_utc"]));
            if(oldBounds.Count==0 && bounds["since_utc"] is not null) { var depth=policy["initial_read_hours"]; Require(JsonRead.TryInteger(depth,out var hours) && AgentAdDcUtc.Parse(Text(bounds["since_utc"]))==AgentAdDcUtc.Parse(Text(header["observed_at_utc"])).AddHours(-(double)hours)); }
        }
        string expected=reset||failed||recovered?"gap":e.FilteredCount>0?"filtered":"not_proven";
        var cursor=header["cursor"]!.AsObject(); Require(cursor.Count==2 && cursor.ContainsKey("after_record_id") && cursor.ContainsKey("last_record_id") && NumberMatches(cursor["after_record_id"],start) && NumberMatches(cursor["last_record_id"],last));
        Require(e.Channel=="ad-dc" && e.Generation==e.SourceInstanceId && Text(header["source"])==sourceName && Text(header["channel"])==channel && Text(progress["generation"])==Text(header["generation"])
            && Integer(after["next"])==(index+1)%channelOrder.Length && Equal(others,oldOthers) && Text(context["pack_id"])==Live && Equal(context["policy_revision"],JsonValue.Create(e.PolicyRevision))
            && NumberMatches(context["filtered_count"],e.FilteredCount) && Bool(context["channel_reset"]) && Flag(context["channel_reset"])==reset
            && (context["read_error"] is null||Text(context["read_error"])=="agent_ad_dc_read_failed") && (!context.ContainsKey("bookmark_recovered")||Bool(context["bookmark_recovered"]))
            && (!recovered || !(reset||failed||previous is null||start is null||Text(previous["bookmark"]).Length==0))
            && e.LostCount==(reset||failed||recovered?null:0) && (e.ContinuityState==expected || transportGap && e.ContinuityState=="gap") && Text(packet["continuity"]!["status"])=="not_proven");
        var ids=rows.Select(r=>Id(r!["record_id"]) ?? throw new ArgumentException()).ToArray();
        Require(ids.All(x=>x>0) && ids.SequenceEqual(ids.Distinct().Order()) && ids.All(n=>(start is null||n>start) && last is not null && n<=last)
            && (last is null||start is null||last>=start) && (e.FilteredCount!=0||failed||last==(ids.Length>0?ids[^1]:start))
            && (e.FilteredCount==0||last is not null&&(start is null||last>start)) && (!failed||rows.Count==0&&e.FilteredCount==0&&last==start)
            && (!failed||previous is null||reset||Equal(progress,previous)));
        if(policy is not null) Require(Text(header["generation"])==(generations[channel] is null?e.SourceInstanceId:Text(generations[channel])) && rows.Count+e.FilteredCount<=Integer(policy["batch_size"]));
        foreach(var node in rows) {
            var row=node!.AsObject(); Require(row.ContainsKey("connect_address")); var eventId=Number(row["event_id"]); var provider=row["provider_name"] is null?"None":Text(row["provider_name"]);
            // Do not strand durable packets captured before the collection table was introduced.
            Require(Catalog.Contains(channel,provider,eventId) || eventId is not null && eventId>=int.MinValue && eventId<=int.MaxValue
                && LegacyIdentities.Contains((channel,UnicodeCaseFold.Fold(provider),(int)eventId)));
            if(policy is not null) { Require(Equal(row["connect_address"],policy["connect_address"])); if(policy["allow_event_ids"] is JsonArray allow) Require(allow.Any(x=>Equal(x,row["event_id"]))); }
            string xml=Text(row["xml"]); var native=EventXml.Parse(xml,sourceName,"",channel);
            native["connect_address"]=row["connect_address"]?.DeepClone();
            Require(Equal(native,row) && EventXml.NativeChannel(EventXml.ParseBounded(xml))==channel
                && (eventId!=4662 || Catalog.AcceptsPayload(row)));
            var when=AgentAdDcUtc.Parse(Text(row["time_created"]));
            if(bounds["since_utc"] is not null && start is null) Require(when>=AgentAdDcUtc.Parse(Text(bounds["since_utc"])));
            if(bounds["before_utc"] is not null) Require(when<AgentAdDcUtc.Parse(Text(bounds["before_utc"])));
        }
        return rows;
    }
    private static JsonObject State(Cursor cursor)
    {
        if(cursor.Strategy!="bookmark") throw new ArgumentException();
        if(cursor.Token=="") return new JsonObject { ["next"]=0,["channels"]=new JsonObject() };
        var obj=JsonNode.Parse(cursor.Token)!.AsObject();
        if(!JsonRead.HasExactly(obj,"next","channels") || !JsonRead.TryInteger(obj["next"],out var n) || n<0 || n>=Channels.Length || obj["channels"] is not JsonObject channels) throw new ArgumentException();
        foreach(var (name,value) in channels) {
            if(!Channels.Contains(name) || value is not JsonObject p || p.Any(x=>x.Key is not ("record_id" or "bookmark" or "generation" or "since_utc" or "before_utc" or "complete")) || !p.ContainsKey("record_id") || !p.ContainsKey("bookmark") || !p.ContainsKey("generation")) throw new ArgumentException();
            var id=Id(p["record_id"]); var bookmark=Text(p["bookmark"]); var generation=Text(p["generation"]);
            if(id<=0 || JsonRead.CodePoints(bookmark)>2048 || (bookmark.Length>0)!=(id is not null) || generation.Length==0 || JsonRead.CodePoints(generation)>128) throw new ArgumentException();
            foreach(string key in new[]{"since_utc","before_utc"}) if(p.ContainsKey(key)) _=AgentAdDcUtc.Parse(Text(p[key]));
            if(p.ContainsKey("complete") && (!Bool(p["complete"])||!p.ContainsKey("before_utc"))) throw new ArgumentException();
        }
        return obj;
    }
    private static JsonObject Bounds(JsonObject p) { var result=new JsonObject(); foreach(string k in new[]{"since_utc","before_utc"}) if(p.ContainsKey(k)) result[k]=p[k]?.DeepClone(); return result; }
    private static string Text(JsonNode? value)=>JsonRead.TryString(value,out var result)?result:throw new ArgumentException();
    private static bool Bool(JsonNode? n)=>n is JsonValue v && v.GetValueKind() is JsonValueKind.True or JsonValueKind.False;
    private static bool Flag(JsonNode? n)=>Bool(n)?n!.GetValue<bool>():throw new ArgumentException();
    private static bool Truthy(JsonNode? n) => n switch
    {
        null => false,
        JsonArray a => a.Count != 0,
        JsonObject o => o.Count != 0,
        JsonValue v when Bool(v) => Flag(v),
        JsonValue v when v.GetValueKind() == JsonValueKind.String => Text(v).Length != 0,
        JsonValue v when JsonRead.TryInteger(v,out var i) => i != 0,
        JsonValue v when v.GetValueKind() == JsonValueKind.Number => double.Parse(v.ToJsonString(),NumberStyles.Float,CultureInfo.InvariantCulture) != 0,
        _ => false
    };
    private static BigInteger Integer(JsonNode? n)=>JsonRead.TryInteger(n,out var result)?result:throw new ArgumentException();
    private static BigInteger? Id(JsonNode? n)=>n is null?null:Integer(n);
    private static BigInteger? Number(JsonNode? node)
    {
        if(Bool(node)) return Flag(node)?BigInteger.One:BigInteger.Zero;
        if(JsonRead.TryInteger(node,out var integer)) return integer;
        if(node is not JsonValue value || value.GetValueKind()!=JsonValueKind.Number) return null;
        return double.TryParse(node.ToJsonString(),NumberStyles.Float,CultureInfo.InvariantCulture,out var d) && double.IsFinite(d) && Math.Truncate(d)==d ? new BigInteger(d) : null;
    }
    private static bool NumberMatches(JsonNode? node,BigInteger? n)
    {
        if(n is null) return node is null;
        if(Bool(node)) return n==(Flag(node)?1:0);
        if(JsonRead.TryInteger(node,out var integer)) return n==integer;
        if(node is not JsonValue v || v.GetValueKind()!=JsonValueKind.Number) return false;
        return double.TryParse(node.ToJsonString(),NumberStyles.Float,CultureInfo.InvariantCulture,out double d) && double.IsFinite(d) && Math.Truncate(d)==d && new BigInteger(d)==n;
    }
    private static bool Equal(JsonNode? a,JsonNode? b)
    {
        if(a is null||b is null) return a is null&&b is null;
        if(Bool(a)||JsonRead.TryInteger(a,out _)) return NumberMatches(b,Bool(a)?(Flag(a)?BigInteger.One:BigInteger.Zero):Integer(a));
        if(Bool(b)||JsonRead.TryInteger(b,out _)) return Equal(b,a);
        if(a is JsonObject x && b is JsonObject y) return x.Count==y.Count && x.All(kv=>y.ContainsKey(kv.Key)&&Equal(kv.Value,y[kv.Key]));
        if(a is JsonArray p && b is JsonArray q) return p.Count==q.Count && p.Zip(q).All(pair=>Equal(pair.First,pair.Second));
        return JsonNode.DeepEquals(a,b);
    }
    private static HashSet<(string,string,int)> LoadLegacyIdentities()
    {
        using var stream=typeof(EventCatalog).Assembly.GetManifestResourceStream("dc-event-catalog.json") ?? throw new InvalidOperationException();
        var data=JsonNode.Parse(stream)!.AsObject();
        return data["events"]!.AsArray().Select(x=>(Text(x!["channel"]),UnicodeCaseFold.Fold(Text(x["provider"])),x["event_id"]!.GetValue<int>())).ToHashSet();
    }
}

