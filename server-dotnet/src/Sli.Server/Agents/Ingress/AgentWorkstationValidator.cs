using System.Numerics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Ingress;

/// <summary>Source workstation packet cursor, rotation, rate and evidence admission.</summary>
public static class AgentWorkstationValidator
{
    public static JsonArray Validate(Envelope envelope,JsonObject packet,WorkstationPolicy policy,Guid host,bool transportGap=false)
    {
        try { return ValidateCore(envelope,packet,policy,host,transportGap); }
        catch (Exception e) when (e is AgentException or ProtocolException or JsonException or ArgumentException or InvalidOperationException or NullReferenceException or FormatException or OverflowException)
        { throw new ProtocolException("agent_workstations_packet_invalid"); }
    }
    private static JsonArray ValidateCore(Envelope e,JsonObject packet,WorkstationPolicy p,Guid host,bool transportGap)
    {
        static void Require(bool value) { if (!value) throw new ArgumentException(); }
        var rows=AgentCollectionRows.ExtractEvents(packet); var header=packet["header"]!.AsObject(); string hostId=host.ToString("D");
        Require(e.SourceInstanceId==hostId && e.Generation==hostId && e.Channel=="workstations" && e.ModuleVersion is "1.0.0" or WorkstationsModule.ModuleVersion
            && e.PayloadContract==CollectionPacket.Contract && e.PolicyRevision==p.Revision && header["source"]!.GetValue<string>()==hostId);
        var channels=e.ModuleVersion=="1.0.0" ? WorkstationPolicy.Channels[..^1] : WorkstationPolicy.Channels;
        var before=State(e.CursorBefore,channels,true); var after=State(e.CursorAfter,channels,false);
        var enabled=Enumerable.Range(0,channels.Length).Where(p.ChannelEnabled).ToHashSet(); Require(enabled.Count>0);
        int next=(int)Integer(before["next"]), index=Enumerable.Range(0,channels.Length).Select(offset=>(next+offset)%channels.Length).First(enabled.Contains);
        int previous=(next+channels.Length-1)%channels.Length; var oldChannels=before["channels"]!.AsObject(); var newChannels=after["channels"]!.AsObject();
        if (header["channel"]!.GetValue<string>()==channels[previous] && enabled.Contains(previous) && oldChannels.ContainsKey(channels[previous])) index=previous;
        string channel=channels[index]; string generation=p.Value["channel_generations"]?[channel]?.GetValue<string>() ?? hostId;
        var old=oldChannels[channel] as JsonObject ?? new JsonObject { ["record_id"]=null,["bookmark"]="",["generation"]=generation };
        bool reset=old["generation"]!.GetValue<string>()!=generation;
        if (reset) old=new JsonObject { ["record_id"]=null,["bookmark"]="",["generation"]=generation };
        var progress=newChannels[channel]!.AsObject(); var start=Id(old["record_id"]); var last=Id(progress["record_id"]);
        var oldOthers=(JsonObject)oldChannels.DeepClone(); oldOthers.Remove(channel); var newOthers=(JsonObject)newChannels.DeepClone(); newOthers.Remove(channel);
        Require(header["channel"]!.GetValue<string>()==channel && header["generation"]!.GetValue<string>()==generation
            && progress["generation"]!.GetValue<string>()==generation && Integer(after["next"])==(index+1)%channels.Length
            && JsonNode.DeepEquals(oldOthers,newOthers)
            && PythonMetadataEquality.Equal(header["cursor"],new JsonObject { ["after_record_id"]=start is null ? null : JsonRead.Integer(start.Value),["last_record_id"]=last is null ? null : JsonRead.Integer(last.Value) }));
        var ids=rows.Select(r=>Id(r!["record_id"]) ?? throw new ArgumentException()).ToArray();
        Require(rows.Count<=p.BatchSize && ids.SequenceEqual(ids.Distinct().Order()) && ids.All(n=>(start is null || n>start) && last is not null && n<=last)
            && (start is null || last is not null && last>=start) && (last is null || progress["bookmark"]!.GetValue<string>().Length>0));
        var context=packet["context"]!["workstations"]!.AsObject();
        BigInteger filtered=Integer(context["filtered_count"]), dropped=Integer(context["dropped_count"]);
        string? readError=context["read_error"]?.GetValue<string>();
        if(context.ContainsKey("bookmark_recovered") && (context["bookmark_recovered"] is not JsonValue flag || flag.GetValueKind() is not (JsonValueKind.True or JsonValueKind.False))) throw new ArgumentException();
        bool recovered=context.ContainsKey("bookmark_recovered") && context["bookmark_recovered"]!.GetValue<bool>();
        var droppedById=context["dropped_by_event_id"]!.AsObject(); var rates=p.Value["rate_limits"]!.AsObject();
        Require(context["policy_revision"]!.GetValue<string>()==p.Revision && filtered>=0 && dropped>=0 && filtered+dropped+rows.Count<=p.BatchSize
            && droppedById.All(x=>rates.ContainsKey(x.Key) && JsonRead.TryInteger(x.Value,out var n) && n>=1)
            && droppedById.Aggregate(BigInteger.Zero,(sum,pair)=>sum+Integer(pair.Value))==dropped
            && context["channel_reset"]!.GetValue<bool>()==reset && PythonMetadataEquality.Equal(context["rate_window_seconds"],JsonValue.Create(p.RateWindowSeconds))
            && readError is null or "agent_workstations_read_failed" && (!recovered || !reset && readError is null && start is not null && old["bookmark"]!.GetValue<string>().Length>0)
            && e.FilteredCount==filtered && (readError is not null || reset || recovered ? e.LostCount is null : e.LostCount==dropped)
            && e.ContinuityState==(transportGap || dropped>0 || reset || readError is not null || recovered ? "gap" : filtered>0 ? "filtered" : "not_proven")
            && packet["continuity"]!["status"]!.GetValue<string>()=="not_proven"
            && (readError is null || rows.Count==0 && filtered==0 && dropped==0 && JsonNode.DeepEquals(progress,old)));
        AgentWorkstationEvidence.Validate(rows,context,p,channel,e.ModuleVersion,header["observed_at_utc"]!.GetValue<string>());
        if (e.ModuleVersion==WorkstationsModule.ModuleVersion)
        {
            var observed=Iso8601.ParseUtc(header["observed_at_utc"]!.GetValue<string>()); long seconds=(long)Math.Truncate((observed-DateTimeOffset.UnixEpoch).TotalSeconds);
            long window=(long)Math.Floor((double)seconds/p.RateWindowSeconds); var oldRate=before["rate"]!.AsObject(); var newRate=after["rate"]!.AsObject();
            BigInteger? oldWindow=oldRate["window"] is null ? null : Integer(oldRate["window"]); BigInteger expectedWindow=oldWindow is not null && oldWindow>window ? oldWindow.Value : window;
            BigInteger previousCount=oldWindow==expectedWindow && oldRate["counts"]!["4104"] is not null ? Integer(oldRate["counts"]!["4104"]) : 0;
            int admitted=channel==WorkstationPolicy.Channels[^1] ? rows.Count : 0; BigInteger limit=Integer(rates["4104"]);
            BigInteger actual=newRate["counts"]!["4104"] is null ? 0 : Integer(newRate["counts"]!["4104"]);
            Require(admitted<=BigInteger.Max(limit-previousCount,0) && Integer(newRate["window"])==expectedWindow && actual==previousCount+admitted);
        }
        return rows;
    }
    private static BigInteger Integer(JsonNode? n)=>JsonRead.TryInteger(n,out var value) ? value : throw new ArgumentException();
    private static BigInteger? Id(JsonNode? n)=>n is null ? null : Integer(n)>=0 ? Integer(n) : throw new ArgumentException();
    private static JsonObject State(Cursor cursor,string[] channels,bool initial)
    {
        if (cursor.Strategy!="bookmark") throw new ArgumentException();
        if (initial && cursor.Token=="") return new JsonObject { ["next"]=0,["channels"]=new JsonObject(),["rate"]=new JsonObject { ["window"]=null,["counts"]=new JsonObject() } };
        var state=JsonNode.Parse(cursor.Token)!.AsObject();
        if (!JsonRead.HasExactly(state,"next","channels","rate") || Integer(state["next"])<0 || Integer(state["next"])>=channels.Length
            || state["channels"] is not JsonObject saved || saved.Any(p=>!channels.Contains(p.Key)) || state["rate"] is not JsonObject rate
            || !JsonRead.HasExactly(rate,"window","counts") || rate["window"] is not null && !JsonRead.TryInteger(rate["window"],out _)
            || rate["counts"] is not JsonObject counts || counts.Count>32 || counts.Any(p=>p.Key.Length==0 || !p.Key.EnumerateRunes().All(System.Text.Rune.IsDigit) || !JsonRead.TryInteger(p.Value,out var n) || n<0)) throw new ArgumentException();
        foreach(var entry in saved)
        {
            if (entry.Value is not JsonObject progress || !JsonRead.HasExactly(progress,"record_id","bookmark","generation")
                || progress["record_id"] is not null && (!JsonRead.TryInteger(progress["record_id"],out var n) || n<0)
                || !JsonRead.TryString(progress["bookmark"],out _) || !JsonRead.TryString(progress["generation"],out _)) throw new ArgumentException();
        }
        return state;
    }
}
