using System.Numerics;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Ingress;

/// <summary>Admission checks from server.sli.agents.nps_ingest for the Security event stream.</summary>
public static class AgentNpsValidator
{
    public static JsonArray Validate(Envelope envelope, JsonObject packet, NpsPolicy policy, Guid host)
    {
        try { return ValidateCore(envelope,packet,policy,host); }
        catch (Exception e) when (e is AgentException or ProtocolException or JsonException or ArgumentException or InvalidOperationException or NullReferenceException or FormatException or OverflowException)
        { throw new ProtocolException("agent_nps_packet_invalid"); }
    }

    private static JsonArray ValidateCore(Envelope e, JsonObject packet, NpsPolicy policy, Guid host)
    {
        static void Require(bool condition) { if (!condition) throw new ArgumentException(); }
        CollectionPacket.Validate(packet);
        var header=packet["header"]!.AsObject();
        Require(policy.Active && e.SourceInstanceId==policy.SourceId && e.Generation==host.ToString("D")
            && e.ModuleVersion=="1.0.0" && e.PolicyRevision==policy.Revision && e.PayloadContract==CollectionPacket.Contract
            && AgentAdDcUtc.Parse(header["observed_at_utc"]!.GetValue<string>())==AgentAdDcUtc.Parse(e.ObservedAtUtc)
            && CanonicalJson.Length(packet)<=NpsPolicy.MaxPayloadBytes);
        var rows=AgentCollectionRows.ExtractEvents(packet); var generation=policy.Text("event_generation");
        var previous=Bookmark(e.CursorBefore,generation); bool reset=previous["generation"]!.GetValue<string>()!=generation;
        if (reset) previous=Bookmark(new Cursor("bookmark",""),generation);
        var after=Bookmark(e.CursorAfter,generation);
        BigInteger? start=Id(previous["record_id"]), last=Id(after["record_id"]);
        var ids=rows.Select(r => Id(r!["record_id"]) ?? throw new ArgumentException()).ToArray();
        var expectedContext=new JsonObject { ["normalizer"]="windows-nps-radius-v1", ["filtered_count"]=e.FilteredCount, ["channel_reset"]=reset };
        var expectedAfter=(JsonObject)after.DeepClone(); var continuity=new JsonObject { ["status"]="not_proven" };
        var context=packet["context"]!.AsObject();
        if (context.ContainsKey("tail_drained"))
        {
            Require(context["tail_drained"] is JsonValue v && v.TryGetValue<bool>(out _));
            bool drained=context["tail_drained"]!.GetValue<bool>(); expectedContext["tail_drained"]=drained;
            bool contiguous=start is not null && last is not null && last-start==ids.Length+e.FilteredCount;
            expectedAfter.Remove("coverage_from_utc");
            var observed=AgentAdDcUtc.Parse(header["observed_at_utc"]!.GetValue<string>());
            string? origin=contiguous && !reset ? previous["coverage_from_utc"]?.GetValue<string>() : null;
            if (origin is not null && AgentAdDcUtc.Parse(origin)>observed) origin=null;
            if (drained && after["anchor_sha256"] is not null)
            {
                if (origin is not null && AgentAdDcUtc.Parse(origin)<observed)
                    continuity=new JsonObject { ["status"]="complete", ["from_utc"]=origin, ["to_utc"]=Iso8601.Format(observed) };
                expectedAfter["coverage_from_utc"]=origin ?? Iso8601.Format(observed);
            }
            else if (origin is not null) expectedAfter["coverage_from_utc"]=origin;
        }
        else Require(!after.ContainsKey("coverage_from_utc") && !previous.ContainsKey("coverage_from_utc"));
        Require(header["source"]!.GetValue<string>()==policy.Text("source_name") && header["channel"]!.GetValue<string>()=="Security"
            && e.Channel=="Security" && header["generation"]!.GetValue<string>()==generation && after["generation"]!.GetValue<string>()==generation
            && PythonMetadataEquality.Equal(header["cursor"],new JsonObject { ["after_record_id"]=start is null ? null : JsonRead.Integer(start.Value), ["last_record_id"]=last is null ? null : JsonRead.Integer(last.Value) })
            && PythonMetadataEquality.Equal(context,expectedContext) && JsonNode.DeepEquals(after,expectedAfter) && JsonNode.DeepEquals(packet["continuity"],continuity)
            && ids.Length+e.FilteredCount<=policy.BatchSize && ids.All(n=>n>0) && ids.SequenceEqual(ids.Distinct().Order())
            && ids.All(n=>(start is null || n>start) && last is not null && n<=last)
            && (start is null || last is not null && last>=start)
            && (e.FilteredCount!=0 || last==(ids.Length>0 ? ids[^1] : start))
            && (e.FilteredCount==0 || last is not null && (start is null || last>start))
            && (ids.Length!=0 || e.FilteredCount!=0 || new[] {"record_id","bookmark","generation","anchor_sha256"}.All(k=>JsonNode.DeepEquals(after[k],previous[k])))
            && e.LostCount==(reset ? null : 0) && e.ContinuityState==(reset ? "gap" : e.FilteredCount>0 ? "filtered" : "not_proven"));
        foreach (var node in rows)
        {
            var row=node!.AsObject(); var xml=row["xml"]!.GetValue<string>();
            Require(JsonRead.TryInteger(row["event_id"],out var eventId) && (eventId==6272 || eventId==6273)
                && row["provider_name"]!.GetValue<string>()=="Microsoft-Windows-Security-Auditing"
                && EventXml.NativeChannel(EventXml.ParseBounded(xml))=="Security" && NpsEventXml.Mask(xml)==xml
                && JsonNode.DeepEquals(EventXml.Parse(xml,policy.Text("source_name"),policy.Text("connect_address"),"Security"),row));
        }
        return rows;
    }

    private static BigInteger? Id(JsonNode? n) => n is null ? null : JsonRead.TryInteger(n,out var number) && number>0 ? number : throw new ArgumentException();

    private static JsonObject Bookmark(Cursor cursor,string generation)
    {
        if (cursor.Strategy!="bookmark") throw new ArgumentException();
        if (cursor.Token=="") return new JsonObject { ["record_id"]=null, ["bookmark"]="", ["generation"]=generation };
        var state=JsonNode.Parse(cursor.Token)!.AsObject();
        if (state.Any(p=>p.Key is not ("record_id" or "bookmark" or "generation" or "coverage_from_utc" or "anchor_sha256"))
            || !state.ContainsKey("record_id") || !state.ContainsKey("bookmark") || !state.ContainsKey("generation")) throw new ArgumentException();
        var id=Id(state["record_id"]); string bookmark=state["bookmark"]!.GetValue<string>(); string gen=state["generation"]!.GetValue<string>();
        if (JsonRead.CodePoints(bookmark)>2048 || (bookmark.Length>0)!=(id is not null) || gen.Length==0 || JsonRead.CodePoints(gen)>128) throw new ArgumentException();
        if (state.ContainsKey("anchor_sha256") && (id is null || !Regex.IsMatch(state["anchor_sha256"]!.GetValue<string>(),"\\A[a-f0-9]{64}\\z"))) throw new ArgumentException();
        if (state.ContainsKey("coverage_from_utc")) { _=AgentAdDcUtc.Parse(state["coverage_from_utc"]!.GetValue<string>()); if (!state.ContainsKey("anchor_sha256")) throw new ArgumentException(); }
        return state;
    }
}
