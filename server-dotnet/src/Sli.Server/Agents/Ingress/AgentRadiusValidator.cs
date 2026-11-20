using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Ingress;

/// <summary>Source NPS accounting admission, including opaque recovery provenance.</summary>
public static class AgentRadiusValidator
{
    public static JsonArray Validate(Envelope envelope,JsonObject packet,NpsPolicy policy,Guid host)
    {
        try { return ValidateCore(envelope,packet,policy,host); }
        catch (Exception e) when (e is AgentException or ProtocolException or JsonException or ArgumentException or InvalidOperationException or NullReferenceException or FormatException or OverflowException)
        { throw new ProtocolException("agent_nps_packet_invalid"); }
    }
    private static JsonArray ValidateCore(Envelope e,JsonObject packet,NpsPolicy policy,Guid host)
    {
        static void Require(bool value) { if (!value) throw new ArgumentException(); }
        CollectionPacket.Validate(packet); var header=packet["header"]!.AsObject();
        Require(policy.Active && e.SourceInstanceId==policy.SourceId && e.Generation==host.ToString("D") && e.ModuleVersion=="1.0.0"
            && e.PolicyRevision==policy.Revision && e.PayloadContract==CollectionPacket.Contract
            && AgentAdDcUtc.Parse(header["observed_at_utc"]!.GetValue<string>())==AgentAdDcUtc.Parse(e.ObservedAtUtc)
            && CanonicalJson.Length(packet)<=NpsPolicy.MaxPayloadBytes && e.CursorBefore.Strategy=="file_offset" && e.CursorAfter.Strategy=="file_offset");
        var previous=e.CursorBefore.Token.Length==0 ? policy.Value["initial_cursor"]!.AsObject() : JsonNode.Parse(e.CursorBefore.Token)!.AsObject();
        var after=JsonNode.Parse(e.CursorAfter.Token)!.AsObject(); var cursor=RadiusCursor.Parse(previous); var updated=RadiusCursor.Parse(after);
        var initial=RadiusCursor.Parse(policy.Value["initial_cursor"]); var bounds=header["cursor"]!.AsObject();
        Require(JsonRead.TryInteger(bounds["start_offset"],out var startValue) && startValue>=0 && startValue<=long.MaxValue
            && JsonRead.TryInteger(bounds["end_offset"],out var endValue) && endValue>=0 && endValue<=long.MaxValue);
        var start=(long)JsonReadInteger(bounds["start_offset"]); var end=(long)JsonReadInteger(bounds["end_offset"]);
        bool rotated=header["generation"]!.GetValue<string>()!=cursor.FileGeneration;
        var lines=new List<string>();
        foreach (var item in packet["records"]!.AsArray())
        {
            Require(item!["format"]!.GetValue<string>()=="accounting_line");
            var line=item["payload"]!.GetValue<string>(); RadiusAccountingRecord.Validate(line); lines.Add(line);
        }
        var context=packet["context"]!.AsObject(); bool progress=context.ContainsKey("empty_progress_v1");
        if (progress)
        {
            var proof=context["empty_progress_v1"]!.AsObject();
            Require(lines.Count==0 && proof.Count==2 && proof.ContainsKey("skipped_bytes") && proof.ContainsKey("physical_lines")
                && JsonRead.TryInteger(proof["skipped_bytes"],out var skipped) && skipped>=0 && skipped<=4*1024*1024
                && JsonRead.TryInteger(proof["physical_lines"],out var physical) && physical>=0 && physical<=policy.BatchSize && physical<=skipped
                && skipped==end-start && (skipped!=0)==(physical!=0) && (skipped!=0 || rotated));
        }
        var expected=lines.Count>0 || progress ? cursor with { FileGeneration=header["generation"]!.GetValue<string>(), ByteOffset=end,
            LastRecordSha256=lines.Count>0 ? Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(lines[^1]))) : cursor.LastRecordSha256 } : cursor;
        var expectedValue=expected.ToJson();
        if (lines.Count>0) { if (previous.ContainsKey("exact_boundary_recovery")) expectedValue["exact_boundary_recovery"]=true; }
        else if (e.CursorBefore.Token.Length==0 && cursor.ByteOffset==0 || progress && rotated) expectedValue["exact_boundary_recovery"]=false;
        else if (previous.ContainsKey("exact_boundary_recovery")) expectedValue["exact_boundary_recovery"]=previous["exact_boundary_recovery"]!.DeepClone();
        if (lines.Count==0 && !progress && !previous.ContainsKey("exact_boundary_recovery") && !after.ContainsKey("exact_boundary_recovery")) expectedValue.Remove("exact_boundary_recovery");
        Require(cursor.SourceId==initial.SourceId && cursor.StreamId==initial.StreamId && cursor.TransportBinding==initial.TransportBinding
            && header["source"]!.GetValue<string>()==cursor.SourceId && header["channel"]!.GetValue<string>()==cursor.StreamId
            && lines.Count<=policy.BatchSize && e.Channel==cursor.StreamId && PythonMetadataEquality.Equal(bounds["before"],cursor.ToJson())
            && start==(rotated ? 0 : cursor.ByteOffset) && end>=start && (lines.Count==0 || end>start)
            && packet["continuity"]!["previous_generation_eof"]!.GetValue<bool>()==rotated
            && packet["continuity"]!["status"]!.GetValue<string>()=="complete" && updated==expected && JsonNode.DeepEquals(after,expectedValue)
            && context["source_timezone_id"]!.GetValue<string>()==policy.Text("source_timezone_id")
            && JsonNode.DeepEquals(context["source_utc_offset_minutes"],policy.Value["source_utc_offset_minutes"])
            && e.ContinuityState=="not_proven" && e.FilteredCount==0 && e.LostCount==0);
        return new JsonArray();
    }
    private static System.Numerics.BigInteger JsonReadInteger(JsonNode? value) => JsonRead.TryInteger(value,out var number) ? number : throw new ArgumentException();
}
