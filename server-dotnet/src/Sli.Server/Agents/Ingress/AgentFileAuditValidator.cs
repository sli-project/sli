using System.Numerics;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Ingress;

public static class AgentFileAuditValidator
{
    internal static bool NativeEventsOnly(JsonObject packet) =>
        packet["records"] is JsonArray { Count: > 0 } records
        && records.All(row => row is JsonObject record && record["format"]?.ToString() == "event_xml");

    internal static bool PermissionsOnly(JsonObject packet)
    {
        if(packet["records"] is not JsonArray records) return false;
        if(records.Count==1 && records[0] is JsonObject lone && lone["format"]?.ToString()=="event_xml")
            return lone["payload"] is JsonObject gap && JsonRead.TryInteger(gap["event_id"],out var gapId) && gapId==1102
                && packet["context"] is JsonObject context && context["read_error"]?.ToString()=="file_audit_journal_gap";
        return records.All(row=>row is JsonObject record && record["format"]?.ToString()=="file_action"
            && record["payload"] is JsonObject action && JsonRead.TryInteger(action["event_id"],out var eventId)
            && eventId==4670 && action["operation"]?.ToString()=="permissions");
    }

    public static JsonArray Validate(Envelope e,JsonObject packet,FileAuditPolicy policy,Guid host,
        bool serverFileEventsOnly=false,bool transportGap=false)
    {
        try { return ValidateCore(e,packet,policy,host,serverFileEventsOnly,transportGap); }
        catch(ProtocolException error) when (error.Code==Receipt.FileAuditInvalid) { throw; }
        catch(Exception error) when (error is AgentException or ProtocolException or JsonException or ArgumentException or InvalidOperationException or NullReferenceException or FormatException or OverflowException)
        { throw new ProtocolException(Receipt.FileAuditInvalid,Receipt.FileAuditInvalidPayload); }
    }
    private static JsonArray ValidateCore(Envelope e,JsonObject packet,FileAuditPolicy p,Guid host,bool serverFileEventsOnly,bool transportGap)
    {
        static void Require(bool value) { if (!value) throw new ArgumentException(); }
        CollectionPacket.Validate(packet);
        var records=packet["records"]!.AsArray();
        bool actions=records.Any(r=>r?["format"]?.GetValue<string>()=="file_action");
        string hostId=host.ToString("D");
        string source=p.Value["source_name"]?.GetValue<string>() ?? hostId; var header=packet["header"]!.AsObject();
        if (!MatchesHost(e,host) || header["source"]!.GetValue<string>()!=source || header["generation"]!.GetValue<string>()!=e.Generation)
            throw new ProtocolException(Receipt.FileAuditInvalid,Receipt.FileAuditHostMismatch);
        var context=packet["context"]!.AsObject();
        if (e.PolicyRevision!=p.Revision || context["policy_revision"]?.GetValue<string>()!=p.Revision)
            throw new ProtocolException(Receipt.FileAuditInvalid,Receipt.FileAuditRevisionMismatch);
        if (serverFileEventsOnly && !actions && records.Any(record => JsonRead.TryInteger(record?["payload"]?["event_id"],out var id)
            && (id<0 || id>int.MaxValue || !p.IsServerFileEvent((int)id))))
            throw new ProtocolException(Receipt.FileAuditInvalid,Receipt.FileAuditWrongEvent);
        if (!actions && records.Any(record => record?["format"]?.GetValue<string>()=="event_xml"
            && !JsonNode.DeepEquals(record["payload"]?["computer_name"],header["source"])))
            throw new ProtocolException(Receipt.FileAuditInvalid,Receipt.FileAuditHostMismatch);
        var rows=actions ? ExtractActions(packet) : AgentCollectionRows.ExtractEvents(packet);
        Require(e.ModuleId==FileAuditPolicy.ModuleId && e.Channel=="Security" && e.ModuleVersion=="1.0.0" && e.PayloadContract==CollectionPacket.Contract
            && header["channel"]!.GetValue<string>()=="Security"
            && AgentAdDcUtc.Parse(header["observed_at_utc"]!.GetValue<string>())==AgentAdDcUtc.Parse(e.ObservedAtUtc)
            && CanonicalJson.Length(packet)<=Math.Min(p.Number("max_bytes"),44*1024));
        var before=State(e.CursorBefore,hostId); var after=State(e.CursorAfter,hostId);
        var start=Id(before["record_id"]); var last=Id(after["record_id"]);
        var objectKinds = context["object_kinds"] as JsonObject;
        string[] contextFields = ["policy_revision","filtered_count","lost_count","read_error"];
        Require(objectKinds is null ? JsonRead.HasExactly(context,contextFields)
            : !actions && !p.Workstation && objectKinds.Count > 0
                && JsonRead.HasExactly(context,[..contextFields,"object_kinds"]));
        Require(
            JsonRead.TryInteger(context["filtered_count"],out var filteredValue) && filteredValue>=0 && filteredValue<=long.MaxValue);
        long filtered=(long)Integer(context["filtered_count"]); long? lost=context["lost_count"] is null ? null : (long)Integer(context["lost_count"]);
        string? error=context["read_error"]?.GetValue<string>(); bool gap=error=="file_audit_journal_gap";
        Require(lost is null || lost>=0);
        string? bound=after["since_utc"]?.GetValue<string>(); string? oldBound=before["since_utc"]?.GetValue<string>();
        if (bound!=oldBound)
        {
            var depth=p.Value["initial_read_hours"];
            Require(oldBound is null && start is null && bound is not null && depth is not null && JsonRead.TryInteger(depth,out var hours)
                && hours>=0 && hours<=876000 && AgentAdDcUtc.Parse(bound)==AgentAdDcUtc.Parse(e.ObservedAtUtc).AddHours(-(double)hours));
        }
        var comparableBefore=(JsonObject)before.DeepClone(); comparableBefore.Remove("since_utc");
        var comparableAfter=(JsonObject)after.DeepClone(); comparableAfter.Remove("since_utc");
        Require(error is null or "file_audit_read_failed" or "file_audit_journal_gap"
            && (lost is null)==(error is not null) && rows.Count+filtered+(lost ?? 0)<=Math.Min(p.Number("max_events"),256)
            && e.FilteredCount==filtered && e.LostCount==lost && e.ContinuityState==(transportGap || error is not null || lost>0 ? "gap" : filtered>0 ? "filtered" : "not_proven")
            && JsonNode.DeepEquals(packet["continuity"],new JsonObject { ["status"]="not_proven" })
            && PythonMetadataEquality.Equal(header["cursor"],new JsonObject { ["after_record_id"]=start is null ? null : JsonRead.Integer(start.Value), ["last_record_id"]=last is null ? null : JsonRead.Integer(last.Value) }));
        Require(after["generation"]!.GetValue<string>()==e.Generation
            && (before["generation"]!.GetValue<string>()==e.Generation || gap && start is null)
            && (!gap || rows.Count!=0 || start is null && last is null && e.Generation!=hostId && before["bookmark"]!.GetValue<string>()=="" && after["bookmark"]!.GetValue<string>()=="")
            && (!gap || rows.Count==0 || rows.Any(r=>JsonRead.TryInteger(r!["event_id"],out var n) && n==1102)));
        var ids=rows.Select(r=>Id(r!["record_id"]) ?? throw new ArgumentException()).ToArray();
        Require(ids.All(n=>n>0) && ids.SequenceEqual(actions ? ids.Order() : ids.Distinct().Order()) && ids.All(n=>(start is null || n>start) && last is not null && n<=last)
            && (start is null || last is not null && last>=start)
            && (filtered!=0 || lost!=0 || gap || last==(ids.Length>0 ? ids[^1] : start))
            && (filtered==0 && !(lost>0) || last is not null && (start is null || last>start))
            && (error!="file_audit_read_failed" || rows.Count==0 && filtered==0 && JsonNode.DeepEquals(comparableAfter,comparableBefore))
            && (rows.Count!=0 || filtered!=0 || lost!=0 || gap || JsonNode.DeepEquals(comparableAfter,comparableBefore)));
        int matchedKinds = 0;
        foreach(var item in rows)
        {
            var row=item!.AsObject();
            if (bound is not null && start is null) Require(AgentAdDcUtc.Parse(row["time_created"]!.GetValue<string>())>=AgentAdDcUtc.Parse(bound));
            if(actions) AgentFileAuditAction.Validate(row,p,source);
            else
            {
                string? objectKind = null;
                if (objectKinds is not null && objectKinds.TryGetPropertyValue(row["record_id"]!.ToJsonString(), out var value))
                {
                    Require(JsonRead.TryString(value,out var kind) && kind is "file" or "directory");
                    objectKind = kind;
                    matchedKinds++;
                }
                AgentFileAuditEvents.Validate(row,p,source,objectKind,serverFileEventsOnly);
            }
        }
        Require(matchedKinds == (objectKinds?.Count ?? 0));
        if(actions) Require(rows.OfType<JsonObject>().Select(r=>new {
            Scope=r["collection_scope_id"]!.GetValue<string>(),Path=r["path"]!.GetValue<string>(),
            Operation=r["operation"]!.GetValue<string>(),Actor=r["subject_user_sid"]!.GetValue<string>(),
            Minute=AgentAdDcUtc.Parse(r["minute_utc"]!.GetValue<string>())
        }).Distinct().Count()==rows.Count);
        return rows;
    }
    private static JsonArray ExtractActions(JsonObject packet)
    {
        var rows=new JsonArray();
        foreach(var item in packet["records"]!.AsArray()) {
            var record=item!.AsObject(); var row=record["payload"]!.AsObject();
            if(record["format"]!.GetValue<string>()!="file_action" || !JsonNode.DeepEquals(record["record_id"],row["record_id"]))
                throw new ArgumentException();
            rows.Add(row.DeepClone());
        }
        return rows;
    }
    private static BigInteger Integer(JsonNode? n) => JsonRead.TryInteger(n,out var number) ? number : throw new ArgumentException();
    private static BigInteger? Id(JsonNode? n) => n is null ? null : Integer(n)>0 ? Integer(n) : throw new ArgumentException();
    private static bool ValidGeneration(string value,string host) => value==host || value.StartsWith(host+":",StringComparison.Ordinal)
        && Guid.TryParseExact(value[(host.Length+1)..],"D",out var guid) && guid.ToString("D")==value[(host.Length+1)..];
    internal static bool MatchesHost(Envelope envelope,Guid host) =>
        envelope.SourceInstanceId==host.ToString("D") && ValidGeneration(envelope.Generation,host.ToString("D"));

    internal static bool CanAdvanceRejected(Envelope envelope,Guid host)
    {
        if (!MatchesHost(envelope,host) || envelope.Channel!="Security" || envelope.ModuleVersion!="1.0.0"
            || envelope.PayloadContract!=CollectionPacket.Contract) return false;
        try
        {
            string hostId=host.ToString("D");
            var before=State(envelope.CursorBefore,hostId);
            var after=State(envelope.CursorAfter,hostId);
            var start=Id(before["record_id"]); var last=Id(after["record_id"]);
            return after["generation"]!.GetValue<string>()==envelope.Generation
                && (before["generation"]!.GetValue<string>()==envelope.Generation || envelope.CursorBefore.Token=="")
                && (start is null || last is not null && last>=start);
        }
        catch (Exception error) when (error is JsonException or ArgumentException or InvalidOperationException or NullReferenceException or FormatException)
        { return false; }
    }

    private static JsonObject State(Cursor cursor,string host)
    {
        if (cursor.Strategy!="bookmark") throw new ArgumentException();
        if (cursor.Token=="") return new JsonObject { ["record_id"]=null,["bookmark"]="",["generation"]=host };
        var value=JsonNode.Parse(cursor.Token)!.AsObject();
        if (value.Any(p=>p.Key is not ("record_id" or "bookmark" or "generation" or "anchor_sha256" or "since_utc"))
            || !value.ContainsKey("record_id") || !value.ContainsKey("bookmark") || !value.ContainsKey("generation")) throw new ArgumentException();
        var id=Id(value["record_id"]); string bookmark=value["bookmark"]!.GetValue<string>();
        if (!ValidGeneration(value["generation"]!.GetValue<string>(),host) || JsonRead.CodePoints(bookmark)>3000 || (id is null)!=(bookmark.Length==0)) throw new ArgumentException();
        if (value.ContainsKey("anchor_sha256") && !Regex.IsMatch(value["anchor_sha256"]!.GetValue<string>(),"\\A[a-f0-9]{64}\\z")) throw new ArgumentException();
        if (value.ContainsKey("since_utc")) _=AgentAdDcUtc.Parse(value["since_utc"]!.GetValue<string>());
        return value;
    }
}
