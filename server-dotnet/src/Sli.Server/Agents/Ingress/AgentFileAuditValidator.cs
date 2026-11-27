using System.Numerics;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Ingress;

public static class AgentFileAuditValidator
{
    private const string InvalidCollection = "invalid_collection_packet";
    private const string InvalidHeader = "invalid_packet_header";
    private const string InvalidObservation = "invalid_observation_time";
    private const string InvalidLimits = "packet_limit_exceeded";
    private const string InvalidContext = "invalid_file_audit_context";
    private const string InvalidContinuity = "invalid_continuity";
    private const string InvalidCursor = "invalid_bookmark_cursor";
    private const string InvalidEvent = "invalid_file_audit_event";
    internal const string InvalidPolicy = "invalid_file_audit_policy";

    internal static bool IsPayloadDetail(string? reason) => reason is InvalidCollection or InvalidHeader or InvalidObservation
        or InvalidLimits or InvalidContext or InvalidContinuity or InvalidCursor or InvalidEvent or InvalidPolicy;

    internal static bool IsRejectionReason(string? reason) =>
        Receipt.IsFileAuditRejectionReason(reason) || IsPayloadDetail(reason);

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
        catch(Exception error) when (InvalidData(error))
        { throw Invalid(Receipt.FileAuditInvalidPayload); }
    }
    private static bool InvalidData(Exception error) => error is AgentException or ProtocolException or JsonException
        or ArgumentException or InvalidOperationException or NullReferenceException or FormatException or OverflowException;

    private static ProtocolException Invalid(string reason) => new(Receipt.FileAuditInvalid, reason);
    private static void Require(bool value, string reason) { if (!value) throw Invalid(reason); }

    private static JsonArray ValidateCore(Envelope e,JsonObject packet,FileAuditPolicy p,Guid host,bool serverFileEventsOnly,bool transportGap)
    {
        try { CollectionPacket.Validate(packet); }
        catch (ProtocolException) { throw Invalid(InvalidCollection); }
        var records=packet["records"]!.AsArray();
        bool actions=records.Any(r=>r?["format"]?.GetValue<string>()=="file_action");
        string hostId=host.ToString("D");
        string source=p.Value["source_name"]?.GetValue<string>() ?? hostId; var header=packet["header"]!.AsObject();
        if (!MatchesHost(e,host) || header["source"]!.GetValue<string>()!=source
            || !JsonRead.TryString(header["generation"],out var generation) || generation!=e.Generation)
            throw new ProtocolException(Receipt.FileAuditInvalid,Receipt.FileAuditHostMismatch);
        var context=packet["context"]!.AsObject();
        if (e.PolicyRevision!=p.Revision || !JsonRead.TryString(context["policy_revision"],out var revision) || revision!=p.Revision)
            throw new ProtocolException(Receipt.FileAuditInvalid,Receipt.FileAuditRevisionMismatch);
        if (serverFileEventsOnly && !actions && records.Any(record => JsonRead.TryInteger(record?["payload"]?["event_id"],out var id)
            && (id<0 || id>int.MaxValue || !p.IsServerFileEvent((int)id))))
            throw new ProtocolException(Receipt.FileAuditInvalid,Receipt.FileAuditWrongEvent);
        if (!actions && records.Any(record => record?["format"]?.GetValue<string>()=="event_xml"
            && !JsonNode.DeepEquals(record["payload"]?["computer_name"],header["source"])))
            throw new ProtocolException(Receipt.FileAuditInvalid,Receipt.FileAuditHostMismatch);
        JsonArray rows;
        try { rows=actions ? ExtractActions(packet) : AgentCollectionRows.ExtractEvents(packet); }
        catch (Exception error) when (InvalidData(error)) { throw Invalid(Receipt.FileAuditInvalidFormat); }
        Require(e.ModuleId==FileAuditPolicy.ModuleId && e.Channel=="Security" && e.ModuleVersion=="1.0.0" && e.PayloadContract==CollectionPacket.Contract
            && header["channel"]!.GetValue<string>()=="Security",InvalidHeader);
        // Older agents took another clock reading when signing. Both times are
        // authenticated, and the collection start must fit the capture budget.
        var observed=AgentAdDcUtc.Parse(header["observed_at_utc"]!.GetValue<string>());
        var signingDelay=AgentAdDcUtc.Parse(e.ObservedAtUtc)-observed;
        Require(signingDelay>=TimeSpan.Zero && signingDelay<=TimeSpan.FromSeconds(p.Number("wall_seconds")),InvalidObservation);
        Require(CanonicalJson.Length(packet)<=Math.Min(p.Number("max_bytes"),44*1024),InvalidLimits);
        JsonObject before, after;
        try { before=State(e.CursorBefore,hostId); after=State(e.CursorAfter,hostId); }
        catch (Exception error) when (InvalidData(error)) { throw Invalid(InvalidCursor); }
        var start=Id(before["record_id"]); var last=Id(after["record_id"]);
        var objectKinds = context["object_kinds"] as JsonObject;
        string[] contextFields = ["policy_revision","filtered_count","lost_count","read_error"];
        Require(objectKinds is null ? JsonRead.HasExactly(context,contextFields)
            : !actions && !p.Workstation && objectKinds.Count > 0
                && JsonRead.HasExactly(context,[..contextFields,"object_kinds"]),InvalidContext);
        Require(JsonRead.TryInteger(context["filtered_count"],out var filteredValue) && filteredValue>=0 && filteredValue<=long.MaxValue,InvalidContext);
        Require(context["lost_count"] is null || JsonRead.TryInteger(context["lost_count"],out var lostValue) && lostValue>=0 && lostValue<=long.MaxValue,InvalidContext);
        Require(context["read_error"] is null || JsonRead.TryString(context["read_error"],out _),InvalidContext);
        long filtered=(long)filteredValue; long? lost=context["lost_count"] is null ? null : (long)Integer(context["lost_count"]);
        string? readError=context["read_error"]?.GetValue<string>(); bool gap=readError=="file_audit_journal_gap";
        string? bound=after["since_utc"]?.GetValue<string>(); string? oldBound=before["since_utc"]?.GetValue<string>();
        if (bound!=oldBound)
        {
            var depth=p.Value["initial_read_hours"];
            Require(oldBound is null && start is null && bound is not null && depth is not null && JsonRead.TryInteger(depth,out var hours)
                && hours>=0 && hours<=876000 && observed-AgentAdDcUtc.Parse(bound)==TimeSpan.FromHours((double)hours),InvalidCursor);
        }
        var comparableBefore=(JsonObject)before.DeepClone(); comparableBefore.Remove("since_utc");
        var comparableAfter=(JsonObject)after.DeepClone(); comparableAfter.Remove("since_utc");
        Require(rows.Count+filteredValue+(lost ?? 0)<=Math.Min(p.Number("max_events"),256),InvalidLimits);
        Require(readError is null or "file_audit_read_failed" or "file_audit_journal_gap"
            && (lost is null)==(readError is not null)
            && e.FilteredCount==filtered && e.LostCount==lost && e.ContinuityState==(transportGap || readError is not null || lost>0 ? "gap" : filtered>0 ? "filtered" : "not_proven")
            && JsonNode.DeepEquals(packet["continuity"],new JsonObject { ["status"]="not_proven" }),InvalidContinuity);
        Require(PythonMetadataEquality.Equal(header["cursor"],new JsonObject { ["after_record_id"]=start is null ? null : JsonRead.Integer(start.Value), ["last_record_id"]=last is null ? null : JsonRead.Integer(last.Value) }),InvalidCursor);
        Require(after["generation"]!.GetValue<string>()==e.Generation
            && (before["generation"]!.GetValue<string>()==e.Generation || gap && start is null)
            && (!gap || rows.Count!=0 || start is null && last is null && e.Generation!=hostId && before["bookmark"]!.GetValue<string>()=="" && after["bookmark"]!.GetValue<string>()=="")
            && (!gap || rows.Count==0 || rows.Any(r=>JsonRead.TryInteger(r!["event_id"],out var n) && n==1102)),InvalidCursor);
        Require(rows.All(r=>JsonRead.TryInteger(r!["record_id"],out var id) && id>0),Receipt.FileAuditInvalidFormat);
        var ids=rows.Select(r=>Integer(r!["record_id"])).ToArray();
        Require(ids.All(n=>n>0) && ids.SequenceEqual(actions ? ids.Order() : ids.Distinct().Order()) && ids.All(n=>(start is null || n>start) && last is not null && n<=last)
            && (start is null || last is not null && last>=start)
            && (filtered!=0 || lost!=0 || gap || last==(ids.Length>0 ? ids[^1] : start))
            && (filtered==0 && !(lost>0) || last is not null && (start is null || last>start))
            && (readError!="file_audit_read_failed" || rows.Count==0 && filtered==0 && JsonNode.DeepEquals(comparableAfter,comparableBefore))
            && (rows.Count!=0 || filtered!=0 || lost!=0 || gap || JsonNode.DeepEquals(comparableAfter,comparableBefore)),InvalidCursor);
        int matchedKinds = 0;
        foreach(var item in rows)
        {
            var row=item!.AsObject();
            try
            {
                string? objectKind = null;
                if (objectKinds is not null && objectKinds.TryGetPropertyValue(row["record_id"]!.ToJsonString(), out var value))
                {
                    Require(JsonRead.TryString(value,out var kind) && kind is "file" or "directory",InvalidContext);
                    objectKind = kind;
                    matchedKinds++;
                }
                if (bound is not null && start is null)
                    Require(AgentAdDcUtc.Parse(row["time_created"]!.GetValue<string>())>=AgentAdDcUtc.Parse(bound),InvalidEvent);
                if(actions) AgentFileAuditAction.Validate(row,p,source);
                else AgentFileAuditEvents.Validate(row,p,source,objectKind,serverFileEventsOnly);
            }
            catch (Exception error) when (InvalidData(error) && error is not ProtocolException { Code: Receipt.FileAuditInvalid })
            { throw Invalid(InvalidEvent); }
        }
        Require(matchedKinds == (objectKinds?.Count ?? 0),InvalidContext);
        if(actions) Require(rows.OfType<JsonObject>().Select(r=>new {
            Scope=r["collection_scope_id"]!.GetValue<string>(),Path=r["path"]!.GetValue<string>(),
            Operation=r["operation"]!.GetValue<string>(),Actor=r["subject_user_sid"]!.GetValue<string>(),
            Minute=AgentAdDcUtc.Parse(r["minute_utc"]!.GetValue<string>())
        }).Distinct().Count()==rows.Count,InvalidEvent);
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
