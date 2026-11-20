using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml;
using System.Xml.Linq;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Semantic.Password;
using Sli.Server.Storage.Direct;

namespace Sli.Server.Semantic.Detections;

public sealed class DetectionFailure(string code) : Exception(code)
{
    // These enums are the entire diagnostic vocabulary: never store XML names or values.
    public enum NativeField { Event, System, EventID, TimeCreated, SystemTime, event_id, occurred_at_utc, source_xml, EventData, Data, Name,
        TargetUserName, TargetDomainName, TargetSid, SubjectUserName, SubjectDomainName, SubjectUserSid,
        ServiceName, TicketEncryptionType, Status, IpAddress, WorkstationName, ProcessName, CommandLine, ScriptBlockText, Computer }
    public enum DifferenceKind { missing, type, value }
    internal NativeField? Field { get; init; }
    internal DifferenceKind? Difference { get; init; }
}

public sealed record DetectionRef(PasswordScope Scope,string Kind,string NativeId,string Sha256)
{
    public JsonObject Document=>new(){["scope"]=Scope.Document,["storage_kind"]=Kind,["native_id"]=NativeId,["sha256"]=Sha256};
    public JsonArray Params=>new(Scope.InstallationId,Scope.PluginId,Scope.SourceInstanceId,Scope.SourceGeneration,Scope.CollectionScopeId,Kind,NativeId,Sha256);
    internal string SortKey=>string.Join('\0',Params.Select(n=>n!.GetValue<string>()));
    public static DetectionRef Read(JsonNode? n)=>new(PasswordScope.Read(n!["scope"]),D.Text(n["storage_kind"]),D.Text(n["native_id"]),D.Text(n["sha256"]));
    internal void Validate()
    {
        if(!Guid.TryParseExact(Scope.InstallationId,"D",out var id)||id.ToString()!=Scope.InstallationId||Scope.SourceInstanceId.Length is <1 or >256||Scope.SourceGeneration.Length is <1 or >512||Scope.CollectionScopeId.Length>256||!PasswordJson.Hex(Sha256)||NativeId.Length is <1 or >512||Kind is not ("core_event" or "ad_directory_observation" or "workstation_observation" or "file_audit_observation"))throw new DetectionFailure("detection_ref_invalid");
    }
}

public sealed record DetectionRow(DetectionRef Ref,DateTimeOffset At,int EventId=0,string Host="",JsonObject? Fields=null,JsonObject? Record=null)
{
    public string Channel { get; init; } = "";
    public string Provider { get; init; } = "";
    public string Get(string key)=>D.Text(Fields?[key]);
}

internal static class D
{
    internal static string Text(JsonNode? n)=>n is JsonValue v&&v.TryGetValue<string>(out var s)?s:"";
    internal static string Hash(JsonNode? n)=>PasswordJson.Hash(n);
    internal static JsonArray Array<T>(IEnumerable<T> items,Func<T,JsonNode?> map)=>PasswordJson.Array(items,map);
    internal static string Stamp(DateTimeOffset at)=>PasswordJson.Stamp(at);
    internal static DateTimeOffset Time(JsonNode? n)=>PasswordJson.Time(n);
    internal static long? Number(JsonNode? n)
    {
        string s=n is JsonValue? n.ToString().Trim():"";
        if(s.StartsWith("0x",StringComparison.OrdinalIgnoreCase))return long.TryParse(s.AsSpan(2),NumberStyles.AllowHexSpecifier,CultureInfo.InvariantCulture,out var h)?h:null;
        return long.TryParse(s,NumberStyles.Integer,CultureInfo.InvariantCulture,out var x)?x:null;
    }
    internal static void Require(bool condition,string code){if(!condition)throw new DetectionFailure(code);}
}

public static class DetectionNative
{
    // The SQL boundary still calls the transport column source_xml for rollback
    // compatibility. New readers return this explicit compact JSON contract;
    // no XML is reconstructed and no host-provided attestation is accepted.
    internal static JsonObject ShortDocument(PasswordScope scope, long id, int kind, DateTimeOffset at, string payload)
    {
        var doc = JsonNode.Parse(payload)!.AsObject();
        D.Require(D.Text(doc["version"]) == "sli.short-event.1" &&
            JsonNode.DeepEquals(doc["scope"], scope.Document) && doc["source_event_id"]!.GetValue<long>() == id &&
            doc["event_id"]!.GetValue<int>() == kind && D.Time(doc["occurred_at_utc"]) == at &&
            doc["fields"] is JsonObject, "detection_short_event_mismatch");
        return doc;
    }
    private static void Check(bool condition,string code,DetectionFailure.NativeField field,DetectionFailure.DifferenceKind difference)
    {
        if(!condition)throw new DetectionFailure(code){Field=field,Difference=difference};
    }
    private static DateTimeOffset NativeTime(JsonNode? node,DetectionFailure.NativeField field)
    {
        Check(node!=null,"detection_native_mismatch",field,DetectionFailure.DifferenceKind.missing);
        Check(node is JsonValue v&&v.TryGetValue<string>(out _),"detection_native_mismatch",field,DetectionFailure.DifferenceKind.type);
        // Reuse the existing Python ISO parser, including microsecond truncation,
        // comma fractions, basic offsets and offset seconds. Naive times fail closed.
        Check(PythonIsoDateTime.TryParse(node!.GetValue<string>(),out var parsed)&&parsed.IsAware&&parsed.TryToUtc(out _),"detection_native_mismatch",field,DetectionFailure.DifferenceKind.type);
        parsed.TryToUtc(out var utc);return utc;
    }
    private static bool SameNativeTime(string? xml,DateTimeOffset stored,string storedText)
    {
        var truncated=NativeTime(JsonValue.Create(xml),DetectionFailure.NativeField.SystemTime);
        // PostgreSQL timestamps are integral microseconds. Do not truncate an
        // untrusted stored fraction and accidentally accept even one extra tick.
        for(int i=0;i<storedText.Length;i++) {
            if(storedText[i] is not ('.' or ','))continue;
            int start=++i;while(i<storedText.Length&&char.IsAsciiDigit(storedText[i]))i++;
            if(i-start>6&&storedText.AsSpan(start+6,i-start-6).IndexOfAnyExcept('0')>=0)return false;
        }
        if(truncated==stored)return true;
        // Intentional correction to Python identity: storage uses HALF_EVEN,
        // XML datetime parsing truncates. Accept only those two representations
        // of this XML instant, never a general +/-1us tolerance.
        if(stored.UtcTicks-truncated.UtcTicks!=10)return false;
        try {return DirectEventTime.Utc(xml!)==stored.UtcDateTime;}
        catch(InvalidDataException) {return false;}
    }
    public static IReadOnlyList<DetectionRow> ParseEvents(PasswordScope scope,IReadOnlyList<JsonObject> rows,bool identity=false)
    {
        D.Require(rows.Count<=10000,"detection_window_truncated");var result=new List<DetectionRow>();long bytes=0;
        foreach(var row in rows){
            Check(row["source_xml"]!=null,"detection_native_fields",DetectionFailure.NativeField.source_xml,DetectionFailure.DifferenceKind.missing);
            Check(row["source_xml"] is JsonValue xmlValue&&xmlValue.TryGetValue<string>(out _),"detection_native_fields",DetectionFailure.NativeField.source_xml,DetectionFailure.DifferenceKind.type);
            string xml=D.Text(row["source_xml"]);int size=Encoding.UTF8.GetByteCount(xml);bytes+=size;
            D.Require(size is >0 and <=4194304&&bytes<=33554432,"detection_xml_budget");
            if (xml.StartsWith('{')) {
                long id = identity ? row["source_event_id"]!.GetValue<long>() : long.Parse(D.Text(row["native_id"]), CultureInfo.InvariantCulture);
                int kind = row["event_id"]!.GetValue<int>(); var time = D.Time(row["occurred_at_utc"]);
                var doc = ShortDocument(scope, id, kind, time, xml);
                var shortReference = new DetectionRef(scope, "core_event", id.ToString(CultureInfo.InvariantCulture), D.Text(row["sha256"])); shortReference.Validate();
                result.Add(new(shortReference, time, kind, D.Text(doc["computer"]), doc["fields"]!.DeepClone().AsObject()) {
                    Channel = D.Text(doc["channel"]), Provider = D.Text(doc["provider"]) });
                continue;
            }
            using var reader=XmlReader.Create(new StringReader(xml),new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=4194304});
            int nodes=0;while(reader.Read())D.Require(reader.Depth<64&&(reader.NodeType!=XmlNodeType.Element||++nodes<=100000),"detection_xml_bound");
            var root=XElement.Parse(xml,LoadOptions.PreserveWhitespace);XNamespace ns="http://schemas.microsoft.com/win/2004/08/events/event";var system=root.Element(ns+"System");
            Check(row["event_id"]!=null,"detection_native_mismatch",DetectionFailure.NativeField.event_id,DetectionFailure.DifferenceKind.missing);
            Check(int.TryParse(row["event_id"]!.ToString(),NumberStyles.None,CultureInfo.InvariantCulture,out int eid),"detection_native_mismatch",DetectionFailure.NativeField.event_id,DetectionFailure.DifferenceKind.type);
            var at=NativeTime(row["occurred_at_utc"],DetectionFailure.NativeField.occurred_at_utc);
            Check(root.Name==ns+"Event","detection_native_mismatch",DetectionFailure.NativeField.Event,DetectionFailure.DifferenceKind.value);
            Check(system!=null,"detection_native_mismatch",DetectionFailure.NativeField.System,DetectionFailure.DifferenceKind.missing);
            var eventId=system!.Element(ns+"EventID");
            Check(eventId!=null,"detection_native_mismatch",DetectionFailure.NativeField.EventID,DetectionFailure.DifferenceKind.missing);
            Check(eventId!.Value==eid.ToString(CultureInfo.InvariantCulture),"detection_native_mismatch",DetectionFailure.NativeField.EventID,DetectionFailure.DifferenceKind.value);
            var stamp=system.Element(ns+"TimeCreated");
            Check(stamp!=null,"detection_native_mismatch",DetectionFailure.NativeField.TimeCreated,DetectionFailure.DifferenceKind.missing);
            Check(SameNativeTime((string?)stamp!.Attribute("SystemTime"),at,D.Text(row["occurred_at_utc"])),"detection_native_mismatch",DetectionFailure.NativeField.SystemTime,DetectionFailure.DifferenceKind.value);
            var payload=identity?root.Element(ns+"EventData")?.Elements()??[]:root.Elements(ns+"EventData").SelectMany(e=>e.Elements(ns+"Data"));
            var fields=new JsonObject();foreach(var node in payload){
                // T109 Python selects EventData/Data; Binary and other payloads are not named fields.
                if(!identity&&node.Name!=ns+"Data")continue;
                string? name=(string?)node.Attribute("Name");
                Check(node.Name==ns+"Data","detection_native_fields",DetectionFailure.NativeField.Data,DetectionFailure.DifferenceKind.type);
                Check(!string.IsNullOrEmpty(name),"detection_native_fields",DetectionFailure.NativeField.Name,DetectionFailure.DifferenceKind.missing);
                var field=Enum.TryParse<DetectionFailure.NativeField>(name,out var known)&&Enum.IsDefined(known)&&known.ToString()==name?known:DetectionFailure.NativeField.EventData;
                Check(!node.HasElements,"detection_native_fields",field,DetectionFailure.DifferenceKind.type);
                Check(!fields.ContainsKey(name!),"detection_native_fields",field,DetectionFailure.DifferenceKind.value);
                fields[name!]=node.Value;
            }
            // Windows 1102 carries its initiator in UserData, rather than EventData.
            if(eid==1102&&root.Element(ns+"UserData") is {} userData) {
                XNamespace log="http://manifests.microsoft.com/win/2004/08/windows/eventlog";
                D.Require(userData.Elements().Count()==1&&userData.Element(log+"LogFileCleared") is not null,"detection_native_fields");
                foreach(var node in userData.Element(log+"LogFileCleared")!.Elements()) {
                    string name=node.Name.LocalName;
                    D.Require(node.Name.Namespace==log&&!node.HasElements&&!fields.ContainsKey(name),"detection_native_fields");
                    fields[name]=node.Value;
                }
            }
            fields.Remove("Computer");string native=identity?row["source_event_id"]!.ToString():D.Text(row["native_id"]);
            var reference=new DetectionRef(scope,scope.PluginId=="sli.workstations"?"workstation_observation":"core_event",native,D.Text(row["sha256"]));reference.Validate();
            result.Add(new(reference,at,eid,system!.Element(ns+"Computer")?.Value??"",fields) {
                Channel=system.Element(ns+"Channel")?.Value??"", Provider=(string?)system.Element(ns+"Provider")?.Attribute("Name")??"" });
        }return result;
    }
    internal static IReadOnlyList<DetectionRow> Snapshots(PasswordScope scope,IReadOnlyList<JsonObject> rows)
    {
        D.Require(rows.Count<=10000,"identity_attack_snapshot_truncated");return rows.Select(row=>new DetectionRow(new(scope,"ad_directory_observation",row["source_event_id"]!.ToString(),D.Text(row["sha256"])),D.Time(row["occurred_at_utc"]),Record:(JsonObject)row["attributes_json"]!)).ToArray();
    }
}

public static class DetectionSignal
{
    public static JsonObject Execution(JsonObject signal)=>new(){["version"]="sli.qw.execution.v1",["kind"]=signal["kind"]!.DeepClone(),["rule_id"]=signal["rule_id"]!.DeepClone(),["rule_version"]=1,["rule_sha256"]=signal["rule_sha256"]!.DeepClone(),["scope"]=signal["evidence_refs"]![0]!["scope"]!.DeepClone()};
    public static string Id(JsonObject signal)=>PasswordSignal.Id(signal);
    public static string PolicyId(JsonObject execution)=>"default:"+D.Text(execution["rule_id"])+":"+D.Hash(execution)[..32];
    internal static JsonObject Create(string rule,string kind,string ruleHash,string entity,string episode,IEnumerable<DetectionRef> evidence,DateTimeOffset at,DateTimeOffset now,string severity,string contextName,JsonObject context,IEnumerable<string>? reasons=null,int total=0)
    {
        var refs=evidence.Distinct().OrderBy(r=>r.SortKey,StringComparer.Ordinal).ToArray();D.Require(refs.Length is >0 and <=256,"detection_evidence_bound");foreach(var r in refs)r.Validate();
        return new(){["kind"]=kind,["rule_id"]=rule,["rule_version"]=1,["rule_sha256"]=ruleHash,["policy_revision"]=1,["evaluation_mode"]="enabled",["entity_key"]=entity,["episode_key"]=episode,["occurred_at_utc"]=D.Stamp(at),["received_at_utc"]=D.Stamp(now),["evidence_refs"]=D.Array(refs,r=>r.Document),["base_severity"]=severity,["effective_severity"]=severity,["severity_reasons"]=D.Array(reasons??[],r=>JsonValue.Create(r)),["quality"]="good",["conclusion_state"]="observed",[contextName]=context.DeepClone(),["evidence_total"]=total==0?null:JsonValue.Create(total)};
    }
    internal static void ValidateEnvelope(JsonObject signal)
    {
        string[] keys=["kind","rule_id","rule_version","rule_sha256","policy_revision","evaluation_mode","entity_key","episode_key","occurred_at_utc","received_at_utc","evidence_refs","base_severity","effective_severity","severity_reasons","quality","conclusion_state","evidence_total","identity_context","attack_context"];
        D.Require(!signal.Select(p=>p.Key).Except(keys).Any()&&(signal["identity_context"]!=null)!=(signal["attack_context"]!=null),"detection_signal_invalid");
        var refs=signal["evidence_refs"]!.AsArray().Select(DetectionRef.Read).ToArray();
        var anchor=signal["attack_context"]?["anchor_ref"];
        D.Require(refs.Length is >0 and <=256&&refs.Distinct().Count()==refs.Length&&refs.SequenceEqual(refs.OrderBy(r=>anchor!=null&&!JsonNode.DeepEquals(r.Document,anchor)).ThenBy(r=>r.SortKey,StringComparer.Ordinal)),"detection_signal_invalid");
        foreach(var r in refs)r.Validate();var scope=refs[0].Scope;
        D.Require(refs.All(r=>r.Scope==scope||D.Text(signal["rule_id"])=="qw.mass-file-read"&&r.Scope with{CollectionScopeId=""}==scope with{CollectionScopeId=""}),"detection_signal_scope");
        D.Require(D.Text(signal["evaluation_mode"])=="enabled"&&D.Text(signal["conclusion_state"])=="observed"&&D.Text(signal["quality"]) is "good" or "degraded"&&signal["rule_version"]!.GetValue<int>()==1&&signal["policy_revision"]!.GetValue<int>()==1&&PasswordJson.Hex(D.Text(signal["entity_key"]))&&PasswordJson.Hex(D.Text(signal["episode_key"])),"detection_signal_invalid");
        D.Time(signal["occurred_at_utc"]);D.Time(signal["received_at_utc"]);D.Require(PasswordJson.SpacedSize(signal)<=524288,"detection_signal_bound");
    }
}
