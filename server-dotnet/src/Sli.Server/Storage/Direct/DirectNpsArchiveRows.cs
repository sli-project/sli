using System.Globalization;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Sli.Agent.Core;
using Sli.Agent.Protocol.Compatibility;

namespace Sli.Server.Storage.Direct;

// Source: build_direct_event_source_row and link_core_from_v1. Values here
// retain original payload for the independently verified archive publisher.
internal static class DirectNpsArchiveRows
{
    internal static string NormalizedAt(DateTime value)
    {
        if(value.Kind!=DateTimeKind.Utc)throw new InvalidDataException("storage_v2_timestamp_invalid");
        long micros=value.Ticks%TimeSpan.TicksPerSecond/10;
        return value.ToString("yyyy-MM-dd HH:mm:ss",CultureInfo.InvariantCulture)+(micros==0?"":"."+micros.ToString("D6",CultureInfo.InvariantCulture))+"+00:00";
    }
    internal static JsonObject Event(long id,long rawId,long serverId,long domainId,long? siteId,long logSourceId,DateTime normalizedAt,JsonObject row,Direct4624Projection p,string? sourceTimestamp=null)
    {
        string? Pick(params string[] keys)=>keys.Select(k=>p.Data.GetValueOrDefault(k)).FirstOrDefault(v=>!string.IsNullOrEmpty(v));
        var eventData=DirectNativeEvent.Data(row);
        return new JsonObject {
            ["id"]=id,["raw_log_file_id"]=rawId,["server_id"]=serverId,["domain_id"]=domainId,["site_id"]=siteId,["log_source_id"]=logSourceId,
            ["event_record_id"]=row["record_id"]?.DeepClone(),["event_id"]=row["event_id"]?.DeepClone(),["version"]=row["version"]?.DeepClone(),["level"]=row["level"]?.DeepClone(),["task"]=row["task"]?.DeepClone(),["opcode"]=row["opcode"]?.DeepClone(),["keywords"]=row["keywords"]?.DeepClone(),
            ["provider_name"]=row["provider_name"]?.DeepClone(),["channel"]=row["channel"]?.DeepClone(),["computer"]=Computer(row),["time_created_utc"]=row["time_created"]?.DeepClone(),
            ["record_xml"]=row["xml"]?.DeepClone(),["message_text"]=row["message"]?.DeepClone(),["event_data_json"]=SourceJson.Serialize(eventData),
            ["subject_user_sid"]=Pick("SubjectUserSid"),["subject_user_name"]=SubjectName(p),["subject_domain_name"]=Pick("SubjectDomainName"),
            ["target_user_sid"]=Pick("TargetUserSid","TargetSid"),["target_user_name"]=Pick("TargetUserName","NewTargetUserName","TargetAccount"),["target_domain_name"]=Pick("TargetDomainName"),
            ["ip_address"]=Pick("IpAddress","ClientAddress","SourceAddress"),["workstation_name"]=Pick("WorkstationName","Workstation"),["logon_id"]=Pick("LogonId","TargetLogonId","SubjectLogonId"),["correlation_id"]=Direct4624Core.NpsCorrelation(p),
            ["normalized_hash"]=p.IdentityHash,["provider_guid"]=row["provider_guid"]?.DeepClone(),["time_created_local"]=row["time_created_local"]?.DeepClone(),["normalized_at"]=sourceTimestamp??NormalizedAt(normalizedAt)
        };
    }
    internal static string Computer(JsonObject row) => row["machine_name"]?.GetValue<string>() is {Length:>0} name ? name : row["computer_name"]!.GetValue<string>();
    internal static string? SubjectName(Direct4624Projection p) => p.Data.GetValueOrDefault("SubjectUserName") is {Length:>0} name ? name : p.CatalogInitiator ?? (p.Normalizer=="radius_event_catalog"?"":null);
    internal static JsonObject Link(long eventId,DirectEntity entity,int entityId,short roleId,int extractedFromId,DateTime createdAt)=>new() {
        ["event_id"]=eventId,["entity_id"]=entityId,["link_role"]=entity.Role,["role_id"]=roleId,["confidence"]=entity.Confidence,
        ["extracted_from"]="event_data",["extracted_from_id"]=extractedFromId,["created_at"]=DirectEntityModel.Timestamp(createdAt),
        ["evidence_json"]=new JsonObject { ["source"]="event_data",["role"]=entity.Role },["attributes_json"]=entity.Attributes.DeepClone()
    };
    internal static void VerifyLinks(IReadOnlyList<JsonObject> expected,IReadOnlyList<JsonObject> actual)
    {
        if(expected.Count!=actual.Count)throw new InvalidDataException("archive_link_count_mismatch");
        string Key(JsonObject row)=>$"{row["event_id"]!.GetValue<long>()}:{row["entity_id"]!.GetValue<int>()}:{row["role_id"]!.GetValue<short>()}";
        byte[] Hash(JsonObject row) {
            var time=DirectEventTime.Utc(row["created_at"]!.GetValue<string>());
            return DirectLinkCore.Hash(row["event_id"]!.GetValue<long>(),row["entity_id"]!.GetValue<int>(),row["role_id"]!.GetValue<short>(),row["extracted_from_id"]!.GetValue<int>(),time,row["confidence"]!.GetValue<double>());
        }
        var wanted=expected.ToDictionary(Key,Hash,StringComparer.Ordinal);
        foreach(var row in actual) if(!wanted.Remove(Key(row),out var hash) || !hash.AsSpan().SequenceEqual(Hash(row)))throw new InvalidDataException("archive_link_hash_mismatch");
        if(wanted.Count!=0)throw new InvalidDataException("archive_link_hash_mismatch");
    }
}
