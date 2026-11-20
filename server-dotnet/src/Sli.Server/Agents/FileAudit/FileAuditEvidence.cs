using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Agents.Registry;
using Sli.Server.Agents.Ingress;

namespace Sli.Server.Agents.FileAudit;

// Source: file_audit/contracts.py and normalizers.py at ddce909d.
// This is only the evidence primitive, not a packet acknowledgement or sink.
internal static class FileAuditEvidence
{
    private const string Provider = "Microsoft-Windows-Security-Auditing";
    private static readonly HashSet<int> Events = [4656,4659,4660,4663,4670,4907,5140,5142,5143,5144,5145,5168,4658,4664];
    private static readonly (string Key,string Field,int Limit)[] Fields = [
        ("subject_user_sid","SubjectUserSid",184), ("logon_id","SubjectLogonId",128),
        ("object_name","ObjectName",4096), ("ip_address","IpAddress",128),
        ("process_name","ProcessName",512), ("share_name","ShareName",256),
        ("share_local_path","ShareLocalPath",4096), ("relative_target_name","RelativeTargetName",4096),
        ("object_type","ObjectType",128), ("access_list","AccessList",4096),
        ("access_reason","AccessReason",8192), ("old_sd","OldSd",65536), ("new_sd","NewSd",65536)];

    public static string EvidenceKey(string agent, string source, string generation, long recordId, int eventId, int version)
    {
        static bool Text(string s) => s.Length>0 && s.EnumerateRunes().Count()<=256 && UnicodeCaseFold.TrimAndFold(s)==UnicodeCaseFold.Fold(s) && !s.Any(c=>c<32);
        if (!Guid.TryParseExact(agent,"D",out var id) || id.ToString("D")!=agent || !Text(source) || !Text(generation)
            || recordId<1 || !Events.Contains(eventId) || version is <0 or >255)
            throw new ArgumentException("file_audit_evidence_identity_invalid");
        JsonArray value=[agent,source,"Security",generation,recordId];
        return Convert.ToHexStringLower(SHA256.HashData(CanonicalJson.ToBytes(value)));
    }

    public static JsonObject NativeFacts(JsonObject row, JsonObject data)
    {
        var result=new JsonObject();
        if (UnicodeCaseFold.Fold(row["channel"]?.GetValue<string>() ?? "")!="security"
            || UnicodeCaseFold.Fold(row["provider_name"]?.GetValue<string>() ?? "")!=UnicodeCaseFold.Fold(Provider)
            || !int.TryParse(row["event_id"]?.ToString(),out int eventId) || !Events.Contains(eventId)) return result;
        foreach (var (key,field,limit) in Fields)
            if (data[field] is JsonValue value && value.TryGetValue<string>(out var s) && s!="-" && s.Length>0 && s.EnumerateRunes().Count()<=limit) result[key]=s;
        foreach (var (key,field,max) in new (string,string,ulong)[] { ("access_mask","AccessMask",uint.MaxValue), ("server_process_id","ProcessId",ulong.MaxValue), ("handle_id","HandleId",ulong.MaxValue), ("logon_id_numeric","SubjectLogonId",ulong.MaxValue) })
            if (TryNumber(data[field]?.GetValue<string>(),out var n) && n>=0 && n<=max) result[key]=(ulong)n;
        string? keywords=row["keywords"]?.GetValue<string>();
        var outcome="unknown";
        if (TryNumber(string.IsNullOrEmpty(keywords)?"0":keywords,out var flags))
        {
            bool success=(flags & 0x20000000000000L)!=0, failure=(flags & 0x10000000000000L)!=0;
            outcome=success && !failure ? "success" : failure && !success ? "failure" : "unknown";
        }
        result["outcome"]=outcome;
        return result;
    }

    internal static bool TryNumber(string? text,out BigInteger value) => AgentFileAuditEvents.TryBaseZero(text,out value);
}
