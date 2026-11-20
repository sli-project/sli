using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol.Compatibility;

namespace Sli.Server.Storage.Direct;

// Source entity_model.extract_event_entities for the bounded 4624 SID profile.
// Reject unhandled values before a caller can reserve an event.
internal static class DirectRich4624Entities
{
    private static readonly HashSet<string> Fields = new(StringComparer.Ordinal) {
        "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
        "TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId",
        "LogonType", "IpAddress", "WorkstationName", "ProcessName", "ProcessId",
        "LogonProcessName", "AuthenticationPackageName", "IpPort", "ElevatedToken",
        "ImpersonationLevel", "LogonGuid", "TransmittedServices", "LmPackageName", "KeyLength",
        "VirtualAccount", "RestrictedAdminMode", "LinkedLogonId", "TargetLinkedLogonId", "NetworkAccountName",
        "NetworkAccountDomain", "TargetOutboundUserName", "TargetOutboundDomainName",
        "Status", "SubStatus", "FailureReason", "ResultCode", "TargetSid", "PrivilegeList"
    };
    internal static IReadOnlyList<DirectEntity> Extract(IReadOnlyDictionary<string,string> data,string host)
    {
        if (data.Keys.Any(k => !Fields.Contains(k)) || data.Values.Any(v => v.Any(c => c < 32 || c > 126) || v != v.Trim()))
            throw new InvalidDataException("storage_v2_event_profile_pending");
        var result = new List<DirectEntity>();
        foreach (var (prefix, role) in new[] { ("Subject", "actor"), ("Target", "target") })
        {
            if (!data.TryGetValue(prefix+"UserName",out var principal) || principal is "" or "-") continue;
            var sid=data.GetValueOrDefault(prefix+"UserSid");
            if(prefix=="Target" && string.IsNullOrEmpty(sid))sid=data.GetValueOrDefault("TargetSid");
            if (!data.TryGetValue(prefix+"UserName",out var name) || !data.TryGetValue(prefix+"DomainName",out var domain) ||
                sid is null ||
                !Regex.IsMatch(name,@"\A[A-Za-z0-9._-]+\z",RegexOptions.CultureInvariant) ||
                !Regex.IsMatch(domain,@"\A[A-Za-z0-9_-]+\z",RegexOptions.CultureInvariant) ||
                !Regex.IsMatch(sid,@"\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\z",RegexOptions.CultureInvariant))
                throw new InvalidDataException("storage_v2_event_profile_pending");
            var d=UnicodeLower.Lower(domain); var n=UnicodeLower.Lower(name);
            if (n is "-" or "null" or "n/a" or "anonymous logon" || n.StartsWith("s-1-",StringComparison.Ordinal))
                throw new InvalidDataException("storage_v2_event_profile_pending");
            var risk=n.StartsWith("svc",StringComparison.Ordinal)||n.StartsWith("service",StringComparison.Ordinal)||n.Contains("service",StringComparison.Ordinal)||n.Contains("admin",StringComparison.Ordinal) ? "important" : "normal";
            result.Add(new DirectEntity("ad_user","sid:"+sid,domain+"\\"+name,role,true,false,new JsonObject {
                ["sid"]=sid,["domain"]=domain,["identity_state"]="resolved",["identity_step"]=1,
                ["identity_aliases"]=new JsonArray("sam:"+d+":"+n,"ad_user:"+d+":"+n),
                ["identity_reason"]=null,["risk_tier"]=risk
            }));
        }
        if (result.Select(e=>e.NaturalKey).Distinct(StringComparer.Ordinal).Count() != result.Count)
            throw new InvalidDataException("storage_v2_event_profile_pending");
        if(data.TryGetValue("WorkstationName",out var ws) && ws.Length>0 && ws!="-")
            result.Add(new DirectEntity("workstation","workstation:"+UnicodeLower.Lower(ws),ws,"source",true,false,new JsonObject{["risk_tier"]="normal"}));
        if(data.TryGetValue("IpAddress",out var ip) && ip.Length>0 && ip is not ("-" or "::1" or "127.0.0.1"))
            result.Add(new DirectEntity("ip_address","ip:"+ip,ip,"source",false,false,new JsonObject{["risk_tier"]="normal"}));
        if(data.TryGetValue("ProcessName",out var process) && process.Length>0 && process!="-")
            result.Add(new DirectEntity("process","process:"+UnicodeLower.Lower(process),process,"source",false,false,new JsonObject{["risk_tier"]="contextual"}));
        var logon = data.GetValueOrDefault("TargetLogonId");
        if (string.IsNullOrEmpty(logon)) logon = data.GetValueOrDefault("SubjectLogonId");
        if(!string.IsNullOrEmpty(logon) && logon is not ("-" or "0x0"))
            result.Add(new DirectEntity("auth_session","logon:"+UnicodeLower.Lower(host)+":"+UnicodeLower.Lower(logon),logon,"context",true,true,new JsonObject{["risk_tier"]="normal"}));
        return result;
    }
    // File-only native fields have no entity semantics in the reference.
    internal static IReadOnlyList<DirectEntity> ExtractFile(IReadOnlyDictionary<string,string> data,string host)
        => Extract(data.Where(p=>Fields.Contains(p.Key)).ToDictionary(p=>p.Key,p=>p.Value,StringComparer.Ordinal),host);
}
