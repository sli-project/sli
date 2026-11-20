using System.Text.Json.Nodes;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Agents.Consumer;
using Sli.Server.Compatibility;

namespace Sli.Server.Storage.Direct;

// entity_model.extract_event_entities shared by NPS and the supported AD/DC
// Security events. No field-name/ASCII allowlist replaces native normalization.
internal static class DirectNpsEntities
{
    internal static IReadOnlyList<DirectEntity> Extract(IReadOnlyDictionary<string,string> data,string host,int kind=0,string channel="Security",string? initiator=null)
    {
        string? Pick(params string[] names) {
            foreach(var name in names) if(data.TryGetValue(name,out var value) && value.Length>0) return value;
            return null;
        }
        string? Clean(string? value) { if(value is null)return null; value=PythonText.Strip(value);return value.Length==0?null:value; }
        var entities=new List<DirectEntity>();
        void Principal(string prefix,string role,bool group=false,bool member=false) {
            string? name=Clean(member?Pick("MemberName","MemberSid"):prefix=="Subject" ? (Pick("SubjectUserName")??initiator) : Pick("TargetUserName","TargetAccount"));
            if(name is null or "-" || !member && prefix=="Subject" && name=="ANONYMOUS LOGON")return;
            string? domain=member?(Clean(Pick("TargetDomainName"))??Clean(Pick("SubjectDomainName"))):Clean(Pick(prefix+"DomainName"));
            string? sid=member?Pick("MemberSid"):Pick(prefix+"UserSid",prefix=="Target"?"TargetSid":"SubjectUserSid");
            string? upn=member?null:Pick(prefix+"UserPrincipalName",prefix+"UPN"),mail=member?null:Pick(prefix+"Email",prefix+"Mail");
            if(domain is null && name.Contains('\\')) domain=Clean(name[..name.LastIndexOf('\\')]);
            string normalized=name;
            if(normalized.Contains(',') && normalized.Contains('=')) { string first=normalized.Split(',')[0];if(first.Contains('=')) normalized=PythonText.Strip(first[(first.IndexOf('=')+1)..]); }
            else if(normalized.Contains('\\'))normalized=PythonText.Strip(normalized[(normalized.LastIndexOf('\\')+1)..]);
            string type=group?"ad_group":normalized.EndsWith('$')?"ad_computer":normalized.StartsWith("S-1-",StringComparison.Ordinal)?"security_principal":"ad_user";
            string legacy=$"{type}:{UnicodeLower.Lower(domain ?? "unknown")}:{UnicodeLower.Lower(normalized)}";
            var values=new Dictionary<string,string?> { ["SubjectUserName"]=normalized,["SubjectDomainName"]=domain,["SubjectUserSid"]=sid,["SubjectUserPrincipalName"]=upn,["SubjectEmail"]=mail };
            var identity=WorkstationLogonProjection.Resolve(values,"Subject",host);
            var aliases=identity.Aliases.Concat([legacy]).Distinct(StringComparer.Ordinal).Select(x=>(JsonNode?)JsonValue.Create(x)).ToArray();
            string display=domain is null?normalized:domain+"\\"+normalized;
            string lower=UnicodeLower.Lower(display);string account=lower.Contains('\\')?lower[(lower.LastIndexOf('\\')+1)..]:lower;
            string risk=account.StartsWith("svc",StringComparison.Ordinal)||account.StartsWith("service",StringComparison.Ordinal)||account.Contains("service",StringComparison.Ordinal)||account.EndsWith('$')||account.Contains("admin",StringComparison.Ordinal)||account.Contains("админ",StringComparison.Ordinal)?"important":"normal";
            if(group)risk=new[]{"domain admins","enterprise admins","schema admins","administrators","account operators","server operators","backup operators","dnsadmins","администраторы домена","администраторы предприятия","администраторы схемы","администраторы"}.Any(lower.Contains)?"critical":"normal";
            entities.Add(new DirectEntity(type,identity.Key.Length==0?legacy:identity.Key,display,role,true,false,new JsonObject { ["sid"]=sid,["domain"]=domain,["identity_state"]=identity.State,["identity_step"]=identity.Step,["identity_aliases"]=new JsonArray(aliases),["identity_reason"]=identity.Reason,["risk_tier"]=risk },identity.Confidence));
        }
        Principal("Subject","actor");
        bool targetGroup=channel=="Security" && kind is 4727 or 4728 or 4729 or 4730 or 4731 or 4732 or 4733 or 4734 or 4735 or 4737 or 4754 or 4755 or 4756 or 4757 or 4758;
        Principal("Target",targetGroup?"affected":"target",targetGroup);
        Principal("Member","affected",member:true);
        string? ws=Clean(Pick("WorkstationName","Workstation"));if(ws is not null and not "-") entities.Add(new("workstation","workstation:"+UnicodeLower.Lower(ws),ws,"source",true,false,new JsonObject{["risk_tier"]="normal"}));
        string? ip=Clean(Pick("IpAddress","ClientAddress","SourceAddress"));if(ip is not null and not ("-" or "::1" or "127.0.0.1")) entities.Add(new("ip_address","ip:"+ip,ip,"source",false,false,new JsonObject{["risk_tier"]="normal"}));
        string? process=Clean(Pick("ProcessName","NewProcessName","Application"));if(process is not null and not "-") entities.Add(new("process","process:"+UnicodeLower.Lower(process),process,"source",false,false,new JsonObject{["risk_tier"]="contextual"}));
        string? service=Clean(Pick("ServiceName","param1"));
        if(service is not null && channel=="System" && kind is 7035 or 7036 or 7040 or 7045)entities.Add(new("service","service:"+UnicodeLower.Lower(service),service,"target",true,false,new JsonObject{["risk_tier"]="contextual"}));
        string? task=Clean(Pick("TaskName","TaskNamePath"));if(task is not null)entities.Add(new("scheduled_task","task:"+UnicodeLower.Lower(task),task,"target",true,false,new JsonObject{["risk_tier"]="contextual"}));
        string? target=Clean(Pick("TargetServerName","ServiceName"));
        if(target is not null and not ("-" or "localhost") && channel=="Security" && kind is 4648 or 4769) {
            var lower=UnicodeLower.Lower(target);
            entities.Add(new("asset","server:"+lower,target,"target",true,false,new JsonObject{["risk_tier"]=lower.StartsWith("dc",StringComparison.Ordinal)||lower.Contains("domain controller",StringComparison.Ordinal)?"critical":"normal"}));
        }
        string? logon=Clean(Pick("LogonId","TargetLogonId","SubjectLogonId"));if(logon is not null and not ("-" or "0x0"))entities.Add(new("auth_session","logon:"+UnicodeLower.Lower(host)+":"+UnicodeLower.Lower(logon),logon,"context",true,true,new JsonObject{["risk_tier"]="normal"}));
        return entities.DistinctBy(x=>(x.Type,x.NaturalKey,x.Role)).ToArray();
    }
}
