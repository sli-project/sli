using System.Globalization;
using System.Net;
using System.Numerics;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Agents.Consumer;

// Workstation events share the AD/DC source projection and identity ladder.
internal static partial class WorkstationLogonProjection
{
    internal sealed record Identity(string Key,int Step,string State,double Confidence,string? Reason,List<string> Aliases);
    private static string Lower(string s)=>UnicodeLower.Lower(s);
    private static string Strip(string s)=>s.Trim('\u0009','\u000A','\u000B','\u000C','\u000D','\u001C','\u001D','\u001E','\u001F','\u0020','\u0085','\u00A0','\u1680','\u2000','\u2001','\u2002','\u2003','\u2004','\u2005','\u2006','\u2007','\u2008','\u2009','\u200A','\u2028','\u2029','\u202F','\u205F','\u3000');
    private static string? Text(IReadOnlyDictionary<string,string?> data,params string[] names) { foreach(var key in names) if(data.TryGetValue(key,out var v) && v is not null && Strip(v) is {Length:>0} s) return s;return null; }
    private static string? Limited(IReadOnlyDictionary<string,string?> data,int limit,params string[] names) {foreach(var k in names) {var s=Text(data,k);if(s is not null && s!="-") return string.Concat(s.EnumerateRunes().Take(limit).Select(x=>x.ToString()));}return null;}
    private static bool NonSubject(string value) { string s=Strip(value); return s.Length>0 && new[]{"-","n/a","null","anonymous logon","анонимный вход","s-1-0-0"}.Contains(UnicodeCaseFold.Fold(s),StringComparer.Ordinal); }
    private static bool IsMatch(string s,string pattern)=>Regex.IsMatch(s,pattern,RegexOptions.CultureInvariant,TimeSpan.FromSeconds(1));
    internal static Identity Resolve(IReadOnlyDictionary<string,string?> data,string prefix,string host)
    {
        string sid=Text(data,prefix+"UserSid",prefix+"Sid")??"",guid=Lower(Text(data,prefix+"UserGuid",prefix+"Guid")??"").Trim('{','}');
        string upn=Lower(Text(data,prefix+"UserPrincipalName",prefix+"UPN")??""),mail=Lower(Text(data,prefix+"Email",prefix+"Mail")??"");
        string sam=Text(data,prefix+"UserName",prefix+"User")??"",domain=Text(data,prefix+"DomainName",prefix+"UserDomain")??"";
        string node=Lower(Strip(host).TrimEnd('.')); if(IPAddress.TryParse(node,out var ip)) node=ip.ToString().ToLowerInvariant();else node=node.Split('.')[0];
        if(domain.Length==0 && sam.Contains('\\')) {int i=sam.LastIndexOf('\\');domain=sam[..i];sam=sam[(i+1)..];}
        domain=Lower(Strip(domain));bool fqdn=domain.Contains('.');domain=domain.Split('.')[0];
        string Sam(string value) { value=Strip(value); return Lower(value.Contains('\\')?value[(value.LastIndexOf('\\')+1)..]:value); }
        var aliases=new List<string>(); if(sam.Length>0) aliases.Add($"sam:{(domain.Length>0?domain:"?")}:{Sam(sam)}");if(upn.Length>0)aliases.Add("upn:"+upn);if(mail.Contains('@'))aliases.Add("mail:"+mail);
        bool sidOk=sid.Length>0&&!NonSubject(sid);if(!sidOk)sid="";
        if(NonSubject(sam)&&!sidOk&&upn.Length==0&&guid.Length==0) return new("",5,"unresolved",0,"не_субъект",[]);
        if(NonSubject(sam))sam="";
        sid=sid.ToUpperInvariant();
        if(IsMatch(sid,@"^S-1-\d+(-\d+)*$")) {
            bool builtin=IsMatch(sid,@"^S-1-5-(18|19|20)$|^S-1-5-32-\d+$");
            if(builtin && node.Length==0)return new("",1,"unresolved",0,"нет_домена",aliases);
            return new(builtin?$"sid:{node}:{sid}":$"sid:{sid}",1,"resolved",1,null,aliases);
        }
        if(IsMatch(guid,@"^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$"))return new("guid:"+guid,2,"resolved",1,null,aliases);
        if(upn.Contains('@'))return new("upn:"+upn,3,"provisional",0.8,null,aliases.Where(x=>!x.StartsWith("upn:",StringComparison.Ordinal)).ToList());
        if(sam.Length>0&&domain.Length>0) {string key=$"sam:{domain}:{Sam(sam)}";return new(key,4,"provisional",fqdn?0.3:0.6,null,(new[]{key}).Concat(aliases).Distinct(StringComparer.Ordinal).ToList());}
        if(sam.Length>0)return new("name:"+Sam(sam),5,"unresolved",0.3,"нет_домена",aliases.Where(x=>!x.StartsWith("sam:",StringComparison.Ordinal)).ToList());
        return new("",5,"unresolved",0,"нет_sid",[]);
    }
    internal static bool PositiveHexStatus(string input)
    {
        string s=string.Concat(Strip(input).EnumerateRunes().Select(r=>Rune.GetUnicodeCategory(r)==UnicodeCategory.DecimalDigitNumber?((char)('0'+(int)Rune.GetNumericValue(r))).ToString():r.ToString()));int p=0;if(p<s.Length && s[p] is '+' or '-') {if(s[p++]=='-')return false;}
        if(p+1<s.Length&&s[p]=='0'&&s[p+1] is 'x' or 'X'){p+=2;if(p<s.Length&&s[p]=='_')p++;}
        bool digit=false,underscore=false;BigInteger value=0;
        foreach(var r in s[p..].EnumerateRunes()) {
            if(r.Value=='_'){if(!digit||underscore)return false;underscore=true;continue;}
            int n=r.Value is >= '0' and <= '9'?r.Value-'0':r.Value is >= 'a' and <= 'f'?r.Value-'a'+10:r.Value is >= 'A' and <= 'F'?r.Value-'A'+10:
                Rune.GetUnicodeCategory(r)==UnicodeCategory.DecimalDigitNumber?(int)Rune.GetNumericValue(r):-1;
            if(n<0)return false;digit=true;underscore=false;value=value*16+n;if(value>uint.MaxValue)return false;
        }
        return digit&&!underscore&&value>0;
    }
    private static JsonObject IdentityQuality(Identity i)=>new() {["key"]=i.Key,["state"]=i.State,["step"]=i.Step,["provisional"]=i.State=="provisional",["confidence"]=i.Confidence,["reason"]=i.Reason,["aliases"]=new JsonArray(i.Aliases.Select(x=>(JsonNode?)JsonValue.Create(x)).ToArray()),["rule"]="identity-ladder/v1"};
    public static (string Semantic,JsonObject Roles,JsonObject Facts,JsonObject Quality) Build(int id,string channel,string provider,IReadOnlyDictionary<string,string?> data,string host,long? ad)
    {
        var roles=new JsonObject{["source_host"]=host};var identities=new JsonObject();var actor=Resolve(data,"Subject",host);var target=Resolve(data,"Target",host);
        if(actor.Key.Length>0){roles["actor"]=actor.Key;identities["actor"]=IdentityQuality(actor);}if(target.Key.Length>0){roles["affected_entity"]=target.Key;identities["affected_entity"]=IdentityQuality(target);}
        string? session=id==4624?Text(data,"TargetLogonId","LogonId"):Text(data,"SubjectLogonId","TargetLogonId","LogonId");
        if(session is not null){string key=host+":"+UnicodeCaseFold.Fold(Strip(session));roles["session_principal"]=key;identities["session_principal"]=new JsonObject{["key"]=key,["state"]="resolved",["step"]="source_scoped_session",["provisional"]=false,["confidence"]=1.0,["reason"]=null,["aliases"]=new JsonArray(),["rule"]="source-host-plus-logon-id/v1"};}
        string? ip=Text(data,"IpAddress","ClientAddress","SourceNetworkAddress");if(ip is not null && ip is not ("-" or "::1" or "127.0.0.1"))roles["source_ip"]=ip;
        string semantic=id switch {4624=>"authentication.session.created",4625=>"authentication.session.failed",4634=>"authentication.session.ended",_=>"authentication.logout.requested"};
        var facts=new JsonObject{["windows_event_id"]=id,["channel"]=channel,["provider"]=provider};
        if(id==4647)facts["lifecycle_role"]="supplemental_logout_only";
        if(id==4625){string? status=Text(data,"Status"),sub=Text(data,"SubStatus");string? chosen=status??sub;
            if(sub is not null && PositiveHexStatus(sub))chosen=sub;
            if(chosen is not null)facts["failure_status"]=chosen;
            facts["result_code_state"]=chosen is null?"unknown":"observed";facts["result"]=chosen is null?"unknown":new[]{"0","0x0","0x00000000","00000000"}.Contains(UnicodeCaseFold.Fold(Strip(chosen)))?"success":"failure";if(chosen is not null)facts["result_code"]=chosen;
        }
        if(id is 4624 or 4625 or 4634 or 4647) facts["logon_type"]=Limited(data,16,"LogonType");
        if(id==4624){facts["logon_user_name"]=Limited(data,256,"TargetUserName");facts["logon_user_domain"]=Limited(data,256,"TargetDomainName");facts["logon_user_sid"]=Limited(data,256,"TargetUserSid");}
        var quality=new JsonObject{["event_data_encoding"]="named",["catalog_independent"]=true,["raw_event_mutated"]=false,["missing_actor_sid"]=Text(data,"SubjectUserSid") is null,["unresolved_actor"]=actor.Key.Length>0 && actor.State!="resolved",["unresolved_target"]=target.Key.Length>0 && target.State!="resolved",["missing_source_ip"]=!roles.ContainsKey("source_ip"),["unknown_event_mapping"]=false,["semantic_mapping_status"]="mapped",["defined_but_not_emitted"]=false};
        if(id is 4688 or 4697 or 7045) semantic=BuildProcess(id,data,roles,facts,quality);
        if(id is 4698 or 4699 or 4700 or 4701 or 4702 or 4719 or 4732 or 4733) semantic=BuildTaskGroupAudit(id,data,roles,facts,quality);
        if(id==4624){string? targetSid=Text(data,"TargetUserSid");bool exact=targetSid is not null&&IsMatch(targetSid,@"(?i)^[sſ]-1-5-21-\d+-\d+-\d+-\d+$");quality["relation_account_identity"]=new JsonObject{["state"]=exact?"exact":"not_exact",["sid_field"]="TargetUserSid"};if(exact)facts["relation_account_sid"]=targetSid!.ToUpperInvariant();}
        quality["identity_roles"]=identities;quality["provisional_identity_roles"]=new JsonArray(identities.Where(x=>x.Value!["provisional"]!.GetValue<bool>()).Select(x=>(JsonNode?)JsonValue.Create(x.Key)).OrderBy(x=>x!.GetValue<string>(),StringComparer.Ordinal).ToArray());
        quality["unresolved_identity_roles"]=new JsonArray(identities.Where(x=>x.Value!["state"]!.GetValue<string>()=="unresolved").Select(x=>(JsonNode?)JsonValue.Create(x.Key)).OrderBy(x=>x!.GetValue<string>(),StringComparer.Ordinal).ToArray());quality["ad_enrichment"]=ad is null?"not_collected":"available";quality["coverage"]="not_proven";
        return(semantic,roles,facts,quality);
    }
}
