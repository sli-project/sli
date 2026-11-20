using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Sli.Agent.Core;
using Sli.Server.Agents.Registry;
using Sli.Server.Compatibility;

namespace Sli.Server.Agents.Radius;

internal sealed record RadiusObservation(string Lifecycle,string RecordHash,string? SessionIdentityKey,string? Principal,DateTimeOffset ObservedAt)
{ public override string ToString()=>nameof(RadiusObservation); }
internal sealed record RadiusPlan(IReadOnlyList<string> EvidenceHashes,IReadOnlyList<RadiusObservation> Observations,IReadOnlyDictionary<string,(string Principal,DateTimeOffset Expires)> Cache)
{ public override string ToString()=>nameof(RadiusPlan); }

// Source sli_collect/radius_contract.py::plan_batch and radius_accounting.py.
internal static class RadiusPlanner
{
    private static string Hash(string value)=>Convert.ToHexStringLower(SHA256.HashData(new UTF8Encoding(false,true).GetBytes(value)));
    private static string ClassScope(string source,string value)=>Hash(UnicodeCaseFold.Fold(source)+"\0"+value);
    private static string? Value(IReadOnlyList<string> fields,int i) { string text=PythonText.Strip(fields[i]);return text.Length==0?null:text; }
    private static string JsonString(string value)
    {
        var result=new StringBuilder("\"");
        foreach(char c in value) {
            switch(c) { case '"':result.Append("\\\"");break;case '\\':result.Append("\\\\");break;case '\b':result.Append("\\b");break;case '\f':result.Append("\\f");break;case '\n':result.Append("\\n");break;case '\r':result.Append("\\r");break;case '\t':result.Append("\\t");break;
                default:if(c<32) result.Append("\\u").Append(((int)c).ToString("x4",CultureInfo.InvariantCulture));else result.Append(c);break; }
        }
        return result.Append('"').ToString();
    }
    private static string SessionKey(string source,string nas,string session,string principal)
    {
        string json="{\"account_session_id\":"+JsonString(session)+",\"exact_principal_key\":"+JsonString(principal)+",\"nas_identity\":"+JsonString(UnicodeCaseFold.Fold(nas))+",\"source_instance_id\":"+JsonString(UnicodeCaseFold.Fold(source))+"}";
        return "radius-session:"+Hash(json);
    }
    internal static RadiusObservation? BuildSessionObservation(string line,string source,string timezone,int offset,string? exactPrincipal)
    {
        if(!Regex.IsMatch(source,@"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\z") || string.IsNullOrWhiteSpace(timezone) || offset is < -840 or >840) throw new ArgumentException("radius_policy_invalid");
        var record=RadiusAccountingContract.Parse(line);
        var observation=RadiusAccountingContract.BuildSessionObservation(record,source,exactPrincipal,sourceTimezoneId:timezone,sourceUtcOffsetMinutes:offset);
        return observation is null?null:new RadiusObservation(observation.LifecycleEvent,record.CanonicalRecordSha256,observation.SessionIdentityKey,observation.ExactPrincipalKey,observation.ObservedAtUtc!.Value);
    }
    public static async Task<RadiusPlan> ProjectAsync(string[] lines,string source,string timezone,int offset,DateTimeOffset observed,Dictionary<string,(string Principal,DateTimeOffset Expires)> initial,Func<string,Task<string?>> resolve)
    {
        if(!Regex.IsMatch(source,@"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\z") || string.IsNullOrWhiteSpace(timezone) || offset is < -840 or >840) throw new ArgumentException("radius_policy_invalid");
        var cache=initial.Where(x=>x.Value.Expires>observed).ToDictionary(x=>x.Key,x=>x.Value,StringComparer.Ordinal);
        var hashes=new List<string>();var sessions=new List<RadiusObservation>();
        foreach(string line in lines) {
            var record=RadiusAccountingContract.Parse(line);string hash=record.CanonicalRecordSha256;hashes.Add(hash);
            string? dn=record.DistinguishedName,classValue=record.ClassAttribute;
            if(record.PacketType==2) {
                string? principal=dn is null?null:await resolve(dn);
                if(principal is not null && !Regex.IsMatch(principal,@"\A[a-z][a-z0-9_.-]*:.{1,500}\z",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant)) throw new ArgumentException("identity_resolver_returned_invalid_key");
                var binding=RadiusAccountingContract.BuildClassIdentityBinding(record,source,principal)!;
                if(binding.ExactIdentityReady) cache[ClassScope(source,binding.ClassAttribute)]=(binding.ExactPrincipalKey!,observed.AddSeconds(604800));
                continue;
            }
            string? principalKey=null;if(classValue is not null && cache.TryGetValue(ClassScope(source,classValue),out var found)) principalKey=found.Principal;
            var observation=RadiusAccountingContract.BuildSessionObservation(record,source,principalKey,sourceTimezoneId:timezone,sourceUtcOffsetMinutes:offset);
            if(observation is not null) sessions.Add(new RadiusObservation(observation.LifecycleEvent,hash,observation.SessionIdentityKey,observation.ExactPrincipalKey,observation.ObservedAtUtc!.Value));
        }
        if(cache.Count>10000) throw new ArgumentException("class_cache_capacity_exceeded");
        return new RadiusPlan(hashes,sessions,cache);
    }
    internal static RadiusObservation? BuildObservation(IReadOnlyList<string> f,string hash,string source,int offset,string? principalKey)
    {
        if(!PythonInt.TryParse(Value(f,4),out var packet) || packet!=4) return null;
        string status=Value(f,31)!;if(status is "7" or "8") return null;
        string lifecycle=status switch { "1"=>"start","2"=>"stop","3"=>"interim_update",_=>throw new ArgumentException("accounting_status_unsupported_or_missing") };
        string session=Value(f,35) ?? throw new ArgumentException("account_session_id_required");
        string nas=Value(f,11) ?? Value(f,12) ?? throw new ArgumentException("nas_identity_required");
        var date=Value(f,2) ?? "";var time=Value(f,3) ?? "";
        if(!DateTime.TryParseExact(date+" "+time,["M/d/yyyy H:m:s","MM/dd/yyyy HH:mm:ss"],CultureInfo.InvariantCulture,DateTimeStyles.None,out var local)) throw new ArgumentException("record_local_timestamp_invalid");
        var utc=new DateTimeOffset(DateTime.SpecifyKind(local.AddMinutes(-offset),DateTimeKind.Utc));
        return new RadiusObservation(lifecycle,hash,principalKey is null?null:SessionKey(source,nas,session,principalKey),principalKey,utc);
    }
}
