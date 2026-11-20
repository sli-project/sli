using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Access;

namespace Sli.Server.Vpn;

public sealed class VpnInputException(string code) : Exception(code);
public sealed class VpnPermissionException(string code) : Exception(code);
internal static class VpnJson
{
    public static JsonObject Obj(object value) => JsonSerializer.SerializeToNode(value)!.AsObject();
    public static string Text(this JsonNode? row, string key, string fallback="") => row?[key]?.ToString() ?? fallback;
    public static long Number(this JsonNode? row, string key) => long.TryParse(row.Text(key),out long n)?n:0;
    public static bool Flag(this JsonNode? row,string key) => row.Text(key)=="true";
    public static JsonArray Array(IEnumerable<JsonObject> rows) => new(rows.Select(x=>(JsonNode)x.DeepClone()).ToArray());
    public static string? Iso(DateTimeOffset? value) => value?.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFF'Z'",CultureInfo.InvariantCulture);
    public static DateTimeOffset? At(this JsonNode? row,string key) => DateTimeOffset.TryParse(row.Text(key),CultureInfo.InvariantCulture,DateTimeStyles.RoundtripKind,out var at)?at.ToUniversalTime():null;
    public static JsonObject Pick(JsonNode row,params string[] keys) { var result=new JsonObject();foreach(string key in keys) result[key]=row[key]?.DeepClone();return result; }
}

public sealed record VpnBranch(string branch,string state,string reason,string dataset_or_resource_group,string? required_capability)
{
    [System.Text.Json.Serialization.JsonIgnore] public bool Allowed=>state=="available";
}
public sealed class VpnAccess(AccessFacts facts)
{
    public CapabilityDecisionSet Capabilities { get; }=new CapabilityComposer().Compose(facts);
    private readonly AccessDecision reports=new ReportEligibility().Compose(facts,new CapabilityComposer().Compose(facts));
    public static IReadOnlyList<IReadOnlyList<AccessResource>> Groups(long domain)=>domain>0?[[new("domain",domain)]]:[];
    public CapabilityResult Report(long domain,string action="view")=>ResourceAccessDecisions.ReportAction(reports,"vpn.audit",action,Groups(domain));
    public CapabilityResult Capability(string key,long domain)=>ResourceAccessDecisions.Capability(Capabilities,key,Groups(domain));
    public VpnBranch Branch(string branch,long domain,string action="view")
    {
        if(action is not ("view" or "export")) throw new VpnInputException("vpn_report_action_invalid");
        var report=Report(domain,action);bool directory=branch=="directory";
        string? capability=directory?null:branch=="sessions"?"vpn.sessions.view":"vpn.session.evidence.read";
        var decision=directory?report:!report.Allowed?new(false,"vpn_report_scope_required"):Capability(capability!,domain);
        if(report.Allowed && action=="export" && !Capabilities.Decide("reports.export").Allowed)
        { decision=new(false,"reports_export_required");if(!directory) capability="reports.export"; }
        return new(directory?"directory_membership":branch,decision.Allowed?"available":"not_authorized",decision.Reason,directory?"ad.accounts.vpn":"vpn.sessions",capability);
    }
    public JsonObject Branches(long domain,string action="view")=>VpnJson.Obj(new {directory=Branch("directory",domain,action),sessions=Branch("sessions",domain,action),session_evidence=Branch("session_evidence",domain,action)});
    public bool Windows(long domain)=>Report(domain).Allowed && Capability("events.view",domain).Allowed;
    public bool Assigned(string action="view")=>reports.Reports.Any(r=>r.ReportKey=="vpn.audit" && r.Allowed && r.Grants.Any(g=>g.AllowedActions.Contains(action)));
    public bool LegacyExecutable=>!Grants("view").Any(g=>g.Scope.TryGetProperty("mode",out _));
    public bool Field(string category,long domain,string action="view")=>ResourceAccessDecisions.ReportAction(reports,"vpn.audit",action,Groups(domain),new HashSet<string>{category}).Allowed;
    public IReadOnlyList<AtomicReportGrant> Grants(string action)=>reports.Reports.FirstOrDefault(r=>r.ReportKey=="vpn.audit" && r.Allowed)?.Grants.Where(g=>g.AllowedActions.Contains(action)).ToArray()??[];
    public bool GrantAllows(AtomicReportGrant grant,long domain,string action)=>ResourceAccessDecisions.ReportAction(reports with {Reports=[new("vpn.audit",true,[grant])]},"vpn.audit",action,Groups(domain)).Allowed;
}

public sealed record VpnQuery(long Domain,string Action,string Timezone,DateTimeOffset? From,DateTimeOffset? To,int Limit,int Offset,string RowId)
{
    public static VpnQuery Parse(string operation,IQueryCollection query)
    {
        string Get(string key,string fallback="")=>query[key].FirstOrDefault() is {Length:>0} value?value:fallback;
        long Integer(string key,long fallback,string error) => long.TryParse(Get(key,fallback.ToString(CultureInfo.InvariantCulture)),NumberStyles.Integer,CultureInfo.InvariantCulture,out long n)?n:throw new VpnInputException(error);
        bool evidence=operation=="sessions/evidence",windows=operation=="windows-authentication",series=operation=="failed-authorizations/series";
        string prefix=evidence?"vpn_session_evidence":windows?"windows_authentication":series?"vpn_audit_failed_authorization":operation=="authorizations"?"vpn_audit_authorization_timeline":"vpn_session";
        long domain=Integer("domain_id",0,prefix+"_domain_invalid");if(domain<=0) throw new VpnInputException(prefix+"_domain_invalid");
        int limit=checked((int)Integer("limit",windows?200:50,prefix+"_limit_invalid"));
        int offset=checked((int)Integer("offset",0,"vpn_session_offset_invalid"));
        if(operation=="sessions" && limit is <1 or >200 || windows && limit is <1 or >500) throw new VpnInputException(prefix+"_limit_invalid");
        if(operation=="sessions" && offset is <0 or >10000) throw new VpnInputException("vpn_session_offset_invalid");
        string row=Get("session_row_id").Trim();
        if(evidence && !Regex.IsMatch(row,@"\Aradius-session-row:[0-9a-f]{64}\z")) throw new VpnInputException(prefix+"_session_row_id_invalid");
        string zone=Get("timezone","UTC"),action=Get("action","view").Trim().ToLowerInvariant();
        if(evidence) return new(domain,action,zone,null,null,limit,offset,row);
        bool required=windows||series||operation=="authorizations";
        if(required && (Get("time_from")=="" || Get("time_to")=="")) throw new VpnInputException(prefix+"_requires_time_bounds");
        var (from,to)=Range(Get("time_from"),Get("time_to"),zone);
        if(required && to-from>TimeSpan.FromDays(windows?90:366)) throw new VpnInputException(prefix+"_period_too_wide");
        return new(domain,action,zone,from,to,limit,offset,row);
    }
    public static (DateTimeOffset? From,DateTimeOffset? To) Range(string from,string to,string timezone)
    {
        TimeZoneInfo zone;try { zone=TimeZoneInfo.FindSystemTimeZoneById(timezone.Trim() is {Length:>0} z?z:"UTC"); } catch(TimeZoneNotFoundException) { throw new VpnInputException("invalid_timezone"); }
        DateTimeOffset? Instant(string raw,bool end)
        {
            if(string.IsNullOrWhiteSpace(raw)) return null;raw=raw.Trim();
            bool date=Regex.IsMatch(raw,@"\A\d{4}-\d{2}-\d{2}\z");
            if(!date && Regex.IsMatch(raw,@"(?:Z|[+-]\d\d:?\d\d)\z"))
                return DateTimeOffset.TryParse(raw,CultureInfo.InvariantCulture,DateTimeStyles.RoundtripKind,out var at)?at.ToUniversalTime():throw new VpnInputException("invalid_datetime");
            if(!DateTime.TryParse(raw,CultureInfo.InvariantCulture,DateTimeStyles.None,out var local)) throw new VpnInputException("invalid_datetime");
            local=DateTime.SpecifyKind(local,DateTimeKind.Unspecified);if(date && end) local=local.AddDays(1);
            if(zone.IsInvalidTime(local)) throw new VpnInputException("nonexistent_local_datetime");
            if(zone.IsAmbiguousTime(local)) throw new VpnInputException("ambiguous_local_datetime_requires_offset");
            return new DateTimeOffset(local,zone.GetUtcOffset(local)).ToUniversalTime();
        }
        var start=Instant(from,false);var stop=Instant(to,true);if(start>=stop) throw new VpnInputException("empty_or_reversed_time_range");return(start,stop);
    }
}
