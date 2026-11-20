using Sli.Server.Access;
namespace Sli.Server.Reports.SecurityCandidates;
internal sealed class SecurityCandidateException(string code):Exception(code){public string Code {get;}=code;}
internal sealed record EntityResource(long Id,long? DomainId,long? ServerId);
internal sealed record SecurityCandidateResult(string State,IReadOnlyList<long> Ids,bool HasMore);
internal interface ISecurityCandidateStore
{
    Task<EntityResource?> EntityAsync(long id,CancellationToken ct);
    Task<IReadOnlyList<long>> CandidatesAsync(long id,long domain,DateTimeOffset start,DateTimeOffset end,int count,CancellationToken ct);
}
internal sealed class SecurityCandidateOwner(ISecurityCandidateStore store)
{
    private static DateTimeOffset MicrosecondUtc(DateTimeOffset value) {var utc=value.ToUniversalTime();return new DateTimeOffset(utc.Ticks-utc.Ticks%10,TimeSpan.Zero);}
    private static readonly IReadOnlySet<string> SecurityFields=new HashSet<string>{"security","technical","raw_evidence"};
    public async Task<SecurityCandidateResult> ReadAsync(long entityId,DateTimeOffset startUtc,DateTimeOffset endUtc,int limit,AccessDecision access,CancellationToken ct)
    {
        if(entityId is <=0 or >9_007_199_254_740_991)throw new SecurityCandidateException("security_events_filter_invalid");
        var start=MicrosecondUtc(startUtc);var end=MicrosecondUtc(endUtc);
        if(start>=end)throw new SecurityCandidateException("empty_or_reversed_time_range");
        var entity=await store.EntityAsync(entityId,ct);
        if(entity is null || entity.DomainId is null)return new("not_collected",[],false);
        var resources=new List<AccessResource>{new("domain",entity.DomainId.Value)};
        if(entity.ServerId is {} server)resources.Add(new("server",server));
        IReadOnlyList<IReadOnlyList<AccessResource>> groups=[resources];
        if(!access.Capabilities.DecideForResourceGroups("objects.view",groups).Allowed ||
           !access.Capabilities.DecideForResourceGroups("investigations.view",groups).Allowed)return new("not_authorized",[],false);
        string? report=new[]{"investigations.workspace","cases.workspace"}.FirstOrDefault(key=>access.Reports.Any(r=>r.ReportKey==key && r.Allowed && r.Grants.Any(g=>g.AllowedActions.Contains("view"))));
        if(report is null || !ResourceAccessDecisions.ReportAction(access,report,"view",groups).Allowed)return new("not_authorized",[],false);
        long domain=entity.DomainId.Value;
        if(domain<=0)throw new SecurityCandidateException("security_events_domain_invalid");
        if(end-start>TimeSpan.FromDays(31))throw new SecurityCandidateException("security_events_period_too_wide");
        if(limit is <1 or >500)throw new SecurityCandidateException("security_events_limit_invalid");
        IReadOnlyList<IReadOnlyList<AccessResource>> domainGroup=[[new("domain",domain)]];
        if(!ResourceAccessDecisions.ReportAction(access,"security.events.chains","view",domainGroup,SecurityFields).Allowed ||
           !access.Capabilities.DecideForResourceGroups("events.view",domainGroup).Allowed)return new("not_authorized",[],false);
        var rows=await store.CandidatesAsync(entityId,domain,start,end,limit+1,ct);
        if(rows.Count>limit+1)throw new InvalidDataException("security_events_candidate_count_invalid");
        return new("available",rows.Take(limit).ToArray(),rows.Count>limit);
    }
}
