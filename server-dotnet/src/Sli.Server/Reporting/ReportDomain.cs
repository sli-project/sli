using Sli.Server.Domains;
using Sli.Server.Reporting.V2;

namespace Sli.Server.Reporting;

public sealed class ReportDomainNotConfiguredException() : Exception(Code)
{
    public const string Code = "report_domain_not_configured";
    public const string UserMessage = "Домен отчётов не задан. Укажите его в разделе «Настройки платформы».";
}

internal static class ReportDomain
{
    internal static async Task<long> ResolveIdAsync(IReportSession db, CancellationToken ct)
    {
        var settings = await db.QueryAsync("select value from platform_settings where key='reports.domain_fqdn'", [], ct);
        string? preferred = settings.FirstOrDefault()?["value"]?.ToString().Trim().ToLowerInvariant();
        if (!string.IsNullOrEmpty(preferred))
        {
            var current = await db.QueryAsync("select id from domains where lower(fqdn)=@p0 and not is_archived order by id", [preferred], ct);
            if (current.Count == 1) return current[0]["id"]!.GetValue<long>();
        }
        var observed = await db.QueryAsync("""
            select d.id,d.fqdn as display_name,d.is_archived,observed.observed_at_utc from domains d
            left join lateral(select max(run.observed_at_utc) as observed_at_utc from ad_context_runs run
                where run.domain_id=d.id and run.status='completed') observed on true
            where not d.is_archived order by d.id
            """, [], ct);
        var domains = observed.Select(row => new DomainItem(row["id"]!.GetValue<long>(), row["display_name"]!.ToString(),
            row["is_archived"]?.GetValue<bool>() == true,
            new DomainFreshness(null, null, null, null, row["observed_at_utc"]?.ToString(), null, null)));
        return ReportV2Metadata.ChooseDomain(domains, preferred)?.Id ?? throw new ReportDomainNotConfiguredException();
    }
}
