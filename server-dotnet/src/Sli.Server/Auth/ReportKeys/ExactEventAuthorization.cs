using System.Globalization;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Infrastructure;
using Sli.Server.Entities;
using Sli.Server.Storage.EventReports;

namespace Sli.Server.Auth.ReportKeys;

public interface IExactEventAuthorization
{
    Task<AuthenticationFailure?> CheckAsync(Principal? principal, string path, CancellationToken ct);
}

public sealed class ExactEventAuthorization(IPostgresConnectionFactory connections, IConfiguration? config = null) : IExactEventAuthorization
{
    private const string Prefix = "/api/v1/events/";
    private static readonly HashSet<string> Fields = ["raw_evidence", "technical", "security"];

    public async Task<AuthenticationFailure?> CheckAsync(Principal? principal, string path, CancellationToken ct)
    {
        if (principal?.RestrictedReportKey != true || !path.StartsWith(Prefix, StringComparison.Ordinal)) return null;
        var denied = new AuthenticationFailure(404, "event_not_found");
        var suffix = path[Prefix.Length..];
        if (!Regex.IsMatch(suffix, @"\A[1-9][0-9]{0,18}\z", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)
            || !long.TryParse(suffix, NumberStyles.None, CultureInfo.InvariantCulture, out long eventId)) return denied;
        await using var connection = await connections.OpenAsync(ct);
        await using var query = new NpgsqlCommand("with short_events as (" + EntityShortSql.Source("@boundary", daily:false) + ") " + """
            select e.domain_id from short_events e
            join servers s on s.id=e.server_id and s.domain_id=e.domain_id
            where e.id=@id and e.channel is not null and e.provider_name is not null
            """, connection);
        query.Parameters.AddWithValue("id", eventId);
        query.Parameters.AddWithValue("boundary", EventReadService.ShortBoundary(config));
        object? value = await query.ExecuteScalarAsync(ct);
        if (!TryDomain(value, out long domainId)) return denied;
        var facts = await new AccessFactsRepository(connections).LoadAsync(principal, ct);
        var capabilities = new CapabilityComposer().Compose(facts);
        var access = new ReportEligibility().Compose(facts, capabilities);
        var report = access.Reports.FirstOrDefault(r => r.ReportKey == "events.explorer" && r.Allowed);
        if (report is null) return denied;
        return report.Grants.Any(grant => grant.AllowedActions.Contains("view")
            && Fields.IsSubsetOf(grant.FieldCategories) && ExactEventScope.AllowsDomain(grant.Scope, domainId)) ? null : denied;
    }

    public static bool TryDomain(object? value, out long domainId)
    {
        domainId = 0;
        if (value is null or DBNull) return false;
        try { domainId = Convert.ToInt64(value, CultureInfo.InvariantCulture); return domainId > 0; }
        catch (Exception error) when (error is FormatException or InvalidCastException or OverflowException) { return false; }
    }
}
