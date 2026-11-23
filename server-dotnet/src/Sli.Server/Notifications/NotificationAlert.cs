using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Problems;

namespace Sli.Server.Notifications;

internal static class NotificationAlert
{
    internal static async Task<ProblemAccess?> QueueAccessAsync(NotificationDatabase database, long userId, CancellationToken ct)
    {
        var principal = await new AccessReadService(database).FindUserAsync(userId, ct);
        if (principal is null) return null;
        var facts = await new AccessFactsRepository(database).LoadAsync(principal, ct);
        var reports = new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts));
        return NotificationAccess.Queue(reports) ? new(reports) : null;
    }

    internal static async Task<string> FormatAsync(NpgsqlConnection db, NpgsqlTransaction tx, NotificationJob job,
        string baseUrl, ProblemAccess? access, TelegramSettings? telegram, CancellationToken ct)
    {
        if (job.Kind == "report_schedule") return NotificationMessage.Format(job, baseUrl, null, null);

        string language = await NotificationLanguages.ReadAsync(db, tx, job.Recipient, telegram, ct);
        if (job.Kind == "test_problem") return NotificationMessage.Format(job, baseUrl, null, null, language);

        await using var command = new NpgsqlCommand("""
            with alert as materialized (
                select public.notification_alert_finding(@job,@lease) as finding
            ), events as materialized (
                select * from public.notification_alert_events(@job,@lease)
            )
            select finding, public.notification_password_facts395(@job,@lease) as password_facts,
                case when f.rule_code not in ('semantic.qw.password-brute-force','semantic.qw.password-spray')
                    then (select min(hostname) from events where hostname not in ('','-') having count(distinct hostname)=1) end as computer,
                (select min(ip_address) from events where ip_address not in ('','-','::','0.0.0.0')
                    having count(distinct ip_address)=1) as source_address,
                public.notification_server_zone()
            from alert cross join lateral jsonb_to_record(finding) as f(id bigint,rule_code text)
            where finding is not null
            """, db, tx);
        command.Parameters.AddWithValue("job", job.Id);
        command.Parameters.AddWithValue("lease", job.Lease);
        await using var rows = await command.ExecuteReaderAsync(ct);
        if (!await rows.ReadAsync(ct)) throw new FormatException();
        var finding = JsonNode.Parse(rows.GetString(0))!.AsObject();
        if (!rows.IsDBNull(1)) finding["presentation_facts"] = JsonNode.Parse(rows.GetString(1));
        if (!rows.IsDBNull(2)) finding["computer"] = rows.GetString(2);
        if (!rows.IsDBNull(3)) finding["source"] = rows.GetString(3);
        else if (!System.Net.IPAddress.TryParse(ProblemJson.Text(finding["source"]), out _)) finding.Remove("source");
        var zone = rows.IsDBNull(4) ? null : AdSnapshotSchedule.FindIanaZone(rows.GetString(4));
        await rows.DisposeAsync();
        if (ProblemPresentation.IsDcCatalogFinding(ProblemJson.Text(finding["rule_code"])))
        {
            if (access is null) throw new UnauthorizedAccessException();
            long[]? domains;
            try { domains = access.Scope("security.queue").Domains(); }
            catch (ProblemException error) { throw new UnauthorizedAccessException("notification_domain_denied", error); }
            await using var domain = new NpgsqlCommand("select public.dc_catalog_notification_domain401(@job,@lease,@domains)", db, tx);
            domain.Parameters.AddWithValue("job", job.Id);
            domain.Parameters.AddWithValue("lease", job.Lease);
            domain.Parameters.AddWithValue("domains", NpgsqlTypes.NpgsqlDbType.Array | NpgsqlTypes.NpgsqlDbType.Bigint, (object?)domains ?? DBNull.Value);
            if (await domain.ExecuteScalarAsync(ct) is not true) throw new UnauthorizedAccessException();
        }
        return NotificationMessage.Format(job, baseUrl, finding, access, language, zone);
    }
}
