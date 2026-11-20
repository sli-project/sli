using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Infrastructure;

namespace Sli.Server.Ad;

// Legacy users-report decisions, distinct from finding-level suppressions.
public sealed class AccountRiskAcceptances(IPostgresConnectionFactory connections, TimeProvider clock)
{
    static readonly string[] RiskKeys = ["password_never_expires", "password_older_than_90_days", "inactive_over_60_days", "account_locked",
        "enabled_account_expired", "disabled_with_direct_privilege", "multiple_direct_privileged_roles", "enabled_without_last_logon_data"];
    static int Length(string value) => value.EnumerateRunes().Count();
    static string Actor(string? value)
    {
        string actor = value?.Trim() ?? "";
        if (Length(actor) is < 1 or > 256) throw new AdInputException("actor_required");
        return actor;
    }
    static async Task RequireAuditReady(NpgsqlConnection db, CancellationToken ct)
    {
        // Migration 099's invoker trigger cannot write the audit as adlog_user.
        // Fail closed until its owner installs a safe definer function, or the
        // connecting role already owns the audit. Never retry as a privileged role.
        var rows = await AdJson.ReadAsync(db, """
            select exists(
                select 1 from pg_trigger t join pg_proc p on p.oid=t.tgfoid
                where t.tgrelid='public.account_risk_acceptances'::regclass
                  and t.tgname='account_risk_acceptance_audit_trigger' and t.tgenabled in ('O','A')
                  and has_function_privilege(p.oid,'EXECUTE')
                  and (p.prosecdef or (has_table_privilege('public.account_risk_acceptance_audit','INSERT')
                       and has_sequence_privilege('public.account_risk_acceptance_audit_id_seq','USAGE')))
            ) as ready
            """, ct);
        if (rows.Single()["ready"]?.GetValue<bool>() != true) throw new AdInputException("account_risk_acceptance_audit_not_ready");
    }

    // The caller supplies the same scoped risk report used for display. It is read
    // only after the human decision has been validated, never from caller evidence.
    public async Task<JsonObject> CreateAsync(long entityId, long[]? domainIds, string riskKey, string reason, string responsible,
        string validUntilUtc, string actor, Func<long[]?, string, CancellationToken, Task<JsonObject>> readRiskReport, CancellationToken ct)
    {
        actor = Actor(actor);
        riskKey = riskKey.Trim(); reason = reason.Trim(); responsible = responsible.Trim();
        if (!RiskKeys.Contains(riskKey)) throw new AdInputException("invalid_risk_key");
        if (Length(reason) is < 10 or > 2000) throw new AdInputException("invalid_acceptance_reason");
        if (Length(responsible) is < 1 or > 256) throw new AdInputException("invalid_acceptance_responsible");
        var now = clock.GetUtcNow();
        if (!DateTimeOffset.TryParse(validUntilUtc, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var until) || until <= now || until > now.AddDays(365))
            throw new AdInputException("invalid_acceptance_expiry");
        var report = await readRiskReport(domainIds, riskKey, ct);
        if (report.Text("state") != "available") throw new AdAccessException("risk_evidence_not_actionable");
        var account = (report["items"] as JsonArray)?.FirstOrDefault(row => row.Int("entity_id") == entityId);
        if (account is null) throw new AdAccessException("risk_subject_not_visible_or_not_qualified");
        await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        await RequireAuditReady(db, ct);
        try
        {
            await AdJson.ReadAsync(db, """
                update account_risk_acceptances set status=case when valid_until<=now() then 'expired' else 'superseded' end,
                    revoked_by=$1,revoke_reason=$2 where entity_id=$3 and risk_key=$4 and rule_version=1 and status='active'
                """, ct, actor, reason, entityId, riskKey);
            var rows = await AdJson.ReadAsync(db, """
                insert into account_risk_acceptances(public_id,entity_id,domain_id,risk_key,rule_version,reason,responsible,valid_until,created_by)
                values($1,$2,$3,$4,1,$5,$6,$7,$8)
                returning public_id,entity_id,domain_id,risk_key,rule_version,reason,responsible,status,valid_from,valid_until,created_by,created_at
                """, ct, Guid.NewGuid(), entityId, account.Int("domain_id"), riskKey, reason, responsible, until.ToUniversalTime(), actor);
            await tx.CommitAsync(ct); return rows.Single();
        }
        catch (PostgresException error) when (error.SqlState == "23505") { throw new AdInputException("active_risk_acceptance_exists"); }
    }

    public async Task<JsonObject> RevokeAsync(string publicId, long[]? domainIds, string actor, string? reason, CancellationToken ct)
    {
        actor = Actor(actor); reason = reason?.Trim() ?? "";
        if (Length(reason) is < 3 or > 2000) throw new AdInputException("invalid_revocation_reason");
        if (!Guid.TryParse(publicId, out var id)) throw new AdInputException("invalid_acceptance_id");
        long[] domains = (domainIds ?? []).Where(d => d > 0).Distinct().Order().ToArray();
        if (domainIds is not null && domains.Length == 0) throw new AdAccessException("users_report_field_category_scope_denied");
        await using var db = await connections.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        await RequireAuditReady(db, ct);
        string sql = """
            update account_risk_acceptances as acceptance
            set status='revoked',revoked_at=now(),revoked_by=$1,revoke_reason=$2
            from entities_v2 as entity
            where acceptance.entity_id=entity.id and acceptance.public_id=$3
              and acceptance.status='active' and acceptance.valid_until>now()
            """;
        object?[] args = [actor, reason, id];
        if (domainIds is not null) { sql += " and entity.domain_id=any($4)"; args = [.. args, domains]; }
        sql += " returning acceptance.public_id,acceptance.status,acceptance.revoked_at,acceptance.revoked_by,acceptance.revoke_reason";
        var rows = await AdJson.ReadAsync(db, sql, ct, args);
        if (rows.Count == 0) throw new AdAccessException("risk_acceptance_not_visible_or_not_active");
        await tx.CommitAsync(ct); return rows.Single();
    }
}
