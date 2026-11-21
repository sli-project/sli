using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.InstallationSetup;

namespace Sli.Server.Agents.Registry;

public sealed partial class AgentEnrollmentService
{
    private static async Task<(long Server, string Name, long Domain, long? Site)?> BootstrapSnapshotDomainAsync(
        NpgsqlConnection db, NpgsqlTransaction tx, JsonObject body, string hostname,
        (long Server, string Name, long Domain, long? Site)? dc, CancellationToken ct, bool useDomainSid = true)
    {
        string? sid = useDomainSid ? StringValue(body, "domain_sid") : null;
        if (useDomainSid && body.ContainsKey("domain_sid") &&
            (sid is null || !Regex.IsMatch(sid, @"\AS-1-5-21-(?:[1-9][0-9]{0,9}|0)(?:-(?:[1-9][0-9]{0,9}|0)){2}\z")
            || sid[9..].Split('-').Any(part => !uint.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out _))))
            return null;
        if (dc is not null && sid is null) return dc;

        string dns, fqdn;
        string? forest;
        try
        {
            dns = InstallationSettings.Dns(StringValue(body, "domain_dns") ?? "");
            forest = body.ContainsKey("forest_dns") ? InstallationSettings.Dns(StringValue(body, "forest_dns") ?? "") : null;
            fqdn = InstallationSettings.Dns(hostname.Contains('.') ? hostname : $"{hostname}.{dns}");
        }
        catch (InstallationException) { return null; }
        if (dns == "example.invalid" || forest == "example.invalid" || fqdn[(fqdn.IndexOf('.') + 1)..] != dns) return null;

        long? domain = null;
        string? knownSid = null;
        await using (var read = new NpgsqlCommand("""
            select d.id,lower(d.fqdn),d.domain_sid,lower(f.name),d.is_archived
            from domains d join forests f on f.id=d.forest_id
            where lower(d.fqdn)=@dns or d.domain_sid=@sid
            order by d.id limit 2 for update of d
            """, db, tx))
        {
            read.Parameters.Add("sid", NpgsqlTypes.NpgsqlDbType.Text).Value = (object?)sid ?? DBNull.Value;
            read.Parameters.AddWithValue("dns", dns);
            await using var rows = await read.ExecuteReaderAsync(ct);
            if (await rows.ReadAsync(ct))
            {
                domain = rows.GetInt64(0);
                knownSid = rows.IsDBNull(2) ? null : rows.GetString(2);
                if (rows.GetString(1) != dns || rows.GetBoolean(4) ||
                    forest is not null && rows.GetString(3) != forest ||
                    sid is not null && knownSid is not null && knownSid != sid
                    || await rows.ReadAsync(ct)) return null;
            }
        }
        if (dc is { } configured && configured.Domain != domain) return null;
        if (domain is null && forest is null) return null;
        if (dc is null)
        {
            await using var known = new NpgsqlCommand("""
                select exists(select 1 from servers where lower(hostname) in (@host,@fqdn) or lower(fqdn) in (@host,@fqdn)
                    or (strpos(@host,'.')=0 and @host=split_part(lower(coalesce(nullif(fqdn,''),hostname)),'.',1))
                    or (strpos(coalesce(nullif(fqdn,''),hostname),'.')=0 and lower(hostname)=split_part(@host,'.',1)))
                """, db, tx);
            known.Parameters.AddWithValue("host", hostname.ToLowerInvariant());
            known.Parameters.AddWithValue("fqdn", fqdn);
            if (await known.ExecuteScalarAsync(ct) is true) return null;
        }

        // An owner-issued grant may establish the SID during first-domain setup.
        // An existing SID remains authoritative when registering another controller.
        long placeholder = 0;
        if (sid is not null && knownSid is null)
        {
            // Older native setup seeded this pair without configuring AD. Keep
            // its ID and history separate from the authenticated directory.
            await using (var legacy = new NpgsqlCommand("""
                select d.id from domains d join forests f on f.id=d.forest_id
                where d.fqdn='example.invalid' and f.name='example.invalid' and not d.is_archived
                    and d.domain_sid is null and d.netbios_name is null
                    and not exists(select 1 from servers where domain_id=d.id)
                    and not exists(select 1 from domain_controller_targets where domain_id=d.id)
                    and not exists(select 1 from sli_agent_module_bindings where password_detection_domain_id=d.id)
                order by d.id limit 1 for update of d
                """, db, tx))
                if (await legacy.ExecuteScalarAsync(ct) is long id) placeholder = id;
            await using var other = new NpgsqlCommand("""
                select exists(select 1 from domains where not is_archived and lower(fqdn)<>@dns and id<>@placeholder)
                """, db, tx);
            other.Parameters.AddWithValue("dns", dns);
            other.Parameters.AddWithValue("placeholder", placeholder);
            if (await other.ExecuteScalarAsync(ct) is true) return null;
        }
        if (domain is null)
        {
            await using var create = new NpgsqlCommand("""
                with known_forest as materialized (select id from forests where lower(name)=@forest),
                     new_forest as (
                         insert into forests(name) select @forest where not exists(select 1 from known_forest)
                         on conflict(name) do update set name=excluded.name returning id
                     )
                insert into domains(forest_id,fqdn,domain_sid)
                select id,@dns,@sid from new_forest
                union all select id,@dns,@sid from known_forest where (select count(*) from known_forest)=1
                on conflict(forest_id,fqdn) do nothing returning id
                """, db, tx);
            create.Parameters.AddWithValue("forest", forest!);
            create.Parameters.AddWithValue("dns", dns);
            create.Parameters.Add("sid", NpgsqlTypes.NpgsqlDbType.Text).Value = (object?)sid ?? DBNull.Value;
            if (await create.ExecuteScalarAsync(ct) is not long created) return null;
            domain = created;
        }
        else if (sid is not null && knownSid is null)
        {
            await using var bind = new NpgsqlCommand("update domains set domain_sid=@sid where id=@domain", db, tx);
            bind.Parameters.AddWithValue("domain", domain.Value);
            bind.Parameters.AddWithValue("sid", sid);
            await bind.ExecuteNonQueryAsync(ct);
        }
        if (dc is null)
        {
            await using var register = new NpgsqlCommand("""
                insert into servers(domain_id,hostname,fqdn,role) values(@domain,@host,@fqdn,'domain_controller')
                on conflict(domain_id,hostname) do nothing returning id
                """, db, tx);
            register.Parameters.AddWithValue("domain", domain.Value);
            register.Parameters.AddWithValue("host", hostname);
            register.Parameters.AddWithValue("fqdn", fqdn);
            if (await register.ExecuteScalarAsync(ct) is not long server) return null;
            dc = (server, hostname, domain.Value, null);
        }
        if (placeholder != 0)
        {
            await using var archive = new NpgsqlCommand("update domains set is_archived=true where id=@placeholder", db, tx);
            archive.Parameters.AddWithValue("placeholder", placeholder);
            await archive.ExecuteNonQueryAsync(ct);
        }
        return dc;
    }

    private static async Task RetireBootstrapDomainAsync(NpgsqlConnection db, NpgsqlTransaction tx, CancellationToken ct)
    {
        long placeholder;
        string replacement;
        await using (var read = new NpgsqlCommand("""
            with preferred as (select lower(btrim(value)) as fqdn from platform_settings where key='reports.domain_fqdn')
            select d.id, (select coalesce(min(real.fqdn) filter(where lower(real.fqdn)=p.fqdn), min(real.fqdn))
                from domains real left join preferred p on true
                where not real.is_archived and lower(real.fqdn)<>'example.invalid'
                having count(*)=1 or count(*) filter(where lower(real.fqdn)=p.fqdn)=1)
            from domains d join forests f on f.id=d.forest_id
            where d.fqdn='example.invalid' and f.name='example.invalid'
                and d.domain_sid is null and d.netbios_name is null
            for update of d
            """, db, tx))
        await using (var rows = await read.ExecuteReaderAsync(ct))
        {
            if (!await rows.ReadAsync(ct) || rows.IsDBNull(1)) return;
            placeholder = rows.GetInt64(0);
            replacement = rows.GetString(1);
        }

        await using (var setting = new NpgsqlCommand("""
            insert into platform_settings(key,value,updated_by) values('reports.domain_fqdn',@replacement,'system:agent-registration')
            on conflict(key) do update set value=excluded.value,updated_by=excluded.updated_by,updated_at=clock_timestamp()
            where lower(btrim(platform_settings.value))='example.invalid'
            """, db, tx))
        {
            setting.Parameters.AddWithValue("replacement", replacement);
            await setting.ExecuteNonQueryAsync(ct);
        }

        // History can use the numeric domain ID without a foreign key. Preserve
        // that history and let restrictive foreign keys protect other owners.
        const string savepoint = "retire_bootstrap_domain";
        await tx.SaveAsync(savepoint, ct);
        try
        {
            await using var delete = new NpgsqlCommand("""
                delete from domains d where d.id=@id
                    and not exists(select 1 from servers where domain_id=d.id)
                    and not exists(select 1 from sites where domain_id=d.id)
                    and not exists(select 1 from domain_controller_targets where domain_id=d.id)
                    and not exists(select 1 from sli_agent_module_bindings where password_detection_domain_id=d.id)
                    and not exists(select 1 from entities_v2 where domain_id=d.id)
                    and not exists(select 1 from event_hot where domain_id=d.id)
                    and not exists(select 1 from event_cold_facts where domain_id=d.id)
                    and not exists(select 1 from event_cold_daily where domain_id=d.id)
                    and not exists(select 1 from semantic_processing_outbox where domain_id=d.id)
                    and not exists(select 1 from finding_event_copies337 where domain_id=d.id)
                    and not exists(select 1 from ad_snapshot_history_confirmations where domain_id=d.id)
                    and not exists(select 1 from ad_snapshot_change_history where domain_id=d.id)
                """, db, tx);
            delete.Parameters.AddWithValue("id", placeholder);
            if (await delete.ExecuteNonQueryAsync(ct) != 0)
            {
                await tx.ReleaseAsync(savepoint, ct);
                return;
            }
        }
        catch (PostgresException error) when (error.SqlState == PostgresErrorCodes.ForeignKeyViolation)
        {
            await tx.RollbackAsync(savepoint, ct);
        }
        await tx.ReleaseAsync(savepoint, ct);
        await using var archive = new NpgsqlCommand("update domains set is_archived=true where id=@id and not is_archived", db, tx);
        archive.Parameters.AddWithValue("id", placeholder);
        await archive.ExecuteNonQueryAsync(ct);
    }

    private static Task RecordAgentReportedDcAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid agent, long server, CancellationToken ct) =>
        AuditAsync(db, tx, "module_assign", "system:agent-registration", agent.ToString("D"),
            new JsonObject { ["module_id"] = "sli.windows.ad-dc", ["server_id"] = server, ["source"] = "agent_reported" }, ct);
}
