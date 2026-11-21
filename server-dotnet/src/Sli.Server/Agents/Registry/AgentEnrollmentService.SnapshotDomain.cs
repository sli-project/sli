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
        if (fqdn[(fqdn.IndexOf('.') + 1)..] != dns) return null;

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
        if (sid is not null && knownSid is null)
        {
            await using var other = new NpgsqlCommand("select exists(select 1 from domains where not is_archived and lower(fqdn)<>@dns)", db, tx);
            other.Parameters.AddWithValue("dns", dns);
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
        if (dc is not null) return dc;
        await using var register = new NpgsqlCommand("""
            insert into servers(domain_id,hostname,fqdn,role) values(@domain,@host,@fqdn,'domain_controller')
            on conflict(domain_id,hostname) do nothing returning id
            """, db, tx);
        register.Parameters.AddWithValue("domain", domain.Value);
        register.Parameters.AddWithValue("host", hostname);
        register.Parameters.AddWithValue("fqdn", fqdn);
        return await register.ExecuteScalarAsync(ct) is long server ? (server, hostname, domain.Value, null) : null;
    }

    private static Task RecordAgentReportedDcAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid agent, long server, CancellationToken ct) =>
        AuditAsync(db, tx, "module_assign", "system:agent-registration", agent.ToString("D"),
            new JsonObject { ["module_id"] = "sli.windows.ad-dc", ["server_id"] = server, ["source"] = "agent_reported" }, ct);
}
