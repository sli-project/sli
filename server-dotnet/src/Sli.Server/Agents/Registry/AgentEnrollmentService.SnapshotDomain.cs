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
        (long Server, string Name, long Domain, long? Site)? dc, CancellationToken ct)
    {
        string? sid = StringValue(body, "domain_sid");
        if (sid is null || !Regex.IsMatch(sid, @"\AS-1-5-21-(?:[1-9][0-9]{0,9}|0)(?:-(?:[1-9][0-9]{0,9}|0)){2}\z")
            || sid[9..].Split('-').Any(part => !uint.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out _)))
            return null;

        string dns, forest, fqdn;
        try
        {
            dns = InstallationSettings.Dns(StringValue(body, "domain_dns") ?? "");
            forest = InstallationSettings.Dns(StringValue(body, "forest_dns") ?? "");
            fqdn = InstallationSettings.Dns(hostname.Contains('.') ? hostname : $"{hostname}.{dns}");
        }
        catch (InstallationException) { return null; }
        if (fqdn.Length > 128 || !fqdn.EndsWith("." + dns, StringComparison.Ordinal)) return null;

        // The owner-issued console token authorizes bootstrapping a first domain.
        // Once a SID is registered, console enrollment cannot take over that scope.
        long? domain = null;
        await using (var read = new NpgsqlCommand("""
            select d.id,d.fqdn,d.domain_sid,f.name from domains d join forests f on f.id=d.forest_id
            where not d.is_archived or d.domain_sid=@sid or lower(d.fqdn)=@dns
            order by d.id limit 2 for update of d
            """, db, tx))
        {
            read.Parameters.AddWithValue("sid", sid);
            read.Parameters.AddWithValue("dns", dns);
            await using var rows = await read.ExecuteReaderAsync(ct);
            if (await rows.ReadAsync(ct))
            {
                domain = rows.GetInt64(0);
                if (!string.Equals(dns, rows.GetString(1), StringComparison.OrdinalIgnoreCase) || !rows.IsDBNull(2)
                    || !string.Equals(forest, rows.GetString(3), StringComparison.OrdinalIgnoreCase)
                    || await rows.ReadAsync(ct)) return null;
            }
        }
        if (dc is { } configured && configured.Domain != domain) return null;
        if (dc is null)
        {
            await using var known = new NpgsqlCommand("""
                select exists(select 1 from servers where lower(hostname) in (@host,@fqdn) or lower(fqdn) in (@host,@fqdn)
                    or (strpos(@host,'.')=0 and @host=split_part(lower(coalesce(nullif(fqdn,''),hostname)),'.',1)))
                """, db, tx);
            known.Parameters.AddWithValue("host", hostname.ToLowerInvariant());
            known.Parameters.AddWithValue("fqdn", fqdn);
            if (await known.ExecuteScalarAsync(ct) is true) return null;
        }

        await using (var bind = new NpgsqlCommand(domain is null ? """
            with forest as (insert into forests(name) values(@forest) on conflict(name) do update set name=excluded.name returning id)
            insert into domains(forest_id,fqdn,domain_sid) select id,@dns,@sid from forest
            on conflict(forest_id,fqdn) do nothing returning id
            """ : """
            update domains set domain_sid=@sid where id=@domain and not is_archived and domain_sid is null returning id
            """, db, tx))
        {
            bind.Parameters.AddWithValue("forest", forest);
            bind.Parameters.AddWithValue("dns", dns);
            bind.Parameters.AddWithValue("sid", sid);
            if (domain is { } id) bind.Parameters.AddWithValue("domain", id);
            if (await bind.ExecuteScalarAsync(ct) is not long idBound) return null;
            domain = idBound;
        }
        if (dc is not null) return dc;
        await using var register = new NpgsqlCommand("""
            insert into servers(domain_id,hostname,fqdn,role) values(@domain,@host,@fqdn,'domain_controller') returning id
            """, db, tx);
        register.Parameters.AddWithValue("domain", domain.Value);
        register.Parameters.AddWithValue("host", hostname);
        register.Parameters.AddWithValue("fqdn", fqdn);
        return ((long)(await register.ExecuteScalarAsync(ct))!, hostname, domain.Value, null);
    }
}
