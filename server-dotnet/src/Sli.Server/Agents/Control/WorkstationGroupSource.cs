using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Groups;
using Sli.Server.Agents.Ingress;
using Sli.Server.InstallationSetup;

namespace Sli.Server.Agents.Control;

internal static class WorkstationGroupSource
{
    internal static async Task<bool> PrepareAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid agent,
        bool installerApprovalAvailable, CancellationToken ct)
    {
        if (await WorkstationJournalAdmission.ReadAsync(db, tx, agent, null, null, ct) is not null) return true;
        if (installerApprovalAvailable && await AgentGroupStore.Scalar(db, tx,
            "select public.workstation_package_approved459(@agent)", ct, ("agent", agent)) is true)
            return await PrepareInstallerAsync(db, tx, agent, ct);

        // Group enrollments still require an explicitly approved AD computer.
        var bindings = await AgentGroupStore.Rows(db, tx, """
            select batch.domain_id,request.computer_entity_id,a.registration_host_name,
                   enrollment.used_at is not null and enrollment.replacement_for is null
                   and request.status='approved' and request.host_id=enrollment.host_id
                   and request.key_fingerprint=enrollment.key_fingerprint
                   and request.instance_name is not distinct from enrollment.instance_name
                   and a.host_id=enrollment.host_id
                   and a.instance_name is not distinct from enrollment.instance_name as valid
            from public.sli_agents a
            join public.sli_agent_enrollment_tokens enrollment on enrollment.enrolled_agent_id=a.id
            join public.sli_agent_group_approval_links link on link.enrollment_token_id=enrollment.id
            join public.sli_agent_group_requests request on request.id=link.request_id
            join public.sli_agent_group_tokens batch on batch.id=request.token_id
            where a.id=@agent
            """, ct, ("agent", agent));
        // Ordinary/replacement enrollment retains its existing inventory admission path.
        if (bindings.Count == 0) return true;
        if (bindings.Count != 1 || bindings[0]["valid"]?.GetValue<bool>() != true) return false;
        var binding = bindings[0];
        long domain = AgentGroupStore.Long(binding, "domain_id");
        long version;
        try
        {
            (version, _) = await AgentGroupDirectory.ResolveAsync(db, tx,
                AgentGroupStore.Long(binding, "computer_entity_id"), domain, false, ct);
        }
        catch (AgentControlException) { return false; }
        var raw = await AgentGroupStore.Scalar(db, tx,
            "select attributes_json::text from public.ad_context_entity_versions where id=@version", ct, ("version", version));
        var attrs = (JsonNode.Parse((string)raw!))?["attributes"];
        string? os = AgentGroupInput.Text(attrs?["operating_system"]);
        if (os is null || !os.StartsWith("Windows ", StringComparison.OrdinalIgnoreCase)
            || os.Contains("Server", StringComparison.OrdinalIgnoreCase)
            || attrs?["user_account_control"] is not JsonValue uac || !uac.TryGetValue<long>(out long flags)
            || (flags & (8192 | 2)) != 0) return false;
        string fqdn;
        try { fqdn = InstallationSettings.Dns(AgentGroupInput.Text(attrs?["dns_host_name"]) ?? ""); }
        catch (InstallationException) { return false; }
        string hostname = fqdn[..fqdn.IndexOf('.')];
        string? registered = AgentGroupInput.Text(binding["registration_host_name"]);
        if (!string.Equals(registered, hostname, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(registered, fqdn, StringComparison.OrdinalIgnoreCase)) return false;
        if (await AgentGroupStore.Scalar(db, tx,
            "select exists(select 1 from public.domains where id=@domain and not is_archived)", ct, ("domain", domain)) is not true)
            return false;

        var existing = await AgentGroupStore.Rows(db, tx, """
            select s.domain_id,s.hostname,s.fqdn,s.role,s.is_active
            from public.servers s join public.domains d on d.id=s.domain_id
            where d.fqdn<>@installer_domain and (lower(s.hostname) in (@host,@fqdn) or lower(s.fqdn) in (@host,@fqdn))
            for update of s
            """, ct, ("host", hostname), ("fqdn", fqdn), ("installer_domain", WorkstationJournalAdmission.InstallerDomain));
        if (existing.Count != 0)
            return existing.Count == 1 && AgentGroupStore.Long(existing[0], "domain_id") == domain
                && existing[0]["is_active"]?.GetValue<bool>() == true
                && AgentGroupInput.Text(existing[0]["role"]) == "workstation"
                && string.Equals(AgentGroupInput.Text(existing[0]["hostname"]), hostname, StringComparison.OrdinalIgnoreCase)
                && string.Equals(AgentGroupInput.Text(existing[0]["fqdn"]), fqdn, StringComparison.OrdinalIgnoreCase);

        // Never relabel or reactivate a conflicting inventory row. A concurrent insert
        // must be revalidated on a fresh attempt, not accepted through the name-only grant.
        return await AgentGroupStore.Execute(db, tx, """
            insert into public.servers(domain_id,hostname,fqdn,role,os_name,os_version,is_active)
            values(@domain,@host,@fqdn,'workstation',@os,@version,true)
            on conflict(domain_id,hostname) do nothing
            """, ct, ("domain", domain), ("host", hostname), ("fqdn", fqdn), ("os", os),
            ("version", AgentGroupInput.Text(attrs?["operating_system_version"]))) == 1;
    }

    private static async Task<bool> PrepareInstallerAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid agent, CancellationToken ct)
    {
        // The short store requires an inventory ID and a domain ID. Keep the
        // installer-owned namespace out of AD enrollment and domain selection.
        return await AgentGroupStore.Execute(db, tx, """
            with forest as (
                insert into public.forests(name) values(@namespace)
                on conflict(name) do update set name=excluded.name returning id
            ), station_scope as (
                insert into public.domains as d(forest_id,fqdn,is_archived)
                select id,@namespace,true from forest
                on conflict(forest_id,fqdn) do update set fqdn=excluded.fqdn
                where d.is_archived and d.domain_sid is null and d.netbios_name is null
                returning id
            )
            insert into public.servers as s(domain_id,hostname,fqdn,role)
            select station_scope.id,lower(a.registration_host_name collate pg_catalog.pg_unicode_fast),a.registration_host_name,'workstation'
            from station_scope cross join public.sli_agents a
            where a.id=@agent and nullif(a.registration_host_name,'') is not null
            on conflict(domain_id,hostname) do update set fqdn=excluded.fqdn,is_active=true
            where s.role='workstation' and lower(s.fqdn collate pg_catalog.pg_unicode_fast)=excluded.hostname
            """, ct, ("namespace", WorkstationJournalAdmission.InstallerDomain), ("agent", agent)) == 1;
    }
}
