using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Ingress;
using Sli.Server.Agents.SnapshotPublication;

namespace Sli.Server.Agents.Registry;

public sealed partial class AgentEnrollmentService
{
    // Registration, upgrade and identity recovery share the same serialization lock.
    internal static Task LockRegistrationAsync(NpgsqlConnection db, NpgsqlTransaction tx, CancellationToken ct) =>
        AdvisoryAsync(db, tx, "sli-agent-registration-reconcile", ct);

    private static async Task<(JsonObject Agent, string Source, string SourceId, bool CanBootstrap, bool Pinned)?>
        ReadDcRegistrationAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid agent, CancellationToken ct)
    {
        await using var read = new NpgsqlCommand("""
            select to_jsonb(a)::text,b.source_name,b.source_instance_id,
                issued.details->>'console_token_id' is not null,issued.details->>'server_id' is not null
            from sli_agents a join sli_agent_module_bindings b on b.agent_id=a.id and b.module_id='sli.windows.ad-dc'
            join lateral (select details,actor from sli_agent_audit where target=a.id::text and action='issue'
                order by id desc limit 1) issued on true
            where a.id=@agent and a.status='active' and not a.rights_probe ? 'identity_conflict'
              and b.source_instance_id=coalesce(a.source_host_id,a.host_id)::text and b.channel='ad-dc'
              and (issued.details->>'console_token_id' is not null or (issued.details->>'server_id' is not null and exists (
                select 1 from sli_agent_audit approved where approved.action='token_create'
                    and issued.actor='enrollment:' || approved.target
                    and approved.details->>'registration_host_name' is not null)))
            """, db, tx);
        read.Parameters.AddWithValue("agent", agent);
        await using var row = await read.ExecuteReaderAsync(ct);
        if (!await row.ReadAsync(ct)) return null;
        var state = JsonNode.Parse(row.GetString(0))!.AsObject();
        string source = row.GetString(1);
        var assignment = AgentPolicyAssignments.FindCurrent(state["assigned_modules"]!.AsArray(), AgentAdDcValidator.Live);
        if (StringValue(assignment?["config"] as JsonObject ?? new(), "source_name") != source) return null;
        return (state, source, row.GetString(2), row.GetBoolean(3), row.GetBoolean(4));
    }

    internal static async Task<bool> NeedsDcIdentityAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid agent, CancellationToken ct)
    {
        if (await ReadDcRegistrationAsync(db, tx, agent, ct) is not { CanBootstrap: true } registration) return false;
        var dc = await ResolveDcAsync(db, tx, registration.Source, ct, agent);
        if (dc is null) return !registration.Pinned;
        await using var read = new NpgsqlCommand("select domain_sid is null and not is_archived from domains where id=@id", db, tx);
        read.Parameters.AddWithValue("id", dc.Value.Domain);
        return await read.ExecuteScalarAsync(ct) is true;
    }

    internal static async Task ReconcileDcSourceAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid agent,
        IConfiguration? configuration, CancellationToken ct, JsonObject? identityReport = null)
    {
        if (await ReadDcRegistrationAsync(db, tx, agent, ct) is not { } registration) return;
        var dc = await ResolveDcAsync(db, tx, registration.Source, ct, agent);
        if (identityReport is not null)
        {
            var host = HostName(StringValue(identityReport, "reported_hostname"));
            // A report can repair an owner-issued console registration. It must identify the
            // same computer and cannot replace a pinned controller or a known domain SID.
            if (!registration.CanBootstrap || dc is null && registration.Pinned || host is null ||
                StringValue(identityReport, "machine_role") != "domain_controller" ||
                !string.Equals(host, StringValue(registration.Agent, "registration_host_name"), StringComparison.OrdinalIgnoreCase) ||
                (dc is null && !string.Equals(host, registration.Source, StringComparison.OrdinalIgnoreCase))) return;
            dc = await BootstrapSnapshotDomainAsync(db, tx, identityReport, host, dc, ct) ?? dc;
        }
        if (dc is null) return;

        string? sid, dns;
        await using (var configure = new NpgsqlCommand("""
            with controller as (
                select d.id,d.domain_sid,lower(d.fqdn) as dns,split_part(s.hostname,'.',1) as hostname,
                    coalesce(nullif(s.fqdn,''),case when strpos(s.hostname,'.')>0 then s.hostname
                        else s.hostname || '.' || lower(d.fqdn) end) as address
                from servers s join domains d on d.id=s.domain_id
                where s.id=@server and s.is_active and s.role='domain_controller' and not d.is_archived
            ), target as (
                insert into domain_controller_targets(hostname,connect_address,domain_id,created_by,updated_by)
                select hostname,address,id,'system:agent-registration','system:agent-registration' from controller
                where length(hostname) between 1 and 63 and length(address) between 3 and 253
                on conflict (lower(hostname)) do nothing
            )
            select domain_sid,dns from controller
            """, db, tx))
        {
            configure.Parameters.AddWithValue("server", dc.Value.Server);
            await using var row = await configure.ExecuteReaderAsync(ct);
            if (!await row.ReadAsync(ct)) return;
            sid = row.IsDBNull(0) ? null : row.GetString(0);
            dns = row.GetString(1);
        }
        if (sid is null || CollectionProfile(configuration) != "beta") return;

        var modules = registration.Agent["assigned_modules"]!.AsArray();
        var updated = modules.DeepClone().AsArray();
        long current = registration.Agent["policy_revision"]!.GetValue<long>();
        long revision = AgentModuleAssignmentRules.NextRevision(current,current);
        string? timezone = null;
        foreach (string module in new[] { SnapshotPolicy.Ad, SnapshotPolicy.Gpo })
        {
            if (modules.Any(item => item is JsonObject obj ? StringValue(obj, "module_id") == module : item?.ToString() == module)) continue;
            await using var existing = new NpgsqlCommand("select 1 from sli_agent_snapshot_bindings where agent_id=@agent and module_id=@module", db, tx);
            existing.Parameters.AddWithValue("agent", agent);
            existing.Parameters.AddWithValue("module", module);
            if (await existing.ExecuteScalarAsync(ct) is not null) continue;
            timezone ??= await AdSnapshotSchedule.ReadZoneAsync(db, tx, ct);
            var assignment = DefaultSnapshotAssignment(module, registration.SourceId, sid, dns, revision.ToString(CultureInfo.InvariantCulture), timezone);
            var config = assignment["config"]!.AsObject();
            try { await AgentSnapshotAssignment.ValidateAsync(db, tx, agent, module, config, true, ct); }
            catch (AgentControlException error) when (error.Message == "agent_snapshot_collector_conflict") { continue; }
            await AgentSnapshotAssignment.PublishAsync(db, tx, agent, module, config, true, ct, followServerTimezone: true);
            updated.Add(assignment);
        }
        if (updated.Count == modules.Count) return;

        var control = AgentControlJson.Element(registration.Agent["collection_policy"]!);
        await AgentPolicyStore.SnapshotAsync(db, tx, agent, current, AgentControlJson.Element(modules), control, ct);
        await AgentPolicyStore.SnapshotAsync(db, tx, agent, revision, AgentControlJson.Element(updated), control, ct);
        await using var update = new NpgsqlCommand("update sli_agents set assigned_modules=@modules::jsonb,policy_revision=@revision where id=@agent", db, tx);
        update.Parameters.AddWithValue("agent", agent);
        update.Parameters.AddWithValue("modules", updated.ToJsonString());
        update.Parameters.AddWithValue("revision", revision);
        await update.ExecuteNonQueryAsync(ct);
    }
}
