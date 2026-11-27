using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Agents.Ingress;

namespace Sli.Server.Agents.Control;

internal static class WorkstationDefaultAssignment
{
    private const string Actor = "system:workstation-default";

    internal static bool IsCandidate(JsonObject agent) =>
        agent["machine_role"]?.ToString() == "workstation"
        && agent["rights_probe"]?["windows_product_type"]?.ToString() == "WinNT"
        && agent["collection_policy"]?["state"]?.ToString() == "active"
        && AgentPolicyAssignments.FindCurrent(agent["assigned_modules"]!.AsArray(), WorkstationsModule.ModuleId) is null;

    // Enrollment and authenticated check-in both own the agent row. Use the same
    // assignment transaction and grant checks as an operator-initiated enable.
    internal static async Task<bool> ReconcileAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid agent,
        IAgentControlAudit audit, CancellationToken ct)
    {
        if (!await WorkstationJournalAdmission.AvailableAsync(db, tx, ct)
            || !await WorkstationJournalAdmission.PluginEnabledAsync(db, tx, ct)) return false;

        await using var eligible = new NpgsqlCommand("""
            select exists(
                select 1 from sli_agents a
                join sli_agent_enrollment_tokens e on e.enrolled_agent_id=a.id
                where a.id=@agent and a.status='active' and a.machine_role='workstation'
                    and a.rights_probe->>'windows_product_type'='WinNT' and a.collection_policy->>'state'='active'
                    and a.template_id is null and e.used_at is not null and e.replacement_for is null
                    and (exists(select 1 from sli_agent_group_approval_links link where link.enrollment_token_id=e.id)
                        or exists(select 1 from sli_agent_audit approval where approval.target=e.id::text
                            and approval.action='token_create'
                            and lower(approval.details->>'registration_host_name')=lower(a.registration_host_name)))
                    and coalesce((select actor=@actor or actor like 'enrollment:%' from sli_agent_audit change
                        where change.target=a.id::text and change.action='module_assign'
                            and change.details->>'module_id'='sli.workstations'
                        order by id desc limit 1), not exists(
                            select 1 from jsonb_array_elements(a.assigned_modules) m
                            where coalesce(m->>'module_id',m#>>'{}')='sli.workstations'))
            )
            """, db, tx);
        eligible.Parameters.AddWithValue("agent", agent);
        eligible.Parameters.AddWithValue("actor", Actor);
        if (await eligible.ExecuteScalarAsync(ct) is not true) return false;

        const string savepoint = "workstation_default";
        await tx.SaveAsync(savepoint, ct);
        try
        {
            await new AgentModuleAssignmentService(audit).AssignAsync(db, tx, JsonSerializer.SerializeToElement(new
            {
                agent_id = agent, module_id = WorkstationsModule.ModuleId, enabled = true,
            }), Actor, ct);
        }
        catch (AgentControlException error) when (error.Message is "agent_source_not_bound" or "agent_channel_owner_conflict"
            or "workstation_journal_profile_unsupported" or "module_disabled")
        {
            await tx.RollbackAsync(savepoint, ct);
            await tx.ReleaseAsync(savepoint, ct);
            return false;
        }
        await tx.ReleaseAsync(savepoint, ct);
        return true;
    }
}
