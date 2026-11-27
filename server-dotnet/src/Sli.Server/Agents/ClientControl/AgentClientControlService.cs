using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Access;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Ingress;
using Sli.Server.Agents.Registry;
using Sli.Server.Agents.Updates;
namespace Sli.Server.Agents.ClientControl;

public sealed class AgentClientControlService(IAgentControlAudit audit,TimeProvider clock,IConfiguration? configuration = null,
    AgentDcSourceDiagnostics? diagnostics = null)
{
    // Authentication already locked the agent then certificate in this transaction.
    private static async Task<JsonObject> ReadAsync(NpgsqlConnection db,NpgsqlTransaction tx,Guid id,CancellationToken ct)
    {
        await using var command=new NpgsqlCommand("select to_jsonb(a)::text from sli_agents a where id=@id",db,tx);command.Parameters.AddWithValue("id",id);
        return JsonNode.Parse((string?)await command.ExecuteScalarAsync(ct) ?? throw new InvalidOperationException("agent_identity_unavailable"))!.AsObject();
    }
    public static async Task LockUpdateWavesAsync(NpgsqlConnection db,NpgsqlTransaction tx,CancellationToken ct)
    { await using var command=new NpgsqlCommand("select pg_advisory_xact_lock(hashtext('sli_agent_update_waves'))",db,tx);await command.ExecuteNonQueryAsync(ct); }
    public async Task<JsonObject> CheckInAsync(NpgsqlConnection db,NpgsqlTransaction tx,AgentIdentity identity,CancellationToken ct)
    {
        var agent=await ReadAsync(db,tx,identity.Id,ct);bool fileHook=true;
        await AgentPolicyAssignments.DisableUnavailableAsync(db,tx,agent,ct);
        await SnapshotPublication.AdSnapshotSchedule.RefreshAsync(db,tx,agent,ct);
        // Bundled file-audit is present in this native build. An activated Python
        // generation's hook inventory awaits M5; never silently assume its hooks.
        if(agent["file_audit"]?["request"] is JsonObject request && request.Count>0 && new PluginGenerationReader().Read("sli.file-audit").Generation is not null)
            throw new InvalidOperationException("agent_plugin_generation_unavailable");
        var result=AgentClientPolicy.CheckIn(agent,fileHook);
        // The management command runs while the server verifies coverage. Until then the agent cannot capture events.
        if(agent["file_audit"] is JsonObject fileAudit
            && fileAudit["permissions_scope"]?.ToString() is { } scope
            && AgentPolicyAssignments.FindCurrent(result["assigned_modules"]!.AsArray(),"sli.file-audit") is { } fileAssignment)
        {
            bool verified = await AgentPolicyAssignments.FilePermissionsAvailableAsync(db,tx,ct)
                && await AgentPolicyAssignments.FilePermissionsAllowedAsync(db,tx,identity.Id,null,true,ct);
            if (!verified)
            {
                fileAssignment["enabled"]=false;
                var receipt = fileAudit["scopes"]?[scope];
                if (receipt?["state"]?.ToString() == "partial" && receipt["reason_code"]?.ToString() == "coverage_incomplete"
                    && await AgentPolicyAssignments.FileActivityAvailableAsync(db,tx,ct))
                    result["file_audit_retry_paged_apply"]=true;
            }
            else if (await AgentPolicyAssignments.FileActivityAvailableAsync(db,tx,ct))
                result["file_audit_activity"]=true;
        }
        await AgentPolicyAssignments.FilterAccountingCheckInAsync(db,tx,result,ct);
        if (AgentEnrollmentService.CollectionProfile(configuration) == "beta" &&
            await AgentEnrollmentService.NeedsDcIdentityAsync(db, tx, identity.Id, ct))
            result["dc_identity_required"] = true;
        result["agent_update"]=await ShippedAgentUpdate.OfferAsync(db,tx,agent,identity,audit,ct);
        return result;
    }
    public async Task<JsonObject> ReportAsync(NpgsqlConnection db,NpgsqlTransaction tx,AgentIdentity identity,JsonNode? body,CancellationToken ct)
    {
        JsonObject? dcIdentity = null;
        if (body is JsonObject report && report.TryGetPropertyValue("dc_identity", out var evidence))
        {
            if (evidence is not JsonObject dc ||
                !dc.ContainsKey("reported_hostname") ||
                dc.Any(field => field.Key is not ("machine_role" or "reported_hostname" or "domain_dns" or "forest_dns" or "domain_sid")))
                throw new AgentControlException("invalid_agent_module_config");
            dcIdentity = dc;
            report.Remove("dc_identity");
        }
        var agent=await ReadAsync(db,tx,identity.Id,ct);var change=AgentClientPolicy.Report(agent,body,clock.GetUtcNow());
        await using(var command=new NpgsqlCommand(change.AppliedRevision is null ? "update sli_agents set rights_probe=@probe where id=@id" :
            "update sli_agents set rights_probe=@probe,applied_policy_revision=@revision where id=@id",db,tx)) {
            command.Parameters.AddWithValue("probe",NpgsqlDbType.Jsonb,change.Probe.ToJsonString());
            if(change.AppliedRevision is not null)command.Parameters.AddWithValue("revision",change.AppliedRevision.Value);
            command.Parameters.AddWithValue("id",identity.Id);await command.ExecuteNonQueryAsync(ct);
        }
        if(change.AppliedState is not null) {
            await using var state=new NpgsqlCommand("update sli_agents set applied_collection_state=@state where id=@id",db,tx);
            state.Parameters.AddWithValue("state",change.AppliedState);state.Parameters.AddWithValue("id",identity.Id);await state.ExecuteNonQueryAsync(ct);
        }
        string id=identity.Id.ToString("D");
        if(change.Acknowledged)await audit.AppendAsync(db,tx,"policy_ack","agent:"+id,id,new { revision=change.AppliedRevision },ct);
        if(change.ProbeResult is not null) {
            var details=(JsonObject)change.ProbeResult.DeepClone();details["revision"]=body!["applied_policy_revision"]!.DeepClone();
            await audit.AppendAsync(db,tx,"probe_report","agent:"+id,id,details,ct);
        }
        if (dcIdentity is not null && AgentEnrollmentService.CollectionProfile(configuration) == "beta")
        {
            await AgentManagementService.LockImportAsync(db, tx, identity.Id, ct);
            if (await AgentEnrollmentService.ReconcileDcSourceAsync(db, tx, identity.Id, configuration, ct, dcIdentity) is { } reason)
                diagnostics?.LogUnbound(identity.Id, reason);
            await AgentModuleAssignmentService.ReconcilePasswordDomainAsync(db, tx, identity.Id, ct);
        }
        return change.Output;
    }
    public static async Task<JsonObject> RemovalCommandAsync(NpgsqlConnection db,NpgsqlTransaction tx,AgentIdentity identity,CancellationToken ct)
    {
        await using var command=new NpgsqlCommand("select command_id from sli_agent_removals where agent_id=@id and state<>'state_cleaned' for update",db,tx);command.Parameters.AddWithValue("id",identity.Id);
        if(await command.ExecuteScalarAsync(ct) is not Guid id)throw new Certificates.AgentCertificateException("agent_certificate_rejected",401);
        return new JsonObject { ["agent_id"]=identity.Id.ToString("D"),["agent_removal"]=new JsonObject { ["command_id"]=id.ToString("D"),["action"]="uninstall" } };
    }
}
