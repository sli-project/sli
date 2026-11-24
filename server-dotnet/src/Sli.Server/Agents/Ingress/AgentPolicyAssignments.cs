using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Ingress;

/// <summary>Resolve the enabled capture-time assignment without widening current authority.</summary>
public static class AgentPolicyAssignments
{
    internal static IDisposable? HoldFilePermissions()
    {
        try { return Control.AgentAssignmentPluginAdmission.Enter("sli.file-audit",
            Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"),Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR")); }
        catch(Exception error) when(error is InvalidOperationException or IOException or UnauthorizedAccessException) { return null; }
    }

    internal static async Task<bool> FilePermissionsAvailableAsync(NpgsqlConnection db,NpgsqlTransaction tx,CancellationToken ct)
    {
        await using var command=new NpgsqlCommand("select to_regprocedure('public.file_permissions_allowed405(uuid,text,text,boolean)') is not null",db,tx);
        return await command.ExecuteScalarAsync(ct) is true;
    }

    internal static async Task<bool> FilePermissionsAllowedAsync(NpgsqlConnection db,NpgsqlTransaction tx,
        Guid agent,string? revision,bool verified,CancellationToken ct)
    {
        await using var command=new NpgsqlCommand("select public.file_permissions_allowed405(@agent,@revision,null,@verified)",db,tx);
        command.Parameters.AddWithValue("agent",agent);
        command.Parameters.AddWithValue("revision",NpgsqlTypes.NpgsqlDbType.Text,(object?)revision??DBNull.Value);
        command.Parameters.AddWithValue("verified",verified);
        return await command.ExecuteScalarAsync(ct) is true;
    }

    public static async Task<bool> ModuleEnabledAsync(NpgsqlConnection db,NpgsqlTransaction tx,string module,CancellationToken ct)
    {
        await using var command=new NpgsqlCommand("select public.agent_module_enabled_v380(@module)",db,tx);
        command.Parameters.AddWithValue("module",module);
        return await command.ExecuteScalarAsync(ct) is true;
    }

    // Authentication owns the agent lock. Publish a new revision only when availability changed.
    public static async Task DisableUnavailableAsync(NpgsqlConnection db,NpgsqlTransaction tx,JsonObject agent,CancellationToken ct)
    {
        var modules=agent["assigned_modules"]!.AsArray();
        Guid id=Guid.Parse(agent["id"]!.GetValue<string>());
        bool fileAllowed=modules.OfType<JsonObject>().Any(m=>m["module_id"]?.ToString()=="sli.file-audit")
            && await FilePermissionsAvailableAsync(db,tx,ct)
            && await FilePermissionsAllowedAsync(db,tx,id,null,false,ct);
        await using var command=new NpgsqlCommand("""
            select coalesce(jsonb_agg(case
              when not public.agent_module_enabled_v380(coalesce(m->>'module_id',m#>>'{}'))
                and not (@file_allowed and coalesce(m->>'module_id',m#>>'{}')='sli.file-audit') then
                case when jsonb_typeof(m)='object' then jsonb_set(m,'{enabled}','false')
                  else jsonb_build_object('module_id',m#>>'{}','enabled',false) end
              else m end order by n),'[]'::jsonb)::text
            from jsonb_array_elements(@modules::jsonb) with ordinality as items(m,n)
            """,db,tx);
        command.Parameters.AddWithValue("modules",modules.ToJsonString());
        command.Parameters.AddWithValue("file_allowed",fileAllowed);
        var available=JsonNode.Parse((string)(await command.ExecuteScalarAsync(ct))!)!.AsArray();
        if(JsonNode.DeepEquals(modules,available)) return;
        long current=agent["policy_revision"]!.GetValue<long>();
        long revision=Control.AgentModuleAssignmentRules.NextRevision(current,current);
        await Control.AgentManagementService.LockImportAsync(db,tx,id,ct);
        var changed=available.OfType<JsonObject>().Where(m=>!JsonNode.DeepEquals(m,
            modules.OfType<JsonObject>().FirstOrDefault(old=>old["module_id"]?.ToString()==m["module_id"]?.ToString()))).ToArray();
        foreach(var item in changed)
            if(item["config"] is JsonObject config && config.ContainsKey("policy_revision"))
                config["policy_revision"]=revision.ToString(CultureInfo.InvariantCulture);
        var control=Control.AgentControlJson.Element(agent["collection_policy"]!);
        await Control.AgentPolicyStore.SnapshotAsync(db,tx,id,current,Control.AgentControlJson.Element(modules),control,ct);
        await Control.AgentPolicyStore.SnapshotAsync(db,tx,id,revision,Control.AgentControlJson.Element(available),control,ct);
        foreach(var item in changed)
            if(item["module_id"]?.ToString() is "sli.ad-snapshot" or "sli.gpo-snapshot" && item["config"] is JsonObject config) {
                string module=item["module_id"]!.GetValue<string>();
                await Control.AgentSnapshotAssignment.ValidateAsync(db,tx,id,module,config,false,ct);
                await Control.AgentSnapshotAssignment.PublishAsync(db,tx,id,module,config,false,ct);
            }
        await using var update=new NpgsqlCommand("update sli_agents set assigned_modules=@modules::jsonb,policy_revision=@revision where id=@id",db,tx);
        update.Parameters.AddWithValue("modules",available.ToJsonString()); update.Parameters.AddWithValue("revision",revision);
        update.Parameters.AddWithValue("id",id);
        await update.ExecuteNonQueryAsync(ct);
        if(changed.Any(m=>m["module_id"]?.ToString()==AgentAdDcValidator.Live))
            await Control.AgentModuleAssignmentService.ReconcilePasswordDomainAsync(db,tx,id,ct);
        agent["assigned_modules"]=available; agent["policy_revision"]=revision;
    }

    // A bounded marker pass also runs when disabled modules are excluded from import claims.
    public static async Task<int> MarkDisabledAsync(NpgsqlConnection db,NpgsqlTransaction tx,int limit,CancellationToken ct)
    {
        // Accounting has a separate consumer that rechecks the live plugin and
        // assignment. A pause must not terminally hide already accepted bytes.
        string gate=await FilePermissionsAvailableAsync(db,tx,ct)
            ? """
              case when i.envelope->>'module_id'='sli.file-audit' then public.file_permissions_allowed405(
                  (select a.id from public.sli_agents a where a.id::text=i.envelope->>'agent_id'),
                  i.envelope->>'policy_revision',null,true)
                else public.agent_module_enabled_v380(i.envelope->>'module_id') end
              """
            : "public.agent_module_enabled_v380(i.envelope->>'module_id')";
        await using var command=new NpgsqlCommand($"""
            with disabled as (
              select i.packet_id from sli_agent_packet_inbox i
              where i.imported_at is null and i.module_disabled_at is null
                and i.envelope->>'module_id' is distinct from 'sli.radius-accounting'
                and (not ({gate})
                  or exists(select 1 from sli_agents a cross join lateral jsonb_array_elements(a.assigned_modules) m
                    where a.id::text=i.envelope->>'agent_id' and m->>'module_id'=i.envelope->>'module_id'
                      and m->'enabled'='false'::jsonb))
              order by i.received_at,i.packet_id limit @limit for update of i skip locked
            ) update sli_agent_packet_inbox i set module_disabled_at=clock_timestamp()
              from disabled d where i.packet_id=d.packet_id
            """,db,tx);
        command.Parameters.AddWithValue("limit",limit);
        return await command.ExecuteNonQueryAsync(ct);
    }

    public static JsonObject? FindCurrent(JsonArray assignments, string module)
    {
        var matches=assignments.OfType<JsonObject>().Where(item => JsonRead.TryString(item["module_id"],out var id) && id==module).ToArray();
        return matches.Length==1 && matches[0]["enabled"] is JsonValue flag && flag.TryGetValue<bool>(out var enabled) && enabled
            ? matches[0] : null;
    }

    public static bool MatchesRevision(JsonObject assignment, string revision)
    {
        if (!assignment.TryGetPropertyValue("config",out var raw)) return revision=="1";
        if (raw is not JsonObject config) return false;
        return !config.TryGetPropertyValue("policy_revision",out var value) ? revision=="1"
            : JsonRead.TryString(value,out var actual) && actual==revision;
    }

    public static bool ValidHistoryRevision(string revision) => revision.Length is > 0 and <= 16
        && revision.All(c=>c is >= '0' and <= '9')
        && long.TryParse(revision,NumberStyles.None,CultureInfo.InvariantCulture,out long value)
        && value is >= 1 and <= 9007199254740991;

    public static async Task<JsonObject?> ResolveAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        JsonArray assignments, Guid agentId, string module, string revision, CancellationToken ct)
    {
        var current=FindCurrent(assignments,module);
        if (current is null) return null;
        if (MatchesRevision(current,revision)) return current;
        if (!ValidHistoryRevision(revision)) return null;
        await using var command=new NpgsqlCommand("""
            select assignment::text from sli_agent_policy_history h
            cross join lateral jsonb_array_elements(h.assigned_modules) assignment
            where h.agent_id=@agent and assignment->>'module_id'=@module
              and assignment->'enabled'='true'::jsonb
              and coalesce(assignment->'config'->>'policy_revision','1')=@revision
            order by h.revision limit 1
            """,connection,transaction);
        command.Parameters.AddWithValue("agent",agentId); command.Parameters.AddWithValue("module",module); command.Parameters.AddWithValue("revision",revision);
        var value=await command.ExecuteScalarAsync(ct);
        if (value is not string json || JsonNode.Parse(json) is not JsonObject retained || !MatchesRevision(retained,revision)) return null;
        return retained;
    }
}
