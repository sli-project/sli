using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Server.Access;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Ingress;
using Sli.Server.Auth;

namespace Sli.Server.Agents.FileAudit;

// Source management.py status/enqueue; caller owns the transaction.
internal sealed class FileAuditControlService(IAgentControlAudit audit)
{
    private static string S(JsonNode? n)=>n!.GetValue<string>();
    private static bool Flag(JsonNode? n)=>n is JsonValue v && v.TryGetValue<bool>(out var b) && b;
    private static bool IsBool(JsonNode? n)=>n is JsonValue v && v.TryGetValue<bool>(out _);
    private static AgentControlException Invalid()=>new("file_audit_request_invalid");
    private static string Source(JsonObject a)=>S(a["source_host_id"] ?? a["host_id"]);
    private static async Task<JsonObject> Lock(NpgsqlConnection db,NpgsqlTransaction tx,Guid id,CancellationToken ct)
    {
        await using var q=new NpgsqlCommand("select to_jsonb(a) from sli_agents a where id=@id for update",db,tx); q.Parameters.AddWithValue("id",id);
        if(await q.ExecuteScalarAsync(ct) is not string json) throw new AgentControlException("agent_not_found",404);
        var agent=JsonNode.Parse(json)!.AsObject(); if(S(agent["status"])!="active") throw new AgentControlException("agent_disabled",409); return agent;
    }
    private static long Revision(JsonObject agent,JsonNode? expected)
    {
        long current=agent["policy_revision"]!.GetValue<long>();
        if(!JsonRead.TryInteger(expected,out var value) || value!=current) throw new AgentControlException("agent_policy_revision_conflict",409);
        if(current>=9007199254740991) throw new AgentControlException("agent_policy_revision_exhausted",409); return current+1;
    }
    private static void RequireScopes(CapabilityDecisionSet access,Principal principal,Guid agent,string source,IEnumerable<string> scopes)
    {
        if(scopes.Any(scope=>!FileAuditAccess.Allowed(access,principal.Role,principal.Type,principal.Id,agent.ToString(),source,scope))) throw new AgentControlException("file_audit_request_denied",403);
    }
    public async Task<JsonElement> Status(NpgsqlConnection db,NpgsqlTransaction tx,string id,Principal principal,CapabilityDecisionSet access,CancellationToken ct)
    {
        Guid agentId=AgentControlJson.Id(id); var agent=await Lock(db,tx,agentId,ct); var state=agent["file_audit"] as JsonObject;
        if(state is null || state.Count==0) throw new AgentControlException("file_audit_not_configured",404);
        var command=(state["request"] ?? state["retired_apply"])!["command"]!.AsObject(); RequireScopes(access,principal,agentId,Source(agent),command["collection_scope_ids"]!.AsArray().Select(S));
        return AgentControlJson.Element(new JsonObject { ["command"]=command.DeepClone(),["state"]=state["state"]!.DeepClone(),["scopes"]=state["scopes"]?.DeepClone() ?? new JsonObject(),["reported_at"]=state["reported_at"]?.DeepClone(),["may_own_audit"]=state["may_own_audit"]!.DeepClone() });
    }
    public async Task<JsonElement> Batch(NpgsqlConnection db,NpgsqlTransaction tx,JsonObject body,Principal principal,CapabilityDecisionSet access,CancellationToken ct)
    {
        var keys=body.Select(p=>p.Key).ToHashSet(StringComparer.Ordinal); string[] required=["agents","config","action","enabled"];
        if(required.Any(k=>!keys.Contains(k)) || keys.Except(required.Concat(["activate_collection"])).Any() || body["agents"] is not JsonArray agents || agents.Count is < 1 or > 64
            || body["config"] is not JsonObject input || !JsonRead.TryString(input["source_kind"],out var sourceKind) || sourceKind!="workstation" || !IsBool(body["enabled"])
            || body.ContainsKey("activate_collection") && !IsBool(body["activate_collection"]) || !JsonRead.TryString(body["action"],out var action) || action is not ("check" or "apply" or "restore")
            || Flag(body["activate_collection"]) && (!Flag(body["enabled"]) || action!="apply")) throw Invalid();
        JsonObject config; try { config=AgentFileAuditPolicy.Parse(input).Value; } catch(Exception e) when(e is ArgumentException or InvalidOperationException or Sli.Agent.Core.AgentException or ProtocolException or FormatException or OverflowException) { throw Invalid(); }
        var selected=new SortedDictionary<string,(Guid Id,JsonNode? Expected)>(StringComparer.Ordinal);
        foreach(var item in agents)
        {
            if(item is not JsonObject row || !JsonRead.HasExactly(row,"agent_id","expected_revision")) throw Invalid();
            Guid id=AgentControlJson.Id(JsonSerializer.SerializeToElement(row["agent_id"])); if(!selected.TryAdd(id.ToString(),(id,row["expected_revision"]?.DeepClone()))) throw Invalid();
        }
        var configurations=new Dictionary<string,JsonObject>();
        foreach(var (key,selection) in selected)
        {
            var agent=await Lock(db,tx,selection.Id,ct); Revision(agent,selection.Expected);
            var retained=agent["file_audit"]?["request"]?["config"] as JsonObject;
            if(action=="restore" && retained?["source_kind"]?.GetValue<string>()!="workstation") throw new AgentControlException("file_audit_restore_required",409);
            configurations[key]=action=="restore"?(JsonObject)retained!.DeepClone():(JsonObject)config.DeepClone();
        }
        var output=new JsonArray();
        foreach(var (key,selection) in selected)
        {
            var candidate=configurations[key]; JsonRead.TryInteger(selection.Expected,out var expectedValue); long expected=(long)expectedValue;
            var command=new JsonObject { ["contract_id"]="sli.file-audit.audit-command.v1",["command_id"]=Guid.NewGuid().ToString(),["action"]=action,["policy_revision"]=(expected+1).ToString(System.Globalization.CultureInfo.InvariantCulture),["collection_scope_ids"]=new JsonArray(candidate["roots"]!.AsArray().OfType<JsonObject>().Select(x=>(JsonNode?)JsonValue.Create(S(x["collection_scope_id"]))).ToArray()) };
            var item=new JsonObject { ["agent_id"]=key,["expected_revision"]=expected,["config"]=candidate,["command"]=command,["enabled"]=action=="restore"?false:Flag(body["enabled"]) };
            if(body.ContainsKey("activate_collection")) item["activate_collection"]=Flag(body["activate_collection"]);
            var result=await Enqueue(db,tx,item,principal,access,ct); var row=JsonNode.Parse(result.GetRawText())!.AsObject(); row["agent_id"]=key;output.Add(row);
        }
        return AgentControlJson.Element(new JsonObject { ["items"]=output });
    }
    public async Task<JsonElement> Enqueue(NpgsqlConnection db,NpgsqlTransaction tx,JsonObject body,Principal principal,CapabilityDecisionSet access,CancellationToken ct)
    {
        if(JsonRead.HasExactly(body,"agent_id","expected_revision","enabled") && IsBool(body["enabled"]) && !Flag(body["enabled"]))
            return await DisablePermissions(db,tx,body,principal,access,ct);
        var keys=body.Select(p=>p.Key).ToHashSet(StringComparer.Ordinal); string[] required=["agent_id","expected_revision","config","command"];
        if(required.Any(k=>!keys.Contains(k)) || keys.Except(required.Concat(["enabled","activate_collection"])).Any() || body["config"] is not JsonObject input || body["command"] is not JsonObject cmd
            || body.ContainsKey("activate_collection") && !IsBool(body["activate_collection"]) || body.ContainsKey("enabled") && !IsBool(body["enabled"])) throw Invalid();
        bool activate=Flag(body["activate_collection"]),enabled=Flag(body["enabled"]);
        if(activate && (!enabled || !JsonRead.TryString(cmd["action"],out var requestedAction) || requestedAction!="apply") || body.ContainsKey("enabled") && !activate && (!JsonRead.TryString(input["source_kind"],out var requestedKind) || requestedKind!="workstation")) throw Invalid();
        Guid id=AgentControlJson.Id(JsonSerializer.SerializeToElement(body["agent_id"])); var agent=await Lock(db,tx,id,ct); long revision=Revision(agent,body["expected_revision"]);
        JsonObject config; JsonArray modules; JsonObject request; string? permissionsScope=null;
        try
        {
            var candidate=(JsonObject)input.DeepClone(); candidate["policy_revision"]=revision.ToString(System.Globalization.CultureInfo.InvariantCulture);
            config=AgentFileAuditPolicy.Parse(candidate).Value;
            if(!FileAuditCommand.Valid(cmd,config)) throw new ArgumentException();
            modules=(JsonArray)agent["assigned_modules"]!.DeepClone(); string kind=config["source_kind"]?.GetValue<string>() ?? "server";
            if(kind=="workstation" && S(cmd["action"])!="restore" && !modules.OfType<JsonObject>().Any(x=>x["module_id"]?.GetValue<string>()=="sli.workstations" && Flag(x["enabled"]))) throw new ArgumentException();
            if(activate || kind=="workstation" && body.ContainsKey("enabled"))
            {
                var replaced=new JsonArray(); foreach(var item in modules) if(!(item is JsonValue v && v.TryGetValue<string>(out var s) && s=="sli.file-audit") && !(item is JsonObject o && o["module_id"]?.GetValue<string>()=="sli.file-audit")) replaced.Add(item?.DeepClone());
                replaced.Add(new JsonObject { ["module_id"]="sli.file-audit",["enabled"]=enabled,["config"]=config.DeepClone() }); modules=replaced;
                if(modules.Count>64) throw new ArgumentException();
                try { AgentModuleAssignmentRules.ValidateChannelOwnership(modules); } catch(AgentControlException) { throw new ArgumentException(); }
            }
            if(activate && kind=="server" && await AgentPolicyAssignments.FilePermissionsAvailableAsync(db,tx,ct))
            {
                var roots=config["roots"]!.AsArray();
                if(roots.Count!=1 || cmd["collection_scope_ids"] is not JsonArray activeScopes || activeScopes.Count!=1
                    || S(activeScopes[0])!=S(roots[0]!["collection_scope_id"])) throw new ArgumentException();
                permissionsScope=S(activeScopes[0]);
            }
            request=new JsonObject { ["config"]=config.DeepClone(),["command"]=cmd.DeepClone() };
            if(CanonicalJson.Length(request)>48*1024) throw new ArgumentException();
            var proposed=(JsonObject)agent.DeepClone(); proposed["file_audit"]=new JsonObject { ["request"]=request.DeepClone() };
            if(CanonicalJson.Length(AgentModuleAssignmentService.CheckIn(proposed,modules,revision))>60*1024-1024) throw new ArgumentException();
            var scopes=activate ? config["roots"]!.AsArray().OfType<JsonObject>().Select(x=>S(x["collection_scope_id"])) : cmd["collection_scope_ids"]!.AsArray().Select(S);
            RequireScopes(access,principal,id,Source(agent),scopes);
        }
        catch(Exception ex) when(ex is ArgumentException or InvalidOperationException or FormatException or Sli.Agent.Core.AgentException or ProtocolException or OverflowException)
        { throw new AgentControlException("file_audit_request_denied",403); }
        string action=S(cmd["action"]); if(action!="check" && !Flag(agent["collection_policy"]?["manage_windows_audit"])) throw new AgentControlException("file_audit_management_disabled",409);
        var prior=agent["file_audit"] as JsonObject ?? new JsonObject(); bool owned=Flag(prior["may_own_audit"]);
        var priorRequest=prior["request"] ?? prior["retired_apply"];
        if(owned && (!JsonNode.DeepEquals(config["roots"],priorRequest?["config"]?["roots"])
            || prior["retired_apply"] is not null && action!="restore"))
            throw new AgentControlException("file_audit_restore_required",409);
        await using(var insert=new NpgsqlCommand("select sli_plugin_file_audit.enqueue_audit(@agent,@source,@config::jsonb,@command::jsonb,@kind,@actor)",db,tx))
        { insert.Parameters.AddWithValue("agent",id);insert.Parameters.AddWithValue("source",Source(agent));insert.Parameters.AddWithValue("config",config.ToJsonString());insert.Parameters.AddWithValue("command",cmd.ToJsonString());insert.Parameters.AddWithValue("kind",principal.Type);insert.Parameters.AddWithValue("actor",principal.Id);await insert.ExecuteNonQueryAsync(ct); }
        var state=new JsonObject { ["request"]=request,["state"]="pending",["scopes"]=new JsonObject(),["may_own_audit"]=owned || action=="apply" };
        if (permissionsScope is not null)
        {
            state["permissions_scope"] = permissionsScope;
            state["permissions_restore_origin"] = CommandReference(cmd);
        }
        if (action is "check" or "restore" && owned
            && JsonRead.TryString(prior["permissions_scope"] ?? prior["permissions_restore_scope"],out var previousScope)
            && cmd["collection_scope_ids"] is JsonArray restoreScopes && restoreScopes.Count==1 && S(restoreScopes[0])==previousScope)
        {
            state["permissions_restore_scope"] = previousScope;
            var origin = prior["permissions_restore_origin"]?.DeepClone();
            if (origin is null && prior["permissions_scope"] is not null
                && priorRequest?["command"] is JsonObject priorApply && priorApply["action"]?.ToString() == "apply")
                origin = CommandReference(priorApply);
            if (origin is not null)
                state["permissions_restore_origin"] = origin;
        }
        if(action=="restore" && prior["retired_apply"] is JsonObject retired)
            state["retired_apply"]=retired.DeepClone();
        var oldModules=AgentControlJson.Element(agent["assigned_modules"]!); var control=AgentControlJson.Element(agent["collection_policy"]!);
        await AgentPolicyStore.SnapshotAsync(db,tx,id,revision-1,oldModules,control,ct);await AgentPolicyStore.SnapshotAsync(db,tx,id,revision,AgentControlJson.Element(modules),control,ct);
        await using(var update=new NpgsqlCommand("update sli_agents set file_audit=@state::jsonb,policy_revision=@revision,assigned_modules=@modules::jsonb where id=@id",db,tx))
        { update.Parameters.AddWithValue("state",state.ToJsonString());update.Parameters.AddWithValue("revision",revision);update.Parameters.AddWithValue("modules",modules.ToJsonString());update.Parameters.AddWithValue("id",id);await update.ExecuteNonQueryAsync(ct); }
        var details=new JsonObject { ["command_id"]=S(cmd["command_id"]),["command_action"]=action,["policy_sha256"]=Packets.Digest(config),["revision"]=revision }; if(activate) details["activate_collection"]=true;
        await audit.AppendAsync(db,tx,"file_audit_command",$"{principal.Type}:{principal.Id}",id.ToString(),details,ct);
        return JsonSerializer.SerializeToElement(new { policy_revision=revision,command_id=S(cmd["command_id"]),state="pending" });
    }

    private static JsonObject CommandReference(JsonObject command) => new()
    {
        ["command_id"] = command["command_id"]!.DeepClone(),
        ["policy_revision"] = command["policy_revision"]!.DeepClone()
    };

    private async Task<JsonElement> DisablePermissions(NpgsqlConnection db,NpgsqlTransaction tx,JsonObject body,
        Principal principal,CapabilityDecisionSet access,CancellationToken ct)
    {
        Guid id=AgentControlJson.Id(JsonSerializer.SerializeToElement(body["agent_id"]));
        var agent=await Lock(db,tx,id,ct);
        long revision=Revision(agent,body["expected_revision"]);
        var state=agent["file_audit"]?.DeepClone().AsObject();
        if(state is null || !JsonRead.TryString(state["permissions_scope"],out var scope))
            throw new AgentControlException("file_audit_not_configured",404);
        RequireScopes(access,principal,id,Source(agent),[scope]);
        var modules=agent["assigned_modules"]!.DeepClone().AsArray();
        var assignment=AgentPolicyAssignments.FindCurrent(modules,"sli.file-audit")
            ?? throw new AgentControlException("file_audit_not_configured",404);
        assignment["enabled"]=false;
        assignment["config"]!["policy_revision"]=revision.ToString(System.Globalization.CultureInfo.InvariantCulture);
        state["state"]="disabled";
        if(state["request"]?["command"]?["action"]?.ToString()=="apply")
        {
            state["retired_apply"]=state["request"]!.DeepClone();
            state.Remove("request");
        }
        var control=AgentControlJson.Element(agent["collection_policy"]!);
        await AgentPolicyStore.SnapshotAsync(db,tx,id,revision-1,AgentControlJson.Element(agent["assigned_modules"]!),control,ct);
        await AgentPolicyStore.SnapshotAsync(db,tx,id,revision,AgentControlJson.Element(modules),control,ct);
        // Inbox cleanup is owned by the poller, which locks inbox rows before the agent.
        await using var update=new NpgsqlCommand("""
            update public.sli_agents set file_audit=@state::jsonb,policy_revision=@revision,assigned_modules=@modules::jsonb where id=@id
            """,db,tx);
        update.Parameters.AddWithValue("id",id);update.Parameters.AddWithValue("state",state.ToJsonString());
        update.Parameters.AddWithValue("revision",revision);update.Parameters.AddWithValue("modules",modules.ToJsonString());
        await update.ExecuteNonQueryAsync(ct);
        await audit.AppendAsync(db,tx,"file_audit_command",$"{principal.Type}:{principal.Id}",id.ToString(),
            new { revision, command_action="disable" },ct);
        return JsonSerializer.SerializeToElement(new { policy_revision=revision,state="disabled" });
    }
}





