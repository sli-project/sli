using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Ingress;
using Sli.Server.Auth.Lifecycle.Security;

namespace Sli.Server.Agents.FileAudit;

internal sealed class FileAuditIngestService
{
    public FileAuditIngestService(FileAuditAdEnrichment enrichment) { }

    // The endpoint holds the mTLS identity lock for this transaction.
    public async Task<JsonObject> Ingest(NpgsqlConnection db,NpgsqlTransaction tx,AgentIdentity identity,JsonNode? input,
        CancellationToken ct,Func<IDisposable>? admit=null)
    {
        if(admit is null || input is not JsonObject report || !JsonRead.TryString(report["policy_revision"],out var revision)
            || !await AgentPolicyAssignments.FilePermissionsAvailableAsync(db,tx,ct))
            throw new AgentControlException("module_disabled",503);
        await using var read=new NpgsqlCommand("select file_audit::text from public.sli_agents where id=@agent for update",db,tx);
        read.Parameters.AddWithValue("agent",identity.Id);
        var stored=await read.ExecuteScalarAsync(ct) as string;
        var state=stored is null ? null : JsonNode.Parse(stored) as JsonObject;
        bool retired=state?["retired_apply"]?["command"]?["policy_revision"]?.ToString()==revision;
        var request=state?[retired ? "retired_apply" : "request"];
        if(state is null || request?["config"] is not JsonObject config
            || request?["command"] is not JsonObject command)
            throw new AgentControlException("module_disabled",503);
        bool restore=JsonRead.TryString(state["permissions_restore_scope"],out var restoreScope)
            && command["action"]?.ToString()=="restore" && command["policy_revision"]?.ToString()==revision
            && command["collection_scope_ids"] is JsonArray restoreScopes && restoreScopes.Count==1
            && restoreScopes[0]?.ToString()==restoreScope;
        if(!retired && !restore && !await AgentPolicyAssignments.FilePermissionsAllowedAsync(db,tx,identity.Id,revision,false,ct))
            throw new AgentControlException("module_disabled",503);
        using var lease=admit();
        if(!FileAuditResult.Valid(report,config,command)) throw new AgentControlException("file_audit_result_invalid");
        // Clear the agent's pending report so it can run restore. A retired apply publishes no evidence.
        if(retired) return new JsonObject { ["status"]="accepted" };
        var scope=report["scopes"]!.AsArray().Single()!.AsObject();
        string scopeId=scope["collection_scope_id"]!.GetValue<string>();
        var root=config["roots"]![0]!["path"];
        bool verified=scope["state"]!.GetValue<string>()=="verified"
            && (restore || report["snapshots"]!.AsArray().Single()!["objects"]!.AsArray().OfType<JsonObject>().Any(item=>
                JsonNode.DeepEquals(item["path"],root) && item["object_type"]?.ToString()=="directory"));
        var observation=(JsonObject)report.DeepClone();
        var receipt=observation["scopes"]![0]!.AsObject();
        if(!verified && receipt["state"]!.GetValue<string>()=="verified")
        {
            receipt["state"]="partial";
            receipt["reason_code"]="coverage_incomplete";
        }
        string digest=Packets.Digest(observation);
        receipt["receipt_id"]=AuthAudit.Uuid5(command["command_id"]!.GetValue<string>()+digest).ToString();
        receipt["result_sha256"]=digest;
        await using var store=new NpgsqlCommand("select sli_plugin_file_audit.store_audit_result(@agent,@result)",db,tx);
        store.Parameters.AddWithValue("agent",identity.Id);
        store.Parameters.AddWithValue("result",NpgsqlDbType.Jsonb,observation.ToJsonString());
        await store.ExecuteNonQueryAsync(ct);

        var observed=Iso8601.ParseUtc(report["observed_at_utc"]!.GetValue<string>());
        if(state["reported_at"] is null || observed>Iso8601.ParseUtc(state["reported_at"]!.GetValue<string>()))
        {
            state["state"]=receipt["state"]!.DeepClone();
            state["scopes"]=new JsonObject { [scopeId]=receipt.DeepClone() };
            state["reported_at"]=report["observed_at_utc"]!.DeepClone();
            state["may_own_audit"]=report["ownership_remaining"]!.DeepClone();
            await using var write=new NpgsqlCommand("update public.sli_agents set file_audit=@state where id=@agent",db,tx);
            write.Parameters.AddWithValue("agent",identity.Id);
            write.Parameters.AddWithValue("state",NpgsqlDbType.Jsonb,state.ToJsonString());
            await write.ExecuteNonQueryAsync(ct);
        }
        return new JsonObject { ["status"]="accepted" };
    }
}
