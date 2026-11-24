using System.Globalization;
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
        if (state is null)
            throw new AgentControlException("module_disabled",503);
        bool retired=state["retired_apply"]?["command"]?["policy_revision"]?.ToString()==revision;
        var request=state[retired ? "retired_apply" : "request"];
        if (!retired && await ReadSupersededPermissionsRequestAsync(db, tx, identity.Id, state, request, report, revision, ct)
            is { } superseded)
        {
            request = superseded;
            retired = true;
        }
        if(request?["config"] is not JsonObject config
            || request?["command"] is not JsonObject command)
            throw new AgentControlException("module_disabled",503);
        bool check = !retired && command["action"]?.ToString() == "check"
            && command["policy_revision"]?.ToString() == revision;
        bool restore=JsonRead.TryString(state["permissions_restore_scope"],out var restoreScope)
            && command["action"]?.ToString()=="restore" && command["policy_revision"]?.ToString()==revision
            && command["collection_scope_ids"] is JsonArray restoreScopes && restoreScopes.Count==1
            && restoreScopes[0]?.ToString()==restoreScope;
        // A read-only check report proves only the current management command.
        if(!retired && !restore && !check && !await AgentPolicyAssignments.FilePermissionsAllowedAsync(db,tx,identity.Id,revision,false,ct))
            throw new AgentControlException("module_disabled",503);
        using var lease=admit();
        if(!FileAuditResult.Valid(report,config,command)) throw new AgentControlException("file_audit_result_invalid");
        // Let the agent clear its pending report without changing the current command or its evidence.
        if(retired) return new JsonObject { ["status"]="accepted" };
        var observation=(JsonObject)report.DeepClone();
        var receipts = observation["scopes"]!.AsArray().OfType<JsonObject>().ToArray();
        var roots = config["roots"]!.AsArray().OfType<JsonObject>()
            .ToDictionary(root => root["collection_scope_id"]!.GetValue<string>(), root => root["path"]);
        var snapshots = report["snapshots"]!.AsArray().OfType<JsonObject>();
        foreach (var receipt in receipts)
        {
            var scope = receipt["collection_scope_id"]!.GetValue<string>();
            if (receipt["state"]!.GetValue<string>() != "verified" || restore
                || snapshots.Any(snapshot => snapshot["collection_scope_id"]!.GetValue<string>() == scope
                    && snapshot["objects"]!.AsArray().OfType<JsonObject>().Any(item =>
                        JsonNode.DeepEquals(item["path"], roots[scope]) && item["object_type"]?.ToString() == "directory")))
                continue;
            receipt["state"] = "partial";
            receipt["reason_code"] = "coverage_incomplete";
        }
        string digest=Packets.Digest(observation);
        foreach (var receipt in receipts)
        {
            var scopeSuffix = receipts.Length == 1 ? "" : ":" + receipt["collection_scope_id"]!.GetValue<string>();
            receipt["receipt_id"] = AuthAudit.Uuid5(command["command_id"]!.GetValue<string>() + digest + scopeSuffix).ToString();
            receipt["result_sha256"] = digest;
        }
        await using var store=new NpgsqlCommand("select sli_plugin_file_audit.store_audit_result(@agent,@result)",db,tx);
        store.Parameters.AddWithValue("agent",identity.Id);
        store.Parameters.AddWithValue("result",NpgsqlDbType.Jsonb,observation.ToJsonString());
        await store.ExecuteNonQueryAsync(ct);

        if (MergeReceipts(state, command, receipts, report["observed_at_utc"]!.GetValue<string>(), check))
        {
            if (!check)
                state["may_own_audit"]=report["ownership_remaining"]!.DeepClone();
            if (restore && state["state"]?.ToString() == "verified" && state["may_own_audit"]?.GetValue<bool>() == false)
                state.Remove("permissions_restore_origin");
            await using var write=new NpgsqlCommand("update public.sli_agents set file_audit=@state where id=@agent",db,tx);
            write.Parameters.AddWithValue("agent",identity.Id);
            write.Parameters.AddWithValue("state",NpgsqlDbType.Jsonb,state.ToJsonString());
            await write.ExecuteNonQueryAsync(ct);
        }
        return new JsonObject { ["status"]="accepted" };
    }

    private static async Task<JsonObject?> ReadSupersededPermissionsRequestAsync(NpgsqlConnection db, NpgsqlTransaction tx,
        Guid agent, JsonObject state, JsonNode? current, JsonObject report, string revision, CancellationToken ct)
    {
        if (current?["command"] is not JsonObject command
            || command["action"]?.ToString() is not ("check" or "restore")
            || state["may_own_audit"]?.GetValue<bool>() != true
            || !JsonRead.TryString(state["permissions_restore_scope"], out var scope)
            || state["permissions_restore_origin"] is not JsonObject origin
            || !long.TryParse(origin["policy_revision"]?.ToString(), NumberStyles.None, CultureInfo.InvariantCulture, out var originalRevision)
            || !long.TryParse(command["policy_revision"]?.ToString(), NumberStyles.None, CultureInfo.InvariantCulture, out var currentRevision)
            || !long.TryParse(revision, NumberStyles.None, CultureInfo.InvariantCulture, out var receivedRevision)
            || receivedRevision < originalRevision || receivedRevision >= currentRevision)
            return null;

        // Only the original apply and checks issued under it can precede this restore.
        var allowedScopes = new JsonArray(scope);
        bool originalApply = receivedRevision == originalRevision;
        string action = originalApply ? "apply" : "check";
        if (!JsonNode.DeepEquals(command["collection_scope_ids"], allowedScopes)
            || !JsonRead.TryString(report["command_id"], out var id) || report["action"]?.ToString() != action
            || originalApply && origin["command_id"]?.ToString() != id)
            throw new AgentControlException("file_audit_result_invalid");

        await using var read = new NpgsqlCommand("select sli_plugin_file_audit.audit_request(@agent,@command)::text", db, tx);
        read.Parameters.AddWithValue("agent", agent);
        read.Parameters.AddWithValue("command", id);
        var value = await read.ExecuteScalarAsync(ct) as string;
        var retained = value is null ? null : JsonNode.Parse(value) as JsonObject;
        if (retained?["command"]?["action"]?.ToString() != action
            || retained["command"]?["policy_revision"]?.ToString() != revision
            || !JsonNode.DeepEquals(retained["command"]?["collection_scope_ids"], allowedScopes)
            || !JsonNode.DeepEquals(retained["config"]?["roots"], current["config"]?["roots"])
            || (retained["config"]?["source_kind"]?.ToString() ?? "server") != "server")
            throw new AgentControlException("file_audit_result_invalid");
        return retained;
    }

    private static bool MergeReceipts(JsonObject state, JsonObject command, JsonObject[] receipts, string observedAt, bool check)
    {
        var previousReportAt = state["reported_at"]?.GetValue<string>();
        var observed = Iso8601.ParseUtc(observedAt);
        bool newest = previousReportAt is null || observed > Iso8601.ParseUtc(previousReportAt);
        if (!check && !newest)
            return false;

        var scopes = (JsonObject?)state["scopes"] ?? new JsonObject();
        bool changed = false;
        foreach (var receipt in receipts)
        {
            var scope = receipt["collection_scope_id"]!.GetValue<string>();
            if (!newest && scopes[scope] is JsonObject current)
            {
                var lastSeen = current["observed_at_utc"]?.GetValue<string>() ?? previousReportAt!;
                if (observed <= Iso8601.ParseUtc(lastSeen))
                    continue;
            }
            var next = (JsonObject)receipt.DeepClone();
            if (check)
                next["observed_at_utc"] = observedAt;
            scopes[scope] = next;
            changed = true;
        }
        if (!changed)
            return false;

        if (state["scopes"] is null)
            state["scopes"] = scopes;
        var reportedStates = scopes.Select(scope => scope.Value!["state"]!.GetValue<string>()).ToHashSet();
        state["state"] = command["collection_scope_ids"]!.AsArray().Count != scopes.Count ? "pending"
            : new[] { "failed", "blocked", "partial" }.FirstOrDefault(reportedStates.Contains) ?? "verified";
        if (newest)
            state["reported_at"] = observedAt;
        return true;
    }
}
