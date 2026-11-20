using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;

namespace Sli.Server.Agents.Control;

public sealed class AgentPolicyService(IAgentControlAudit audit) : IAgentPolicyService
{
    public async Task<JsonElement> UpdateControlAsync(NpgsqlConnection db, NpgsqlTransaction tx, JsonElement payload, string actor, CancellationToken ct)
    {
        if (payload.ValueKind != JsonValueKind.Object || !payload.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(["agent_id", "expected_revision", "collection_policy"])
            || payload.GetProperty("collection_policy").ValueKind != JsonValueKind.Object) throw new AgentControlException("invalid_agent_collection_policy");
        Guid id = AgentControlJson.Id(payload.GetProperty("agent_id"));
        JsonObject agent;
        await using (var read = new NpgsqlCommand("select to_jsonb(a) from sli_agents a where id=@id for update", db, tx))
        {
            read.Parameters.AddWithValue("id", id);
            if (await read.ExecuteScalarAsync(ct) is not string row) throw new AgentControlException("agent_not_found", 404);
            agent = JsonNode.Parse(row)!.AsObject();
        }
        if (agent["status"]!.GetValue<string>() != "active") throw new AgentControlException("agent_disabled", 409);
        long current = agent["policy_revision"]!.GetValue<long>(); var expected = payload.GetProperty("expected_revision");
        if (expected.ValueKind != JsonValueKind.Number || !expected.TryGetInt64(out long n) || n != current) throw new AgentControlException("agent_policy_revision_conflict", 409);
        if (current >= 9007199254740991) throw new AgentControlException("agent_policy_revision_exhausted", 409);
        long revision = current + 1;
        var oldControl = AgentControlJson.Element(agent["collection_policy"]!);
        var merged = JsonNode.Parse(oldControl.GetRawText())!.AsObject();
        foreach (var property in payload.GetProperty("collection_policy").EnumerateObject()) merged[property.Name] = JsonNode.Parse(property.Value.GetRawText());
        var control = AgentPolicyStore.NormalizeCollectionPolicy(AgentControlJson.Element(merged));
        var modules = AgentControlJson.Element(agent["assigned_modules"]!);
        await AgentPolicyStore.SnapshotAsync(db, tx, id, current, modules, oldControl, ct);
        await AgentPolicyStore.SnapshotAsync(db, tx, id, revision, modules, control, ct);
        await using (var update = new NpgsqlCommand("update sli_agents set collection_policy=@control::jsonb,policy_revision=@revision where id=@id", db, tx))
        { update.Parameters.AddWithValue("control", control.GetRawText()); update.Parameters.AddWithValue("revision", revision); update.Parameters.AddWithValue("id", id); await update.ExecuteNonQueryAsync(ct); }
        var details = JsonNode.Parse(control.GetRawText())!.AsObject(); details["revision"] = revision;
        details["changed_fields"] = JsonSerializer.SerializeToNode(payload.GetProperty("collection_policy").EnumerateObject().Select(p => p.Name).Distinct().Order(StringComparer.Ordinal).ToArray());
        await audit.AppendAsync(db, tx, "policy_update", actor, id.ToString(), details, ct);
        return JsonSerializer.SerializeToElement(new { agent_id = id, policy_revision = revision, collection_policy = control });
    }
}
