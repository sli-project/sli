using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Auth.Lifecycle;

namespace Sli.Server.Agents.Control;

public sealed partial class AgentLifecycleService(AgentManagementService management, IAgentControlAudit audit)
{
    public async Task<JsonElement> RequestRemovalAsync(NpgsqlConnection db, NpgsqlTransaction tx, JsonElement payload, string actor, CancellationToken ct)
    {
        if (payload.ValueKind != JsonValueKind.Object || !payload.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(["operation_id", "agent_ids"]))
            throw new AgentControlException("agent_removal_invalid");
        Guid operation = AgentControlJson.Id(payload.GetProperty("operation_id")); var values = payload.GetProperty("agent_ids");
        if (values.ValueKind != JsonValueKind.Array || values.GetArrayLength() is < 1 or > 100) throw new AgentControlException("agent_removal_invalid");
        var ids = values.EnumerateArray().Select(AgentControlJson.Id).OrderBy(id => id.ToString(), StringComparer.Ordinal).ToArray();
        if (ids.Distinct().Count() != ids.Length) throw new AgentControlException("agent_removal_invalid");
        await using (var gate = new NpgsqlCommand("select pg_advisory_xact_lock(hashtext(@key))", db, tx))
        { gate.Parameters.AddWithValue("key", "agent-removal:" + operation); await gate.ExecuteNonQueryAsync(ct); }
        await using (var replay = new NpgsqlCommand("select 1 from sli_agent_removals where operation_id=@operation", db, tx))
        { replay.Parameters.AddWithValue("operation", operation); if (await replay.ExecuteScalarAsync(ct) is not null) throw new AgentControlException("agent_removal_replay", 409); }
        var locked = new HashSet<Guid>(); var replaced=new HashSet<Guid>();
        await using (var selection = new NpgsqlCommand("select id,status from sli_agents where id=any(@ids) order by id for update", db, tx))
        { selection.Parameters.AddWithValue("ids", ids); await using var rows = await selection.ExecuteReaderAsync(ct); while (await rows.ReadAsync(ct)) { locked.Add(rows.GetGuid(0)); if(rows.GetString(1)=="replaced")replaced.Add(rows.GetGuid(0)); } }
        if (!locked.SetEquals(ids)) throw new AgentControlException("agent_not_found", 404);
        await using (var existing = new NpgsqlCommand("select 1 from sli_agent_removals where agent_id=any(@ids)", db, tx))
        { existing.Parameters.AddWithValue("ids", ids); if (await existing.ExecuteScalarAsync(ct) is not null) throw new AgentControlException("agent_removal_replay", 409); }
        var items = new List<object>();
        foreach (Guid id in ids)
        {
            Guid command = Guid.NewGuid();
            await using (var insert = new NpgsqlCommand("insert into sli_agent_removals(agent_id,operation_id,command_id) values(@agent,@operation,@command)", db, tx))
            { insert.Parameters.AddWithValue("agent", id); insert.Parameters.AddWithValue("operation", operation); insert.Parameters.AddWithValue("command", command); await insert.ExecuteNonQueryAsync(ct); }
            // One existing source revocation producer: status, certificate rows,
            // feed lock and audits stay in this same caller-owned transaction.
            await management.RevokeAsync(db, tx, JsonSerializer.SerializeToElement(new { agent_id = id }), actor, true, ct);
            if(replaced.Contains(id))
            {
                // Removal-only authentication requires revocation at/after this
                // owner's command. Keep certificates revoked and record the new
                // revocation; the original time remains in the existing audit.
                var serials=new List<string>();
                await using(var revoke=new NpgsqlCommand("update sli_agent_certificates set revoked_at=clock_timestamp() where agent_id=@id and revoked_at is not null and not_after>clock_timestamp() returning serial",db,tx))
                { revoke.Parameters.AddWithValue("id",id); await using var rows=await revoke.ExecuteReaderAsync(ct); while(await rows.ReadAsync(ct))serials.Add(rows.GetString(0)); }
                foreach(var serial in serials)await audit.AppendAsync(db,tx,"revoke",actor,id.ToString(),new { serial,reason="removal_request" },ct);
            }
            await audit.AppendAsync(db, tx, "removal_request", actor, id.ToString(), new { operation_id = operation, command_id = command }, ct);
            items.Add(new { agent_id = id, command_id = command, state = "pending" });
        }
        return JsonSerializer.SerializeToElement(new { operation_id = operation, items });
    }

    public async Task<JsonElement> RequestProbeAsync(NpgsqlConnection db, NpgsqlTransaction tx, JsonElement payload, string actor, CancellationToken ct)
    {
        if (payload.ValueKind != JsonValueKind.Object || !payload.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(["agent_id"]))
            throw new AgentControlException("invalid_agent_probe_request");
        Guid id = AgentControlJson.Id(payload.GetProperty("agent_id")); JsonObject probe;
        await using (var read = new NpgsqlCommand("select status,rights_probe from sli_agents where id=@id for update", db, tx))
        {
            read.Parameters.AddWithValue("id", id); await using var reader = await read.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct)) throw new AgentControlException("agent_not_found", 404);
            if (reader.GetString(0) != "active") throw new AgentControlException("agent_disabled", 409);
            probe = JsonNode.Parse(reader.GetString(1))!.AsObject();
        }
        if (!AuthJsonBody.Truthy(probe["pending"] is null ? JsonSerializer.SerializeToElement<object?>(null) : AgentControlJson.Element(probe["pending"]!)))
        {
            Guid request = Guid.NewGuid(); probe["pending"] = new JsonObject { ["request_id"] = request.ToString(), ["requested_at"] = AgentControlJson.Stamp(AgentControlJson.Now(), true) };
            await using var update = new NpgsqlCommand("update sli_agents set rights_probe=@probe::jsonb where id=@id", db, tx);
            update.Parameters.AddWithValue("probe", probe.ToJsonString()); update.Parameters.AddWithValue("id", id); await update.ExecuteNonQueryAsync(ct);
            await audit.AppendAsync(db, tx, "probe_request", actor, id.ToString(), new { request_id = request }, ct);
        }
        return JsonSerializer.SerializeToElement(new { rights_probe = probe });
    }
}
