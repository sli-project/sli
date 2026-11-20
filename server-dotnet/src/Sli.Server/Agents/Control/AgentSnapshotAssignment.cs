using System.Text.Json.Nodes;
using Npgsql;

namespace Sli.Server.Agents.Control;

// The caller already holds the agent row lock and owns the transaction. The
// advisory lock serializes both conflict checks and binding publication.
internal static class AgentSnapshotAssignment
{
    internal static async Task ValidateAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid agent, string module,
        JsonObject config, bool enabled, CancellationToken ct)
    {
        await using (var gate=new NpgsqlCommand("select pg_advisory_xact_lock(170,1)",db,tx))
            await gate.ExecuteNonQueryAsync(ct);
        await using (var read=new NpgsqlCommand("select config::text from sli_agent_snapshot_bindings where agent_id=@agent and module_id=@module",db,tx))
        {
            read.Parameters.AddWithValue("agent",agent); read.Parameters.AddWithValue("module",module);
            if (await read.ExecuteScalarAsync(ct) is string raw &&
                !AgentModuleAssignmentRules.SameSnapshotIdentity(JsonNode.Parse(raw)!.AsObject(),config))
                throw new AgentControlException("agent_snapshot_binding_immutable",409);
        }
        if (enabled)
        {
            await using var conflict=new NpgsqlCommand("select agent_id from sli_agent_snapshot_bindings where module_id=@module and domain_sid=@domain and enabled and agent_id<>@agent",db,tx);
            conflict.Parameters.AddWithValue("module",module); conflict.Parameters.AddWithValue("domain",config["domain_sid"]!.GetValue<string>()); conflict.Parameters.AddWithValue("agent",agent);
            if (await conflict.ExecuteScalarAsync(ct) is not null) throw new AgentControlException("agent_snapshot_collector_conflict",409);
        }
    }

    internal static async Task PublishAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid agent, string module,
        JsonObject config, bool enabled, CancellationToken ct, bool followServerTimezone = false)
    {
        await using var write=new NpgsqlCommand("""
            insert into sli_agent_snapshot_bindings(agent_id,module_id,config,enabled,follow_server_timezone)
            values(@agent,@module,@config::jsonb,@enabled,@follow) on conflict(agent_id,module_id)
            do update set config=excluded.config,enabled=excluded.enabled,follow_server_timezone=excluded.follow_server_timezone;
            update sli_agent_snapshot_policies set superseded_at=clock_timestamp()
            where agent_id=@agent and module_id=@module and superseded_at is null;
            insert into sli_agent_snapshot_policies(agent_id,module_id,config,enabled)
            values(@agent,@module,@config::jsonb,@enabled)
            """,db,tx);
        write.Parameters.AddWithValue("agent",agent);write.Parameters.AddWithValue("module",module);
        write.Parameters.AddWithValue("config",config.ToJsonString());write.Parameters.AddWithValue("enabled",enabled);
        write.Parameters.AddWithValue("follow",followServerTimezone);
        await write.ExecuteNonQueryAsync(ct);
    }
}
