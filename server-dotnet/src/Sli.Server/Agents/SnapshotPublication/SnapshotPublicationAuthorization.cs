using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;

namespace Sli.Server.Agents.SnapshotPublication;

// The caller owns the publication worker connection and transaction.
public static class SnapshotPublicationAuthorization
{
    public static async Task AuthorizeAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid agentId,
        JsonObject cyclePolicy, SnapshotCycleRow first, CancellationToken ct)
    {
        var envelope = Envelope.Parse(first.Envelope);
        if (envelope.AgentId != agentId.ToString("D") || envelope.ModuleId is not ("sli.gpo-snapshot" or "sli.ad-snapshot")) throw Pending("agent_snapshot_module_invalid");
        JsonArray assignments;
        await using (var cmd = new NpgsqlCommand("select status,assigned_modules::text from sli_agents where id=@id for key share", db, tx))
        {
            cmd.Parameters.AddWithValue("id", agentId);
            await using var r = await cmd.ExecuteReaderAsync(ct);
            if (!await r.ReadAsync(ct) || r.GetString(0) != "active") throw Pending("agent_disabled");
            assignments = JsonNode.Parse(r.GetString(1))!.AsArray();
        }
        var assignment = RequireAssignment(envelope.ModuleId, assignments);
        await using (var cmd = new NpgsqlCommand("select envelope::text,envelope_sha256 from sli_agent_receipts where packet_id=@packet and agent_id=@agent and module_id=@module",db,tx))
        {
            cmd.Parameters.AddWithValue("packet",Guid.Parse(envelope.PacketId)); cmd.Parameters.AddWithValue("agent",agentId); cmd.Parameters.AddWithValue("module",envelope.ModuleId);
            await using var r = await cmd.ExecuteReaderAsync(ct);
            if (!await r.ReadAsync(ct) || !PythonMetadataEquality.Equal(JsonNode.Parse(r.GetString(0)), first.Envelope)
                || r.GetString(1) != Packets.Digest(first.Envelope) || Packets.Digest(first.Payload) != envelope.PayloadSha256)
                throw Pending("agent_packet_attestation_invalid");
        }
        ValidateBinding(assignment, cyclePolicy);
        await using (var cmd = new NpgsqlCommand("select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'))",db,tx)) await cmd.ExecuteNonQueryAsync(ct);
        await using (var cmd = new NpgsqlCommand("select installed,enabled from read_plugin_states_v1() where plugin_id=@plugin",db,tx))
        {
            cmd.Parameters.AddWithValue("plugin", envelope.ModuleId == "sli.ad-snapshot" ? "sli.ad" : "sli.gpo");
            await using var r = await cmd.ExecuteReaderAsync(ct);
            if (!await r.ReadAsync(ct) || !r.GetBoolean(0) || !r.GetBoolean(1)) throw Pending("agent_plugin_disabled");
        }
    }
    public static void ValidateAssignment(string module, JsonArray assignments, JsonObject cyclePolicy)
        => ValidateBinding(RequireAssignment(module, assignments), cyclePolicy);

    private static JsonObject RequireAssignment(string module, JsonArray assignments)
    {
        if (module is not ("sli.ad-snapshot" or "sli.gpo-snapshot")) throw Pending("agent_snapshot_module_invalid");
        var matches = assignments.OfType<JsonObject>().Where(a => JsonRead.TryString(a["module_id"], out var id) && id == module).ToArray();
        if (matches.Length != 1 || matches[0]["enabled"]?.GetValueKind() != System.Text.Json.JsonValueKind.True) throw Pending("agent_module_not_assigned");
        return matches[0];
    }
    private static void ValidateBinding(JsonObject assignment, JsonObject cyclePolicy)
    {
        var current = assignment["config"] as JsonObject ?? new JsonObject();
        foreach (var key in new[] { "source_instance_id", "domain_sid", "domain_dns", "scope" })
            if (!PythonMetadataEquality.Equal(current[key], cyclePolicy[key])) throw Pending("agent_source_not_bound");
        if (assignment["module_id"]!.GetValue<string>() == "sli.ad-snapshot")
            foreach (var key in new[] { "search_bases", "groups", "dc", "expensive_flags" })
                if (!PythonMetadataEquality.Equal(current[key], cyclePolicy[key])) throw Pending("agent_source_not_bound");
    }
    private static ProtocolException Pending(string code) => new(code);
}
