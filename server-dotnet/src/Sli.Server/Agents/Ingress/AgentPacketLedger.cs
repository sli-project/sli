using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Ingress;

public sealed class AgentPacketLedger(NpgsqlConnection connection, NpgsqlTransaction transaction)
{
    private NpgsqlCommand Command(string sql) => new(sql, connection, transaction);
    private static void Json(NpgsqlCommand command, string name, JsonNode? value) => command.Parameters.AddWithValue(name, NpgsqlDbType.Jsonb, PacketStorageJson.Serialize(value));

    public async Task<(string Hash, JsonObject Receipt)?> ExistingAsync(Envelope envelope, CancellationToken ct)
    {
        await using var command = Command("select envelope_sha256,receipt::text from sli_agent_receipts where agent_id=@agent and module_id=@module and sequence=@sequence");
        command.Parameters.AddWithValue("agent", Guid.Parse(envelope.AgentId)); command.Parameters.AddWithValue("module", envelope.ModuleId); command.Parameters.AddWithValue("sequence", envelope.Sequence);
        await using var reader = await command.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? (reader.GetString(0), JsonNode.Parse(reader.GetString(1))!.AsObject()) : null;
    }

    public async Task<bool> PacketExistsAsync(string id, string agentId, CancellationToken ct)
    {
        await using var command = Command("""
            select exists(select 1 from sli_agent_receipts where packet_id=@id)
              or exists(select 1 from sli_agents a, jsonb_each(a.packet_expiry) m
                where a.id=@agent and m.value->'expired_envelope'->>'packet_id'=@id::text)
            """);
        command.Parameters.AddWithValue("id", Guid.Parse(id)); command.Parameters.AddWithValue("agent", Guid.Parse(agentId));
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    public async Task<JsonObject?> SummaryAsync(Envelope envelope, CancellationToken ct)
    {
        await using var command = Command("select (packet_expiry->@module)::text from sli_agents where id=@agent");
        command.Parameters.AddWithValue("agent", Guid.Parse(envelope.AgentId)); command.Parameters.AddWithValue("module", envelope.ModuleId);
        var value = await command.ExecuteScalarAsync(ct);
        return value is string text ? JsonNode.Parse(text)!.AsObject() : null;
    }

    private async Task SaveSummaryAsync(Envelope envelope, JsonObject summary, CancellationToken ct)
    {
        await using var command = Command("update sli_agents set packet_expiry=jsonb_set(packet_expiry,array[@module],@summary) where id=@agent");
        command.Parameters.AddWithValue("agent", Guid.Parse(envelope.AgentId)); command.Parameters.AddWithValue("module", envelope.ModuleId);
        Json(command,"summary",summary); await command.ExecuteNonQueryAsync(ct);
    }

    // One transport tip and one latest gap per module, rather than an unbounded rejection ledger.
    public async Task ExpireAsync(Envelope envelope, JsonObject? previous, JsonObject? summary, CancellationToken ct)
    {
        summary ??= new JsonObject();
        if (summary["expiry_pending"]?.GetValue<bool>() != true)
            summary["data_gap"] = new JsonObject { ["from_utc"] = previous?["observed_at_utc"]?.DeepClone() ?? JsonValue.Create(envelope.ObservedAtUtc) };
        summary["data_gap"]!["to_utc"] = envelope.ObservedAtUtc;
        summary["expired_envelope"] = envelope.ToJson();
        summary["expiry_pending"] = true;
        await SaveSummaryAsync(envelope,summary,ct);
    }

    public async Task GapAsync(Envelope envelope, JsonObject? previous, JsonObject? summary, CancellationToken ct)
    {
        summary ??= new JsonObject();
        if (summary["expiry_pending"]?.GetValue<bool>() != true)
            summary["data_gap"] = new JsonObject { ["from_utc"] = previous?["observed_at_utc"]?.DeepClone() ?? JsonValue.Create(envelope.ObservedAtUtc) };
        summary["data_gap"]!["to_utc"] = envelope.ObservedAtUtc;
        summary["expiry_pending"] = false;
        await SaveSummaryAsync(envelope,summary,ct);
    }

    public async Task<bool> HistoryPendingAsync(Guid agent,CancellationToken ct)
    {
        await using var command=Command("""
            select exists(select 1 from sli_agent_packet_inbox
              where envelope->>'agent_id'=@agent and envelope->>'module_id'='sli.windows.ad-dc-history'
                and imported_at is null)
            """);
        command.Parameters.AddWithValue("agent",agent.ToString("D"));
        return (bool)(await command.ExecuteScalarAsync(ct))!;
    }

    public async Task<JsonObject?> LatestAsync(Envelope envelope, CancellationToken ct)
    {
        await using var command = Command("select envelope::text from (" + AgentReceiptSummary.LatestSql + ") latest");
        command.Parameters.AddWithValue("agent", Guid.Parse(envelope.AgentId)); command.Parameters.AddWithValue("module", envelope.ModuleId);
        var value = await command.ExecuteScalarAsync(ct); return value is string text ? JsonNode.Parse(text)?.AsObject() : null;
    }

    public async Task<(JsonArray Assignments, Guid? SourceHost)> AgentStateAsync(Guid id, CancellationToken ct)
    {
        await using var command = Command("select assigned_modules::text,source_host_id from sli_agents where id=@id"); command.Parameters.AddWithValue("id", id);
        await using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) throw new InvalidOperationException("Authenticated agent missing");
        return (JsonNode.Parse(reader.GetString(0))!.AsArray(), reader.IsDBNull(1) ? null : reader.GetGuid(1));
    }

    public async Task<(string SourceId, string SourceName, string Channel, string Version, string Revision)?> BindingAsync(Envelope envelope, CancellationToken ct)
    {
        await using var command = Command("select source_instance_id,source_name,channel,module_version,policy_revision from sli_agent_module_bindings where agent_id=@id and module_id=@module");
        command.Parameters.AddWithValue("id", Guid.Parse(envelope.AgentId)); command.Parameters.AddWithValue("module", envelope.ModuleId);
        await using var reader = await command.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? (reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4)) : null;
    }

    public async Task StoreAsync(Envelope envelope, JsonObject payload, JsonArray? rows, JsonObject receipt, CancellationToken ct)
    {
        await using var command = Command("""
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            values(@agent,@module,@sequence,@packet,@hash,@envelope,@receipt)
            """);
        command.Parameters.AddWithValue("agent", Guid.Parse(envelope.AgentId)); command.Parameters.AddWithValue("module", envelope.ModuleId);
        command.Parameters.AddWithValue("sequence", envelope.Sequence); command.Parameters.AddWithValue("packet", Guid.Parse(envelope.PacketId));
        command.Parameters.AddWithValue("hash", Packets.Digest(envelope.ToJson())); Json(command,"envelope",envelope.ToJson()); Json(command,"receipt",receipt);
        await command.ExecuteNonQueryAsync(ct);
        if (rows is null) return;
        await using var inbox = Command("insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows) values(@packet,@envelope,@payload,@rows)");
        inbox.Parameters.AddWithValue("packet", Guid.Parse(envelope.PacketId)); Json(inbox,"envelope",envelope.ToJson()); Json(inbox,"payload",payload); Json(inbox,"rows",rows);
        await inbox.ExecuteNonQueryAsync(ct);
    }
}
