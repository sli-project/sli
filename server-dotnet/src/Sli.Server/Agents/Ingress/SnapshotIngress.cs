using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Ingress;

// Prepared only while the caller holds the authenticated agent lock and the snapshot advisory lock.
public sealed class SnapshotPrepared
{
    internal SnapshotPrepared(Envelope envelope, JsonObject payload, SnapshotPolicy policy)
    {
        Envelope = envelope;
        Payload = (JsonObject)payload.DeepClone();
        Policy = new SnapshotPolicy(policy.ModuleId, (JsonObject)policy.Config.DeepClone());
    }
    internal Envelope Envelope { get; }
    internal JsonObject Payload { get; }
    internal SnapshotPolicy Policy { get; }
}

public static class SnapshotIngress
{
    public static async Task<SnapshotPrepared> ValidateAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        AgentIdentity identity, Envelope envelope, JsonObject payload, JsonArray assignedModules, CancellationToken ct, bool transportGap=false)
    {
        static ProtocolException Reject(string code) => new(code);
        if (identity.Id.ToString("D") != envelope.AgentId) throw Reject("agent_identity_mismatch");
        var matches = assignedModules.OfType<JsonObject>().Where(x => JsonRead.TryString(x["module_id"], out var id) && id == envelope.ModuleId).ToArray();
        if (matches.Length != 1 || matches[0]["enabled"]?.GetValueKind() != JsonValueKind.True) throw Reject("agent_module_not_assigned");
        var config = matches[0].ContainsKey("config") ? matches[0]["config"] as JsonObject : new JsonObject();
        if (config is null) throw Reject("agent_snapshot_policy_invalid");
        SnapshotPolicy current;
        try { current = SnapshotIngressPolicy.Parse(envelope.ModuleId, config); }
        catch (AgentException error) { throw Reject(error.Code); }
        var agent = identity.Id;
        await using (var binding = new NpgsqlCommand("select config::text from sli_agent_snapshot_bindings where agent_id=@agent and module_id=@module and enabled", connection, transaction))
        {
            binding.Parameters.AddWithValue("agent", agent); binding.Parameters.AddWithValue("module", envelope.ModuleId);
            var value = await binding.ExecuteScalarAsync(ct);
            if (value is not string text || !JsonNode.DeepEquals(JsonNode.Parse(text), current.Config)) throw Reject("agent_source_not_bound");
        }
        if (!JsonRead.TryString(payload["cycle_id"], out var cycleText) || !Guid.TryParseExact(cycleText, "D", out var cycleId) || cycleId.ToString("D") != cycleText)
            throw Reject("agent_snapshot_chunk_invalid");
        SnapshotPolicy selected = current;
        bool existing = false;
        await using (var cycle = new NpgsqlCommand("select agent_id,module_id,slot_start_utc,policy::text,transport_state from sli_agent_snapshot_cycles where cycle_id=@cycle", connection, transaction))
        {
            cycle.Parameters.AddWithValue("cycle", cycleId);
            await using var reader = await cycle.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                existing = true;
                if (reader.GetGuid(0) != agent || reader.GetString(1) != envelope.ModuleId
                    || !JsonRead.TryString(payload["slot_start_utc"], out var slotText) || reader.GetString(2) != slotText || reader.GetString(4) != "pending")
                    throw Reject("agent_snapshot_cycle_conflict");
                selected = new SnapshotPolicy(envelope.ModuleId, JsonNode.Parse(reader.GetString(3))!.AsObject());
            }
        }
        if (!existing && envelope.PolicyRevision != current.Revision)
        {
            await using var historical = new NpgsqlCommand("select config::text,enabled,superseded_at from sli_agent_snapshot_policies where agent_id=@agent and module_id=@module and policy_revision=@revision", connection, transaction);
            historical.Parameters.AddWithValue("agent", agent); historical.Parameters.AddWithValue("module", envelope.ModuleId); historical.Parameters.AddWithValue("revision", envelope.PolicyRevision);
            await using var reader = await historical.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct) || !reader.GetBoolean(1) || reader.IsDBNull(2) || !JsonRead.TryString(payload["slot_start_utc"], out var slotText)
                || !Iso8601.TryParseUtc(slotText, out var slot) || slot > new DateTimeOffset(reader.GetDateTime(2))) throw Reject("agent_snapshot_chunk_invalid");
            selected = new SnapshotPolicy(envelope.ModuleId, JsonNode.Parse(reader.GetString(0))!.AsObject());
        }
        foreach (var field in new[] { "source_instance_id", "domain_sid", "domain_dns", "scope" })
            if (!JsonNode.DeepEquals(current.Config[field], selected.Config[field])) throw Reject("agent_source_not_bound");
        SnapshotChunkValidator.Validate(envelope, payload, selected, transportGap);
        await using (var held = new NpgsqlCommand("select pg_advisory_xact_lock(170,1)", connection, transaction)) await held.ExecuteNonQueryAsync(ct);
        if (await ConflictAsync(connection, transaction, envelope, payload, selected, ct)) throw Reject("agent_snapshot_chunk_conflict");
        return new SnapshotPrepared(envelope, payload, selected);
    }

    private static async Task<bool> ConflictAsync(NpgsqlConnection db, NpgsqlTransaction tx, Envelope envelope, JsonObject payload, SnapshotPolicy policy, CancellationToken ct)
    {
        string cycle = payload["cycle_id"]!.GetValue<string>(), family = payload["family"]!.GetValue<string>(), slot = payload["slot_start_utc"]!.GetValue<string>();
        await using (var command = new NpgsqlCommand("select cycle_id from sli_agent_snapshot_cycles where domain_sid=@sid and module_id=@module and slot_start_utc=@slot", db, tx))
        {
            command.Parameters.AddWithValue("sid", policy.Config["domain_sid"]!.GetValue<string>()); command.Parameters.AddWithValue("module", envelope.ModuleId); command.Parameters.AddWithValue("slot", slot);
            var value = await command.ExecuteScalarAsync(ct);
            if (value is Guid existing && existing.ToString("D") != cycle) return true;
        }
        await using (var command = new NpgsqlCommand("select payload::text from sli_agent_snapshot_chunks where cycle_id=@cycle and family=@family order by chunk_index limit 1", db, tx))
        {
            command.Parameters.AddWithValue("cycle", Guid.Parse(cycle)); command.Parameters.AddWithValue("family", family);
            if (await command.ExecuteScalarAsync(ct) is string text)
            {
                var prior = JsonNode.Parse(text)!.AsObject();
                foreach (var name in new[] { "chunk_count", "total_objects", "total_bytes", "family_sha256", "cycle_families" })
                    if (!JsonNode.DeepEquals(prior[name], payload[name])) return true;
            }
        }
        await using (var command = new NpgsqlCommand("select 1 from sli_agent_snapshot_chunks where cycle_id=@cycle and family=@family and chunk_index=@index", db, tx))
        {
            command.Parameters.AddWithValue("cycle", Guid.Parse(cycle)); command.Parameters.AddWithValue("family", family); command.Parameters.AddWithValue("index", Integer(payload["chunk_index"]));
            if (await command.ExecuteScalarAsync(ct) is not null) return true;
        }
        long objects = Integer(payload["total_objects"]);
        long bytes = family == "computers_v6" ? 0 : Integer(payload["total_bytes"]);
        await using (var command = new NpgsqlCommand("select distinct family,payload->>'total_bytes',payload->>'total_objects' from sli_agent_snapshot_chunks where cycle_id=@cycle and family<>@family", db, tx))
        {
            command.Parameters.AddWithValue("cycle", Guid.Parse(cycle)); command.Parameters.AddWithValue("family", family);
            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                long otherObjects = long.Parse(reader.GetString(2), System.Globalization.CultureInfo.InvariantCulture);
                objects = envelope.ModuleId == SnapshotPolicy.Gpo ? Math.Max(objects, otherObjects) : checked(objects + otherObjects);
                if (reader.GetString(0) != "computers_v6") bytes = checked(bytes + long.Parse(reader.GetString(1), System.Globalization.CultureInfo.InvariantCulture));
            }
        }
        return objects > policy.Number("max_objects") || bytes > policy.Number("max_bytes");
    }

    private static int Integer(JsonNode? value) => JsonRead.TryInteger(value, out var n) && n >= 0 && n <= int.MaxValue ? (int)n : throw new ProtocolException("agent_snapshot_chunk_invalid");

    public static async Task<string?> CheckQuotaAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        SnapshotPrepared plan, JsonObject receipt, AgentInboxLimits limits, CancellationToken ct)
    {
        var e = plan.Envelope;
        await using (var held = new NpgsqlCommand("select pg_advisory_xact_lock(170,1)", connection, transaction)) await held.ExecuteNonQueryAsync(ct);
        long[] usage = new long[6];
        await using (var command = new NpgsqlCommand("""
            select count(*) filter(where r.agent_id=@agent),coalesce(sum(octet_length(c.payload::text)+2048) filter(where r.agent_id=@agent),0),
              count(*) filter(where r.module_id=@module),coalesce(sum(octet_length(c.payload::text)+2048) filter(where r.module_id=@module),0),
              count(*),coalesce(sum(octet_length(c.payload::text)+2048),0)
              from sli_agent_snapshot_chunks c join sli_agent_receipts r using(packet_id)
              join sli_agent_snapshot_cycles s using(cycle_id) where s.transport_state='pending'
            """, connection, transaction))
        {
            command.Parameters.AddWithValue("agent", Guid.Parse(e.AgentId)); command.Parameters.AddWithValue("module", e.ModuleId);
            await using var reader = await command.ExecuteReaderAsync(ct); await reader.ReadAsync(ct);
            for (int i=0;i<6;i++) usage[i] = Convert.ToInt64(reader.GetValue(i));
        }
        long addition = checked((long)CanonicalJson.Length(plan.Payload) + CanonicalJson.Length(e.ToJson()) + CanonicalJson.Length(receipt) + 4096);
        long[] bounds = [limits.AgentCount, limits.SnapshotAgentBytes, limits.ModuleCount, limits.ModuleBytes, limits.GlobalCount, limits.GlobalBytes];
        string[] names = ["agent_count", "agent_bytes", "module_count", "module_bytes", "global_count", "global_bytes"];
        for (int i=0;i<6;i++) if (usage[i] > bounds[i] - (i % 2 == 1 ? addition : 1)) return "agent_snapshot_" + names[i] + "_limit";
        long current = await AgentInboxQuota.LiveStorageBytesAsync(connection, transaction,
            ["sli_agent_snapshot_chunks", "sli_agent_snapshot_cycles", "sli_agent_snapshot_policies", "sli_agent_snapshot_bindings", "sli_agent_receipts"], ct);
        if (current > limits.StorageBytes - checked(2 * addition + 65536)) return "agent_snapshot_storage_bytes_limit";
        return null;
    }

    public static async Task StoreAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, SnapshotPrepared plan, CancellationToken ct)
    {
        var e = plan.Envelope; var payload = plan.Payload;
        await using (var cycle = new NpgsqlCommand("""
            insert into sli_agent_snapshot_cycles(cycle_id,agent_id,module_id,slot_start_utc,domain_sid,policy)
            select @cycle,@agent,@module,@slot,@sid,config from sli_agent_snapshot_policies
             where agent_id=@agent and module_id=@module and policy_revision=@revision and enabled
            on conflict(cycle_id) do nothing
            """, connection, transaction))
        {
            cycle.Parameters.AddWithValue("cycle", Guid.Parse(payload["cycle_id"]!.GetValue<string>())); cycle.Parameters.AddWithValue("agent", Guid.Parse(e.AgentId));
            cycle.Parameters.AddWithValue("module", e.ModuleId); cycle.Parameters.AddWithValue("slot", payload["slot_start_utc"]!.GetValue<string>());
            cycle.Parameters.AddWithValue("sid", payload["domain_sid"]!.GetValue<string>()); cycle.Parameters.AddWithValue("revision", e.PolicyRevision);
            await cycle.ExecuteNonQueryAsync(ct);
        }
        await using var chunk = new NpgsqlCommand("insert into sli_agent_snapshot_chunks(packet_id,cycle_id,family,chunk_index,payload) values(@packet,@cycle,@family,@index,@payload)", connection, transaction);
        chunk.Parameters.AddWithValue("packet", Guid.Parse(e.PacketId)); chunk.Parameters.AddWithValue("cycle", Guid.Parse(payload["cycle_id"]!.GetValue<string>()));
        chunk.Parameters.AddWithValue("family", payload["family"]!.GetValue<string>()); chunk.Parameters.AddWithValue("index", Integer(payload["chunk_index"]));
        chunk.Parameters.AddWithValue("payload", NpgsqlDbType.Jsonb, PacketStorageJson.Serialize(payload));
        await chunk.ExecuteNonQueryAsync(ct);
    }
}
