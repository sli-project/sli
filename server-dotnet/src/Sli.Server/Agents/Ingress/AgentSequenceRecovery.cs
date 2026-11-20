using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Ingress;

public sealed class AgentSequenceRecovery(NpgsqlConnection connection, NpgsqlTransaction tx)
{
    private async Task<(long Id, JsonObject Details, DateTimeOffset Time)?> LatestAsync(string action, string where, string value, string? module, CancellationToken ct)
    {
        string predicate = where == "target" ? "target=@value and details->>'module_id'=@module" : "details->>'observation_id'=@value";
        await using var command = new NpgsqlCommand($"select id,details::text,occurred_at from sli_agent_audit where action=@action and {predicate} order by id desc limit 1", connection, tx);
        command.Parameters.AddWithValue("action",action); command.Parameters.AddWithValue("value",value);
        if (where == "target") command.Parameters.AddWithValue("module",module!);
        await using var reader = await command.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? (reader.GetInt64(0),JsonNode.Parse(reader.GetString(1))!.AsObject(),new DateTimeOffset(reader.GetDateTime(2),TimeSpan.Zero)) : null;
    }
    private async Task AuditAsync(string action, string agent, JsonObject details, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("insert into sli_agent_audit(action,actor,target,details) values(@action,@actor,@target,@details)",connection,tx);
        command.Parameters.AddWithValue("action",action); command.Parameters.AddWithValue("actor","agent:"+agent); command.Parameters.AddWithValue("target",agent);
        command.Parameters.AddWithValue("details",NpgsqlDbType.Jsonb,details.ToJsonString()); await command.ExecuteNonQueryAsync(ct);
    }
    public async Task<string?> ObserveAsync(AgentIdentity identity, Envelope e, JsonObject? previous, DateTimeOffset now, CancellationToken ct)
    {
        string agent=e.AgentId; string hash=Packets.Digest(e.ToJson()); string? previousHash=previous is null ? null : Packets.Digest(previous);
        var observed=await LatestAsync("sequence_gap_observed","target",agent,e.ModuleId,ct);
        if (observed is { } found && found.Details["previous_hash"]?.GetValue<string>() == previousHash && found.Details["key_fingerprint"]?.GetValue<string>() == identity.KeyFingerprint)
        {
            if (found.Details["envelope_hash"]?.GetValue<string>() != hash) return null;
        }
        else
        {
            long expected=(previous?["sequence"]?.GetValue<long>() ?? 0)+1;
            var details=new JsonObject { ["module_id"]=e.ModuleId,["packet_id"]=e.PacketId,["envelope_hash"]=hash,["previous_hash"]=previousHash,
                ["key_fingerprint"]=identity.KeyFingerprint,["expected_sequence"]=expected.ToString(),["received_sequence"]=e.Sequence.ToString(),
                ["missing_packets"]=(e.Sequence-expected).ToString(),["previous_observed_at"]=previous?["observed_at_utc"]?.DeepClone(),
                ["packet_observed_at"]=e.ObservedAtUtc,["loss_event_count"]=null,["loss_time_bounds_known"]=false,
                ["reason"]="authenticated_sequence_gap",["first_buffer_proven"]=false };
            await AuditAsync("sequence_gap_observed",agent,details,ct);
            observed=await LatestAsync("sequence_gap_observed","target",agent,e.ModuleId,ct);
        }
        if (observed is null) throw new InvalidOperationException("Recovery observation missing");
        string id=observed.Value.Id.ToString(System.Globalization.CultureInfo.InvariantCulture);
        if (await LatestAsync("sequence_gap_accepted","observation",id,null,ct) is not null) return null;
        var authorization=await LatestAsync("sequence_gap_authorized","observation",id,null,ct);
        return authorization is null || now > authorization.Value.Time.AddMinutes(20) ? null : id;
    }
    public Task AcceptAsync(string id, Envelope e, DateTimeOffset now, CancellationToken ct) => AuditAsync("sequence_gap_accepted",e.AgentId,
        new JsonObject { ["observation_id"]=id,["module_id"]=e.ModuleId,["packet_id"]=e.PacketId,
            ["accepted_at"]=Iso8601.Format(now),["reason"]="operator_confirmed_sequence_gap" },ct);
}
