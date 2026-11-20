using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;

namespace Sli.Server.Agents.Control;

// Source sequence_recovery.py. Caller owns the transaction, authority and commit.
public sealed partial class AgentRecoveryService(IAgentControlAudit audit)
{
    private const string Observed = "sequence_gap_observed", Authorized = "sequence_gap_authorized", Accepted = "sequence_gap_accepted";
    private sealed record Agent(Guid Id, string Status, string Fingerprint);
    private sealed record Gap(string Id, JsonObject Details, DateTimeOffset OccurredAt, bool Accepted,
        DateTimeOffset? AuthorizedAt, DateTimeOffset Now, JsonObject? Previous);
    private static Task BoundAsync(NpgsqlConnection db, NpgsqlTransaction tx, CancellationToken ct)
    {
        var command = new NpgsqlCommand("select set_config('statement_timeout',least(3000,coalesce(nullif(setting::bigint,0),3000))::text,true) from pg_settings where name='statement_timeout'", db, tx);
        return ExecuteAndDisposeAsync(command, ct);
    }
    private static async Task ExecuteAndDisposeAsync(NpgsqlCommand command, CancellationToken ct)
    { await using (command) await command.ExecuteNonQueryAsync(ct); }
    private static async Task<Agent?> ReadAgentAsync(NpgsqlConnection db, NpgsqlTransaction tx, Guid id, bool locked, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("select id,status,key_fingerprint from sli_agents where id=@id" + (locked ? " for update" : ""), db, tx);
        command.Parameters.AddWithValue("id", id); await using var reader = await command.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? new(reader.GetGuid(0), reader.GetString(1), reader.GetString(2)) : null;
    }
    private static JsonObject Public(Gap gap, Guid agent, string status) => new() {
        ["id"] = gap.Id, ["agent_id"] = agent.ToString("D"), ["module_id"] = gap.Details["module_id"]?.DeepClone(),
        ["expected_sequence"] = gap.Details["expected_sequence"]?.DeepClone(), ["received_sequence"] = gap.Details["received_sequence"]?.DeepClone(),
        ["missing_packets"] = gap.Details["missing_packets"]?.DeepClone(), ["observed_at"] = AgentControlJson.Stamp(gap.OccurredAt, iso:true),
        ["previous_observed_at"] = gap.Details["previous_observed_at"]?.DeepClone(), ["packet_observed_at"] = gap.Details["packet_observed_at"]?.DeepClone(),
        ["loss_event_count"] = null, ["loss_time_bounds_known"] = false, ["status"] = status
    };
    private static string Status(Gap gap) => gap.Accepted ? "accepted" : gap.AuthorizedAt is { } at && gap.Now <= at.AddMinutes(20) ? "authorized" : "pending";
    private static bool SameTip(JsonObject details, JsonObject? previous, string fingerprint) =>
        details["previous_hash"]?.GetValue<string>() == (previous is null ? null : Packets.Digest(previous))
        && details["key_fingerprint"]?.GetValue<string>() == fingerprint;
    private static async Task<List<Gap>> ReadGapsAsync(NpgsqlCommand command, bool previous, CancellationToken ct)
    {
        var gaps = new List<Gap>(); await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) gaps.Add(new(reader.GetString(0),JsonNode.Parse(reader.GetString(1))!.AsObject(),reader.GetFieldValue<DateTimeOffset>(2),
            !reader.IsDBNull(3),reader.IsDBNull(4) ? null : reader.GetFieldValue<DateTimeOffset>(4),reader.GetFieldValue<DateTimeOffset>(5),
            !previous || reader.IsDBNull(6) ? null : JsonNode.Parse(reader.GetString(6))!.AsObject()));
        return gaps;
    }
    private static void Bind(NpgsqlCommand command, Guid id)
    { command.Parameters.AddWithValue("id",id); command.Parameters.AddWithValue("target",id.ToString("D")); }
    public async Task<JsonElement> ListAsync(NpgsqlConnection db, NpgsqlTransaction tx, string? rawAgent, CancellationToken ct)
    {
        Guid id = AgentControlJson.Id(rawAgent); await BoundAsync(db,tx,ct);
        await using var command = new NpgsqlCommand("""
            select o.id::text,o.details::text,o.occurred_at,accepted.id,permission.occurred_at,clock_timestamp()
            from (select id,details,occurred_at from sli_agent_audit where target=@target and action='sequence_gap_observed' order by id desc limit 101) o
            left join lateral (select id from sli_agent_audit where action='sequence_gap_accepted' and details->>'observation_id'=o.id::text order by id desc limit 1) accepted on true
            left join lateral (select occurred_at from sli_agent_audit where action='sequence_gap_authorized' and details->>'observation_id'=o.id::text order by id desc limit 1) permission on true
            order by o.id desc
            """,db,tx);
        command.Parameters.AddWithValue("target",id.ToString("D")); var gaps = await ReadGapsAsync(command,false,ct);
        var streams = await EligibleAsync(db,tx,await ReadAgentAsync(db,tx,id,false,ct),ct);
        return AgentControlJson.Element(new JsonObject {
            ["gaps"] = new JsonArray(gaps.Take(100).Select(g => (JsonNode)Public(g,id,Status(g))).ToArray()),
            ["truncated"] = gaps.Count > 100, ["recovery_preview"] = Preview(id,streams)
        });
    }
    private static JsonObject Preview(Guid id, List<Gap> streams)
    {
        var boundaries = new JsonArray(streams.Select(s => (JsonNode)new JsonObject { ["id"] = s.Id, ["proof"] = Packets.Digest(s.Details) }).ToArray());
        string token = Packets.Digest(new JsonObject { ["agent_id"] = id.ToString("D"), ["boundaries"] = boundaries });
        return new JsonObject { ["agent_id"] = id.ToString("D"), ["observation_ids"] = new JsonArray(streams.Select(s => (JsonNode)JsonValue.Create(s.Id)!).ToArray()),
            ["preview_token"] = token, ["streams"] = new JsonArray(streams.Select(s => (JsonNode)Public(s,id,Status(s))).ToArray()) };
    }
    private static async Task<List<Gap>> EligibleAsync(NpgsqlConnection db, NpgsqlTransaction tx, Agent? agent, CancellationToken ct)
    {
        if (agent is null || agent.Status != "active") return [];
        await BoundAsync(db,tx,ct);
        await using var command = new NpgsqlCommand("""
            select o.id::text,o.details::text,o.occurred_at,accepted.id,permission.occurred_at,clock_timestamp(),r.envelope::text
            from (select distinct on (details->>'module_id') id,details,occurred_at from sli_agent_audit
                where target=@target and action='sequence_gap_observed' order by details->>'module_id',id desc) o
            left join lateral (
            """ + Sli.Server.Agents.Ingress.AgentReceiptSummary.LatestSql.Replace("@agent", "@id").Replace("@module", "(o.details->>'module_id')") + """
            ) r on true
            left join lateral (select id from sli_agent_audit where action='sequence_gap_accepted' and details->>'observation_id'=o.id::text order by id desc limit 1) accepted on true
            left join lateral (select occurred_at from sli_agent_audit where action='sequence_gap_authorized' and details->>'observation_id'=o.id::text order by id desc limit 1) permission on true
            order by o.id limit 101
            """,db,tx);
        Bind(command,agent.Id); var rows = await ReadGapsAsync(command,true,ct);
        if (rows.Count > 100) throw new AgentControlException("agent_sequence_recovery_preview_limit",409);
        return rows.Where(row => !row.Accepted && SameTip(row.Details,row.Previous,agent.Fingerprint)
            && row.Now <= PacketTime(row.Details).AddDays(7)).ToList();
    }
    private static DateTimeOffset PacketTime(JsonObject details) =>
        PythonIsoDateTime.TryParseUtc(details["packet_observed_at"]!.GetValue<string>(),out var time) ? time : throw new InvalidDataException();
}
