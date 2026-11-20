using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Control;

public sealed partial class AgentRecoveryService
{
    public async Task<JsonElement> AuthorizeAsync(NpgsqlConnection db, NpgsqlTransaction tx, JsonElement body, string actor, CancellationToken ct)
    {
        var input = AgentRecoveryInput.Authorization(body); await BoundAsync(db,tx,ct);
        var agent = await ReadAgentAsync(db,tx,input.Agent,true,ct);
        if (agent is null || agent.Status != "active") throw new AgentControlException("agent_sequence_recovery_stale",409);
        var streams = await EligibleAsync(db,tx,agent,ct); var preview = Preview(input.Agent,streams);
        if (!input.ObservationIds.ToHashSet(StringComparer.Ordinal).SetEquals(streams.Select(s => s.Id))
            || input.PreviewToken != preview["preview_token"]!.GetValue<string>())
            throw new AgentControlException("agent_sequence_recovery_stale",409);
        // The complete set is checked before the first append. The agent lock is
        // held through each repeat-tip check, authorization and caller commit.
        foreach (var gap in streams) await AuthorizeOneAsync(db,tx,agent,gap,actor,ct);
        return AgentControlJson.Element(new JsonObject { ["status"] = "authorized", ["agent_id"] = input.Agent.ToString("D"),
            ["observation_ids"] = preview["observation_ids"]!.DeepClone(), ["preview_token"] = input.PreviewToken });
    }
    private async Task AuthorizeOneAsync(NpgsqlConnection db,NpgsqlTransaction tx,Agent agent,Gap gap,string actor,CancellationToken ct)
    {
        string sql = """
            select o.id::text,o.details::text,
                (select envelope::text from (
            """ + Sli.Server.Agents.Ingress.AgentReceiptSummary.LatestSql.Replace("@agent", "@id") + """
                ) tip),
                exists(select 1 from sli_agent_audit where action='sequence_gap_accepted' and details->>'observation_id'=@observation),
                (select occurred_at from sli_agent_audit where action='sequence_gap_authorized' and details->>'observation_id'=@observation order by id desc limit 1),
                clock_timestamp()
            from sli_agent_audit o where target=@target and action='sequence_gap_observed' and details->>'module_id'=@module
            order by o.id desc limit 1
            """;
        DateTimeOffset? permission; DateTimeOffset now;
        await using (var command = new NpgsqlCommand(sql,db,tx))
        {
            Bind(command,agent.Id); command.Parameters.AddWithValue("module",gap.Details["module_id"]!.GetValue<string>());
            command.Parameters.AddWithValue("observation",gap.Id);
            await using var reader = await command.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct) || reader.GetString(0) != gap.Id
                || !SameTip(JsonNode.Parse(reader.GetString(1))!.AsObject(),reader.IsDBNull(2) ? null : JsonNode.Parse(reader.GetString(2))!.AsObject(),agent.Fingerprint)
                || reader.GetBoolean(3)) throw new AgentControlException("agent_sequence_recovery_stale",409);
            permission = reader.IsDBNull(4) ? null : reader.GetFieldValue<DateTimeOffset>(4); now = reader.GetFieldValue<DateTimeOffset>(5);
        }
        if (permission is null || now > permission.Value.AddMinutes(20))
            await audit.AppendAsync(db,tx,Authorized,actor,agent.Id.ToString("D"),new { observation_id = gap.Id,
                module_id = gap.Details["module_id"]!.GetValue<string>(), confirm_loss = true },ct);
    }
}
