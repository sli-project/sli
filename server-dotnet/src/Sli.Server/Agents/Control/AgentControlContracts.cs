using System.Text.Json;
using Npgsql;

namespace Sli.Server.Agents.Control;

public sealed class AgentControlException(string code, int status = 400) : Exception(code)
{
    public int Status { get; } = status;
}

public interface IAgentControlAudit
{
    Task AppendAsync(NpgsqlConnection db, NpgsqlTransaction tx, string action, string actor, string target, object details, CancellationToken ct);
}

public sealed class AgentControlAudit : IAgentControlAudit
{
    public async Task AppendAsync(NpgsqlConnection db, NpgsqlTransaction tx, string action, string actor, string target, object details, CancellationToken ct)
    {
        await using var query = new NpgsqlCommand("insert into sli_agent_audit(action,actor,target,details) values(@action,@actor,@target,@details::jsonb)", db, tx);
        query.Parameters.AddWithValue("action", action); query.Parameters.AddWithValue("actor", actor); query.Parameters.AddWithValue("target", target);
        query.Parameters.AddWithValue("details", JsonSerializer.Serialize(details)); await query.ExecuteNonQueryAsync(ct);
    }
}

public interface IAgentPolicyService
{
    Task<JsonElement> UpdateControlAsync(NpgsqlConnection db, NpgsqlTransaction tx, JsonElement payload, string actor, CancellationToken ct);
}
