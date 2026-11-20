using System.Text.Json;
using Npgsql;

namespace Sli.Server.Agents.Control;

public sealed class AgentReplacementService
{
    private static readonly HashSet<string> Conflicts = new(StringComparer.Ordinal) {
        "agent_replacement_not_ready", "agent_replacement_hostname_mismatch", "agent_replacement_token_mismatch",
        "agent_replacement_target_used", "agent_replacement_conflict", "agent_replacement_pending_import",
        "agent_replacement_policy_changed", "agent_replacement_module_unsupported", "agent_replacement_policy_size",
        "agent_replacement_client_unsupported"
    };
    public async Task<JsonElement> ReplaceAsync(NpgsqlConnection db, NpgsqlTransaction tx, JsonElement body, string actor, CancellationToken ct)
    {
        var input = AgentRecoveryInput.Replacement(body);
        try
        {
            await using var command = new NpgsqlCommand("select public.replace_agent_runtime_v296(@old,@new,@phase,@actor) as result", db, tx);
            command.Parameters.AddWithValue("old", input.OldAgent); command.Parameters.AddWithValue("new", input.NewAgent);
            command.Parameters.AddWithValue("phase", input.Phase); command.Parameters.AddWithValue("actor", actor);
            var json = await command.ExecuteScalarAsync(ct) as string ?? throw new InvalidOperationException();
            using var result = JsonDocument.Parse(json); return result.RootElement.Clone();
        }
        catch (PostgresException error) when (error.SqlState == "55000" && Conflicts.Contains(error.MessageText))
        { throw new AgentControlException(error.MessageText, 409); }
    }
}