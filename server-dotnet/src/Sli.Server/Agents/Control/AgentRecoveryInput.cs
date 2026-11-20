using System.Globalization;
using System.Text.Json;

namespace Sli.Server.Agents.Control;

internal sealed record AgentRecoveryAuthorization(Guid Agent, string[] ObservationIds, string PreviewToken);
internal sealed record AgentReplacementInput(Guid OldAgent, Guid NewAgent, string Phase);

internal static class AgentRecoveryInput
{
    private static bool Shape(JsonElement body, params string[] names) => body.ValueKind == JsonValueKind.Object
        && body.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal).SetEquals(names);
    internal static AgentRecoveryAuthorization Authorization(JsonElement body)
    {
        const string error = "agent_sequence_recovery_invalid";
        if (!Shape(body, "agent_id", "observation_ids", "preview_token", "confirm_loss")
            || body.GetProperty("confirm_loss").ValueKind != JsonValueKind.True
            || body.GetProperty("observation_ids") is not { ValueKind: JsonValueKind.Array } ids
            || ids.GetArrayLength() is < 1 or > 100
            || AgentControlJson.String(body.GetProperty("preview_token")) is not { Length: 64 } token
            || token.Any(c => c is not (>= 'a' and <= 'f' or >= '0' and <= '9')))
            throw new AgentControlException(error);
        Guid agent = AgentControlJson.Id(body.GetProperty("agent_id"));
        var values = new List<string>();
        foreach (var item in ids.EnumerateArray())
        {
            string? value = AgentControlJson.String(item);
            if (value is null || value.Length is < 1 or > 19 || value[0] == '0'
                || value.Any(c => c is < '0' or > '9')
                || !long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long parsed) || parsed <= 0)
                throw new AgentControlException(error);
            values.Add(value);
        }
        if (values.Distinct(StringComparer.Ordinal).Count() != values.Count) throw new AgentControlException(error);
        return new(agent, values.ToArray(), token);
    }
    internal static AgentReplacementInput Replacement(JsonElement body)
    {
        if (!Shape(body, "old_agent_id", "new_agent_id", "phase", "confirm")
            || body.GetProperty("confirm").ValueKind != JsonValueKind.True
            || AgentControlJson.String(body.GetProperty("phase")) is not ("prepare" or "complete"))
            throw new AgentControlException("agent_replacement_invalid");
        var old = AgentControlJson.Id(body.GetProperty("old_agent_id")); var next = AgentControlJson.Id(body.GetProperty("new_agent_id"));
        if (old == next) throw new AgentControlException("agent_replacement_invalid");
        return new(old, next, body.GetProperty("phase").GetString()!);
    }
}