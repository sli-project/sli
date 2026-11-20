using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

/// <summary>One-use token or scoped group bootstrap, optionally base64url encoded for MSI.</summary>
public sealed record EnrollmentInput(string Token, long? ComputerEntityId = null, DateTimeOffset? ExpiresAt = null)
{
    public static EnrollmentInput Parse(string value, DateTimeOffset now)
    {
        try
        {
            if (value.Length > 8192) throw new FormatException();
            value = value.Trim();
            if (Regex.IsMatch(value, "^[A-Za-z0-9_-]{43}$")) return new(value);
            if (!value.StartsWith('{'))
            {
                value = value.Replace('-', '+').Replace('_', '/');
                value = Encoding.UTF8.GetString(Convert.FromBase64String(value.PadRight((value.Length + 3) / 4 * 4, '=')));
            }
            var body = JsonNode.Parse(value)!.AsObject();
            if (!JsonRead.HasExactly(body, "kind", "token", "computer_entity_id", "expires_at") || body["kind"]!.GetValue<string>() != "group"
                || !JsonRead.TryString(body["token"], out var token) || !Regex.IsMatch(token, "^[A-Za-z0-9_-]{43}$")
                || !JsonRead.TryInteger(body["computer_entity_id"], out var entity) || entity < 1 || entity > long.MaxValue
                || !Iso8601.TryParseUtc(body["expires_at"]!.GetValue<string>(), out var expires) || expires <= now || expires > now.AddDays(7)) throw new FormatException();
            return new(token, (long)entity, expires);
        }
        catch (Exception exception) when (exception is FormatException or InvalidOperationException or System.Text.Json.JsonException or NullReferenceException)
        {
            throw new AgentException("agent_bootstrap_invalid");
        }
    }
}
