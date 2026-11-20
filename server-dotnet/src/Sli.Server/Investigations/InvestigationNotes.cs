using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;

namespace Sli.Server.Investigations;

public sealed class InvestigationException(string code, string message, int status = 400) : Exception(message)
{
    public long? InvestigationId { get; init; }
    public string Code { get; } = code;
    public int Status { get; } = status;
}

public sealed record InvestigationIdentity(BigInteger? Id, Guid? PublicId)
{
    public string Column => Id.HasValue ? "id" : "public_id";
    public string Display => Id?.ToString(CultureInfo.InvariantCulture) ?? PublicId!.Value.ToString();
    public static InvestigationIdentity Parse(string value)
    {
        // Python str.isdigit accepts decimal Unicode digits; int normalizes them.
        if (value.Length > 0 && value.EnumerateRunes().All(r => Rune.GetUnicodeCategory(r) == UnicodeCategory.DecimalDigitNumber))
        {
            var digits = string.Concat(value.EnumerateRunes().Select(r => ((int)Rune.GetNumericValue(r)).ToString(CultureInfo.InvariantCulture)));
            var id = BigInteger.Parse(digits, CultureInfo.InvariantCulture);
            if (id <= 0) throw new InvestigationException("invalid_investigation_id", "Investigation ID must be positive");
            return new(id, null);
        }
        string clean = value.Replace("urn:", "", StringComparison.Ordinal).Replace("uuid:", "", StringComparison.Ordinal).Trim('{', '}').Replace("-", "", StringComparison.Ordinal);
        if (Guid.TryParseExact(clean, "N", out var uuid)) return new(null, uuid);
        throw new InvestigationException("invalid_investigation_id", "Investigation ID is invalid");
    }
}

public sealed record InvestigationNote(
    [property: JsonPropertyName("id")] long Id,
    [property: JsonPropertyName("body")] string Body,
    [property: JsonPropertyName("created_by")] string? CreatedBy,
    [property: JsonPropertyName("created_at")] string CreatedAt);

public static class InvestigationAccess
{
    public const string Capability = "investigations.manage";
    public const string Action = "start_case";
    public static string? ReportKey(AccessDecision access) => new[] { "investigations.workspace", "cases.workspace" }
        .FirstOrDefault(key => access.Reports.Any(r => r.ReportKey == key && r.Allowed && r.Grants.Any(g => g.AllowedActions.Contains(Action))));
    public static bool Allowed(AccessDecision access, string key, IReadOnlyList<IReadOnlyList<AccessResource>> groups) =>
        access.Capabilities.DecideForResourceGroups(Capability, groups).Allowed &&
        ResourceAccessDecisions.ReportAction(access, key, Action, groups).Allowed;

    public static string CleanBody(JsonElement payload)
    {
        var value = payload.ValueKind == JsonValueKind.Object && payload.TryGetProperty("body", out var item) ? item : default;
        string body = AssignmentValidation.Strip(Sli.Server.Auth.Lifecycle.AuthJsonBody.Truthy(value) ? InvestigationPythonString.String(value) : "");
        string clean = string.Concat(body.EnumerateRunes().Take(4000).Select(r => r.ToString()));
        if (clean.Length == 0) throw new InvestigationException("invalid_note", "Note text is required");
        return clean;
    }
    public static string Actor(Principal principal) => !string.IsNullOrEmpty(principal.Username) ? principal.Username :
        !string.IsNullOrEmpty(principal.Label) ? principal.Label : !string.IsNullOrEmpty(principal.Type) ? principal.Type : "operator";
}

public interface IInvestigationRepository
{
    Task<IReadOnlyList<IReadOnlyList<AccessResource>>> ResourceGroupsAsync(InvestigationIdentity identity, CancellationToken ct);
    Task<InvestigationNote> AddNoteAsync(InvestigationIdentity identity, string body, string actor, CancellationToken ct);
}
