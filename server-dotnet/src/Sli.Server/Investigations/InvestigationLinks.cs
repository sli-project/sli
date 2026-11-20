using System.Numerics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Sli.Server.Access.Administration;
using Sli.Server.Auth.Lifecycle;

namespace Sli.Server.Investigations;

public sealed record InvestigationEvidenceInput(string Kind, BigInteger Domain, string Reference, string Relation)
{
    public static BigInteger Integer(JsonElement body, string name, string error, bool rejectBool = false)
    {
        try
        {
            if (!body.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null ||
                rejectBool && value.ValueKind is JsonValueKind.True or JsonValueKind.False) throw new FormatException();
            return AssignmentValidation.Integer(value);
        }
        catch (Exception e) when (e is FormatException or InvalidOperationException or ArgumentException or AuthInputException or AssignmentValidationException)
        { throw new InvestigationException(error, error); }
    }
    static string Text(JsonElement body, string key, string fallback = "") =>
        body.TryGetProperty(key, out var value) && AuthJsonBody.Truthy(value) ? InvestigationPythonString.String(value) : fallback;
    public static InvestigationEvidenceInput Parse(JsonElement body) => new(
        AssignmentValidation.Strip(Text(body, "evidence_kind")), Integer(body, "source_domain_id", "invalid_evidence_ref"),
        AssignmentValidation.Strip(Text(body, "reference_id")), AssignmentValidation.Strip(Text(body, "relation_status", "confirmed")).ToLowerInvariant());
    public void Validate()
    {
        if (Kind != "vpn_accounting_session") throw new InvestigationException("invalid_evidence_kind", "Unsupported evidence kind");
        if (Domain <= 0 || !Regex.IsMatch(Reference, @"\Aradius-session-row:[0-9a-f]{64}\z", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase))
            throw new InvestigationException("invalid_evidence_ref", "Accounting evidence reference is invalid");
        if (Relation is not ("confirmed" or "excluded")) throw new InvestigationException("invalid_relation_status", "Relation status must be confirmed or excluded");
    }
}

public interface IInvestigationLinksRepository
{
    Task<long[]> FindingEventsAsync(BigInteger finding, CancellationToken ct);
    Task<System.Text.Json.Nodes.JsonObject> LinkFindingAsync(InvestigationIdentity? identity, BigInteger finding, string actor, CancellationToken ct);
    Task<System.Text.Json.Nodes.JsonObject> AddEvidenceAsync(InvestigationIdentity identity, InvestigationEvidenceInput input, string actor, CancellationToken ct);
}

public interface IInvestigationVpnSessionEvidence
{
    Task<bool> AvailableAsync(Sli.Server.Access.AccessDecision access, BigInteger domain, string reference, CancellationToken ct);
}
