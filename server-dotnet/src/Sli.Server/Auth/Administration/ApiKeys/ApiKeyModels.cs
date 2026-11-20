using System.Numerics;
using System.Text.Json;

namespace Sli.Server.Auth.Administration.ApiKeys;

public sealed record ReportKeyContext(long SubjectId, long DomainId, string[] Reports);
public sealed record IssueApiKeyCommand(string Label, string Role = "viewer", DateTimeOffset? ExpiresAt = null, ReportKeyContext? Report = null);
public sealed record ApiKeyIssueResult(JsonElement Item, string Token);
public sealed class ApiKeyAdministrationException(string code) : Exception(code);

public interface IApiKeyAdministration
{
    Task<IReadOnlyList<JsonElement>> ListAsync(CancellationToken ct);
    Task<ApiKeyIssueResult> IssueAsync(IssueApiKeyCommand command, UserAdministrationActor actor, CancellationToken ct);
    Task<bool> RevokeAsync(BigInteger keyId, UserAdministrationActor actor, CancellationToken ct);
}
