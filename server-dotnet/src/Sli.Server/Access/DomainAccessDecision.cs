using Sli.Server.Auth;

namespace Sli.Server.Access;

public sealed record DomainAccessDecision(bool CapabilityAllowed, string CapabilityReason, DomainGrant Grant);

public interface IDomainAccessService
{
    Task<DomainAccessDecision> EvaluateAsync(Principal principal, CancellationToken ct);
}
