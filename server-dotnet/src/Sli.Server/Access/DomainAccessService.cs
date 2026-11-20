using Sli.Server.Auth;
using Sli.Server.Infrastructure;

namespace Sli.Server.Access;

public sealed class DomainAccessService : IDomainAccessService
{
    private readonly IAccessFactsRepository facts;
    private readonly ICapabilityComposer capabilities = new CapabilityComposer();
    private readonly IReportEligibility eligibility = new ReportEligibility();
    private readonly IReportScopeResolver scopes = new ReportScopeResolver();
    private readonly IReportCatalogProvider catalog;

    public DomainAccessService(IPostgresConnectionFactory connections, IReportCatalogProvider? catalog = null,
        IAccessFactsRepository? facts = null)
    {
        this.facts = facts ?? new AccessFactsRepository(connections);
        this.catalog = catalog ?? new ReportRuleCatalog();
    }

    public async Task<DomainAccessDecision> EvaluateAsync(Principal principal, CancellationToken ct)
    {
        var captured = catalog.Capture();
        var loaded = (await facts.LoadAsync(principal, ct)) with { ReportCatalog = captured };
        var composed = capabilities.Compose(loaded);
        var workspace = composed.Decide("workspace.view");
        if (!workspace.Allowed) return new(false, workspace.Reason, DomainGrant.None);
        var reports = eligibility.Compose(loaded, composed);
        // A changed/fenced owner cannot use declarations captured before the SQL facts.
        // Unaffected core and unguarded workstation contributions continue to work.
        var current = catalog.Recheck(loaded.ReportCatalog);
        return new(true, workspace.Reason, scopes.PermittedDomains(reports, current.Rules));
    }
}
