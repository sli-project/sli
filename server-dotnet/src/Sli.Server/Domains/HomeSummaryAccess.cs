using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;

namespace Sli.Server.Domains;

public sealed record HomeReport(ReportRule Rule, ReportDecision Decision, JsonElement Definition, JsonElement Preference)
{
    public CapabilityDecisionSet? Capabilities { get; init; }
    public bool Registered { get; init; } = true;
    public Func<bool> Available { get; init; } = () => true;
    public bool RequiresDomain { get; init; }
    public Func<HomeSummaryReaders, long[], HomeSummaryQuery, CancellationToken, Task<JsonObject>>? Reader { get; init; }
    public IReadOnlyDictionary<string, IReadOnlySet<string>> MetricCategories { get; init; } = new Dictionary<string, IReadOnlySet<string>>();
    public IReadOnlyList<HomeContribution> Contributions { get; init; } = HomeContribution.BuiltIn(Rule.RegistryKey);
    public string Key => Rule.RegistryKey;
    public string Title => Key switch
    {
        "security.problems" => HomePresentation.Text("reports.v2.security.problems.title"), "ad.infrastructure" => "Состояние Active Directory",
        "ad.computers.v6" => "Компьютеры", "vpn.connections" => "VPN-подключения", "security.events.chains" => "Действия безопасности",
        "ad.users.v2" => "Пользователи", "ad.gpo.v2" => "Групповые политики", _ => Definition.Text("name", Key)
    };
    public int? Order => Key switch
    {
        "security.problems" => 10, "ad.infrastructure" => 20, "ad.users.v2" => 30, "ad.computers.v6" => 40,
        "security.events.chains" => 15, "ad.gpo.v2" => 50, "vpn.connections" => 60, _ => null
    };
    public DomainGrant Grant => Rule.Scope == "delegated" && !Rule.AcceptsGenericScope && Decision.Grants.Any(g => g.Scope.Get("mode").ValueKind != JsonValueKind.Undefined)
        ? DomainGrant.None : Resolve(Rule.RequiredFields);
    private DomainGrant Resolve(IReadOnlySet<string> fields) => new ReportScopeResolver().PermittedDomains(
        new AccessDecision("viewer", new CapabilityDecisionSet(false, new HashSet<string>(), new HashSet<string>(), [], new Dictionary<string, JsonElement>()), [Decision]),
        [Rule with { Scope = "domain", RequiredFields = fields, RequiredCapabilities = new HashSet<string>(), RequiredRole = null }]);

    public bool Fields(long[]? domains, params string[] fields)
    {
        var required = Rule.RequiredFields.Concat(fields).ToHashSet(StringComparer.Ordinal);
        var grant = Resolve(required);
        return grant.Kind == DomainGrantKind.All || domains is not null && domains.Length > 0
            && grant.Kind == DomainGrantKind.Scoped && domains.All(grant.DomainIds.Contains);
    }
    public long[]? Intersect(IEnumerable<DomainItem> domains) => Grant.Kind == DomainGrantKind.None ? null
        : domains.Where(d => Grant.Kind == DomainGrantKind.All || Grant.DomainIds.Contains(d.Id)).Select(d => d.Id).Order().ToArray();
}

public interface IHomeSummaryAccess
{
    Task<IReadOnlyList<HomeReport>> LoadAsync(Principal principal, CancellationToken ct);
}

public sealed class HomeSummaryAccess(IPostgresConnectionFactory connections, IReportCatalogProvider catalog, IAccessFactsRepository? repository = null) : IHomeSummaryAccess
{
    public async Task<IReadOnlyList<HomeReport>> LoadAsync(Principal principal, CancellationToken ct)
    {
        var captured = catalog.Capture();
        var facts = (await (repository ?? new AccessFactsRepository(connections)).LoadAsync(principal, true, ct)) with { ReportCatalog = captured };
        var capabilities = new CapabilityComposer().Compose(facts);
        if (!capabilities.Decide("workspace.view").Allowed) throw new HomeQueryException("workspace_view_required", 403);
        var decision = new ReportEligibility().Compose(facts, capabilities);
        var current = catalog.Recheck(captured);
        var reports = current.Rules.Where(r => !r.DeclarationOnly && r.RequiredCapabilities.IsSubsetOf(capabilities.Capabilities)
                && (r.RequiredRole is null || r.RequiredRole == decision.CoarseRole)
                && (!r.GlobalScopeOnly || r.RequiredCapabilities.All(c => capabilities.Decide(c).Allowed)))
            .Select(r => new { Rule = r, Decision = decision.Reports.FirstOrDefault(d => d.ReportKey == r.ReportKey && d.Allowed) })
            .Where(r => r.Decision is not null)
            .Select(r => new HomeReport(r.Rule, r.Decision!, facts.Definitions.FirstOrDefault(d => d.Text("report_key") == r.Rule.ReportKey),
                facts.Preferences.FirstOrDefault(d => d.Text("report_key") == r.Rule.ReportKey)) { Capabilities = capabilities,
                    Available = () => catalog.Recheck(current).Rules.Any(rule => rule.RegistryKey == r.Rule.RegistryKey) }).ToList();
        foreach (var preference in facts.Preferences.Where(p => p.Get("pinned").ValueKind == JsonValueKind.True))
        {
            var key = preference.Text("report_key");
            var report = decision.Reports.FirstOrDefault(r => r.ReportKey == key && r.Allowed);
            if (report is null || reports.Any(r => r.Rule.ReportKey == key)) continue;
            reports.Add(new(new(key, key, "delegated", new HashSet<string>(), new HashSet<string>(), null, false), report,
                facts.Definitions.FirstOrDefault(d => d.Text("report_key") == key), preference) { Registered = false });
        }
        return reports;
    }
}
