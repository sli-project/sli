using System.Text.Json.Nodes;

namespace Sli.Server.Domains;

// Executable declarations belong to the report, as in the frozen registry's
// HomeContribution. They are compiled code; database metadata cannot supply hooks.
public sealed record HomeContribution(string Key, string MetricKey, string LabelCode, string UnitCode)
{
    public int Order { get; init; } = 100;
    public string PeriodKind { get; init; } = "snapshot";
    public int DefinitionVersion { get; init; } = 1;
    public bool Health { get; init; } = true;
    public string Meaning { get; init; } = "neutral";
    public IReadOnlySet<string> RequiredFields { get; init; } = new HashSet<string>();
    public IReadOnlyDictionary<string, object?> Filters { get; init; } = new Dictionary<string, object?>();
    public Func<HomeSummaryReaders, long[], HomeSummaryQuery, CancellationToken, Task<JsonObject>>? Reader { get; init; }
    public Func<string>? Availability { get; init; }
    public Func<JsonObject, string, IEnumerable<JsonObject>>? Attention { get; init; }

    internal static IReadOnlyList<HomeContribution> BuiltIn(string key) => key switch
    {
        "security.problems" => [new("attention", "attention", "home.kpi.attention", "home.unit.problems")
            { Order = 10, Filters = new Dictionary<string, object?> { ["population"] = "attention" } }],
        "ad.infrastructure" => [new("ad_failed", "failed", "home.kpi.ad_failed", "home.unit.checks")
            { Order = 20, Filters = new Dictionary<string, object?> { ["qualification"] = "failed" } },
            new("privileged_changes", "privileged_changes", "home.kpi.privileged_changes", "home.unit.events")
            { Order = 30, PeriodKind = "observations", RequiredFields = new HashSet<string> { "privilege", "technical" },
                Filters = new Dictionary<string, object?> { ["tab"] = "privileged_changes" }, Reader = (reads, ids, query, ct) => reads.Changes(ids, query, ct) }],
        "vpn.connections" => [new("vpn_closed", "closed", "home.kpi.vpn_closed", "home.unit.sessions")
            { Order = 40, PeriodKind = "observations", Filters = new Dictionary<string, object?> { ["status"] = "closed" },
                Reader = (reads, ids, query, ct) => query.Domain is null
                    ? Task.FromResult(HomeSummaryReaders.Result("not_collected", reason: "domain_required")) : reads.Vpn(query.Domain.Value, query, ct) }],
        _ => []
    };
}
