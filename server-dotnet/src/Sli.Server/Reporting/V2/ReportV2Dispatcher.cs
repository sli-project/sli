using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Domains;
using Sli.Server.Workstations;
namespace Sli.Server.Reporting.V2;

public sealed record ReportQueryContext(ReportDefinition Definition, AccessDecision Access, Principal Principal,
    JsonObject Params, ReportPaging Paging, ReportScope Scope, long[]? DomainIds, string Action,
    Func<IEnumerable<string>, bool> FieldAccess, IReadOnlyList<AtomicReportGrant> Grants)
{
    public DateTimeOffset RequestTime { get; init; } = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    public JsonObject? DomainSelection { get; init; }
    public JsonArray? Domains { get; init; }
    public string Language { get; init; } = "";
    // Set only by the current workstation binding reader, never from a URL.
    internal long? WorkstationServerId { get; init; }
    internal string? WorkstationProgram { get; init; }
    internal WorkstationActivity? StationActivity { get; init; }
    // Native readers must apply Scope.SqlFilter before aggregation and paging;
    // delegated readers receive the original atomic grants and enforce their legacy resource policy.
}
public interface IReportV2Reader
{
    string OwnerId { get; }
    bool Handles(string reportKey);
    Task<JsonObject> QueryAsync(ReportQueryContext context, CancellationToken ct);
    Task<JsonObject> DetailAsync(ReportQueryContext context, string rowId, CancellationToken ct) => throw new ReportRequestException("report_detail_not_available", 404);
    Task<ReportExport> ExportAsync(ReportQueryContext context, CancellationToken ct) => throw new ReportRequestException("report_export_not_available", 404);
    Task<JsonObject> OptionsAsync(ReportDefinition definition, AccessDecision access, CancellationToken ct) => Task.FromResult(new JsonObject());
}
public interface IReportDomains
{
    Task<IReadOnlyList<DomainItem>> ReadAsync(long[]? ids, CancellationToken ct);
}
public sealed class ReportDomains(DomainRepository repository) : IReportDomains
{
    public Task<IReadOnlyList<DomainItem>> ReadAsync(long[]? ids, CancellationToken ct) => repository.ReadAsync(ids is null ? DomainGrant.All : DomainGrant.Scoped(ids), ct);
}
public sealed class ReportV2Dispatcher(IEnumerable<IReportV2Reader> readers)
{
    public IReportV2Reader? Resolve(ReportRule rule)
    {
        if (rule.DeclarationOnly) throw new ReportRequestException("plugin_callable_generation_unsupported", 503);
        var matches = readers.Where(r => r.OwnerId == rule.OwnerId && r.Handles(rule.RegistryKey)).ToArray();
        if (matches.Length > 1) throw new InvalidOperationException("duplicate_report_reader");
        return matches.SingleOrDefault();
    }
}
