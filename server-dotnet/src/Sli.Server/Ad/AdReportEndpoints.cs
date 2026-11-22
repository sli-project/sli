using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Ad;

public sealed record AdReportRequest(string Kind, bool Sources, bool Export, long Domain, AdPeriod? Period, int Limit, JsonObject Filters, string? Cursor)
{
    public DateTimeOffset? AuthenticationCutoff { get; init; }
    internal bool IncludeChangeSnapshotValues { get; init; }
}
public interface IAdReportStore
{
    Task<IReadOnlyList<long>> DomainsAsync(long after, CancellationToken ct);
    Task<bool> HasSourceAsync(string kind, long domain, CancellationToken ct);
    Task<JsonObject> ReadAsync(AdReportRequest request, bool sensitive, CancellationToken ct);
}

public static class AdReportEndpoints
{
    public static readonly string[] Routes = [
        "/api/v1/reports/ad.state/account-change-sources", "/api/v1/reports/ad.state/account-changes",
        "/api/v1/reports/ad.state/security-event-sources", "/api/v1/reports/ad.state/security-events", "/api/v1/reports/ad.state/security-events.csv",
        "/api/v1/reports/ad.groups/membership-changes", "/api/v1/reports/dc.powershell/activity"
    ];
    public static IServiceCollection AddAdReports(this IServiceCollection services)
    {
        services.TryAddScoped<IAccessFactsRepository, AccessFactsRepository>();
        services.TryAddScoped<IAdReportStore, AdReportStore>();
        services.TryAddScoped<AccountRiskAcceptances>();
        return services;
    }
    public static IEndpointRouteBuilder MapAdReports(this IEndpointRouteBuilder endpoints)
    { foreach (string route in Routes) endpoints.MapGet(route, HandleAsync); return endpoints; }
    public static bool Allowed(AccessDecision access, string kind, long domain, bool export = false)
    {
        IReadOnlyList<IReadOnlyList<AccessResource>> groups = [[new("domain", domain)]];
        if (!ResourceAccessDecisions.Capability(access.Capabilities, "events.view", groups).Allowed) return false;
        return kind switch
        {
            "account" => ResourceAccessDecisions.ReportAction(access, "ad.state", "view", groups).Allowed,
            "security" => ResourceAccessDecisions.ReportAction(access, "security.events.chains", export ? "export" : "view", groups, new HashSet<string> { "security", "technical", "raw_evidence" }).Allowed,
            _ => true
        };
    }
    public static AdReportRequest Parse(HttpRequest request)
    {
        string path = request.Path.Value ?? "";
        string kind = path.Contains("membership-changes") ? "membership" : path.Contains("powershell") ? "powershell" : path.Contains("security-event") ? "security" : "account";
        bool sources = path.EndsWith("sources", StringComparison.Ordinal), export = path.EndsWith(".csv", StringComparison.Ordinal);
        string? First(string key) => request.Query[key].FirstOrDefault();
        if (sources) return new(kind, true, false, 0, null, 100, new(), null);
        if (kind == "security")
        {
            string[] allowed = ["domain_id", "time_from", "time_to", "timezone", "limit", "cursor", "category", "event_id", "event_db_id", "entity_id", "outcome", "actor", "target", "group", "source", "q"];
            if (request.Query.Keys.Any(k => !allowed.Contains(k) || export && k is "cursor" or "limit")) throw new AdInputException("unknown_security_events_filter");
        }
        string prefix = AdHistory.Prefix(kind);
        if (!long.TryParse(First("domain_id") ?? "0", NumberStyles.Integer, CultureInfo.InvariantCulture, out long domain) || domain <= 0) throw new AdInputException(prefix + "_domain_invalid");
        var period = AdPeriod.Parse(First("time_from"), First("time_to"), First("timezone"), prefix, kind == "powershell" ? 31 : 365);
        if (!int.TryParse(First("limit") is null or "" ? "200" : First("limit"), out int limit) || limit is < 1 or > 500) throw new AdInputException(prefix + "_limit_invalid");
        if (export) limit = 500;
        var filters = kind == "security" ? AdSecurity.Normalize(request.Query) : new JsonObject();
        string? cursor = First("cursor");
        if (kind == "security" && !string.IsNullOrEmpty(cursor)) AdSecurity.DecodeCursor(cursor, domain, period, filters);
        return new(kind, false, export, domain, period, limit, filters, cursor);
    }
    public static async Task HandleAsync(HttpContext context)
    {
        var ct = context.RequestAborted;
        try
        {
            var services = context.RequestServices;
            if (services.GetRequiredService<TransportGate>().CheckTransport(context) is {} transport) { await DomainHttp.WriteFailureAsync(context, transport, ct); return; }
            Principal principal;
            if (services.GetRequiredService<AuthRequestPolicy>().AuthRequired)
            {
                var auth = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
                if (!auth.Succeeded) { await DomainHttp.WriteFailureAsync(context, auth.Failure ?? new(401, "authentication_required"), ct); return; }
                principal = auth.Principal!;
                if (TransportGate.CheckViewerRole(principal) is {} role) { await DomainHttp.WriteFailureAsync(context, role, ct); return; }
            }
            else principal = new("", 0, "operator");
            var facts = await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, ct);
            var caps = new CapabilityComposer().Compose(facts);
            var access = new ReportEligibility().Compose(facts, caps);
            var request = Parse(context.Request);
            var store = services.GetRequiredService<IAdReportStore>();
            JsonObject result;
            if (request.Sources) result = await SourcesAsync(access, request.Kind, store, ct);
            else if (!Allowed(access, request.Kind, request.Domain, request.Export)) result = AdHistory.Base(request.Kind, request.Domain, request.Period!, request.Limit, true);
            else
            {
                bool sensitive = ResourceAccessDecisions.Capability(caps, "field.sensitive", [[new AccessResource("domain", request.Domain)]]).Allowed;
                result = await store.ReadAsync(request, sensitive, ct);
            }
            if (request.Export)
            {
                if (result.Text("state") == "not_authorized") { await DomainHttp.WriteAsync(context, new { error = "security_events_export_not_authorized" }, 403, ct); return; }
                await WriteCsvAsync(context, result, ct); return;
            }
            await DomainHttp.WriteAsync(context, result, 200, ct);
        }
        catch (AdInputException error) { await DomainHttp.WriteAsync(context, new { error = error.Message }, 400, ct); }
        catch (PostgresException error) when (error.SqlState == "57014") { await Timeout(context, ct); }
        catch (TimeoutException) { await Timeout(context, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception error) { if (context.Response.HasStarted) throw; await AuthResponse.UnexpectedAsync(context, error, ct, login: false); }
    }
    static Task Timeout(HttpContext c, CancellationToken ct) => DomainHttp.WriteAsync(c, new { error = "report_read_timeout", state = "unavailable" }, 503, ct);
    private static async Task<JsonObject> SourcesAsync(AccessDecision access, string kind, IAdReportStore store, CancellationToken ct)
    {
        long after = 0; int scanned = 0, authorized = 0; var items = new List<object>();
        while (items.Count <= 100)
        {
            var domains = await store.DomainsAsync(after, ct); if (domains.Count == 0) break;
            scanned += domains.Count;
            if (scanned > 10000) throw new AdInputException(kind == "account" ? "ad_account_change_source_discovery_scan_limit" : "security_events_source_discovery_scan_limit");
            foreach (long domain in domains)
            {
                if (!Allowed(access, kind, domain)) continue;
                authorized++;
                if (await store.HasSourceAsync(kind, domain, ct)) items.Add(new { source_domain_id = domain });
            }
            after = domains[^1]; if (domains.Count < 256) break;
        }
        var (contract, report) = AdHistory.Identity(kind);
        return AdJson.Obj(new { contract_id = contract, report_key = report, state = items.Count > 0 ? "available" : authorized > 0 ? "not_collected" : "not_authorized", items = items.Take(100), bounded = true, limit = 100, has_more = items.Count > 100 });
    }
    private static async Task WriteCsvAsync(HttpContext c, JsonObject result, CancellationToken ct)
    {
        byte[] body = [0xef, 0xbb, 0xbf, .. Encoding.UTF8.GetBytes(AdSecurity.Csv(result))];
        int count = result["items"]!.AsArray().Count; bool more = result["has_more"]!.GetValue<bool>();
        c.Response.ContentType = "text/csv; charset=utf-8"; c.Response.ContentLength = body.Length;
        c.Response.Headers.ContentDisposition = $"attachment; filename=\"sli-security-events-{(more ? $"INCOMPLETE-first-{count}-rows" : $"complete-{count}-rows")}.csv\"";
        c.Response.Headers["X-Sli-Export-Truncated"] = more ? "true" : "false";
        c.Response.Headers["X-Sli-Export-Rows"] = count.ToString(CultureInfo.InvariantCulture);
        await c.Response.Body.WriteAsync(body, ct);
    }
}
