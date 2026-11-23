using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http.Timeouts;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
using static Sli.Server.Gpo.GpoJson;

namespace Sli.Server.Gpo;

internal sealed record GpoRequest(string View,string Query,string? Tab,string? Sort,string Direction,int Limit,string? Cursor,string Timezone,DateTimeOffset From,DateTimeOffset To)
{
    internal string? PolicyId { get; init; }
    internal long? DomainId { get; init; }
    internal bool ListPolicySnapshots { get; init; }
    internal (Guid Before, Guid After)? ComparePolicySnapshots { get; init; }

    internal static GpoRequest Parse(IQueryCollection query,DateTimeOffset now)
    {
        string First(string key)=>query[key].FirstOrDefault()?.Trim()??"";
        var known=new HashSet<string>{"period","view","q","from","to","cursor","limit","sort","direction","tz","tab","policy_id","domain","snapshots","before_snapshot","after_snapshot"};
        string? unknown=query.Keys.Except(known).Order(StringComparer.Ordinal).FirstOrDefault();if(unknown is not null) throw new ArgumentException("report_parameter_unknown:"+unknown);
        string zone=First("tz");if(zone.Length==0) zone="UTC";TimeZoneInfo timezone;
        try { timezone=TimeZoneInfo.FindSystemTimeZoneById(zone); }catch(Exception e) when(e is TimeZoneNotFoundException or InvalidTimeZoneException) { throw new ArgumentException("report_timezone_invalid"); }
        string period=First("period");if(period.Length==0) period="7d";DateTimeOffset from,to;
        var days=new Dictionary<string,int>{{"24h",1},{"7d",7},{"30d",30},{"90d",90}};
        if(days.TryGetValue(period,out int length)) { from=now.AddDays(-length);to=now; }
        else if(period=="custom")
        {
            string a=First("from"),b=First("to");
            try
            {
                if((a+b).Contains('T'))
                {
                    if(!System.Text.RegularExpressions.Regex.IsMatch(a,@"(?:Z|[+-]\d{2}:?\d{2})$")||!System.Text.RegularExpressions.Regex.IsMatch(b,@"(?:Z|[+-]\d{2}:?\d{2})$")) throw new FormatException();
                    from=Stamp(a);to=Stamp(b);
                }
                else
                {
                    var first=DateOnly.ParseExact(a,"yyyy-MM-dd",CultureInfo.InvariantCulture);var last=DateOnly.ParseExact(b,"yyyy-MM-dd",CultureInfo.InvariantCulture);
                    from=new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(first.ToDateTime(TimeOnly.MinValue),timezone));to=new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(last.AddDays(1).ToDateTime(TimeOnly.MinValue),timezone));
                }
            }
            catch(Exception e) when(e is FormatException or ArgumentException) { throw new ArgumentException("report_period_invalid"); }
            if(from>=to) throw new ArgumentException("report_period_invalid");
        }
        else throw new ArgumentException("report_period_invalid");
        if(to-from>TimeSpan.FromDays(3650)) throw new ArgumentException("report_period_too_wide");
        string view=First("view");if(view.Length==0) view="attention";if(!new[]{"attention","unverified","assignment","all","linked","unlinked","version_mismatch","unlinked_version_mismatch"}.Contains(view)||First("q").EnumerateRunes().Count()>256) throw new ArgumentException("report_parameter_invalid:"+(First("q").EnumerateRunes().Count()>256?"q":"view"));
        int limit=500;string raw=First("limit");
        if(raw.Length>0) try { var parsed=Sli.Server.Agents.SnapshotPublication.GovernanceInteger.Parse(JsonValue.Create(raw));if(parsed<1||parsed>10000) throw new InvalidDataException();limit=(int)parsed; } catch(InvalidDataException) { throw new ArgumentException("report_limit_invalid"); }
        string direction=First("direction");if(direction.Length==0) direction="asc";string sort=First("sort");
        if(direction is not ("asc" or "desc")||sort.Length>0&&!Metadata["declaration"].Rows("columns").Any(c=>c.Text("key")==sort&&c.True("sortable"))) throw new ArgumentException("report_sort_invalid");
        string tab=First("tab");if(tab.Length>0&&!Metadata["declaration"].Rows("views").Any(v=>v.Text("key")==tab)) throw new ArgumentException("report_tab_invalid");
        string policyId=First("policy_id"),domain=First("domain");
        if(policyId.Length>256||policyId.Length>0&&tab is not ("gpos" or "changes")) throw new ArgumentException("report_parameter_invalid:policy_id");
        long? domainId=null;
        if(domain.Length>0)
        {
            if(tab!="gpos"&&!(tab=="changes"&&policyId.Length>0)||!long.TryParse(domain,NumberStyles.None,CultureInfo.InvariantCulture,out long id)||id<=0) throw new ArgumentException("report_parameter_invalid:domain");
            domainId=id;
        }
        bool listSnapshots = query.ContainsKey("snapshots");
        bool compareSnapshots = query.ContainsKey("before_snapshot") || query.ContainsKey("after_snapshot");
        (Guid Before, Guid After)? snapshots = null;
        if (listSnapshots || compareSnapshots)
        {
            if (tab != "gpos" || policyId.Length == 0 || domainId is null || (listSnapshots && (compareSnapshots || First("snapshots") != "1")))
                throw new ArgumentException("report_parameter_invalid:snapshots");
            if (compareSnapshots)
            {
                if (!Guid.TryParseExact(First("before_snapshot"), "D", out var before) ||
                    !Guid.TryParseExact(First("after_snapshot"), "D", out var after) || before == after)
                    throw new ArgumentException("report_parameter_invalid:snapshots");
                snapshots = (before, after);
            }
        }
        return new(view,First("q"),tab.Length==0?null:tab,sort.Length==0?null:sort,direction,limit,First("cursor"),zone,from,to)
        {
            PolicyId = policyId.Length > 0 ? policyId : null, DomainId = domainId,
            ListPolicySnapshots = listSnapshots, ComparePolicySnapshots = snapshots,
        };
    }
}
public interface IGpoReadStore
{
    Task<JsonObject> PairAsync(long[]? domains,CancellationToken ct);
    Task<JsonObject> GraphAsync(JsonObject snapshot,long[]? domains,CancellationToken ct);
    Task<JsonObject> HistoryAsync(long[]? domains,DateTimeOffset from,DateTimeOffset to,string query,CancellationToken ct);
    Task<JsonObject> PolicyHistoryAsync(long[] domains,DateTimeOffset from,DateTimeOffset to,string policyId,string guid,CancellationToken ct);
}
public sealed class GpoSourceException() : Exception("gpo_snapshot_unavailable");

public static class GpoEndpoints
{
    public static IServiceCollection AddGpoReports(this IServiceCollection services)
    {
        services.TryAddScoped<IAccessFactsRepository,AccessFactsRepository>();services.TryAddScoped<IGpoReadStore,GpoReadStore>();
        services.TryAddScoped<IGpoSnapshotReadStore, GpoReadStore>();
        return services;
    }
    public static IEndpointRouteBuilder MapGpoReports(this IEndpointRouteBuilder routes)
    {
        foreach(string suffix in new[]{"","/data","/export.csv","/rows/{row}/detail"}) routes.MapGet("/api/v2/reports/ad.gpo.v2"+suffix,HandleAsync);
        return routes;
    }
    internal static long[]? Authorize(AccessDecision access,string action,ReportRule rule)
    {
        var report=access.Reports.FirstOrDefault(r=>r.ReportKey=="ad.gpo.v2"&&r.Allowed);
        if(report is null||!report.Grants.Any(g=>g.AllowedActions.Contains(action))) throw new UnauthorizedAccessException("report_access_denied");
        var eligible=report.Grants.Where(g=>g.AllowedActions.Contains(action)&&rule.RequiredFields.IsSubsetOf(g.FieldCategories)).ToArray();
        if(eligible.Length==0) throw new UnauthorizedAccessException("report_field_categories_not_allowed");
        var executable=eligible.Select(g=>g with { AllowedActions=new HashSet<string>{"view"} }).ToArray();
        var result=new ReportScopeResolver().PermittedDomains(access with { Reports=[new("ad.gpo.v2",true,executable)] },[rule]);
        if(result.Kind==DomainGrantKind.None) throw new UnauthorizedAccessException("report_scope_not_executable");
        return result.Kind==DomainGrantKind.All?null:result.DomainIds.Order().ToArray();
    }
    internal static JsonObject AccessSummary()=>new() { ["allowed"]=true,["hidden_categories"]=new JsonArray(),["reason"]=null };
    static async Task HandleAsync(HttpContext c)
    {
        var hostDeadline=c.Features.Get<IHttpRequestTimeoutFeature>()?.RequestTimeoutToken??default;
        // One host-owned deadline spans metadata and ClickHouse; never restart it per phase.
        using var readCancellation=CancellationTokenSource.CreateLinkedTokenSource(c.RequestAborted,hostDeadline);
        var ct=readCancellation.Token;
        try
        {
            var services=c.RequestServices;if(services.GetRequiredService<TransportGate>().CheckTransport(c) is {} failure) { await DomainHttp.WriteFailureAsync(c,failure,ct);return; }
            Principal principal;
            if(services.GetRequiredService<AuthRequestPolicy>().AuthRequired)
            {
                var auth=await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(c,ct);
                if(!auth.Succeeded) { await DomainHttp.WriteFailureAsync(c,auth.Failure??new(401,"authentication_required"),ct);return; }principal=auth.Principal!;
                if(TransportGate.CheckViewerRole(principal) is {} role) { await DomainHttp.WriteFailureAsync(c,role,ct);return; }
            }
            else principal=new("",0,"operator");
            var catalog=services.GetRequiredService<IReportCatalogProvider>();var captured=catalog.Capture();var facts=(await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal,ct)) with { ReportCatalog=captured };
            var access=new ReportEligibility().Compose(facts,new CapabilityComposer().Compose(facts));
            if(!access.Reports.Any(r=>r.ReportKey=="ad.gpo.v2"&&r.Allowed)) { await DomainHttp.WriteAsync(c,new {error="report_access_denied"},403,ct);return; }
            var current=catalog.Recheck(captured);var rule=current.Rules.FirstOrDefault(r=>r.RegistryKey=="ad.gpo.v2");
            if(rule is null) { await DomainHttp.WriteAsync(c,new {error="report_not_found"},404,ct);return; }
            if(rule.DeclarationOnly) { await DomainHttp.WriteAsync(c,new {error="plugin_callable_generation_unsupported"},503,ct);return; }
            bool detail=c.Request.RouteValues.ContainsKey("row"),export=c.Request.Path.Value!.EndsWith("/export.csv",StringComparison.Ordinal),declaration=c.Request.Path.Value=="/api/v2/reports/ad.gpo.v2";
            if(detail) { await DomainHttp.WriteAsync(c,new {error="report_detail_not_available"},404,ct);return; }
            var domains=Authorize(access,export?"export":"view",rule);
            if(declaration)
            {
                var body=Metadata["declaration"]!.AsObject().Copy();body["access"]=AccessSummary();foreach(var v in body.Rows("views")) v["access"]=new JsonObject { ["allowed"]=true };body["detail"]!["access"]=new JsonObject { ["allowed"]=true };body["filter_options"]=new JsonObject();
                await DomainHttp.WriteAsync(c,body,200,ct);return;
            }
            var request=GpoRequest.Parse(c.Request.Query,DateTimeOffset.UtcNow);
            if(request.DomainId is long domain)
            {
                if(domains is not null&&!domains.Contains(domain)) throw new UnauthorizedAccessException("report_scope_not_executable");
                domains=[domain];
            }
            if(export&&request.PolicyId is not null) throw new ArgumentException("report_parameter_invalid:policy_id");
            var result = request.ListPolicySnapshots || request.ComparePolicySnapshots is not null
                ? await GpoSnapshotComparison.QueryAsync(services.GetRequiredService<IGpoSnapshotReadStore>(), request, ct)
                : await GpoReport.QueryAsync(services.GetRequiredService<IGpoReadStore>(), domains, request, ct);
            ct.ThrowIfCancellationRequested();result["access"]=AccessSummary();
            if(!catalog.Recheck(captured).Rules.Any(r=>r.RegistryKey=="ad.gpo.v2"&&!r.DeclarationOnly)) { await DomainHttp.WriteAsync(c,new {error="report_plugin_unavailable"},503,ct);return; }
            result["state_message"]=Metadata["messages"]![DomainHttp.SelectEnglish(c.Request.Headers.AcceptLanguage.ToString())?"en":"ru"]!["reports.state."+result.Text("state")]!.DeepClone();
            if(!export) { await DomainHttp.WriteAsync(c,result,200,ct);return; }
            if(result.Text("state")=="error") throw new ArgumentException("gpo_history_not_exportable");
            var view=Metadata["declaration"].Rows("views").FirstOrDefault(v=>v.Text("key")==request.Tab)??Metadata["declaration"].Rows("views").First();
            var columns=view["columns"] as JsonArray??Metadata["declaration"]!["columns"]!.AsArray();var rows=view.Text("source")=="items"?result.Rows("items"):result["collections"].Rows(view.Text("source"));var array=rows.ToArray();
            bool truncated=result["coverage"]?["reasons"] is JsonArray reasons&&reasons.Any(r=>r?.ToString()=="history_truncated")||result.Rows("limitations").Any(l=>l.Text("code")==view.Text("key")+"_truncated");
            byte[] bytes=new UTF8Encoding(true).GetPreamble().Concat(Encoding.UTF8.GetBytes(Csv(columns,array))).ToArray();
            string suffix=truncated?$"INCOMPLETE-first-{array.Length}-rows":$"complete-{array.Length}-rows";
            c.Response.StatusCode=200;c.Response.ContentType="text/csv; charset=utf-8";c.Response.Headers.ContentDisposition=$"attachment; filename=\"sli-ad.gpo.v2-{suffix}.csv\"";c.Response.Headers["X-Sli-Export-Truncated"]=truncated?"true":"false";c.Response.Headers["X-Sli-Export-Rows"]=array.Length.ToString(CultureInfo.InvariantCulture);c.Response.ContentLength=bytes.Length;await c.Response.Body.WriteAsync(bytes,ct);
        }
        catch(UnauthorizedAccessException e) { await DomainHttp.WriteAsync(c,new {error=e.Message,state="denied",reason=e.Message},403,ct); }
        catch(DomainScopeCompositionException) { await DomainHttp.WriteAsync(c,new {error="invalid_scope_dimension"},400,ct); }
        catch(GpoSourceException) { c.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Sli.Server.Gpo.GpoEndpoints").LogWarning("GPO source contract violation");await DomainHttp.WriteAsync(c,new {error="gpo_snapshot_unavailable",state="error",reason="source_contract_error",message=Metadata["messages"]![DomainHttp.SelectEnglish(c.Request.Headers.AcceptLanguage.ToString())?"en":"ru"]!["reports.renderer.error_gpo_snapshot"]!.DeepClone()},503,ct); }
        catch(ArgumentException e) { await DomainHttp.WriteAsync(c,new {error=e.Message},400,ct); }
        catch(PostgresException e) when(e.SqlState=="57014") { await DomainHttp.WriteAsync(c,new {error="report_read_timeout",state="unavailable"},503,c.RequestAborted); }
        catch(TimeoutException) { await DomainHttp.WriteAsync(c,new {error="report_read_timeout",state="unavailable"},503,c.RequestAborted); }
        catch(OperationCanceledException) when(c.RequestAborted.IsCancellationRequested) { }
        catch(OperationCanceledException) when(hostDeadline.IsCancellationRequested) { await DomainHttp.WriteAsync(c,new {error="report_read_timeout",state="unavailable"},503,c.RequestAborted); }
        catch(Exception e) { if(c.Response.HasStarted) throw;await AuthResponse.UnexpectedAsync(c,e,ct,login:false); }
    }
    internal static string Csv(JsonArray columns,IEnumerable<JsonObject> rows)
    {
        string Quote(string s)=>s.IndexOfAny([',','"','\r','\n'])>=0?"\""+s.Replace("\"","\"\"")+"\"":s;
        string String(JsonNode? n)=>n is null?"":n.GetValueKind() switch { JsonValueKind.True=>"True",JsonValueKind.False=>"False",JsonValueKind.String=>n.GetValue<string>(),_=>n.ToString() };
        var cols=columns.OfType<JsonObject>().ToArray();var b=new StringBuilder();b.Append(string.Join(',',cols.Select(col=>Quote(col.Text("label"))))).Append("\r\n");
        foreach(var r in rows)
        {
            b.Append(string.Join(',',cols.Select(col=>
            {
                JsonNode? value=r;foreach(string part in col.Text("path").Split('.')) value=(value as JsonObject)?[part];
                if(col["labels"] is JsonObject labels&&value is not null&&labels.TryGetPropertyValue(String(value),out var label)) value=label;
                string text=value is JsonArray a?string.Join(", ",a.Select(String)):String(value);
                if(text.StartsWith('\t')||text.StartsWith('\r')||text.StartsWith('\n')||text.TrimStart().StartsWith('=')||text.TrimStart().StartsWith('+')||text.TrimStart().StartsWith('-')||text.TrimStart().StartsWith('@')) text="'"+text;
                return Quote(text);
            }))).Append("\r\n");
        }
        return b.ToString();
    }
}
