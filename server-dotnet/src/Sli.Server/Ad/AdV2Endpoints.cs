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
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

public sealed class AdAccessException(string code) : Exception(code);
public sealed record AdV2Request(string Key, string Action, string? Row, long[] Domains, JsonObject Params, string Tab, string? Sort, bool Descending, int Limit, string? Cursor, string Timezone)
{
    public Principal? Principal {get;init;}
    public bool QualifyNames {get;init;}
    internal AccessFacts? Facts {get;init;}
    internal AccessDecision? Access {get;init;}
}
public interface IAdV2Store
{
    Task<IReadOnlyList<JsonObject>> DomainsAsync(DomainGrant grant, CancellationToken ct);
    Task<JsonObject> ReadAsync(AdV2Request request, Func<IEnumerable<string>, bool> fields, CancellationToken ct);
}
public static class AdV2Endpoints
{
    public static readonly JsonObject Definitions = JsonNode.Parse(new StreamReader(typeof(AdV2Endpoints).Assembly.GetManifestResourceStream("Sli.Server.Ad.report-definitions.json")!).ReadToEnd())!.AsObject();
    public static IServiceCollection AddAdV2(this IServiceCollection services)
    { services.TryAddScoped<IAccessFactsRepository, AccessFactsRepository>(); services.TryAddScoped<IAdV2Store, AdV2Store>();services.TryAddSingleton<IReportCatalogProvider,ReportRuleCatalog>(); return services; }
    public static IEndpointRouteBuilder MapAdV2(this IEndpointRouteBuilder endpoints)
    {
        foreach (var key in Definitions.Select(p => p.Key))
        {
            string prefix = "/api/v2/reports/" + key;
            endpoints.MapGet(prefix, c => HandleAsync(c, key, "declaration"));
            endpoints.MapGet(prefix + "/data", c => HandleAsync(c, key, "view"));
            endpoints.MapGet(prefix + "/export.csv", c => HandleAsync(c, key, "export"));
            endpoints.MapGet(prefix + "/rows/{row}/detail", c => HandleAsync(c, key, "detail"));
        }
        return endpoints;
    }
    internal static IEnumerable<string> Strings(JsonNode? node) => node is JsonArray values ? values.Select(n => n!.GetValue<string>()) : [];
    static async Task HandleAsync(HttpContext c, string key, string action)
    {
        var hostDeadline = c.Features.Get<IHttpRequestTimeoutFeature>()?.RequestTimeoutToken ?? default;
        // Keep the host deadline across domains, settings, confirmations and history.
        using var readCancellation = CancellationTokenSource.CreateLinkedTokenSource(c.RequestAborted, hostDeadline);
        var ct = readCancellation.Token;
        try
        {
            var services = c.RequestServices;
            if (services.GetRequiredService<TransportGate>().CheckTransport(c) is {} transport) { await DomainHttp.WriteFailureAsync(c, transport, ct); return; }
            Principal principal;
            if (services.GetRequiredService<AuthRequestPolicy>().AuthRequired)
            {
                var auth = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(c, ct);
                if (!auth.Succeeded) { await DomainHttp.WriteFailureAsync(c, auth.Failure ?? new(401, "authentication_required"), ct); return; }
                principal = auth.Principal!; if (TransportGate.CheckViewerRole(principal) is {} role) { await DomainHttp.WriteFailureAsync(c, role, ct); return; }
            }
            else principal = new("", 0, "operator");
            var catalog=services.GetRequiredService<IReportCatalogProvider>();var captured=catalog.Capture();
            var facts = await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, ct); var caps = new CapabilityComposer().Compose(facts); var access = new ReportEligibility().Compose(facts, caps);
            var definition = Definitions[key]!.AsObject(); string accessKey = definition.Text("access_key")!;
            var report = access.Reports.FirstOrDefault(r => r.ReportKey == accessKey && r.Allowed);
            if (report is null) throw new AdAccessException("report_access_denied");
            bool Available()=>catalog.Recheck(captured).Rules.Any(r=>r.RegistryKey==key&&r.OwnerId=="sli.ad"&&!r.DeclarationOnly);
            if(!Available()){await DomainHttp.WriteAsync(c,new{error="report_plugin_unavailable"},503,ct);return;}
            var declaration = (JsonObject)definition["declaration"]!.DeepClone();
            if (action == "detail" && key != "ad.users.v2" && (declaration["detail"] is not JsonObject detail || detail.Text("kind")!="sub"))
            { await DomainHttp.WriteAsync(c, new { error = "report_detail_not_available" }, 404, ct); return; }
            if (action == "export" && declaration["export"]?.GetValue<bool>() != true)
            { await DomainHttp.WriteAsync(c, new { error = "report_export_not_available" }, 404, ct); return; }
            string grantAction = action == "export" ? "export" : "view";
            var core = Strings(definition["required_fields"]).ToHashSet();
            var eligible = report.Grants.Where(g => g.AllowedActions.Contains(grantAction) && core.IsSubsetOf(g.FieldCategories)).ToArray();
            if (eligible.Length == 0) throw new AdAccessException(report.Grants.Any(g => g.AllowedActions.Contains(grantAction)) ? "report_field_categories_not_allowed" : "report_access_denied");
            if (definition.Text("scope") == "delegated" && eligible.Any(g => g.Scope.TryGetProperty("mode", out _))) throw new AdAccessException("report_scope_not_executable");
            var scopeAccess = access with { Reports = [new(accessKey, true, eligible.Select(g => g with { AllowedActions = new HashSet<string> { "view" } }).ToArray())] };
            var rule = new ReportRule(key, accessKey, "domain", core, new HashSet<string>(), null, false);
            var grant = new ReportScopeResolver().PermittedDomains(scopeAccess, [rule]);
            if (grant.Kind != DomainGrantKind.All && grant.DomainIds.Count == 0) throw new AdAccessException("report_scope_not_executable");
            long? selectedId = action == "declaration" ? null : SelectDomain(c.Request.Query);
            if (selectedId is {} requested)
            {
                if (grant.Kind != DomainGrantKind.All && !grant.DomainIds.Contains(requested)) throw new AdAccessException("domain_scope_denied");
                grant = DomainGrant.Scoped([requested]);
            }
            var store = services.GetRequiredService<IAdV2Store>();
            IReadOnlyList<JsonObject> domains;
            try { domains = await store.DomainsAsync(grant, ct); }
            catch (Exception error) when (key == "ad.new-logon-pairs" && error is not (UnauthorizedAccessException or AdAccessException or OperationCanceledException or PostgresException { SqlState: "42501" }))
            { await DomainHttp.WriteAsync(c, AdLogonPairs.Failure(error, "domain_context_unavailable"), 200, ct); return; }
            if(!Available()){await DomainHttp.WriteAsync(c,new{error="report_plugin_unavailable"},503,ct);return;}
            if (selectedId is not null && domains.Count == 0) throw new AdAccessException("domain_scope_denied");
            if(definition.Text("scope")!="delegated"&&!c.Request.Query.ContainsKey("domain")&&!c.Request.Query.ContainsKey("domain_id"))domains=domains.Where(d=>AdInventoryRows.Bool(d["is_archived"])!=true).ToArray();
            long[] ids = domains.Select(d => d.Int("id")).ToArray();
            bool Fields(IEnumerable<string> required) => ids.Length > 0 && ResourceAccessDecisions.ReportAction(access, accessKey, grantAction, ids.Select(id => (IReadOnlyList<AccessResource>)new AccessResource[] { new("domain", id) }).ToArray(), core.Concat(required).ToHashSet()).Allowed;
            ProjectDeclaration(declaration, definition, Fields);
            if (action == "declaration")
            {
                declaration["filter_options"] = Obj(new { domain = domains.Select(d => new { value = d.Int("id").ToString(CultureInfo.InvariantCulture), label = d.Text("display_name") }) });
                var chosen=domains.FirstOrDefault(d=>AdInventoryRows.Bool(d["is_archived"])!=true&&AdInventoryRows.Bool(d["is_preferred"])==true)??domains.Where(d=>AdInventoryRows.Bool(d["is_archived"])!=true&&AdInventoryRows.Date(d["observed_at_utc"]) is {} at&&at<=DateTimeOffset.UtcNow).OrderByDescending(d=>AdInventoryRows.Date(d["observed_at_utc"])).ThenBy(d=>d.Int("id")).FirstOrDefault();
                declaration["default_domain_id"] = chosen?["id"]?.DeepClone(); declaration["default_domain_state"] = chosen is not null ? "available" : "unknown";
                await DomainHttp.WriteAsync(c, Sli.Server.Reporting.V2.ReportPresentation.Apply(declaration, DomainHttp.SelectEnglish(c.Request.Headers.AcceptLanguage.ToString())), 200, ct); return;
            }
            var request = Parse(c.Request, key, action, ids) with {Principal=principal,Facts=facts,Access=access,QualifyNames=!c.Request.Query.ContainsKey("domain")&&!c.Request.Query.ContainsKey("domain_id")};
            if(definition.Text("scope")=="delegated")
            {
                var selected=domains.FirstOrDefault(d=>AdInventoryRows.Bool(d["is_report_domain"])==true);
                if(selected is null)
                {
                    if(domains.Any(d=>d.Int("report_domain_id")>0))throw new AdAccessException("report_scope_not_executable");
                    var missing=AdV2Store.Result(key,"error");missing["limitations"]=new JsonArray(Obj(new{code="report_domain_not_configured",text="Домен отчётов не задан: укажите его в разделе «Настройки платформы»."}));await DomainHttp.WriteAsync(c,missing,200,ct);return;
                }
                request=request with{Domains=[selected.Int("id")]};
            }
            bool SelectedFields(IEnumerable<string> required) => request.Domains.Length == 0
                ? eligible.Any(g => core.Concat(required).All(g.FieldCategories.Contains))
                : ResourceAccessDecisions.ReportAction(access, accessKey, grantAction, request.Domains.Select(id => (IReadOnlyList<AccessResource>)new AccessResource[] { new("domain", id) }).ToArray(), core.Concat(required).ToHashSet()).Allowed;
            foreach (string parameter in c.Request.Query.Keys)
                if (definition["param_fields"]?[parameter] is {} required && !SelectedFields(Strings(required))) throw new AdAccessException("report_field_categories_not_allowed");
            if (!SelectedFields(Strings(definition["view_fields"]?[request.Tab])) || request.Sort is not null && !SelectedFields(Strings(definition["column_fields"]?[request.Sort]))) throw new AdAccessException("report_field_categories_not_allowed");
            if(!Available()){await DomainHttp.WriteAsync(c,new{error="report_plugin_unavailable"},503,ct);return;}
            var result = request.Domains.Length == 0 ? AdV2Store.Empty(request) : await store.ReadAsync(request, SelectedFields, ct);
            ct.ThrowIfCancellationRequested();
            if(!Available()){await DomainHttp.WriteAsync(c,new{error="report_plugin_unavailable"},503,ct);return;}
            AdV2Result.Finish(result);
            bool reviewAccounts = AdReviewChecks.UsesAccountRows(request);
            Redact(result, definition, SelectedFields, reviewAccounts ? "all" : request.Tab);
            if(request.Tab=="checks"&&key is "ad.users.v2" or "ad.computers.v6")AdReviewChecks.Localize(result,DomainHttp.SelectEnglish(c.Request.Headers.AcceptLanguage.ToString()));
            bool selectedDomain=c.Request.Query.ContainsKey("domain")||c.Request.Query.ContainsKey("domain_id");
            result["domain_scope"] = Obj(new { mode = selectedDomain ? "domain" : "accessible", domain_id = selectedDomain&&request.Domains.Length==1 ? (long?)request.Domains[0] : null, domain_ids = request.Domains,state=request.Domains.Length>0?"available":"no_domains" });
            result["domains"] = Array(domains.Where(d => request.Domains.Contains(d.Int("id"))).Select(d=>new JsonObject{["id"]=d["id"]?.DeepClone(),["display_name"]=d["display_name"]?.DeepClone(),["is_archived"]=AdInventoryRows.Bool(d["is_archived"])==true,["freshness"]=new JsonObject{["observed_at_utc"]=d["observed_at_utc"]?.DeepClone()}}));
            if (action == "export")
            {
                if(result.Text("state") is not ("ok" or "partial" or "stale" or "empty")) throw new AdInputException(key switch{"ad.users.v2"=>"users_v2_export_unavailable","ad.infrastructure"=>request.Tab=="changes"?"active_directory_history_not_exportable":"active_directory_evidence_not_exportable",_=>"computers_v6_export_unavailable"});
                var exportView=declaration["views"]!.AsArray().FirstOrDefault(v=>v!.Text("key")==request.Tab);
                var exportColumns=reviewAccounts ? ReviewAccountColumns(declaration)
                    : exportView?["columns"] as JsonArray ?? declaration["columns"]!.AsArray();
                var exportRows=exportView.Text("source") is {} collection&&result["collections"]?[collection] is JsonArray collectionRows?collectionRows:result["items"]!.AsArray();
                if(key=="ad.computers.v6"&&request.Tab=="checks")exportRows=Array(exportRows.OfType<JsonObject>().Select(r=>{var row=(JsonObject)r.DeepClone();row["objects"]=Array((r["objects"] as JsonArray??[]).Select(o=>o!.Text("name")));return row;}));
                string csv = key=="ad.computers.v6"&&request.Tab=="computers"?AdInventoryRows.ComputerCsv(exportRows):key=="ad.infrastructure"&&request.Tab is not ("semantic" or "changes" or "spn_collisions" or "privileged_changes")?AdInfrastructure.CsvControls(exportRows):Csv(exportColumns,exportRows);
                byte[] body = [0xef, 0xbb, 0xbf, .. Encoding.UTF8.GetBytes(csv)]; c.Response.ContentType = "text/csv; charset=utf-8"; c.Response.ContentLength = body.Length;
                c.Response.Headers.ContentDisposition = $"attachment; filename=\"sli-{key}.csv\""; c.Response.Headers["X-Sli-Export-Truncated"] = result["has_more"]!.GetValue<bool>() ? "true" : "false";
                c.Response.Headers["X-Sli-Export-Rows"] = exportRows.Count.ToString(CultureInfo.InvariantCulture); await c.Response.Body.WriteAsync(body, ct); return;
            }
            await DomainHttp.WriteAsync(c, Sli.Server.Reporting.V2.ReportPresentation.Apply(result, DomainHttp.SelectEnglish(c.Request.Headers.AcceptLanguage.ToString())), 200, ct);
        }
        catch (AdAccessException e) { await DomainHttp.WriteAsync(c, new { error = e.Message, state = "denied", reason = e.Message }, 403, ct); }
        catch (AdInputException e) { await DomainHttp.WriteAsync(c, new { error = e.Message }, 400, ct); }
        catch (KeyNotFoundException) { await DomainHttp.WriteAsync(c, new { error = "report_row_not_found" }, 404, ct); }
        catch (PostgresException e) when (e.SqlState == "57014") { await DomainHttp.WriteAsync(c, new { error = "report_read_timeout", state = "unavailable" }, 503, c.RequestAborted); }
        catch (OperationCanceledException) when (c.RequestAborted.IsCancellationRequested) { }
        catch (OperationCanceledException) when (hostDeadline.IsCancellationRequested) { await DomainHttp.WriteAsync(c, new { error = "report_read_timeout", state = "unavailable" }, 503, c.RequestAborted); }
        catch (Exception e) { if (c.Response.HasStarted) throw; await AuthResponse.UnexpectedAsync(c, e, ct, login: false); }
    }
    public static AdV2Request Parse(HttpRequest request, string key, string action, long[] domains)
    {
        var d = Definitions[key]!["declaration"]!; var q = request.Query; string? First(string k) => q[k].FirstOrDefault();
        long? selected = SelectDomain(q);
        var declarations = d["params"]!.AsArray(); var names = declarations.Select(p => p!.Text("key")!).ToHashSet();
        string[] reserved = ["cursor", "limit", "sort", "direction", "tz", "tab", ..(names.Contains("period")?new[]{"from","to"}:System.Array.Empty<string>())];
        string? unknown = q.Keys.Except(names.Concat(reserved)).Order(StringComparer.Ordinal).FirstOrDefault();
        if (unknown is not null) throw new AdInputException("report_parameter_unknown:" + unknown);
        string zone = First("tz") ?? "UTC"; try { _ = TimeZoneInfo.FindSystemTimeZoneById(zone); } catch (TimeZoneNotFoundException) { throw new AdInputException("report_timezone_invalid"); }
        var p = new JsonObject();
        foreach (var param in declarations.OfType<JsonObject>())
        {
            string name = param!.Text("key")!, kind = param.Text("kind")!; string? value = First(name); if (string.IsNullOrEmpty(value)) value = param.Text("default");
            if (kind == "period")
            {
                string preset = value ?? (action == "detail" && key == "ad.users.v2" ? "30d" : "7d");
                var end = DateTimeOffset.UtcNow; DateTimeOffset start;
                if (preset == "custom")
                {
                    try { var period = AdPeriod.Parse(First("from"), First("to"), zone, "report", (int)(param.Int("max_days") is > 0 and var max ? max : 365)); start = period.Start; end = period.End; } catch (AdInputException e) { throw new AdInputException(e.Message == "report_period_too_wide" ? e.Message : "report_period_invalid"); }
                }
                else start = end.AddDays(preset switch { "24h" => -1, "7d" => -7, "30d" => -30, "90d" => -90, _ => throw new AdInputException("report_period_invalid") });
                if (param.Int("max_days") > 0 && (end - start).TotalDays > param.Int("max_days")) throw new AdInputException("report_period_too_wide");
                p[name] = Obj(new { preset, from_utc = Iso(start), to_utc = Iso(end) }); continue;
            }
            if (string.IsNullOrEmpty(value)) { if (param["required"]?.GetValue<bool>() == true) throw new AdInputException("report_parameter_required:" + name); continue; }
            if (value.EnumerateRunes().Count() > (param.Int("max_length") > 0 ? param.Int("max_length") : 256)) throw new AdInputException("report_parameter_invalid:" + name);
            if (kind is "int" or "domain") { if (!long.TryParse(value, out long number) || number <= 0) throw new AdInputException("report_parameter_invalid:" + name); p[name] = number; }
            else
            {
                bool savedComputerFilter = key == "ad.computers.v6" && name == "activity"
                    && value is "within_threshold" or "over_threshold" or "over_60_days" or "missing";
                if (kind == "choice" && !savedComputerFilter && param["options"] is JsonArray { Count: > 0 } options
                    && !options.Any(o => o!.Text("value") == value))
                    throw new AdInputException("report_parameter_invalid:" + name);
                p[name] = value;
            }
        }
        if(key=="ad.users.v2")_ = AdUsersActivity.Window(p);
        if (selected is not null && !domains.Contains(selected.Value)) throw new AdAccessException("domain_scope_denied");
        int limit = (int)d["limits"]!.Int("default"); if (First("limit") is {} raw && !int.TryParse(raw, out limit) || limit < 1 || limit > d["limits"]!.Int("max")) throw new AdInputException("report_limit_invalid");
        string tab = First("tab") ?? (key == "ad.computers.v6" ? "computers" : d["views"]![0]!.Text("key")!), direction = First("direction") ?? "asc";
        if (!d["views"]!.AsArray().Any(v => v!.Text("key") == tab)) throw new AdInputException("report_tab_invalid");
        if (action == "view" && (tab == "checks" && (key is "ad.users.v2" or "ad.computers.v6")
            || tab == "computers" && key == "ad.computers.v6") && First("entity_id") is {} entityId)
        {
            if (!long.TryParse(entityId, NumberStyles.None, CultureInfo.InvariantCulture, out long entity) || entity <= 0)
                throw new AdInputException("report_parameter_invalid:entity_id");
            p["entity_id"] = entity;
        }
        if (key == "ad.infrastructure" && action == "detail")
        {
            if (tab != "controls") throw new KeyNotFoundException();
            limit = Math.Min(limit, (int)d["detail"]!.Int("default_limit"));
        }
        string? sort = First("sort");
        if (direction is not ("asc" or "desc") || sort is not null && !d["columns"]!.AsArray().Any(col => col!.Text("key") == sort && col!["sortable"]?.GetValue<bool>() == true)) throw new AdInputException("report_sort_invalid");
        return new(key, action, request.RouteValues["row"]?.ToString(), selected is null ? domains : [selected.Value], p, tab, sort, direction == "desc", action == "export" ? key=="ad.users.v2"?100000:10000 : limit, action=="export"?null:First("cursor"), zone);
    }
    static long? SelectDomain(IQueryCollection query)
    {
        long? selected = null;
        foreach (string key in new[] { "domain_id", "domain" })
        {
            if (!query.ContainsKey(key)) continue;
            var values = query[key];
            if (values.Count != 1 || !System.Text.RegularExpressions.Regex.IsMatch(values[0] ?? "", @"\A[1-9][0-9]{0,18}\z")
                || !long.TryParse(values[0], NumberStyles.None, CultureInfo.InvariantCulture, out long id)
                || selected is not null && selected != id) throw new AdInputException("domain_scope_invalid");
            selected = id;
        }
        return selected;
    }
    static void ProjectDeclaration(JsonObject d, JsonObject definition, Func<IEnumerable<string>, bool> fields)
    {
        foreach (var (array, metadata) in new[] { ("params", "param_fields"), ("columns", "column_fields") })
            foreach (var item in d[array]!.AsArray().ToArray()) if (!fields(Strings(definition[metadata]?[item!.Text("key")!]))) d[array]!.AsArray().Remove(item);
        foreach (var view in d["views"]!.AsArray())
        {
            bool allowed = fields(Strings(definition["view_fields"]?[view!.Text("key")!]));
            view!["access"] = Obj(new { allowed });
        }
    }
    static void Redact(JsonObject result, JsonObject definition, Func<IEnumerable<string>, bool> fields, string tab)
    {
        var paths = new Dictionary<string, IEnumerable<string>>();
        // Check rows have their own columns and mandatory view field grant.
        // Inventory job-title metadata must not redact the check's title.
        if(tab!="checks")
        {
            foreach (var p in definition["row_categories"]!.AsObject()) paths[p.Key] = Strings(p.Value);
            foreach (var p in definition["column_fields"]!.AsObject()) paths.TryAdd(p.Key, Strings(p.Value));
        }
        else foreach(var column in definition["declaration"]!["views"]!.AsArray().Single(v=>v!.Text("key")==tab)!["columns"]!.AsArray())
            paths[column!.Text("path")??column.Text("key")!]=Strings(definition["view_column_fields"]?[tab]?[column.Text("key")!]);
        void Remove(JsonObject row,string path)
        { string[] parts=path.Split('.'); JsonNode? parent=row;foreach(string part in parts[..^1])parent=parent?[part];if(parent is JsonObject obj)obj.Remove(parts[^1]); }
        foreach (var row in result["items"]!.AsArray().OfType<JsonObject>()) foreach (var (path, required) in paths) if (!fields(required)) Remove(row,path);
        if(result["collections"] is JsonObject collections) foreach(var (source,value) in collections.ToArray())
        {
            var view=definition["declaration"]!["views"]!.AsArray().FirstOrDefault(v=>v!.Text("source")==source);
            if(view is null||!fields(Strings(definition["view_fields"]?[view.Text("key")!]))) {collections.Remove(source);continue;}
            foreach(var row in value!.AsArray().OfType<JsonObject>())
            {
                foreach(var (path,required) in paths)if(!fields(required))Remove(row,path);
                foreach(var column in view["columns"] as JsonArray??[])
                    if(!fields(Strings(definition["view_column_fields"]?[view.Text("key")!]?[column!.Text("key")!])))Remove(row,column!.Text("path")??column.Text("key")!);
            }
        }
        if (result["metrics"] is JsonArray metrics) foreach (var metric in metrics.ToArray()) if (!fields(Strings(definition["metric_categories"]?[metric!.Text("key")!]))) metrics.Remove(metric);
        if (result["filter_options"] is JsonObject options)
        {
            var visible = definition["declaration"]!["params"]!.AsArray().OfType<JsonObject>()
                .Where(p => fields(Strings(definition["param_fields"]?[p.Text("key")!])))
                .Select(p => p.Text("options_from") ?? p.Text("key")).ToHashSet(StringComparer.Ordinal);
            foreach (string key in options.Select(p => p.Key).ToArray()) if (!visible.Contains(key)) options.Remove(key);
        }
    }
    internal static string PythonText(JsonNode? node)=>node switch{null=>"",JsonArray array=>string.Join(", ",array.Select(PythonText)),JsonObject=>node.ToJsonString(),_=>AdInventoryRows.Bool(node) switch{true=>"True",false=>"False",_=>node.ToString()}};
    static JsonArray ReviewAccountColumns(JsonObject declaration)
    {
        var columns = declaration["columns"]!.AsArray();
        return Array(new[] { "name", "privilege_basis", "activity", "reason" }
            .Select(key => columns.FirstOrDefault(column => column.Text("key") == key))
            .Where(column => column is not null).Select(column =>
            {
                var copy = column!.DeepClone().AsObject();
                copy["path"] = copy.Text("key") switch { "name" => "account_label", "privilege_basis" => "review_privileges", _ => copy.Text("path") };
                return copy;
            }));
    }
    internal static string CsvCell(string value,char delimiter=',')
    {
        if(value.StartsWith('\t')||value.StartsWith('\r')||value.StartsWith('\n')||value.TrimStart().Length>0&&"=+-@".Contains(value.TrimStart()[0]))value="'"+value;
        return value.IndexOfAny([delimiter,'"','\r','\n'])>=0?"\""+value.Replace("\"","\"\"")+"\"":value;
    }
    internal static string Csv(JsonArray columns, JsonArray rows)
    {
        string Cell(JsonNode column,JsonNode? row)
        {var node=(column.Text("path")??column.Text("key")!).Split('.').Aggregate(row,(value,part)=>value?[part]);string value=PythonText(node);if(column["labels"] is JsonObject labels&&labels[value] is {} label)value=label.ToString();return CsvCell(value);}
        var b = new StringBuilder(); b.AppendJoin(',', columns.Select(c => CsvCell(c!.Text("label")??""))).Append("\r\n");
        foreach (var row in rows) b.AppendJoin(',', columns.Select(c=>Cell(c!,row))).Append("\r\n");return b.ToString();
    }
}
