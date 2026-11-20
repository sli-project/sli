using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Primitives;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
namespace Sli.Server.Reporting.V2;

public sealed class GpoReportSourceException : Exception;
public static class ReportV2Endpoints
{
    private static readonly Regex Route = new(@"\A/api/v2/reports/(?<key>[a-z0-9][a-z0-9_.-]{1,79})(?:/(?<action>data|export\.csv)|/rows/(?<row>(?:[A-Za-z0-9_.:-]|%[a-fA-F0-9]{2}){1,128})/detail)?\z", RegexOptions.CultureInvariant);
    private static readonly Regex Row = new(@"\A[A-Za-z0-9_.:-]{1,128}\z", RegexOptions.CultureInvariant);
    public static IServiceCollection AddReportV2Engine(this IServiceCollection services)
    {
        services.TryAddSingleton<IReportDefinitionRegistry, ReportDefinitionRegistry>();
        services.TryAddSingleton<ReportRuleCatalog>();
        services.TryAddSingleton<IReportCatalogProvider>(s => s.GetRequiredService<ReportRuleCatalog>());
        services.TryAddScoped<IAccessFactsRepository, AccessFactsRepository>();
        services.TryAddScoped<DomainRepository>();
        services.TryAddScoped<IReportDomains, ReportDomains>();
        services.TryAddScoped<ReportV2Dispatcher>();
        services.TryAddScoped<BuiltinReportExports>();
        services.TryAddScoped<IReportV2Metadata, ReportV2Metadata>();
        services.TryAddEnumerable(ServiceDescriptor.Scoped<IReportV2Reader, NotificationReportReader>());
        services.TryAddScoped<Sli.Server.Semantic.ISemanticDatabase, Sli.Server.Semantic.SemanticDatabase>();
        services.TryAddEnumerable(ServiceDescriptor.Scoped<IReportV2Reader, FileAuditReportReader>());
        Sli.Server.Problems.ProblemEndpoints.AddProblemLifecycle(services);
        services.TryAddScoped<ISecurityProblemEvidence, SecurityProblemEvidence>();
        services.TryAddEnumerable(ServiceDescriptor.Scoped<IReportV2Reader, SecurityProblemsReader>());
        services.TryAddEnumerable(ServiceDescriptor.Scoped<IReportV2Reader, EventsJournalReader>());
        services.TryAddEnumerable(ServiceDescriptor.Scoped<IReportV2Reader, RuleQualityReader>());
        services.TryAddEnumerable(ServiceDescriptor.Scoped<IReportV2Reader, SecurityEventsReader>());
        return services;
    }
    public static IEndpointRouteBuilder MapReportV2Engine(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v2/reports/{key}", HandleAsync);
        endpoints.MapGet("/api/v2/reports/{key}/data", HandleAsync);
        endpoints.MapGet("/api/v2/reports/{key}/export.csv", HandleAsync);
        endpoints.MapGet("/api/v2/reports/{key}/rows/{row}/detail", HandleAsync);
        endpoints.MapGet("/api/v2/reports/{key}/rows/{**tail}", InvalidRouteAsync);
        return endpoints;
    }
    private static Task InvalidRouteAsync(HttpContext context) => DomainHttp.WriteAsync(context, new { error = "not_found" }, 404, context.RequestAborted);
    public static async Task HandleAsync(HttpContext http)
    {
        var ct = http.RequestAborted; ReportAccess? projection = null;
        try
        {
            var services = http.RequestServices;
            if (services.GetRequiredService<TransportGate>().CheckTransport(http) is { } failure) { await DomainHttp.WriteFailureAsync(http, failure, ct); return; }
            Principal principal;
            if (services.GetRequiredService<AuthRequestPolicy>().AuthRequired)
            {
                var auth = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(http, ct);
                if (!auth.Succeeded) { await DomainHttp.WriteFailureAsync(http, auth.Failure ?? new(401, "authentication_required"), ct); return; }
                principal = auth.Principal!;
                if (TransportGate.CheckViewerRole(principal) is { } role) { await DomainHttp.WriteFailureAsync(http, role, ct); return; }
            }
            else principal = new("", 0, "operator");
            // Validate the encoded path once. In particular %252F must not become a row separator.
            string? rawTarget = http.Features.Get<IHttpRequestFeature>()?.RawTarget;
            string raw = string.IsNullOrEmpty(rawTarget) ? http.Request.Path.Value ?? "" : rawTarget.Split('?')[0];
            var match = Route.Match(raw);
            if (!match.Success) { await InvalidRouteAsync(http); return; }
            string key = match.Groups["key"].Value;
            string? row = match.Groups["row"].Success ? Uri.UnescapeDataString(match.Groups["row"].Value) : null;
            if (row is not null && !Row.IsMatch(row)) { await InvalidRouteAsync(http); return; }
            var definition = services.GetRequiredService<IReportDefinitionRegistry>().Get(key);
            if (definition is null) { await DomainHttp.WriteAsync(http, new { error = "report_not_found" }, 404, ct); return; }
            var catalog = services.GetRequiredService<IReportCatalogProvider>();
            var captured = catalog.Capture();
            if (captured.Rules.Any(r => r.RegistryKey == key && r.DeclarationOnly))
                throw new ReportRequestException("plugin_callable_generation_unsupported", 503);
            var facts = await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, ct);
            var capabilities = new CapabilityComposer().Compose(facts);
            var access = new ReportEligibility().Compose(facts, capabilities);
            var grant = access.Reports.FirstOrDefault(r => r.ReportKey == definition.AccessKey && r.Allowed);
            if (grant is null) { await DomainHttp.WriteAsync(http, new { error = "report_access_denied" }, 403, ct); return; }
            bool export = match.Groups["action"].Value == "export.csv";
            if (row is not null && !definition.HasDetail) throw new ReportRequestException("report_detail_not_available", 404);
            if (export && !definition.HasExport) throw new ReportRequestException("report_export_not_available", 404);
            string action = export ? definition.Rule.Text("export_action", "export") : "view";
            projection = new ReportAccess(definition, access, action);
            if (!match.Groups["action"].Success && row is null)
            {
                var declaration = projection.Declaration();
                var owner = catalog.Recheck(captured).Rules.FirstOrDefault(r => r.RegistryKey == key);
                if (owner is null) throw new ReportRequestException("report_owner_unavailable", 503);
                var options = await (services.GetRequiredService<ReportV2Dispatcher>().Resolve(owner)?.OptionsAsync(definition, access, ct) ?? Task.FromResult(new JsonObject()));
                var visibleOptions = declaration.Objects("params").Select(p => p.Text("options_from", p.Text("key"))).ToHashSet(StringComparer.Ordinal);
                declaration["filter_options"] = new JsonObject(options.Where(p => visibleOptions.Contains(p.Key)).Select(p => KeyValuePair.Create(p.Key, p.Value?.DeepClone())));
                if (key is "ad.users.v2" or "ad.computers.v6" or "ad.infrastructure" or "vpn.connections")
                {
                    try
                    {
                        var metadata = services.GetRequiredService<IReportV2Metadata>();
                        var available = await services.GetRequiredService<IReportDomains>().ReadAsync(projection.ResolveScope().DomainIds(), ct);
                        if (key == "vpn.connections")
                        {
                            var allowed = options.Objects("domain").Select(o => o["value"]?.ToString()).ToHashSet();
                            available = available.Where(d => allowed.Contains(d.Id.ToString(CultureInfo.InvariantCulture))).ToArray();
                        }
                        var chosen = ReportV2Metadata.ChooseDomain(available, await metadata.PreferredDomainAsync(ct));
                        declaration["default_domain_id"] = chosen?.Id;
                        declaration["default_domain_state"] = chosen is null ? "unknown" : "available";
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                    catch (Exception error)
                    {
                        declaration["default_domain_id"] = null;
                        declaration["default_domain_state"] = error is ReportRequestException { Status: 403 } ? "denied" : "unavailable";
                    }
                }
                EnsureCurrent(catalog, captured, key);
                ReportV2Metadata.Annotate(declaration, await services.GetRequiredService<IReportV2Metadata>().PluginAsync(key, ct));
                if (key == "security.problems") SecurityProblemsReader.Localize(declaration, http.Request.Headers.AcceptLanguage.ToString(), declaration: true);
                await DomainHttp.WriteAsync(http, ReportPresentation.Apply(declaration, DomainHttp.SelectEnglish(http.Request.Headers.AcceptLanguage.ToString())), 200, ct); return;
            }
            var query = http.Request.Query;
            projection.Validate(query, ReportParameters.First(query, "tab"), ReportParameters.First(query, "sort"), row is not null);
            var current = catalog.Recheck(captured);
            var rule = current.Rules.FirstOrDefault(r => r.RegistryKey == key && r.ReportKey == definition.AccessKey);
            if (rule is null) throw new ReportRequestException("report_owner_unavailable", 503);
            var reader = services.GetRequiredService<ReportV2Dispatcher>().Resolve(rule);
            JsonArray? domains = null; JsonObject? domainSelection = null; long[]? domainIds = null;
            if (key is "ad.users.v2" or "ad.computers.v6" or "ad.infrastructure")
            {
                long? selected = SelectDomain(query, "domain_id");
                if (query.ContainsKey("domain"))
                {
                    long? legacy = SelectDomain(query, "domain");
                    if (selected is not null && selected != legacy) throw new ReportRequestException("domain_scope_invalid");
                    selected = legacy;
                }
                var permitted = projection.Scope.DomainIds();
                if (selected is not null && permitted is not null && !permitted.Contains(selected.Value)) throw new ReportRequestException("domain_scope_denied", 403);
                var rows = await services.GetRequiredService<IReportDomains>().ReadAsync(selected is not null ? [selected.Value] : permitted, ct);
                if (selected is not null && rows.Count == 0) throw new ReportRequestException("domain_scope_denied", 403);
                rows = rows.Where(d => selected is not null || !d.IsArchived).ToArray();
                domains = JsonSerializer.SerializeToNode(rows)!.AsArray(); domainIds = rows.Select(d => d.Id).ToArray();
                domainSelection = new() { ["mode"] = selected is null ? "accessible" : "domain", ["domain_id"] = selected,
                    ["domain_ids"] = JsonSerializer.SerializeToNode(domainIds), ["state"] = rows.Count > 0 ? "available" : "no_domains" };
                if (selected is not null) query = With(query, "domain", selected.Value.ToString(CultureInfo.InvariantCulture));
            }
            if (key == "vpn.connections")
            {
                if (query["scope"].SequenceEqual(new StringValues("all"))) throw new ReportRequestException("report_parameter_required:domain");
                if (query.ContainsKey("domain_id"))
                {
                    long? selected = SelectDomain(query, "domain_id");
                    if (query.ContainsKey("domain") && selected != SelectDomain(query, "domain")) throw new ReportRequestException("domain_scope_invalid");
                    var values = query.ToDictionary(p => p.Key, p => p.Value); values.Remove("domain_id"); values["domain"] = selected!.Value.ToString(CultureInfo.InvariantCulture); query = new QueryCollection(values);
                }
            }
            var visible = projection.VisibleDefinition();
            foreach (var param in visible.Params.Where(p => p.Text("kind") == "domain" && p.Flag("required") && string.IsNullOrEmpty(ReportParameters.First(query, p.Text("key")))))
            {
                var options = param.Objects("options");
                if (options.Length == 0 && reader is not null) options = (await reader.OptionsAsync(visible, access, ct)).Objects(param.Text("options_from", param.Text("key")));
                var values = options.Select(o => o["value"]?.ToString()).Where(s => !string.IsNullOrEmpty(s)).ToArray();
                if (key == "vpn.connections")
                {
                    try
                    {
                        var metadata = services.GetRequiredService<IReportV2Metadata>();
                        string? preferred = await metadata.PreferredDomainAsync(ct);
                        var available = await services.GetRequiredService<IReportDomains>().ReadAsync(projection.ResolveScope().DomainIds(), ct);
                        var chosen = ReportV2Metadata.ChooseDomain(available.Where(d => values.Contains(d.Id.ToString(CultureInfo.InvariantCulture))), preferred);
                        if (chosen is not null) query = With(query, "domain", chosen.Id.ToString(CultureInfo.InvariantCulture));
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                    catch (Exception) { } // Source metadata failure never selects an unrelated default.
                    continue;
                }
                string? declared = param["default"]?.ToString();
                if (declared is not null && values.Contains(declared)) query = With(query, param.Text("key"), declared);
                else if (values.Length == 1) query = With(query, param.Text("key"), values[0]!);
                else if (!string.IsNullOrEmpty(declared)) throw new ReportRequestException("report_parameter_required:" + param.Text("key"));
            }
            var requestTime = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            var (parameters, paging) = ReportParameters.Parse(visible, query, requestTime);
            projection.Validate(query, paging.Tab, paging.Sort, row is not null);
            var scope = projection.Restrict(parameters);
            if (domains is null && definition.ScopeKind == "domain") domainIds = scope.DomainIds();
            var binding = new JsonObject { ["scope"] = scope.Fingerprint, ["report"] = key, ["params"] = parameters.DeepClone(),
                ["sort"] = paging.Sort, ["direction"] = paging.Direction, ["tab"] = paging.Tab,
                ["principal"] = JsonSerializer.SerializeToNode(principal), ["policy"] = JsonSerializer.SerializeToNode(access) };
            if (row is not null) binding["row"] = row;
            if (definition.Generic && !string.IsNullOrEmpty(paging.Cursor)) paging = paging with { Cursor = ReportCursor.Decode(paging.Cursor, binding) };
            if (row is not null) paging = paging with { Limit = Math.Min(paging.Limit, definition.Detail?["default_limit"]?.GetValue<int>() ?? 50) };
            var context = new ReportQueryContext(definition, access, principal, parameters, paging, scope, domainIds, export ? "export" : "view", projection.FieldsAllowed, grant.Grants)
                { RequestTime = requestTime, Domains = domains, DomainSelection = domainSelection, Language = http.Request.Headers.AcceptLanguage.ToString() };
            if (reader is null && !(export && BuiltinReportExports.Handles(key)))
            {
                // Domain implementations are separately assigned in pieces 13–18. Absence of a reader
                // is an explicit failed source, never an invented empty or not-collected snapshot.
                if (export) throw new ReportRequestException("report_reader_unavailable", 503);
                var unavailable = ReportResult.Create(key, "error", coverage: new() { ["reason"] = "report_reader_unavailable", ["source"] = rule.OwnerId });
                var projected = projection.Project(unavailable, row is not null);
                ReportV2Metadata.Annotate(projected, await services.GetRequiredService<IReportV2Metadata>().PluginAsync(key, ct));
                await WriteResult(http, projected, ct); return;
            }
            EnsureCurrent(catalog, captured, key);
            if (export)
            {
                var document = reader is null ? await services.GetRequiredService<BuiltinReportExports>().ExportAsync(context, ct) : await reader.ExportAsync(context, ct);
                string body = ReportCsv.Project(document.Body, definition, projection);
                EnsureCurrent(catalog, captured, key);
                byte[] data = [0xef, 0xbb, 0xbf, .. Encoding.UTF8.GetBytes(body)];
                string suffix = document.Truncated ? $"INCOMPLETE-first-{document.Rows}-rows" : $"complete-{document.Rows}-rows";
                http.Response.StatusCode = 200; http.Response.ContentType = "text/csv; charset=utf-8";
                http.Response.Headers.ContentDisposition = $"attachment; filename=\"sli-{key}-{suffix}.csv\"";
                http.Response.Headers["X-Sli-Export-Truncated"] = document.Truncated ? "true" : "false";
                http.Response.Headers["X-Sli-Export-Rows"] = document.Rows.ToString(CultureInfo.InvariantCulture);
                http.Response.ContentLength = data.Length; await http.Response.Body.WriteAsync(data, ct); return;
            }
            var payload = projection.Project(row is null ? await reader!.QueryAsync(context, ct) : await reader!.DetailAsync(context, row, ct), row is not null);
            EnsureCurrent(catalog, captured, key);
            if (domainSelection is not null) { payload["domain_scope"] = domainSelection.DeepClone(); payload["domains"] = domains?.DeepClone(); }
            if (definition.Generic && payload["next_cursor"] is JsonValue next && next.TryGetValue<string>(out string? token) && !string.IsNullOrEmpty(token)) payload["next_cursor"] = ReportCursor.Encode(binding, token);
            ReportV2Metadata.Annotate(payload, await services.GetRequiredService<IReportV2Metadata>().PluginAsync(key, ct));
            if (key == "security.problems" && row is null) SecurityProblemsReader.Localize(payload, http.Request.Headers.AcceptLanguage.ToString());
            await WriteResult(http, payload, ct);
        }
        catch (ReportRequestException error)
        {
            var payload = new JsonObject { ["error"] = error.Message };
            if (error.Status == 403)
            {
                payload["state"] = "denied"; payload["reason"] = error.Message;
                payload["state_message"] = ReportResult.Message("reports.state.denied", DomainHttp.SelectEnglish(http.Request.Headers.AcceptLanguage.ToString()));
                if (projection is not null) { var summary = projection.Summary(); summary["allowed"] = false; summary["reason"] = error.Message; payload["access"] = summary; }
            }
            await DomainHttp.WriteAsync(http, payload, error.Status, ct);
        }
        catch (GpoReportSourceException)
        {
            http.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Sli.Server.Reporting.V2.ReportV2Endpoints").LogWarning("GPO source contract violation");
            await DomainHttp.WriteAsync(http, new { error = "gpo_snapshot_unavailable", state = "error", reason = "source_contract_error", message = ReportResult.Message("reports.renderer.error_gpo_snapshot", DomainHttp.SelectEnglish(http.Request.Headers.AcceptLanguage.ToString())) }, 503, ct);
        }
        catch (Exception error) when (error is TimeoutException or Npgsql.PostgresException { SqlState: "57014" }
            or Npgsql.NpgsqlException { InnerException: TimeoutException })
        { await DomainHttp.WriteAsync(http, new { error = "report_read_timeout", state = "unavailable" }, 503, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception error) { if (http.Response.HasStarted) throw; await AuthResponse.UnexpectedAsync(http, error, ct, login: false); }
    }
    private static IQueryCollection With(IQueryCollection query, string key, string value)
    { var values = query.ToDictionary(p => p.Key, p => p.Value); values[key] = value; return new QueryCollection(values); }
    private static long? SelectDomain(IQueryCollection query, string key)
    {
        if (!query.ContainsKey(key)) return null;
        var values = query[key];
        if (values.Count != 1 || values[0] is not { } value || !Regex.IsMatch(value, @"\A[1-9][0-9]{0,18}\z") || !long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long id)) throw new ReportRequestException("domain_scope_invalid");
        return id;
    }
    private static void EnsureCurrent(IReportCatalogProvider provider, ReportCatalogSnapshot captured, string key)
    { if (!provider.Recheck(captured).Rules.Any(r => r.RegistryKey == key)) throw new ReportRequestException("report_owner_unavailable", 503); }
    private static Task WriteResult(HttpContext http, JsonObject payload, CancellationToken ct)
    {
        payload["state_message"] = ReportResult.Message("reports.state." + payload.Text("state"), DomainHttp.SelectEnglish(http.Request.Headers.AcceptLanguage.ToString()));
        if (payload.Text("report_key") == "events.journal") EventsJournalReader.Localize(payload, DomainHttp.SelectEnglish(http.Request.Headers.AcceptLanguage.ToString()));
        return DomainHttp.WriteAsync(http, ReportPresentation.Apply(payload, DomainHttp.SelectEnglish(http.Request.Headers.AcceptLanguage.ToString())), 200, ct);
    }
}
