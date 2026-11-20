using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
using static Sli.Server.Reporting.ReportJson;

namespace Sli.Server.Reporting;

public static class ReportStudioEndpoints
{
    public static IServiceCollection AddReportStudio(this IServiceCollection services)
    {
        services.TryAddScoped<IAccessFactsRepository, AccessFactsRepository>();
        services.TryAddScoped<IReportDatabase, ReportDatabase>();
        services.AddScoped<ReportStudioService>(); services.AddScoped<ReportRunner>(); return services;
    }
    public static IEndpointRouteBuilder MapReportStudio(this IEndpointRouteBuilder endpoints)
    {
        foreach (string route in new[] { "/api/reports", "/api/v1/reports/catalog", "/api/v1/reports/datasets", "/api/v1/reports/definitions", "/api/v1/reports/definitions/{key}",
            "/api/v1/reports/{key}/data", "/api/v1/reports/{key}/export.csv", "/api/v1/reports/{key}/access-summary", "/api/v1/reports/{key}/access-trace" }) endpoints.MapGet(route, HandleAsync);
        foreach (string route in new[] { "/api/v1/reports/builder/preview", "/api/v1/reports/definitions", "/api/v1/reports/definitions/{key}/retire",
            "/api/v1/reports/definitions/{key}/visibility", "/api/v1/reports/definitions/{key}/versions/{version}/publish" }) endpoints.MapPost(route, HandleAsync);
        return endpoints;
    }
    public static async Task HandleAsync(HttpContext context)
    {
        var ct = context.RequestAborted;
        try
        {
            var services = context.RequestServices; var transport = services.GetRequiredService<TransportGate>().CheckTransport(context);
            if (transport is not null) { await AuthResponse.ErrorAsync(context, transport.Code, transport.StatusCode, ct, login: false); return; }
            var policy = services.GetRequiredService<AuthRequestPolicy>(); var identity = policy.Resolve(context);
            bool write = HttpMethods.IsPost(context.Request.Method);
            if (write && !policy.OriginAllowed(context, identity)) { await AuthResponse.ErrorAsync(context, "cross_origin_request_rejected", 403, ct, login: false); return; }
            Principal principal;
            if (policy.AuthRequired)
            {
                var auth = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
                if (!auth.Succeeded) { await AuthResponse.ErrorAsync(context, auth.Failure?.Code ?? "authentication_required", auth.Failure?.StatusCode ?? 401, ct, login: false); return; }
                principal = auth.Principal!;
            }
            else
            {
                string expected = services.GetRequiredService<IConfiguration>()["Sli:OperatorToken"] ?? Environment.GetEnvironmentVariable("ADLOG_OPERATOR_TOKEN") ?? "";
                if (write && expected.Trim().Length > 0 && !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(expected.Trim())), SHA256.HashData(Encoding.UTF8.GetBytes(context.Request.Headers["X-ADLog-Operator-Token"].ToString()))))
                { await AuthResponse.ErrorAsync(context, "operator_token_required", 401, ct, login: false); return; }
                principal = new("local", 0, "operator", Username: "local-operator");
            }
            string path = context.Request.Path.Value ?? ""; string key = context.Request.RouteValues["key"]?.ToString() ?? "";
            bool preview = path == "/api/v1/reports/builder/preview", create = write && path == "/api/v1/reports/definitions", lifecycle = write && !preview && !create;
            Require(!policy.AuthRequired || principal.Role is "viewer" or "operator" or "admin", "insufficient_permissions", 403);
            if (write && policy.AuthRequired) Require(preview || (create ? principal.Role is "operator" or "admin" : principal.Role == "admin"), "insufficient_permissions", 403);
            var facts = await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, true, ct);
            var caps = new CapabilityComposer().Compose(facts); var access = new ReportEligibility().Compose(facts, caps);
            var projection = JsonSerializer.SerializeToNode(AccessReadPresentation.Apply(AccessReadProjection.Compose(principal, facts, caps, access, false), "effective", context.Request.Headers.AcceptLanguage.ToString()))!.AsObject();
            var caller = new ReportCaller(principal, facts, caps, projection);
            string? capability = write ? preview ? "reports.design" : "reports.publish" : path.EndsWith("/access-summary", StringComparison.Ordinal) ? null
                : path.StartsWith("/api/v1/reports/definitions", StringComparison.Ordinal) || path == "/api/v1/reports/datasets" ? "reports.design" : "reports.catalog";
            if (capability is not null)
            {
                var decision = caps.Decide(capability);
                if (!decision.Allowed) { await DomainHttp.WriteAsync(context, new { error = decision.Reason, required_capability = capability }, 403, ct); return; }
            }
            var service = services.GetRequiredService<ReportStudioService>();
            var query = ParseQuery(context);
            object result; int status = 200;
            if (write)
            {
                JsonObject body = new();
                if (preview || create || path.EndsWith("/visibility", StringComparison.Ordinal))
                { using var doc = await AuthJsonBody.ReadAsync(context, ct); body = JsonNode.Parse(doc.RootElement.GetRawText())!.AsObject(); }
                if (preview) result = await service.PreviewAsync(caller, body, ct);
                else if (create) { result = new JsonObject { ["item"] = await service.PublishAsync(caller, body, identity.Address, ct) }; status = 201; }
                else result = new JsonObject { ["item"] = await service.LifecycleAsync(caller, key, path.EndsWith("/retire", StringComparison.Ordinal) ? "retire" : path.EndsWith("/visibility", StringComparison.Ordinal) ? "visibility" : "publish", context.Request.RouteValues["version"]?.ToString(), body, identity.Address, ct) };
            }
            else if (path == "/api/v1/reports/datasets") result = await service.DatasetsAsync(caller, ct);
            else if (path == "/api/v1/reports/definitions") result = await service.DefinitionsAsync(caller, Integer(query, "limit", 200), ct);
            else if (path.StartsWith("/api/v1/reports/definitions/", StringComparison.Ordinal)) result = await service.DetailAsync(caller, key, ct);
            else if (path.EndsWith("/access-summary", StringComparison.Ordinal)) result = await service.SummaryAsync(caller, key, ct);
            else if (path.EndsWith("/access-trace", StringComparison.Ordinal)) result = ReportStudioService.Trace(caller, key);
            else if (path == "/api/v1/reports/catalog") result = Catalog(caller);
            else if (path == "/api/reports") result = LegacyCatalog(services.GetRequiredService<IConfiguration>());
            else
            {
                var filters = Filters(query);
                string[] fields = query.GetValueOrDefault("field", []).SelectMany(v => v.Split(',')).Where(v => v.Length > 0).ToArray();
                bool export = path.EndsWith("/export.csv", StringComparison.Ordinal);
                var data = await services.GetRequiredService<ReportRunner>().ExecuteAsync(caller, key, export ? 200 : Integer(query, "limit", 50), fields.Length == 0 ? null : fields, export ? "export" : "view", filters, ct);
                if (export) { await ExportAsync(context, key, data, ct); return; }
                result = data;
            }
            await DomainHttp.WriteAsync(context, result, status, ct);
        }
        catch (ReportDomainNotConfiguredException)
        { await DomainHttp.WriteAsync(context, new { error = ReportDomainNotConfiguredException.Code, message = ReportDomainNotConfiguredException.UserMessage }, 503, ct); }
        catch (ReportException error) { await DomainHttp.WriteAsync(context, new { error = error.Message }, error.Status, ct); }
        catch (AuthInputException error) { await AuthResponse.ErrorAsync(context, error.Code, error.StatusCode, ct, login: false); }
        catch (Exception error) when (error is TimeoutException or Npgsql.PostgresException { SqlState: "57014" }
            or Npgsql.NpgsqlException { InnerException: TimeoutException })
        { await DomainHttp.WriteAsync(context, new { error = "report_read_timeout", state = "unavailable" }, 503, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception error) { if (context.Response.HasStarted) throw; await AuthResponse.UnexpectedAsync(context, error, ct, login: false); }
    }
    private static Dictionary<string, string[]> ParseQuery(HttpContext context) => context.Request.Query.Where(p => p.Value.Any(v => !string.IsNullOrEmpty(v)))
        .ToDictionary(p => p.Key, p => p.Value.Where(v => !string.IsNullOrEmpty(v)).Select(v => v!).ToArray(), StringComparer.Ordinal);
    private static int Integer(Dictionary<string, string[]> query, string key, int fallback)
    {
        string value = query.GetValueOrDefault(key, [fallback.ToString(CultureInfo.InvariantCulture)])[0];
        var number = ReportJson.Integer(value);
        return (int)System.Numerics.BigInteger.Clamp(number, int.MinValue, int.MaxValue);
    }
    private static Dictionary<string, string> Filters(Dictionary<string, string[]> query)
    {
        string[] allowed = ["limit", "field", "q", "server", "time_from", "time_to", "cursor", "grant_branch", "sort", "direction", "entity_type", "activity_state", "privileged_overlap", "application_state", "link_count", "has_executable_components", "view"];
        Require(!query.Keys.Except(allowed).Any(), "unknown_report_query_filter");
        var result = new Dictionary<string, string>();
        foreach (var (key, values) in query.Where(p => p.Key is not ("limit" or "field")))
        { Require(values.Length <= 1, "duplicate_report_query_filter"); if (values.Length > 0 && values[0].Trim().Length > 0) result[key] = values[0].Trim(); }
        return result;
    }
    private static JsonObject Catalog(ReportCaller caller)
    {
        string[] nonCatalog = ["/events", "/investigations", "/cases", "/access", "/access-center", "/operations", "/project-readiness", "/report-management", "/report-editor"];
        var reports = caller.Access.Array("reports").OfType<JsonObject>().Where(r => !nonCatalog.Contains(r.Text("target_path").StartsWith("/app") ? r.Text("target_path")[4..] : r.Text("target_path"))).ToList();
        var vpn = reports.FirstOrDefault(r => r.Text("report_key") == "vpn.audit");
        if (vpn is not null && !reports.Any(r => r.Text("report_key") == "vpn.connections"))
        {
            var item = vpn.Copy(); string[] missing = Sorted(vpn.Strings("missing_capabilities").Concat(caller.Caps.Contains("vpn.sessions.view") ? [] : new[] { "vpn.sessions.view" }));
            bool allowed = vpn.Flag("allowed") && missing.Length == 0;
            item["report_key"] = "vpn.connections"; item["version"] = 1; item["name"] = "VPN — подключения и доступы";
            item["purpose"] = "Сотрудники, подтверждённые RADIUS Accounting сессии, текущие AD-доступы и durable NPS 6273.";
            item["dataset_key"] = "vpn.sessions"; item["dataset_version"] = 1; item["target_path"] = "/report/vpn.connections"; item["allowed"] = allowed;
            item["explanation"] = "Использует существующее назначение vpn.audit; session-ветка дополнительно проверяется сервером по vpn.sessions.view и domain scope.";
            item["missing_capabilities"] = Nodes(missing); item["discoverable"] = true; item["requestable"] = false;
            item["access_state"] = allowed ? vpn["access_valid_until"] is not null ? "available_until" : "available" : "request_unavailable";
            item["request"] = null; item["resource_context_required"] = true; item["allowed_actions"] = allowed ? new JsonArray("view") : new JsonArray();
            item["pinned"] = false; item["preference_supported"] = false; item["preference_updated_at"] = null; item["dashboard_metrics"] = new JsonArray();
            item["selected_optional_metric_keys"] = new JsonArray(); item["focus_preference_configured"] = false; reports.Add(item);
        }
        reports.RemoveAll(r => r.Text("report_key") == "vpn.audit");
        return new() { ["api_version"] = "v4", ["state"] = reports.Count > 0 ? "available" : "empty", ["items"] = Nodes(reports), ["allowed_count"] = reports.Count(r => r.Flag("allowed")), ["total_count"] = reports.Count, ["explain_contract"] = "assignment + required capabilities - explicit deny" };
    }
    private static JsonObject LegacyCatalog(IConfiguration configuration)
    {
        string root = Path.GetFullPath(configuration["Sli:Root"] ?? Directory.GetCurrentDirectory());
        string sibling = Path.Combine(Directory.GetParent(root)?.FullName ?? root, "sli_data");
        string data = configuration["Sli:DataDirectory"] ?? Environment.GetEnvironmentVariable("ADLOG_DATA_DIR") ?? Environment.GetEnvironmentVariable("SLI_DATA_DIR") ?? (Directory.Exists(sibling) ? sibling : Path.Combine(root, "data"));
        string directory = Path.GetFullPath(Path.Combine(data, "reports"), root);
        var metadata = ReportDatasetCatalog.Data["legacy_metadata"]!.AsObject(); var items = new List<JsonObject>();
        if (Directory.Exists(directory)) foreach (var path in Directory.EnumerateFiles(directory, "*.html").Where(p => metadata.ContainsKey(Path.GetFileName(p)) || Path.GetFileName(p).EndsWith("-security-profile.html", StringComparison.Ordinal)).OrderByDescending(File.GetLastWriteTimeUtc))
        {
            string name = Path.GetFileName(path); var file = new FileInfo(path);
            var item = metadata[name] is JsonObject m ? m.Copy() : new JsonObject { ["kind"] = name.StartsWith("server-") ? "server_security_profile" : "html_report", ["server"] = name.StartsWith("server-") ? name[7..^22] : null,
                ["title"] = name.StartsWith("server-") ? "Профиль безопасности " + name[7..^22] : name, ["roles"] = new JsonArray("security", "it", "technical"), ["focus_group"] = "shared", ["navigation_priority"] = 1000 };
            item["name"] = name; item["path"] = Path.GetRelativePath(root, path).StartsWith("..") ? path : Path.GetRelativePath(root, path); item["size_bytes"] = file.Length;
            item["updated_at"] = (file.LastWriteTimeUtc - DateTime.UnixEpoch).TotalSeconds; item["url"] = "/reports/" + name; items.Add(item);
        }
        var existing = items.Select(i => i.Text("name")).ToHashSet();
        var dynamic = ReportDatasetCatalog.Data.Strings("legacy_dynamic").Where(n => !existing.Contains(n)).Select(n => { var item = metadata[n]!.AsObject().Copy(); item["name"] = n; item["path"] = "dynamic:/reports/" + n; item["url"] = "/reports/" + n; item["size_bytes"] = null; item["updated_at"] = null; item["dynamic"] = true; return item; });
        return new() { ["items"] = Nodes(dynamic.Concat(items)) };
    }
    public static async Task ExportAsync(HttpContext context, string key, JsonObject data, CancellationToken ct)
    {
        DomainHttp.ApplyHeaders(context);
        var rows = data.Array("items"); var fields = data.Array("fields").OfType<JsonObject>().ToArray();
        var csv = new StringBuilder();
        csv.AppendJoin(',', fields.Select(f => Cell(JsonValue.Create(f.Text("label", f.Text("key")))))).Append("\r\n");
        foreach (var row in rows) csv.AppendJoin(',', fields.Select(f => Cell(row?[f.Text("key")]))).Append("\r\n");
        bool more = data.Flag("has_more"), truncated = more || (data["limits"]?.Number("total_count", -1) ?? -1) > rows.Count;
        string safe = Regex.Replace(key, "[^A-Za-z0-9._-]+", "-").Trim('-'); if (safe.Length == 0) safe = "report";
        string filename = $"sli-report-{safe}-" + (truncated ? $"INCOMPLETE-first-{rows.Count}-rows.csv" : $"complete-{rows.Count}-rows.csv");
        context.Response.ContentType = "text/csv; charset=utf-8"; context.Response.Headers.ContentDisposition = "attachment; filename=\"" + filename + "\"";
        context.Response.Headers["X-Sli-Export-Truncated"] = truncated ? "true" : "false"; context.Response.Headers["X-Sli-Export-Rows"] = rows.Count.ToString(CultureInfo.InvariantCulture);
        context.Response.Headers["X-Sli-Export-Row-Limit"] = "200"; context.Response.Headers["X-Sli-Export-Has-More"] = more ? "true" : "false";
        context.Response.Headers["X-Sli-Export-Total-Count"] = data["limits"].Text("total_count", "not_calculated");
        byte[] body = new byte[] { 0xef, 0xbb, 0xbf }.Concat(Encoding.UTF8.GetBytes(csv.ToString())).ToArray(); context.Response.ContentLength = body.Length;
        await context.Response.Body.WriteAsync(body, ct);
    }
    private static string Cell(JsonNode? node)
    {
        string value = node is null ? "" : node is JsonObject or JsonArray ? node.ToJsonString(new JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping })
            : node is JsonValue v && v.TryGetValue<bool>(out bool b) ? b ? "True" : "False" : node.ToString();
        if (value.TrimStart().StartsWith('=') || value.TrimStart().StartsWith('+') || value.TrimStart().StartsWith('-') || value.TrimStart().StartsWith('@')) value = "'" + value;
        return value.IndexOfAny([',', '"', '\r', '\n']) >= 0 ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;
    }
}
