using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.InstallationSetup;

public static class InstallationEndpoints
{
    public static IServiceCollection AddInstallation(this IServiceCollection services)
    {
        services.TryAddScoped<IAccessFactsRepository, AccessFactsRepository>();
        services.TryAddScoped<IInstallationDatabase, InstallationDatabase>();
        services.TryAddSingleton<InstallationPackages>();
        services.TryAddScoped<InstallationService>();
        services.TryAddScoped<PluginRuntimeActivationExecutor>();
        return services;
    }

    public static IEndpointRouteBuilder MapInstallation(this IEndpointRouteBuilder routes)
    {
        foreach (string path in new[] { "/api/v1/setup/status", "/api/v1/setup/domains", "/api/v1/setup/domain-controllers",
            "/api/v1/platform-settings", "/api/v1/plugins", "/api/v1/operations/plugins", "/api/v1/operations/plugins/{**id}",
            "/api/plugins/{**tail:regex((^|.*/)settings$)}", "/api/v1/ui/plugins/{id}/descriptor", "/api/v1/ui/plugins/{id}/assets/{hash}/{**asset}", "/api/v1/ui/plugins/{**tail}" })
            routes.MapGet(path, HandleAsync);
        foreach (string path in new[] { "/api/v1/setup/domains", "/api/v1/setup/domains/{**id}",
            "/api/v1/setup/domain-controllers", "/api/v1/setup/domain-controllers/{**id}",
            "/api/v1/platform-settings/{**id}", "/api/v1/plugins/{**id}" })
            routes.MapPost(path, HandleAsync);
        routes.MapPut("/api/plugins/{**tail:regex((^|.*/)settings$)}", HandleAsync);
        return routes;
    }

    public static async Task HandleAsync(HttpContext context)
    {
        var ct = context.RequestAborted;
        string path = context.Request.Path.Value ?? "";
        bool mutation = !HttpMethods.IsGet(context.Request.Method);
        bool toggle = mutation && path.StartsWith("/api/v1/plugins/", StringComparison.Ordinal);
        bool ui = path.StartsWith("/api/v1/ui/plugins/", StringComparison.Ordinal);
        string capability = ui ? "workspace.view" : path.StartsWith("/api/v1/operations/", StringComparison.Ordinal)
            || path.StartsWith("/api/v1/plugins", StringComparison.Ordinal) ? "operations.view" : "access.manage";
        try
        {
            var services = context.RequestServices;
            var transport = services.GetRequiredService<TransportGate>().CheckTransport(context);
            if (transport is not null) { await DomainHttp.WriteFailureAsync(context, transport, ct); return; }
            var policy = services.GetRequiredService<AuthRequestPolicy>();
            var identity = policy.Resolve(context);
            if (mutation && !policy.OriginAllowed(context, identity)) throw new InstallationException("cross_origin_request_rejected", 403);
            Principal principal;
            if (policy.AuthRequired)
            {
                var auth = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
                if (!auth.Succeeded) { await DomainHttp.WriteFailureAsync(context, auth.Failure ?? new(401, "authentication_required"), ct); return; }
                principal = auth.Principal!;
                if (TransportGate.CheckViewerRole(principal) is not null || mutation && !toggle && principal.Role != "admin")
                    throw new InstallationException("insufficient_permissions", 403);
            }
            else
            {
                if (mutation)
                {
                    string token = services.GetRequiredService<IConfiguration>()["Sli:OperatorToken"] ?? Environment.GetEnvironmentVariable("ADLOG_OPERATOR_TOKEN") ?? "";
                    if (token.Trim().Length > 0 && !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(token.Trim())),
                        SHA256.HashData(Encoding.UTF8.GetBytes(context.Request.Headers["X-ADLog-Operator-Token"].ToString()))))
                        throw new InstallationException("operator_token_required", 401);
                }
                principal = new("local", 0, "operator", Username: "local-operator");
            }
            var facts = await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, ct);
            var access = new CapabilityComposer().Compose(facts);
            async Task<bool> Require(string key)
            {
                var decision = access.Decide(key);
                if (decision.Allowed) return true;
                await DomainHttp.WriteAsync(context, new { error = decision.Reason, required_capability = key }, 403, ct);
                return false;
            }
            if (!await Require(capability)) return;
            bool canManage = CanManage(principal, access);
            if (toggle && !canManage) throw new InstallationException("plugin_management_owner_or_admin_required", 403);
            var service = services.GetRequiredService<InstallationService>();
            if (ui)
            {
                string[] parts = path["/api/v1/ui/plugins/".Length..].Split('/');
                if (!(parts.Length == 2 && parts[1] == "descriptor" || parts.Length >= 4 && parts[1] == "assets")) throw new InstallationException("not_found", 404);
                var package = services.GetRequiredService<InstallationPackages>().LoadUi(parts[0]);
                foreach (var required in package.Descriptor["required_capabilities"]!.AsArray())
                    if (!await Require(required!.GetValue<string>())) return;
                if (parts.Length == 2 && parts[1] == "descriptor")
                    await DomainHttp.WriteAsync(context, package.Descriptor, 200, ct);
                else
                {
                    if (parts.Length < 4 || parts[2] != package.Descriptor["entry"]!["sha256"]!.GetValue<string>()
                        || string.Join('/', parts.Skip(3)) != package.Descriptor["entry"]!["path"]!.GetValue<string>())
                        throw new InstallationException("plugin_ui_integrity_failed", 409);
                    context.Response.ContentType = "application/javascript; charset=utf-8";
                    context.Response.ContentLength = package.Payload.Length;
                    await context.Response.Body.WriteAsync(package.Payload, ct);
                }
                return;
            }
            using var body = mutation ? await AuthJsonBody.ReadAsync(context, ct) : JsonDocument.Parse("{}");
            var result = await service.DispatchAsync(context.Request.Method, path, JsonNode.Parse(body.RootElement.GetRawText())!.AsObject(),
                principal, identity.Address, canManage, mutation ? CancellationToken.None : ct);
            int status = mutation && path is "/api/v1/setup/domains" or "/api/v1/setup/domain-controllers" ? 201 : 200;
            await DomainHttp.WriteAsync(context, result, status, ct);
        }
        catch (InstallationException e)
        {
            string code = e.Message; int status = e.Status;
            if (path.StartsWith("/api/v1/plugins", StringComparison.Ordinal) && status == 503) code = "plugin_state_unavailable";
            if (HttpMethods.IsGet(context.Request.Method) && path.StartsWith("/api/plugins/", StringComparison.Ordinal) && status == 400)
            { code = "plugin_settings_unavailable"; status = 503; }
            if (path == "/api/v1/platform-settings" && !mutation || path.StartsWith("/api/v1/setup/domain-controllers", StringComparison.Ordinal) && (code is "plugin_update_draining" or "plugin_admission_unavailable"))
            { await AuthResponse.UnexpectedAsync(context, e, ct, login: false); return; }
            await ErrorAsync(context, code, status, ui && code != "not_found", ct);
        }
        catch (AuthInputException e) { await DomainHttp.WriteAsync(context, new { error = e.Code }, e.StatusCode, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception e) when (e is NpgsqlException or IOException or InvalidOperationException or JsonException)
        {
            if (!ui && !path.StartsWith("/api/v1/plugins", StringComparison.Ordinal) && !(HttpMethods.IsGet(context.Request.Method) && path.StartsWith("/api/plugins/", StringComparison.Ordinal)))
            { await AuthResponse.UnexpectedAsync(context, e, ct, login: false); return; }
            string error = ui ? "plugin_ui_invalid_descriptor" : path.StartsWith("/api/v1/plugins", StringComparison.Ordinal)
                ? "plugin_state_unavailable" : path.StartsWith("/api/plugins/", StringComparison.Ordinal) ? "plugin_settings_unavailable" : "installation_unavailable";
            await ErrorAsync(context, error, 503, ui, ct);
        }
    }
    static Task ErrorAsync(HttpContext context, string code, int status, bool ui, CancellationToken ct)
    {
        if (code is "plugin_settings_not_found" or "plugin_settings_unavailable" or "invalid_plugin_setting_value")
        {
            string locale = DomainHttp.SelectEnglish(context.Request.Headers.AcceptLanguage.ToString()) ? "en" : "ru";
            using var stream = typeof(InstallationEndpoints).Assembly.GetManifestResourceStream("Sli.Server.Access.Administration.server." + locale + ".json")!;
            var catalog = JsonSerializer.Deserialize<Dictionary<string, string>>(stream)!;
            return DomainHttp.WriteAsync(context, new { error = code, message = new { code, @params = new { }, text = catalog[code] } }, status, ct);
        }
        return ui ? DomainHttp.WriteAsync(context, new { error = code, state = "unavailable" }, status, ct)
            : AuthResponse.ErrorAsync(context, code, status, ct, login: false);
    }
    public static bool CanManage(Principal p, CapabilityDecisionSet access) => p.Id > 0 && access.Decide("plugins.manage").Allowed
        && p.Type is "session" or "api_key" && (p.Role == "admin" || p.Type == "session" && access.IsOwner);
}
