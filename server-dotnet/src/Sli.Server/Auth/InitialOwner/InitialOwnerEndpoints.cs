using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Domains;
using Sli.Server.Auth.Recovery;

namespace Sli.Server.Auth.InitialOwner;

public static class InitialOwnerEndpoints
{
    public static IServiceCollection AddInitialOwner(this IServiceCollection services)
    {
        services.AddScoped<IInitialOwnerSetup, InitialOwnerSetup>();
        services.TryAddSingleton<OwnerRecoveryTerminal>();
        services.AddScoped<IInitialOwnerOperatorConnections, InitialOwnerOperatorConnections>();
        services.AddScoped<ProtectedOwnerCodeStore>();
        services.AddScoped<IInitialOwnerCodeConsole, InitialOwnerCodeConsole>();
        return services;
    }

    public static IEndpointRouteBuilder MapInitialOwnerEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/auth/bootstrap", context => HandleAsync(context, false));
        endpoints.MapPost("/api/auth/bootstrap", context => HandleAsync(context, true));
        return endpoints;
    }

    private static async Task HandleAsync(HttpContext context, bool claim)
    {
        CancellationToken ct = context.RequestAborted;
        try
        {
            var services = context.RequestServices;
            var policy = services.GetRequiredService<AuthRequestPolicy>();
            var setup = services.GetRequiredService<IInitialOwnerSetup>();
            if (!claim)
            {
                if (await setup.IsPendingAsync(ct)) await InitialOwnerPage.SendAsync(context);
                else await Error(context, "not_found", 404);
                return;
            }
            if (!policy.OwnerSetup || !policy.AuthRequired) { await Error(context, "not_found", 404); return; }
            var transport = services.GetRequiredService<TransportGate>();
            // Bootstrap has stricter transport and source-specific precedence than normal login.
            if (!transport.IsSecureTransport(context)) { await Error(context, "secure_transport_required", 403); return; }
            var identity = policy.Resolve(context);
            if (!policy.OriginAllowed(context, identity)) { await Error(context, "cross_origin_request_rejected", 403); return; }
            var admission = services.GetRequiredService<ISourceAdmission>().TryReserve(identity.Address);
            if (!admission.Allowed)
            {
                context.Response.Headers.RetryAfter = admission.RetryAfterSeconds.ToString(CultureInfo.InvariantCulture);
                await Error(context, "login_temporarily_locked", 429);
                return;
            }
            // Reuse the common body parser, adding only this route's source 16KiB bound.
            if (string.IsNullOrEmpty(context.Request.Headers.TransferEncoding.ToString())
                && long.TryParse(context.Request.Headers.ContentLength.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out long length)
                && length > 16384) throw new AuthInputException("request_body_too_large", 413);
            using var document = await AuthJsonBody.ReadAsync(context, ct);
            string? StringProperty(string name) => document.RootElement.TryGetProperty(name, out var value)
                && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
            var result = await setup.ClaimAsync(new(StringProperty("code"), StringProperty("password")), new(identity.Address), ct);
            if (!result.Succeeded) { await Error(context, "invalid_or_used_setup_code", 401); return; }
            context.Response.Headers.SetCookie = AuthEndpoints.Cookie(result.SessionToken!, 43200, transport.IsSecureTransport(context) || policy.SecureCookie);
            await DomainHttp.WriteAsync(context, new { authenticated = true, principal = AuthEndpoints.PublicPrincipal(result.Principal!) }, 200, ct);
        }
        catch (InitialOwnerPasswordException) { await Error(context, "new_password_required", 400); }
        catch (AuthInputException error) { await Error(context, error.Code, error.StatusCode); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception error)
        {
            if (context.Response.HasStarted) throw;
            // No exception text/SQL parameters/credentials enter this diagnostic.
            try { context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Sli.Server.InitialOwner")
                .LogError("initial_owner_setup_failed exception_type={ErrorType}", error.GetType().Name); }
            catch (Exception) { }
            await Error(context, "internal_server_error", 500);
        }
    }

    private static Task Error(HttpContext context, string error, int status) =>
        AuthResponse.ErrorAsync(context, error, status, context.RequestAborted, login: false);
}
