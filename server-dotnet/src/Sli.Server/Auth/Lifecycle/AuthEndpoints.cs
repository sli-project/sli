using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Auth.Recovery;
using Sli.Server.Domains;

namespace Sli.Server.Auth.Lifecycle;

public static class AuthEndpoints
{
    public static IServiceCollection AddAuthLifecycle(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.AddReportKeyRequestGate();
        services.AddSingleton<AuthRequestPolicy>();
        services.AddSingleton<ICredentialTokens, CredentialTokens>();
        services.AddSingleton<IPasswordCodec, PasswordCodec>();
        services.AddScoped<ISessionLifecycle, SessionLifecycle>();
        services.AddScoped<ILoginService, LoginService>();
        return services;
    }

    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/api/auth/login", (HttpContext context) => HandleAsync(context, context.RequestAborted, Operation.Login));
        endpoints.MapGet("/api/auth/me", (HttpContext context) => HandleAsync(context, context.RequestAborted, Operation.Me));
        endpoints.MapPost("/api/auth/logout", (HttpContext context) => HandleAsync(context, context.RequestAborted, Operation.Logout));
        return endpoints;
    }

    private enum Operation { Login, Me, Logout }

    private static async Task HandleAsync(HttpContext context, CancellationToken ct, Operation operation)
    {
        try { await HandleCoreAsync(context, ct, operation); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception error)
        {
            if (context.Response.HasStarted) throw;
            await AuthResponse.UnexpectedAsync(context, error, ct);
        }
    }

    private static async Task HandleCoreAsync(HttpContext context, CancellationToken ct, Operation operation)
    {
        bool login = operation == Operation.Login, logout = operation == Operation.Logout, me = operation == Operation.Me;
        var services = context.RequestServices;
        var transport = services.GetRequiredService<TransportGate>();
        var transportFailure = transport.CheckTransport(context);
        if (transportFailure is not null) { await AuthResponse.ErrorAsync(context, transportFailure.Code, transportFailure.StatusCode, ct); return; }
        var policy = services.GetRequiredService<AuthRequestPolicy>();
        var identity = policy.Resolve(context);
        if (me)
        {
            var auth = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
            if (!auth.Succeeded) await AuthResponse.ErrorAsync(context, auth.Failure?.Code ?? "authentication_required", auth.Failure?.StatusCode ?? 401, ct);
            else await DomainHttp.WriteAsync(context, new { authenticated = true, principal = PublicPrincipal(auth.Principal!) }, 200, ct);
            return;
        }
        if (login && !policy.AuthRequired) { await AuthResponse.ErrorAsync(context, "authentication_not_enabled", 409, ct); return; }
        if (!policy.OriginAllowed(context, identity)) { await AuthResponse.ErrorAsync(context, "cross_origin_request_rejected", 403, ct); return; }
        if (logout)
        {
            await services.GetRequiredService<ISessionLifecycle>().RevokeAsync(
                PrincipalAuthenticator.SessionTokenFromCookie(context.Request.Headers.Cookie.ToString()), ct);
            context.Response.Headers.SetCookie = Cookie("", 0, transport.IsSecureTransport(context) || policy.SecureCookie);
            await DomainHttp.WriteAsync(context, new { status = "ok" }, 200, ct);
            return;
        }
        if (!transport.IsSecureTransport(context) && !policy.AllowInsecureHttp)
        { await AuthResponse.ErrorAsync(context, "secure_transport_required", 403, ct); return; }
        var admission = services.GetRequiredService<ISourceAdmission>().TryReserve(identity.Address);
        if (!admission.Allowed)
        {
            await services.GetRequiredService<IAuthAudit>().WriteAsync(new("anonymous", null, "login", "throttled", identity.Address), ct);
            await AuthResponse.ErrorAsync(context, "login_temporarily_locked", 429, ct, admission.RetryAfterSeconds);
            return;
        }
        try
        {
            using var document = await AuthJsonBody.ReadAsync(context, ct);
            var payload = document.RootElement;
            var command = new LoginCommand(AuthJsonBody.CredentialString(payload, "username"), AuthJsonBody.CredentialString(payload, "password"),
                payload.TryGetProperty("remember", out var remember) && AuthJsonBody.Truthy(remember));
            var result = payload.TryGetProperty("recovery_code", out _)
                ? await services.GetRequiredService<IOwnerRecoveryService>().LoginAsync(command,
                    AuthJsonBody.CredentialString(payload, "recovery_code"), new(identity.Address), ct)
                : await services.GetRequiredService<ILoginService>().LoginAsync(command, new(identity.Address), ct);
            if (result.RetryAfterSeconds > 0) await AuthResponse.ErrorAsync(context, "login_temporarily_locked", 429, ct, result.RetryAfterSeconds);
            else if (!result.Succeeded) await AuthResponse.ErrorAsync(context, "invalid_credentials", 401, ct);
            else
            {
                context.Response.Headers.SetCookie = Cookie(result.SessionToken!, command.Remember ? 1209600 : 43200, transport.IsSecureTransport(context) || policy.SecureCookie);
                await DomainHttp.WriteAsync(context, new { authenticated = true, principal = PublicPrincipal(result.Principal!) }, 200, ct);
            }
        }
        catch (AuthInputException error) { await AuthResponse.ErrorAsync(context, error.Code, error.StatusCode, ct); }
    }

    public static Dictionary<string, object> PublicPrincipal(Principal principal)
    {
        var fields = new Dictionary<string, object> { ["type"] = principal.Type, ["id"] = principal.Id, ["role"] = principal.Role };
        if (principal.Username is not null) fields["username"] = principal.Username;
        if (principal.Label is not null) fields["label"] = principal.Label;
        return fields;
    }

    public static string Cookie(string token, int maxAge, bool secure) =>
        $"adlog_session={token}; Path=/; Max-Age={maxAge}; HttpOnly; SameSite=Strict{(secure ? "; Secure" : "")}";
}
