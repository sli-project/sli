using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Text.Json;
using Sli.Server.Auth.InitialOwner;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Auth.Recovery;
using Sli.Server.Domains;

namespace Sli.Server.Auth.Lifecycle;

public static class AuthEndpoints
{
    private const string LogoutApi = "/api/auth/logout";

    public static IServiceCollection AddAuthLifecycle(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.AddReportKeyRequestGate();
        services.AddSingleton<AuthRequestPolicy>();
        services.AddSingleton<ICredentialTokens, CredentialTokens>();
        services.AddSingleton<IPasswordCodec, PasswordCodec>();
        services.AddScoped<ISessionLifecycle, SessionLifecycle>();
        services.AddScoped<ILoginService, LoginService>();
        services.AddScoped<InitialAdminPassword>();
        return services;
    }

    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/api/auth/login", (HttpContext context) => HandleAsync(context, context.RequestAborted, Operation.Login));
        endpoints.MapGet("/api/auth/me", (HttpContext context) => HandleAsync(context, context.RequestAborted, Operation.Me));
        endpoints.MapPost(LogoutApi, (HttpContext context) => HandleAsync(context, context.RequestAborted, Operation.Logout));
        endpoints.MapPost(InitialAdminPassword.ChangeApi, (HttpContext context) => HandleAsync(context, context.RequestAborted, Operation.ChangePassword));
        return endpoints;
    }

    public static IApplicationBuilder UseInitialPasswordGate(this IApplicationBuilder app) => app.Use(async (context, next) =>
    {
        if (InitialAdminPassword.RequestToken(context) is null) { await next(context); return; }
        var request = context.Request;
        if (HttpMethods.IsGet(request.Method))
        {
            if (request.Path == "/login" || request.Path == InitialAdminPassword.ChangePage
                || request.Path == "/sli-login.css" || request.Path == "/sli-login.js"
                || request.Path.StartsWithSegments("/assets/sli-login"))
            { await next(context); return; }
            if (!request.Path.StartsWithSegments("/api"))
            {
                context.Response.Redirect(InitialAdminPassword.ChangePage + QueryString.Create("next", request.Path + request.QueryString));
                return;
            }
        }
        if (HttpMethods.IsPost(request.Method) && (request.Path == InitialAdminPassword.ChangeApi || request.Path == LogoutApi))
        {
            await next(context);
            return;
        }
        await AuthResponse.ErrorAsync(context, "password_change_required", 403, context.RequestAborted);
    });

    private enum Operation { Login, Me, Logout, ChangePassword }

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
        if (operation == Operation.ChangePassword)
        {
            await ChangePasswordAsync(context, transport, identity, ct);
            return;
        }
        if (logout)
        {
            await services.GetRequiredService<ISessionLifecycle>().RevokeAsync(
                PrincipalAuthenticator.SessionTokenFromCookie(context.Request.Headers.Cookie.ToString()), ct);
            context.Response.Headers.SetCookie = Cookie("", 0, transport.IsSecureTransport(context) || policy.SecureCookie);
            await DomainHttp.WriteAsync(context, new { status = "ok" }, 200, ct);
            return;
        }
        bool secure = transport.IsSecureTransport(context);
        if (!secure && !policy.AllowInsecureHttp)
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
                : await services.GetRequiredService<ILoginService>().LoginAsync(command, new(identity.Address, secure), ct);
            if (result.RetryAfterSeconds > 0) await AuthResponse.ErrorAsync(context, "login_temporarily_locked", 429, ct, result.RetryAfterSeconds);
            else if (result.PasswordChangeRequired && !secure)
                await AuthResponse.ErrorAsync(context, "secure_transport_required", 403, ct);
            else if (!result.Succeeded) await AuthResponse.ErrorAsync(context, "invalid_credentials", 401, ct);
            else
            {
                context.Response.Headers.SetCookie = Cookie(result.SessionToken!, command.Remember && !result.PasswordChangeRequired ? 1209600 : 43200, secure || policy.SecureCookie);
                if (result.PasswordChangeRequired)
                    await DomainHttp.WriteAsync(context, new { password_change_required = true }, 200, ct);
                else
                    await DomainHttp.WriteAsync(context, new { authenticated = true, principal = PublicPrincipal(result.Principal!) }, 200, ct);
            }
        }
        catch (AuthInputException error) { await AuthResponse.ErrorAsync(context, error.Code, error.StatusCode, ct); }
    }

    private static async Task ChangePasswordAsync(HttpContext context, TransportGate transport, AuthRequestIdentity identity, CancellationToken ct)
    {
        if (!transport.IsSecureTransport(context))
        {
            await AuthResponse.ErrorAsync(context, "secure_transport_required", 403, ct);
            return;
        }
        try
        {
            string? token = InitialAdminPassword.RequestToken(context);
            if (token is not null)
            {
                using var document = await AuthJsonBody.ReadAsync(context, ct);
                string? Field(string name) => document.RootElement.TryGetProperty(name, out var value)
                    && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
                var result = await context.RequestServices.GetRequiredService<InitialAdminPassword>()
                    .ChangeAsync(token, Field("password"), Field("repeat"), identity.Address, ct);
                if (result.Succeeded)
                {
                    context.Response.Headers.SetCookie = Cookie(result.SessionToken!, 43200, true);
                    await DomainHttp.WriteAsync(context, new { authenticated = true }, 200, ct);
                    return;
                }
                context.Response.Headers.SetCookie = Cookie("", 0, true);
            }
            await AuthResponse.ErrorAsync(context, "authentication_required", 401, ct);
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
