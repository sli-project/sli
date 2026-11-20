using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Access;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Auth.Administration;

public static class UserAdministrationEndpoints
{
    public static IServiceCollection AddUserAdministration(this IServiceCollection services)
    {
        services.AddScoped<IUserAdministration, UserAdministrationService>();
        services.TryAddScoped<IAccessFactsRepository, AccessFactsRepository>();
        services.TryAddSingleton<ICapabilityComposer, CapabilityComposer>();
        return services;
    }

    public static IEndpointRouteBuilder MapUserAdministrationEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/auth/users", context => HandleAsync(context, false));
        endpoints.MapPost("/api/auth/users", context => HandleAsync(context, true));
        endpoints.MapPost("/api/auth/users/{**tail}", context => HandleAsync(context, true));
        return endpoints;
    }

    private static async Task HandleAsync(HttpContext context, bool mutation)
    {
        var ct = context.RequestAborted;
        try
        {
            var services = context.RequestServices;
            var transport = services.GetRequiredService<TransportGate>();
            var failure = transport.CheckTransport(context);
            if (failure is not null) { await AuthResponse.ErrorAsync(context, failure.Code, failure.StatusCode, ct); return; }
            var policy = services.GetRequiredService<AuthRequestPolicy>();
            var identity = policy.Resolve(context);
            if (mutation && !policy.OriginAllowed(context, identity))
            { await AuthResponse.ErrorAsync(context, "cross_origin_request_rejected", 403, ct); return; }
            if (mutation && !policy.AuthRequired)
            {
                string expected = UserAdministrationService.Strip(services.GetRequiredService<IConfiguration>()["Sli:OperatorToken"]
                    ?? Environment.GetEnvironmentVariable("ADLOG_OPERATOR_TOKEN") ?? "");
                if (expected.Length > 0 && !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(expected)),
                    SHA256.HashData(Encoding.UTF8.GetBytes(context.Request.Headers["X-ADLog-Operator-Token"].ToString()))))
                { await AuthResponse.ErrorAsync(context, "operator_token_required", 401, ct); return; }
            }
            var authenticated = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
            if (!authenticated.Succeeded)
            { await AuthResponse.ErrorAsync(context, authenticated.Failure?.Code ?? "authentication_required", authenticated.Failure?.StatusCode ?? 401, ct); return; }
            var principal = authenticated.Principal!;
            if (principal.Role != "admin") { await AuthResponse.ErrorAsync(context, "insufficient_permissions", 403, ct); return; }
            var facts = await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, ct);
            var access = services.GetRequiredService<ICapabilityComposer>().Compose(facts).Decide("access.manage");
            if (!access.Allowed)
            { await DomainHttp.WriteAsync(context, new { error = access.Reason, required_capability = "access.manage" }, 403, ct); return; }
            string raw = context.Features.Get<IHttpRequestFeature>()?.RawTarget is { Length: > 0 } target ? target : context.Request.Path.Value ?? "";
            string path = raw.Split('?', 2)[0];
            // Preserve source case-sensitive route dispatch after the shared gates.
            if (path != "/api/auth/users" && (!mutation || !path.StartsWith("/api/auth/users/", StringComparison.Ordinal)))
            { await AuthResponse.ErrorAsync(context, "not_found", 404, ct); return; }
            var users = services.GetRequiredService<IUserAdministration>();
            if (!mutation)
            {
                await DomainHttp.WriteAsync(context, new { items = await users.ListAsync(ct), roles = new[] {
                    new { id = "viewer", label = "ИБ", description = "Расследования, события и отчёты ИБ" },
                    new { id = "operator", label = "ИТ", description = "Отчёты ИБ и эксплуатационные отчёты" },
                    new { id = "admin", label = "Администратор", description = "Полный доступ и управление пользователями" }
                } }, 200, ct);
                return;
            }
            bool create = path == "/api/auth/users";
            bool reset = !create && path.EndsWith("/password", StringComparison.Ordinal);
            BigInteger id = 0;
            if (!create)
            {
                string[] parts = path.Split('/');
                if (!TryId(parts[reset ? parts.Length - 2 : parts.Length - 1], out id))
                { await AuthResponse.ErrorAsync(context, "invalid_user_id", 400, ct); return; }
            }
            using var body = await AuthJsonBody.ReadAsync(context, ct);
            var payload = body.RootElement;
            var actor = new UserAdministrationActor(principal.Type, principal.Id, identity.Address);
            object item;
            if (create)
            {
                string role = AuthJsonBody.CredentialString(payload, "role");
                item = await users.CreateAsync(new(AuthJsonBody.CredentialString(payload, "username"),
                    AuthJsonBody.CredentialString(payload, "password"), role.Length == 0 ? "viewer" : role), actor, ct);
            }
            else if (reset) item = await users.ResetPasswordAsync(id, AuthJsonBody.CredentialString(payload, "password"), actor, ct);
            else
            {
                bool? active = null;
                if (payload.TryGetProperty("is_active", out var flag) && flag.ValueKind != System.Text.Json.JsonValueKind.Null)
                {
                    if (flag.ValueKind is not (System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False))
                    { await AuthResponse.ErrorAsync(context, "is_active_must_be_boolean", 400, ct); return; }
                    active = flag.GetBoolean();
                }
                string? role = payload.TryGetProperty("role", out var roleValue) && roleValue.ValueKind != System.Text.Json.JsonValueKind.Null
                    ? AuthJsonBody.CredentialString(payload, "role") : null;
                item = await users.UpdateAsync(new(id, role, active), actor, ct);
            }
            await DomainHttp.WriteAsync(context, new { item }, create ? 201 : 200, ct);
        }
        catch (UserAdministrationException error) { await AuthResponse.ErrorAsync(context, error.Message, 400, ct, login: false); }
        catch (AuthInputException error) { await AuthResponse.ErrorAsync(context, error.Code, error.StatusCode, ct, login: false); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception error) { if (context.Response.HasStarted) throw; await AuthResponse.UnexpectedAsync(context, error, ct, login: false); }
    }

    private static bool TryId(string value, out BigInteger id)
    {
        // Python int accepts signed decimal Unicode digits and interior underscores.
        var text = new StringBuilder();
        bool previousDigit = false;
        int digits = 0;
        foreach (var rune in value.Trim().EnumerateRunes())
        {
            if (text.Length == 0 && rune.Value is '+' or '-') { text.Append((char)rune.Value); continue; }
            if (rune.Value == '_' && previousDigit) { previousDigit = false; continue; }
            if (Rune.GetUnicodeCategory(rune) != UnicodeCategory.DecimalDigitNumber) { id = 0; return false; }
            text.Append((char)('0' + (int)Rune.GetNumericValue(rune))); previousDigit = true; digits++;
        }
        id = 0;
        return previousDigit && digits <= 4300 && BigInteger.TryParse(text.ToString(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out id);
    }
}
