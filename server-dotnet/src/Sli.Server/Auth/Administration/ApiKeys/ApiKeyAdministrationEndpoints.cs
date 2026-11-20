using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Access;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Auth.Administration.ApiKeys;

public static class ApiKeyAdministrationEndpoints
{
    private const string Route = "/api/auth/api-keys";

    public static IServiceCollection AddApiKeyAdministration(this IServiceCollection services)
    {
        services.AddScoped<IApiKeyAdministration, ApiKeyAdministrationService>();
        services.TryAddScoped<IAccessFactsRepository, AccessFactsRepository>();
        services.TryAddSingleton<ICapabilityComposer, CapabilityComposer>();
        return services;
    }

    public static IEndpointRouteBuilder MapApiKeyAdministrationEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(Route, context => HandleAsync(context, false));
        endpoints.MapPost(Route, context => HandleAsync(context, true));
        endpoints.MapPost(Route + "/{**tail}", context => HandleAsync(context, true));
        return endpoints;
    }

    private static async Task HandleAsync(HttpContext context, bool mutation)
    {
        var ct = context.RequestAborted;
        try
        {
            var services = context.RequestServices;
            var failure = services.GetRequiredService<TransportGate>().CheckTransport(context);
            if (failure is not null) { await Error(context, failure.Code, failure.StatusCode); return; }
            var policy = services.GetRequiredService<AuthRequestPolicy>();
            var identity = policy.Resolve(context);
            if (mutation && !policy.OriginAllowed(context, identity)) { await Error(context, "cross_origin_request_rejected", 403); return; }
            if (mutation && !policy.AuthRequired)
            {
                string expected = UserAdministrationService.Strip(services.GetRequiredService<IConfiguration>()["Sli:OperatorToken"]
                    ?? Environment.GetEnvironmentVariable("ADLOG_OPERATOR_TOKEN") ?? "");
                if (expected.Length > 0 && !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(expected)),
                    SHA256.HashData(Encoding.UTF8.GetBytes(context.Request.Headers["X-ADLog-Operator-Token"].ToString()))))
                { await Error(context, "operator_token_required", 401); return; }
            }
            // Source explicitly requires admin even after auth-off mutation admission.
            var authenticated = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
            if (!authenticated.Succeeded)
            { await Error(context, authenticated.Failure?.Code ?? "authentication_required", authenticated.Failure?.StatusCode ?? 401); return; }
            var principal = authenticated.Principal!;
            if (principal.Role != "admin") { await Error(context, "insufficient_permissions", 403); return; }
            var facts = await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, ct);
            var decision = services.GetRequiredService<ICapabilityComposer>().Compose(facts).Decide("access.manage");
            if (!decision.Allowed)
            { await DomainHttp.WriteAsync(context, new { error = decision.Reason, required_capability = "access.manage" }, 403, ct); return; }
            string raw = context.Features.Get<IHttpRequestFeature>()?.RawTarget is { Length: > 0 } target ? target : context.Request.Path.Value ?? "";
            string path = raw.Split('?', 2)[0];
            bool create = path == Route;
            bool revoke = mutation && path.StartsWith(Route + "/", StringComparison.Ordinal) && path.EndsWith("/revoke", StringComparison.Ordinal);
            if (!create && !revoke) { await Error(context, "not_found", 404); return; }
            var keys = services.GetRequiredService<IApiKeyAdministration>();
            if (!mutation) { await DomainHttp.WriteAsync(context, new { items = await keys.ListAsync(ct) }, 200, ct); return; }
            var actor = new UserAdministrationActor(principal.Type, principal.Id, identity.Address);
            if (revoke)
            {
                if (!TryId(path.Split('/')[^2], out var id)) { await Error(context, "invalid_api_key_id", 400); return; }
                if (!await keys.RevokeAsync(id, actor, ct)) { await Error(context, "api_key_not_found_or_already_revoked", 404); return; }
                await DomainHttp.WriteAsync(context, new { status = "revoked" }, 200, ct);
                return;
            }
            using var document = await AuthJsonBody.ReadAsync(context, ct);
            string role = AuthJsonBody.CredentialString(document.RootElement, "role");
            // Expiry exists in the service/DB contract, but source HTTP does not accept a public expiry setter.
            var issued = await keys.IssueAsync(new(AuthJsonBody.CredentialString(document.RootElement, "label"),
                role.Length == 0 ? "viewer" : role), actor, ct);
            await DomainHttp.WriteAsync(context, new { item = issued.Item, token = issued.Token }, 201, ct);
        }
        catch (ApiKeyAdministrationException error) { await Error(context, error.Message, 400); }
        catch (AuthInputException error) { await Error(context, error.Code, error.StatusCode); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception error) { if (context.Response.HasStarted) throw; await AuthResponse.UnexpectedAsync(context, error, ct, login: false); }
    }

    public static bool TryId(string value, out BigInteger id)
    {
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

    private static Task Error(HttpContext context, string error, int status) =>
        AuthResponse.ErrorAsync(context, error, status, context.RequestAborted, login: false);
}
