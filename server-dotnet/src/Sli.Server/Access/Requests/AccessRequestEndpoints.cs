using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
using Sli.Server.Infrastructure;

namespace Sli.Server.Access.Requests;

public static class AccessRequestEndpoints
{
    public static IServiceCollection AddAccessRequests(this IServiceCollection services)
    {
        services.TryAddScoped<AccessReadService>();
        services.TryAddScoped<IReportAssignmentWriter, ReportAssignmentWriter>();
        services.TryAddScoped<IAccessRequestEvaluator, AccessRequestEvaluator>();
        services.TryAddSingleton<IAccessRequestAudit, AccessRequestAudit>();
        services.AddScoped<IAccessRequestService, AccessRequestService>();
        return services;
    }

    public static IEndpointRouteBuilder MapAccessRequestEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v1/access/report-requests", context => HandleAsync(context, Operation.List));
        endpoints.MapPost("/api/v1/access/report-requests", context => HandleAsync(context, Operation.Create));
        endpoints.MapPost("/api/v1/access/report-requests/{**tail:regex((^|.*/)decision$)}", context => HandleAsync(context, Operation.Decide));
        endpoints.MapPost("/api/v1/reports/{**tail:regex((^|.*/)preference$)}", context => HandleAsync(context, Operation.Preference));
        return endpoints;
    }

    private enum Operation { List, Create, Decide, Preference }

    private static async Task HandleAsync(HttpContext context, Operation operation)
    {
        var ct = context.RequestAborted;
        try
        {
            var services = context.RequestServices;
            var transport = services.GetRequiredService<TransportGate>();
            var transportFailure = transport.CheckTransport(context);
            if (transportFailure is not null) { await AuthResponse.ErrorAsync(context, transportFailure.Code, transportFailure.StatusCode, ct, login: false); return; }
            var policy = services.GetRequiredService<AuthRequestPolicy>();
            var identity = policy.Resolve(context);
            bool mutation = operation != Operation.List;
            if (mutation && !policy.OriginAllowed(context, identity)) { await AuthResponse.ErrorAsync(context, "cross_origin_request_rejected", 403, ct, login: false); return; }
            Principal principal;
            if (policy.AuthRequired)
            {
                var authentication = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
                if (!authentication.Succeeded)
                { await AuthResponse.ErrorAsync(context, authentication.Failure?.Code ?? "authentication_required", authentication.Failure?.StatusCode ?? 401, ct, login: false); return; }
                principal = authentication.Principal!;
                if (operation == Operation.Decide ? principal.Role != "admin" : TransportGate.CheckViewerRole(principal) is not null)
                { await AuthResponse.ErrorAsync(context, "insufficient_permissions", 403, ct, login: false); return; }
            }
            else
            {
                if (mutation)
                {
                    string expected = RequestJson.Strip(services.GetRequiredService<IConfiguration>()["Sli:OperatorToken"] ?? Environment.GetEnvironmentVariable("ADLOG_OPERATOR_TOKEN") ?? "");
                    if (expected.Length > 0 && !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(expected)), SHA256.HashData(Encoding.UTF8.GetBytes(context.Request.Headers["X-ADLog-Operator-Token"].ToString()))))
                    { await AuthResponse.ErrorAsync(context, "operator_token_required", 401, ct, login: false); return; }
                }
                principal = new("local", 0, "operator", Username: "local-operator");
            }
            string capability = operation == Operation.Decide ? "access.manage" : "reports.catalog";
            var facts = await new AccessFactsRepository(services.GetRequiredService<IPostgresConnectionFactory>()).LoadAsync(principal, ct);
            var access = new CapabilityComposer().Compose(facts).Decide(capability);
            if (!access.Allowed) { await DomainHttp.WriteAsync(context, new { error = access.Reason, required_capability = capability }, 403, ct); return; }
            string raw = context.Features.Get<IHttpRequestFeature>()?.RawTarget is { Length: > 0 } target ? target.Split('?', 2)[0] : context.Request.Path.Value ?? "";
            if (!Classified(raw, operation)) { await AuthResponse.ErrorAsync(context, "not_found", 404, ct, login: false); return; }
            var service = services.GetRequiredService<IAccessRequestService>();
            if (operation == Operation.List)
            {
                string limit = Values(context, "limit").FirstOrDefault() ?? "100";
                var result = await service.ListAsync(principal, Values(context, "scope").FirstOrDefault() == "all",
                    AssignmentValidation.Integer(System.Text.Json.JsonSerializer.SerializeToElement(limit)), ct);
                await DomainHttp.WriteAsync(context, RequestJson.Present(result, context.Request.Headers.AcceptLanguage.ToString()), 200, ct);
                return;
            }
            System.Numerics.BigInteger requestId = 0;
            string reportKey = "";
            if (operation == Operation.Decide)
            {
                string id = raw["/api/v1/access/report-requests/".Length..];
                if (id.EndsWith("/decision", StringComparison.Ordinal)) id = id[..^"/decision".Length];
                requestId = AssignmentValidation.Integer(System.Text.Json.JsonSerializer.SerializeToElement(id.Trim('/')));
            }
            else if (operation == Operation.Preference)
            {
                string key = raw["/api/v1/reports/".Length..];
                if (key.EndsWith("/preference", StringComparison.Ordinal)) key = key[..^"/preference".Length];
                reportKey = Uri.UnescapeDataString(key.Trim('/'));
            }
            using var body = await AuthJsonBody.ReadAsync(context, ct);
            // Once an admitted body is complete, the source synchronous mutation
            // continues independently of a client disconnect. No background job.
            var durable = CancellationToken.None;
            var item = operation switch
            {
                Operation.Create => await service.CreateAsync(body.RootElement, principal, identity.Address, durable),
                Operation.Decide => await service.DecideAsync(requestId, body.RootElement, principal, identity.Address, durable),
                _ => await service.SetPreferenceAsync(reportKey, body.RootElement, principal, identity.Address, durable)
            };
            await DomainHttp.WriteAsync(context, new { item }, operation == Operation.Create ? 201 : 200, ct);
        }
        catch (AccessRequestException error) { await AuthResponse.ErrorAsync(context, error.Message, error.Status, ct, login: false); }
        catch (RequestJson.IterableTypeException error) when (operation == Operation.Decide)
        { await AuthResponse.ErrorAsync(context, error.Message, 400, ct, login: false); }
        catch (AssignmentValidationException error) { await AuthResponse.ErrorAsync(context, error.Message, 400, ct, login: false); }
        catch (AuthInputException error) { await AuthResponse.ErrorAsync(context, error.Code, error.StatusCode, ct, login: false); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception error) { if (context.Response.HasStarted) throw; await AuthResponse.UnexpectedAsync(context, error, ct, login: false); }
    }

    private static bool Classified(string path, Operation operation) => operation switch
    {
        Operation.List or Operation.Create => path == "/api/v1/access/report-requests",
        Operation.Decide => path.StartsWith("/api/v1/access/report-requests/", StringComparison.Ordinal) && path.EndsWith("/decision", StringComparison.Ordinal),
        _ => path.StartsWith("/api/v1/reports/", StringComparison.Ordinal) && path.EndsWith("/preference", StringComparison.Ordinal)
    };
    private static string[] Values(HttpContext context, string key) => (context.Request.QueryString.Value is { Length: > 0 } query ? query[1..] : "")
        .Split('&').Select(part => part.Split('=', 2)).Where(pair => pair.Length == 2 && WebUtility.UrlDecode(pair[0]) == key)
        .Select(pair => WebUtility.UrlDecode(pair[1])).Where(value => value.Length > 0).ToArray();
}
