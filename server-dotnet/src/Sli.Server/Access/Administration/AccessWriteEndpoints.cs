using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http.Features;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Access.Administration;

public static class AccessWriteEndpoints
{
    public static IServiceCollection AddAccessWrites(this IServiceCollection services)
    {
        services.AddScoped<IReportAssignmentWriter, ReportAssignmentWriter>();
        services.AddScoped<AssignmentPackageWriter>();
        return services;
    }

    public static IEndpointRouteBuilder MapAccessWriteEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/api/v1/access/assignments", context => HandleAsync(context, false));
        endpoints.MapPost("/api/v1/access/package-assignments", context => HandleAsync(context, true));
        return endpoints;
    }

    private static async Task HandleAsync(HttpContext context, bool package)
    {
        var ct = context.RequestAborted;
        string route = package ? "/api/v1/access/package-assignments" : "/api/v1/access/assignments";
        try
        {
            var services = context.RequestServices;
            var transport = services.GetRequiredService<TransportGate>();
            var failure = transport.CheckTransport(context);
            if (failure is not null) { await AuthResponse.ErrorAsync(context, failure.Code, failure.StatusCode, ct); return; }
            var policy = services.GetRequiredService<AuthRequestPolicy>();
            var identity = policy.Resolve(context);
            if (!policy.OriginAllowed(context, identity)) { await AuthResponse.ErrorAsync(context, "cross_origin_request_rejected", 403, ct); return; }
            Principal principal;
            AssignmentActor? actor;
            if (policy.AuthRequired)
            {
                var authentication = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
                if (!authentication.Succeeded)
                { await AuthResponse.ErrorAsync(context, authentication.Failure?.Code ?? "authentication_required", authentication.Failure?.StatusCode ?? 401, ct); return; }
                principal = authentication.Principal!;
                if (principal.Role != "admin") { await DomainHttp.WriteAsync(context, new { error = "insufficient_permissions" }, 403, ct); return; }
                actor = new(principal.Type, principal.Id);
            }
            else
            {
                // Source _authorize_mutation skips role lookup when auth is off;
                // _require_capability then evaluates its existing local/operator default.
                string expected = AssignmentValidation.Strip(services.GetRequiredService<IConfiguration>()["Sli:OperatorToken"]
                    ?? Environment.GetEnvironmentVariable("ADLOG_OPERATOR_TOKEN") ?? "");
                if (expected.Length > 0 && !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(expected)),
                    SHA256.HashData(Encoding.UTF8.GetBytes(context.Request.Headers["X-ADLog-Operator-Token"].ToString()))))
                { await DomainHttp.WriteAsync(context, new { error = "operator_token_required" }, 401, ct); return; }
                principal = new("local", 0, "operator", Username: "local-operator"); actor = null;
            }
            var facts = await new AccessFactsRepository(services.GetRequiredService<Sli.Server.Infrastructure.IPostgresConnectionFactory>()).LoadAsync(principal, ct);
            string capability = package ? "access.manage" : "reports.assign";
            var decision = new CapabilityComposer().Compose(facts).Decide(capability);
            if (!decision.Allowed) { await DomainHttp.WriteAsync(context, new { error = decision.Reason, required_capability = capability }, 403, ct); return; }
            string raw = context.Features.Get<IHttpRequestFeature>()?.RawTarget is { Length: > 0 } target ? target.Split('?', 2)[0] : context.Request.Path.Value ?? "";
            if (raw != route) { await DomainHttp.WriteAsync(context, new { error = "not_found" }, 404, ct); return; }
            using var body = await AuthJsonBody.ReadAsync(context, ct);
            var item = package ? await services.GetRequiredService<AssignmentPackageWriter>().CreateAsync(body.RootElement, actor, identity.Address, ct)
                : (await services.GetRequiredService<IReportAssignmentWriter>().CreateAsync(new(body.RootElement), actor, identity.Address, ct)).Item;
            await DomainHttp.WriteAsync(context, new { item }, 201, ct);
        }
        catch (AssignmentValidationException error) { await DomainHttp.WriteAsync(context, new { error = error.Message }, 400, ct); }
        // These are ordinary access routes, so source does not add login-only
        // input/unavailable envelopes. Known auth/origin codes above still localize.
        catch (AuthInputException error) { await DomainHttp.WriteAsync(context, new { error = error.Code }, error.StatusCode, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception error)
        {
            if (context.Response.HasStarted) throw;
            await DomainHttp.WriteUnexpectedAsync(context, ServicesLogger(context), error, ct, route);
        }
    }

    private static ILogger ServicesLogger(HttpContext context) => context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Sli.Server.Access.Writes");
}
