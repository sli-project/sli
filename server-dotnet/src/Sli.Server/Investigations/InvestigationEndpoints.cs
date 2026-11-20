using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Investigations;

public static class InvestigationEndpoints
{
    internal static async Task HandleDisabledAsync(HttpContext context)
    {
        var ct = context.RequestAborted;
        try
        {
            bool mutation = !HttpMethods.IsGet(context.Request.Method);
            var authorized = await InvestigationRequest.Authorize(context, mutation, ct);
            if (authorized is null) return;
            if (await InvestigationRequest.Module(context, authorized.Value.Access, mutation, ct) is null) return;
            await DomainHttp.WriteAsync(context, new { error = "module_disabled", state = "disabled" }, 503, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception error)
        { if (context.Response.HasStarted) throw; await AuthResponse.UnexpectedAsync(context, error, ct, login: false); }
    }

    public static IServiceCollection AddInvestigationNotes(this IServiceCollection services)
    {
        services.TryAddScoped<IAccessFactsRepository, AccessFactsRepository>();
        services.TryAddScoped<IInvestigationRepository, InvestigationRepository>();
        services.TryAddScoped<IInvestigationCaseMutationRepository, InvestigationCaseMutationRepository>();
        services.TryAddScoped<IInvestigationVpnEvidence, InvestigationVpnEvidence>();
        return services;
    }

    public static IEndpointRouteBuilder MapInvestigationNoteEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/api/v1/investigations/{**tail:regex((^|.*/)notes$)}", InvestigationEndpoints.HandleDisabledAsync);
        endpoints.MapPost("/api/v1/investigations/{**tail:regex((^|.*/)(status|owner)$)}", InvestigationEndpoints.HandleDisabledAsync);
        return endpoints;
    }

    public static Task HandleNoteAsync(HttpContext context) => HandleMutationAsync(context, "notes");
    public static Task HandleCaseMutationAsync(HttpContext context) => HandleMutationAsync(context, context.Request.Path.Value!.Split('/').Last());

    private static async Task HandleMutationAsync(HttpContext context, string operation)
    {
        var ct = context.RequestAborted;
        try
        {
            var services = context.RequestServices;
            var failure = services.GetRequiredService<TransportGate>().CheckTransport(context);
            if (failure is not null) { await AuthResponse.ErrorAsync(context, failure.Code, failure.StatusCode, ct, login: false); return; }
            var policy = services.GetRequiredService<AuthRequestPolicy>();
            var request = policy.Resolve(context);
            if (!policy.OriginAllowed(context, request)) { await AuthResponse.ErrorAsync(context, "cross_origin_request_rejected", 403, ct, login: false); return; }
            Principal principal;
            if (policy.AuthRequired)
            {
                var authentication = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
                if (!authentication.Succeeded)
                { await AuthResponse.ErrorAsync(context, authentication.Failure?.Code ?? "authentication_required", authentication.Failure?.StatusCode ?? 401, ct, login: false); return; }
                principal = authentication.Principal!;
                if (TransportGate.CheckViewerRole(principal) is not null)
                { await AuthResponse.ErrorAsync(context, "insufficient_permissions", 403, ct, login: false); return; }
            }
            else
            {
                string expected = AssignmentValidation.Strip(services.GetRequiredService<IConfiguration>()["Sli:OperatorToken"] ?? Environment.GetEnvironmentVariable("ADLOG_OPERATOR_TOKEN") ?? "");
                if (expected.Length > 0 && !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(expected)), SHA256.HashData(Encoding.UTF8.GetBytes(context.Request.Headers["X-ADLog-Operator-Token"].ToString()))))
                { await AuthResponse.ErrorAsync(context, "operator_token_required", 401, ct, login: false); return; }
                principal = new("", 0, "operator");
            }
            string raw = context.Features.Get<IHttpRequestFeature>()?.RawTarget is { Length: > 0 } target ? target.Split('?', 2)[0] : context.Request.Path.Value ?? "";
            string[] parts = raw.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length <= 3)
            { await AuthResponse.ErrorAsync(context, "invalid_investigation_id", 400, ct, login: false); return; }
            // Module authorization precedes identifier resolution and body IO.
            var facts = await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, ct);
            var caps = new CapabilityComposer().Compose(facts);
            var access = new ReportEligibility().Compose(facts, caps);
            string? report = InvestigationAccess.ReportKey(access);
            if (report is null)
            { await DomainHttp.WriteAsync(context, new { error = "report_not_assigned", required_report = "investigations.workspace", required_action = InvestigationAccess.Action }, 403, ct); return; }
            if (!caps.Capabilities.Contains(InvestigationAccess.Capability) && !caps.ResourceCapabilities.Contains(InvestigationAccess.Capability))
            { await DomainHttp.WriteAsync(context, new { error = "insufficient_capability", required_capability = InvestigationAccess.Capability }, 403, ct); return; }
            var identity = InvestigationIdentity.Parse(parts[3]);
            var repository = services.GetRequiredService<IInvestigationRepository>();
            var groups = await repository.ResourceGroupsAsync(identity, ct);
            if (!InvestigationAccess.Allowed(access, report, groups))
                throw new InvestigationException("not_found", "Investigation resource was not found", 404);
            using var body = await AuthJsonBody.ReadAsync(context, ct);
            if (operation == "notes")
            {
                string clean = InvestigationAccess.CleanBody(body.RootElement);
                var note = await repository.AddNoteAsync(identity, clean, InvestigationAccess.Actor(principal), CancellationToken.None);
                await DomainHttp.WriteAsync(context, new { status = "ok", note }, 201, ct);
            }
            else
            {
                var input = InvestigationCaseMutationInput.Parse(operation, body.RootElement);
                var mutation = services.GetRequiredService<IInvestigationCaseMutationRepository>();
                var result = await mutation.ApplyAsync(identity, input, InvestigationAccess.Actor(principal), CancellationToken.None);
                var rendered = InvestigationCaseRenderer.Render(result, access, services.GetRequiredService<IInvestigationVpnEvidence>());
                await DomainHttp.WriteAsync(context, rendered, 200, ct);
            }
        }
        catch (InvestigationException error)
        { await DomainHttp.WriteAsync(context, new { error = error.Code, message = error.Message }, error.Status, ct); }
        catch (AuthInputException error)
        { await AuthResponse.ErrorAsync(context, error.Code, error.StatusCode, ct, login: false); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception error)
        { if (context.Response.HasStarted) throw; await AuthResponse.UnexpectedAsync(context, error, ct, login: false); }
    }
}
