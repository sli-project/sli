using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Investigations;

public static class InvestigationLinksEndpoints
{
    public static IServiceCollection AddInvestigationLinks(this IServiceCollection services)
    {
        services.AddInvestigationNotes(); services.AddInvestigationEvents();
        services.TryAddScoped<IInvestigationLinksRepository, InvestigationLinksRepository>();
        services.TryAddScoped<IInvestigationVpnSessionEvidence, InvestigationVpnSessionEvidence>();
        return services;
    }
    public static IEndpointRouteBuilder MapInvestigationLinks(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/api/v1/investigations/from-finding", InvestigationEndpoints.HandleDisabledAsync);
        endpoints.MapPost("/api/v1/investigations/{id}/findings", InvestigationEndpoints.HandleDisabledAsync);
        endpoints.MapPost("/api/v1/investigations/{id}/evidence-refs", InvestigationEndpoints.HandleDisabledAsync);
        return endpoints;
    }
    public static async Task HandleAsync(HttpContext context)
    {
        var ct = context.RequestAborted;
        try
        {
            var session = await InvestigationRequest.Authorize(context, true, ct);
            if (session is null) return;
            var (principal, access) = session.Value;
            string? report = await InvestigationRequest.Module(context, access, true, ct);
            if (report is null) return;
            string path = context.Request.Path.Value ?? "";
            bool create = path.EndsWith("/from-finding", StringComparison.Ordinal), evidence = path.EndsWith("/evidence-refs", StringComparison.Ordinal);
            using var body = await AuthJsonBody.ReadAsync(context, ct);
            var repo = context.RequestServices.GetRequiredService<IInvestigationLinksRepository>();
            var groups = new List<IReadOnlyList<AccessResource>>();
            InvestigationIdentity? identity = null;
            // Finding handlers read the finding ID before resolving the target case.
            BigInteger finding = evidence ? 0 : InvestigationEvidenceInput.Integer(body.RootElement, "finding_id", "invalid_finding_id", true);
            InvestigationEvidenceInput? input = evidence ? InvestigationEvidenceInput.Parse(body.RootElement) : null;
            if (!create)
            {
                string id = path.Split('/', StringSplitOptions.RemoveEmptyEntries)[3];
                identity = InvestigationIdentity.Parse(id);
                groups.AddRange(await context.RequestServices.GetRequiredService<IInvestigationRepository>().ResourceGroupsAsync(identity, ct));
            }
            if (input is not null)
                groups.Add(input.Domain >= long.MinValue && input.Domain <= long.MaxValue ? [new("domain", (long)input.Domain)] : []);
            else
                foreach (long ev in await repo.FindingEventsAsync(finding, ct))
                    groups.Add(await context.RequestServices.GetRequiredService<IInvestigationEventRepository>().EventResourcesAsync(ev, ct));
            if (!InvestigationAccess.Allowed(access, report, groups)) throw InvestigationRequest.Hidden();
            string actor = InvestigationAccess.Actor(principal);
            if (input is not null)
            {
                if (!await context.RequestServices.GetRequiredService<IInvestigationVpnSessionEvidence>().AvailableAsync(access, input.Domain, input.Reference, ct)) throw InvestigationRequest.Hidden();
                input.Validate();
                var result = await repo.AddEvidenceAsync(identity!, input, actor, CancellationToken.None);
                await DomainHttp.WriteAsync(context, new { status = "ok", evidence_ref = result }, 201, ct);
            }
            else
            {
                var result = await repo.LinkFindingAsync(identity, finding, actor, CancellationToken.None);
                var rendered = InvestigationCaseRenderer.Render(new(result, false), access, context.RequestServices.GetRequiredService<IInvestigationVpnEvidence>());
                string locale = DomainHttp.SelectEnglish(context.Request.Headers.AcceptLanguage.ToString()) ? "en" : "ru";
                using var stream = typeof(InvestigationLinksEndpoints).Assembly.GetManifestResourceStream("Sli.Server.Access.Administration.server." + locale + ".json")!;
                var catalog = JsonSerializer.Deserialize<Dictionary<string, string>>(stream)!;
                string code = "investigations.caseStatus." + rendered["status"];
                if (catalog.TryGetValue(code, out var label)) rendered["status_message"] = new JsonObject { ["code"] = code, ["params"] = new JsonObject(), ["text"] = label };
                await DomainHttp.WriteAsync(context, rendered, 201, ct);
            }
        }
        catch (InvestigationException e) { await InvestigationRequest.Error(context, e, ct); }
        catch (AuthInputException e) { await AuthResponse.ErrorAsync(context, e.Code, e.StatusCode, ct, login: false); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception e) { if (context.Response.HasStarted) throw; await AuthResponse.UnexpectedAsync(context, e, ct, login: false); }
    }
}

internal static class InvestigationRequest
{
    internal static InvestigationException Hidden() => new("not_found", "Investigation resource was not found", 404);
    internal static Task Error(HttpContext c, InvestigationException e, CancellationToken ct)
    {
        var body = new JsonObject { ["error"] = e.Code };
        if (e.Message != e.Code) body["message"] = e.Message;
        if (e.InvestigationId is { } id) body["investigation_id"] = id;
        return DomainHttp.WriteAsync(c, body, e.Status, ct);
    }
    internal static async Task<(Principal Principal, AccessDecision Access)?> Authorize(HttpContext c, bool mutation, CancellationToken ct)
    {
        var s = c.RequestServices;
        if (s.GetRequiredService<TransportGate>().CheckTransport(c) is { } transport)
        { await DomainHttp.WriteFailureAsync(c, transport, ct); return null; }
        var policy = s.GetRequiredService<AuthRequestPolicy>();
        if (mutation && !policy.OriginAllowed(c, policy.Resolve(c)))
        { await AuthResponse.ErrorAsync(c, "cross_origin_request_rejected", 403, ct, login: false); return null; }
        Principal principal;
        if (policy.AuthRequired)
        {
            var result = await s.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(c, ct);
            if (!result.Succeeded) { await DomainHttp.WriteFailureAsync(c, result.Failure ?? new(401, "authentication_required"), ct); return null; }
            principal = result.Principal!;
            if (TransportGate.CheckViewerRole(principal) is { } role) { await DomainHttp.WriteFailureAsync(c, role, ct); return null; }
        }
        else
        {
            if (mutation)
            {
                string token = AssignmentValidation.Strip(s.GetRequiredService<IConfiguration>()["Sli:OperatorToken"] ?? Environment.GetEnvironmentVariable("ADLOG_OPERATOR_TOKEN") ?? "");
                if (token.Length > 0 && !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(token)), SHA256.HashData(Encoding.UTF8.GetBytes(c.Request.Headers["X-ADLog-Operator-Token"].ToString()))))
                { await AuthResponse.ErrorAsync(c, "operator_token_required", 401, ct, login: false); return null; }
            }
            principal = new("", 0, "operator");
        }
        var facts = await s.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, ct);
        return (principal, new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts)));
    }
    internal static async Task<string?> Module(HttpContext c, AccessDecision access, bool mutation, CancellationToken ct, string? capability = null)
    {
        string action = mutation ? "start_case" : "view", cap = capability ?? (mutation ? "investigations.manage" : "investigations.view");
        string? report = mutation ? InvestigationAccess.ReportKey(access) : InvestigationList.ReportKey(access);
        if (report is null) { await DomainHttp.WriteAsync(c, new { error = "report_not_assigned", required_report = "investigations.workspace", required_action = action }, 403, ct); return null; }
        if (!access.Capabilities.Capabilities.Contains(cap) && !access.Capabilities.ResourceCapabilities.Contains(cap))
        { await DomainHttp.WriteAsync(c, new { error = "insufficient_capability", required_capability = cap }, 403, ct); return null; }
        return report;
    }
}
