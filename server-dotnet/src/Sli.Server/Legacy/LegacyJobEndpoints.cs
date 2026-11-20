using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Legacy;

public static class LegacyJobEndpoints
{
    public static IServiceCollection AddLegacyJobs(this IServiceCollection services, bool hosted = true)
    {
        Sli.Server.Operations.OperationsEndpoints.AddOperations(services);
        services.TryAddScoped<IAccessFactsRepository, AccessFactsRepository>();
        services.TryAddSingleton<LegacySettings>();
        services.TryAddSingleton<LegacyJobStore>();
        services.TryAddSingleton<LegacyWorkQueue>();
        services.TryAddScoped<ILegacyJobs, LegacyJobs>();
        services.TryAddScoped<LegacyJobs>();
        services.TryAddScoped<ILegacyEnvironment, LegacyEnvironment>();
        services.TryAddSingleton<ILegacyAudit, LegacyAudit>();
        services.TryAddScoped<ILegacyAnalysis, LegacyAnalysis>();
        services.TryAddScoped<LegacyFindings>(sp => new LegacyFindings(new LegacyAdmittedDatabase(sp.GetRequiredService<Sli.Server.Infrastructure.IPostgresConnectionFactory>())));
        services.TryAddScoped<ILegacyFindings>(sp => sp.GetRequiredService<LegacyFindings>());
        services.TryAddScoped<LegacyPartialTimeoutWatermark>(sp => new(new LegacyAdmittedDatabase(sp.GetRequiredService<Sli.Server.Infrastructure.IPostgresConnectionFactory>())));
        services.TryAddScoped<ILegacyStorageSnapshot, LegacyStorageSnapshot>();
        services.TryAddScoped<LegacyPostCollection>();
        services.TryAddScoped<LegacyHeartbeat>();
        services.TryAddScoped<ILegacyHeartbeat>(sp => sp.GetRequiredService<LegacyHeartbeat>());
        services.TryAddScoped<ILegacyCollectionState>(sp => new LegacyCollectionState(new Sli.Server.Semantic.SemanticDatabase(
            sp.GetRequiredService<Sli.Server.Infrastructure.IPostgresConnectionFactory>())));
        services.TryAddScoped<ILegacyWindowsContext, LegacyWindowsContext>();
        services.TryAddScoped<LegacyCollectionPreflight>();
        services.TryAddScoped<LegacyCollectionWorker>();
        services.TryAddScoped<CollectionRuntimePipeline>();
        services.TryAddScoped<Sli.Server.Agents.Radius.NpsPipelineRuntime>();
        services.TryAddScoped<ILegacyPostStore, LegacyPostStore>();
        services.TryAddScoped<ILegacyAcquisition, LegacyAcquisition>();
        services.TryAddScoped<LegacyAdaptiveCollection>(sp => new(new Sli.Server.Semantic.SemanticDatabase(
            sp.GetRequiredService<Sli.Server.Infrastructure.IPostgresConnectionFactory>()), sp.GetRequiredService<LegacySettings>(),
            sp.GetRequiredService<TimeProvider>()));
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddScoped(sp => new NpsWorkerRuntime(
            new Sli.Server.Semantic.SemanticDatabase(sp.GetRequiredService<Sli.Server.Infrastructure.IPostgresConnectionFactory>()),
            sp.GetRequiredService<LegacySettings>(), sp.GetRequiredService<ILegacyAcquisition>(),
            new Sli.Server.Operations.OperationsFiles(sp.GetRequiredService<IConfiguration>()), sp.GetRequiredService<LegacyHeartbeat>()));
        services.TryAddScoped<LegacyJobExecution>();
        services.TryAddScoped<ILegacyJobExecution>(sp => sp.GetRequiredService<LegacyJobExecution>());
        return services;
    }

    public static IEndpointRouteBuilder MapLegacyJobs(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/api/jobs/collect", context => HandleAsync(context, true));
        endpoints.MapPost("/api/jobs/analyze", context => HandleAsync(context, false));
        return endpoints;
    }

    public static async Task HandleAsync(HttpContext context, bool collect)
    {
        var ct = context.RequestAborted;
        try {
            var services = context.RequestServices;
            var transport = services.GetRequiredService<TransportGate>().CheckTransport(context);
            if (transport is not null) { await DomainHttp.WriteFailureAsync(context, transport, ct); return; }
            var policy = services.GetRequiredService<AuthRequestPolicy>();
            if (!policy.OriginAllowed(context, policy.Resolve(context))) {
                await Error("cross_origin_request_rejected", 403); return;
            }
            Principal principal;
            if (policy.AuthRequired) {
                var auth = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
                if (!auth.Succeeded) { await DomainHttp.WriteFailureAsync(context, auth.Failure ?? new(401, "authentication_required"), ct); return; }
                principal = auth.Principal!;
                if (principal.RestrictedReportKey) { await Error("report_key_route_denied", 403); return; }
                if (principal.Role is not ("operator" or "admin")) { await Error("insufficient_permissions", 403); return; }
            } else {
                string expected = (services.GetRequiredService<IConfiguration>()["Sli:OperatorToken"]
                    ?? Environment.GetEnvironmentVariable("ADLOG_OPERATOR_TOKEN") ?? "").Trim();
                string supplied = context.Request.Headers["X-ADLog-Operator-Token"].ToString();
                if (expected.Length != 0 && !CryptographicOperations.FixedTimeEquals(
                    SHA256.HashData(Encoding.UTF8.GetBytes(expected)), SHA256.HashData(Encoding.UTF8.GetBytes(supplied)))) {
                    await Error("operator_token_required", 401); return;
                }
                principal = new("", 0, "operator");
            }
            var facts = await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, ct);
            var access = new CapabilityComposer().Compose(facts).Decide("operations.view");
            if (!access.Allowed) {
                await DomainHttp.WriteAsync(context, new { error = access.Reason, required_capability = "operations.view" }, 403, ct); return;
            }
            using var body = await AuthJsonBody.ReadAsync(context, ct);
            var input = LegacyJobInput.Parse(body.RootElement, collect);
            await DomainHttp.WriteAsync(context, new { error = "module_disabled", state = "disabled" }, 503, ct);
        }
        catch (AuthInputException error) { await Error(error.Code, error.StatusCode); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception error) {
            if (context.Response.HasStarted) throw;
            await AuthResponse.UnexpectedAsync(context, error, ct, login: false);
        }
        async Task Error(string code, int status) => await DomainHttp.WriteAsync(context, new { error = code }, status, ct);
    }
}
