using Sli.Server.Access;
using Sli.Server.Auth;

namespace Sli.Server.Domains;

public static class HomeSummaryEndpoints
{
    public static IEndpointRouteBuilder MapHomeSummary(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v1/home/summary", HandleAsync);
        return endpoints;
    }

    public static async Task HandleAsync(HttpContext context)
    {
        var ct = context.RequestAborted;
        try
        {
            var services = context.RequestServices;
            var failure = services.GetRequiredService<TransportGate>().CheckTransport(context);
            if (failure is not null) { await DomainHttp.WriteFailureAsync(context, failure, ct); return; }
            var authentication = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
            if (!authentication.Succeeded)
            {
                await DomainHttp.WriteFailureAsync(context, authentication.Failure ?? new(401, "authentication_required"), ct);
                return;
            }
            var principal = authentication.Principal!;
            failure = TransportGate.CheckViewerRole(principal);
            if (failure is not null) { await DomainHttp.WriteFailureAsync(context, failure, ct); return; }
            var access = await services.GetRequiredService<IDomainAccessService>().EvaluateAsync(principal, ct);
            if (!access.CapabilityAllowed)
            {
                await DomainHttp.WriteAsync(context, new { error = "workspace_view_required" }, 403, ct);
                return;
            }
            var query = HomeSummaryQuery.Parse(context.Request.Query, DateTimeOffset.UtcNow) with { Language = context.Request.Headers.AcceptLanguage.ToString() };
            var payload = await services.GetRequiredService<HomeSummaryService>().BuildAsync(principal, query, ct);
            await DomainHttp.WriteAsync(context, payload, 200, ct);
        }
        catch (HomeQueryException error)
        { await DomainHttp.WriteAsync(context, new { error = error.Status == 400 ? "home_parameters_invalid" : error.Message }, error.Status, ct); }
        catch (DomainScopeCompositionException)
        { await DomainHttp.WriteAsync(context, new { error = "home_parameters_invalid" }, 400, ct); }
        catch (Exception error) when (error is TimeoutException or Npgsql.PostgresException { SqlState: "57014" }
            or Npgsql.NpgsqlException { InnerException: TimeoutException })
        { await DomainHttp.WriteAsync(context, new { error = "report_read_timeout", state = "unavailable" }, 503, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception error)
        {
            if (context.Response.HasStarted) throw;
            await DomainHttp.WriteUnexpectedAsync(context, context.RequestServices.GetRequiredService<ILoggerFactory>()
                .CreateLogger("HomeSummary"), error, ct, "/api/v1/home/summary");
        }
    }
}
