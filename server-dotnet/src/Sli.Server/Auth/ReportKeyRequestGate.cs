using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Domains;
using Sli.Server.Auth.ReportKeys;

namespace Sli.Server.Auth;

public interface IReportKeyRequestGate
{
    ValueTask<AuthenticationFailure?> CheckAsync(HttpContext context, CancellationToken ct);
}

public sealed class ReportKeyRequestGate(TransportGate transport, Func<PrincipalAuthenticator> authenticator,
    Func<IExactEventAuthorization> exactEvents) : IReportKeyRequestGate
{
    public async ValueTask<AuthenticationFailure?> CheckAsync(HttpContext context, CancellationToken ct)
    {
        var failure = transport.CheckTransport(context);
        if (failure is not null) return failure;
        if (!PrincipalAuthenticator.HasCandidateKey(context.Request)) return null;
        // Public login/static routes need the candidate-key restriction, without
        // resolving or touching an ordinary session just to inspect key authority.
        var candidate = await authenticator().CandidateKeyAsync(context, ct);
        string path = context.Request.Path.Value ?? "";
        failure = PrincipalAuthenticator.CheckReportKeyRoute(candidate, context.Request.Method, path);
        if (failure is not null) return failure;
        if (candidate?.RestrictedReportKey == true && path.StartsWith("/api/v1/events/", StringComparison.Ordinal))
            return await exactEvents().CheckAsync(candidate, path, ct);
        return null;
    }
}

public static class ReportKeyRequestGateExtensions
{
    public static IServiceCollection AddReportKeyRequestGate(this IServiceCollection services)
    {
        services.TryAddScoped<PrincipalAuthenticator>();
        services.TryAddScoped<IExactEventAuthorization, ExactEventAuthorization>();
        services.TryAddScoped<IReportKeyRequestGate>(provider => new ReportKeyRequestGate(
            provider.GetRequiredService<TransportGate>(), () => provider.GetRequiredService<PrincipalAuthenticator>(),
            () => provider.GetRequiredService<IExactEventAuthorization>()));
        return services;
    }

    public static IApplicationBuilder UseReportKeyRequestGate(this IApplicationBuilder app) => app.Use(async (context, next) =>
    {
        var failure = await context.RequestServices.GetRequiredService<IReportKeyRequestGate>().CheckAsync(context, context.RequestAborted);
        if (failure is not null)
        {
            await DomainHttp.WriteFailureAsync(context, failure, context.RequestAborted);
            return;
        }
        await next(context);
    });
}
