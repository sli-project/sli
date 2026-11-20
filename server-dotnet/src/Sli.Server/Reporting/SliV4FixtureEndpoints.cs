using System.Net;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Reporting;

public static class SliV4FixtureEndpoints
{
    public static IEndpointRouteBuilder MapSliV4Fixture(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/api/test/sli-v4/session", HandleAsync);
        return endpoints;
    }

    private static async Task HandleAsync(HttpContext context)
    {
        var ct = context.RequestAborted;
        var config = context.RequestServices.GetRequiredService<IConfiguration>();
        string flag = (config["ADLOG_SLI_V4_FIXTURE"] ?? "0").Trim().ToLowerInvariant();
        var addresses = context.RequestServices.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses;
        // Check actual listener bindings, never Host/forwarded headers or the peer IP:
        // a loopback request to a wildcard listener must not expose this fixture.
        if (flag is not ("1" or "true" or "yes" or "on") || addresses is not { Count: > 0 } || !addresses.All(Loopback))
        {
            await DomainHttp.WriteAsync(context, new { error = "not_found" }, 404, ct);
            return;
        }
        try
        {
            using var body = await AuthJsonBody.ReadAsync(context, ct);
            var decision = SliV4Fixture.Evaluate(body.RootElement);
            context.Response.Headers.SetCookie = $"sli_v4_fixture_actor={decision["actor"]!.GetValue<string>()}; Path=/; SameSite=Strict";
            await DomainHttp.WriteAsync(context, new { status = "ok", decision }, 200, ct);
        }
        catch (ArgumentException error) when (error.Message == "invalid_sli_v4_fixture_actor")
        { await DomainHttp.WriteAsync(context, new { error = error.Message }, 400, ct); }
        catch (AuthInputException error)
        { await DomainHttp.WriteAsync(context, new { error = error.Code }, error.StatusCode, ct); }
    }

    private static bool Loopback(string address)
    {
        if (!Uri.TryCreate(address, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")) return false;
        string host = uri.Host.Trim('[', ']').ToLowerInvariant();
        return host is "localhost" or "localhost." || (IPAddress.TryParse(host, out var ip) && IPAddress.IsLoopback(ip));
    }
}
