using Npgsql;
using Sli.Server.Domains;
using Sli.Server.Infrastructure;
using System.Text.Json.Nodes;

namespace Sli.Server.Hosting;

public static class HealthHosting
{
    private static readonly string InstanceId = (Environment.GetEnvironmentVariable("ADLOG_RUNTIME_INSTANCE_ID") ?? Guid.NewGuid().ToString("N")).Trim();
    private static readonly string Started = DateTimeOffset.UtcNow.ToString("O");
    internal static JsonObject RuntimeIdentity(ReleaseMetadata release)
    {
        var identity = release.ToJson();
        identity["runtime_instance_id"] = InstanceId;
        identity["process_pid"] = Environment.ProcessId;
        identity["parent_pid"] = null;
        identity["process_started_at_utc"] = Started;
        return identity;
    }

    public static IEndpointRouteBuilder MapSliHealth(this IEndpointRouteBuilder endpoints)
    {
        var release = ReleaseMetadata.Read(endpoints.ServiceProvider.GetRequiredService<IConfiguration>());
        foreach (string path in new[] { "/health", "/api/health", "/api/health/live" })
            endpoints.MapGet(path, async context => await DomainHttp.WriteAsync(context, new {
                status = "ok", service = "ad-log-reports", runtime_identity = RuntimeIdentity(release)
            }, 200, context.RequestAborted));
        endpoints.MapGet("/api/health/ready", async context => {
            bool ready;
            string code;
            try {
                await using var connection = await context.RequestServices.GetRequiredService<IPostgresConnectionFactory>().OpenAsync(context.RequestAborted);
                await using var command = new NpgsqlCommand("select 1 as ready", connection);
                ready = Convert.ToInt32(await command.ExecuteScalarAsync(context.RequestAborted)) == 1;
                code = ready ? "ready" : "postgres_not_ready";
            } catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { return; }
              catch (Exception) { ready = false; code = "postgres_unavailable"; }
            await DomainHttp.WriteAsync(context, new { ready, code }, ready ? 200 : 503, context.RequestAborted);
        });
        return endpoints;
    }
}
