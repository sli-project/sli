using Npgsql;
using Sli.Server.Domains;
using Sli.Server.Infrastructure;
using System.Text.Json.Nodes;

namespace Sli.Server.Hosting;

public static class HealthHosting
{
    private static readonly string InstanceId = (Environment.GetEnvironmentVariable("ADLOG_RUNTIME_INSTANCE_ID") ?? Guid.NewGuid().ToString("N")).Trim();
    private static readonly string Started = DateTimeOffset.UtcNow.ToString("O");
    internal static JsonObject RuntimeIdentity() => new() {
        ["runtime_instance_id"] = InstanceId, ["process_pid"] = Environment.ProcessId, ["parent_pid"] = null,
        ["process_started_at_utc"] = Started, ["project_version"] = "2026.07.19-pg-product-sli-v4",
        ["baseline_id"] = "pg-product-sli-v4-20260719", ["build_id"] = Environment.GetEnvironmentVariable("ADLOG_BUILD_ID") ?? "pg-product-sli-v4-20260719", ["git_commit"] = null };

    public static IEndpointRouteBuilder MapSliHealth(this IEndpointRouteBuilder endpoints)
    {
        var release=ReleaseMetadata.Read(endpoints.ServiceProvider.GetRequiredService<IConfiguration>());
        foreach (string path in new[] { "/health", "/api/health", "/api/health/live" })
            endpoints.MapGet(path, async context => await DomainHttp.WriteAsync(context, new {
                status = "ok", service = "ad-log-reports", runtime_identity = new {
                    runtime_instance_id = InstanceId, process_pid = Environment.ProcessId, parent_pid = (int?)null,
                    process_started_at_utc = Started, project_version = release.ProjectVersion,
                    baseline_id = release.BaselineId, build_id = release.BuildId, git_commit = release.GitCommit
                } }, 200, context.RequestAborted));
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
