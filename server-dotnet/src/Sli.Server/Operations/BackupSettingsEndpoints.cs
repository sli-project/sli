using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Operations;

internal static class BackupSettingsEndpoints
{
    private const string Path = "/api/v1/admin/backup-settings";
    private const int BodyLimit = 16 * 1024;
    private static readonly BackupSettingsState Unavailable = new(new(false, null, null), "unavailable");

    internal static IEndpointRouteBuilder MapBackupSettings(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(Path, context => HandleAsync(context, mutation: false));
        endpoints.MapPut(Path, context => HandleAsync(context, mutation: true));
        return endpoints;
    }

    private static async Task HandleAsync(HttpContext context, bool mutation)
    {
        var services = context.RequestServices;
        var ct = context.RequestAborted;
        try
        {
            var transport = services.GetRequiredService<TransportGate>();
            if (transport.CheckTransport(context) is { } failure)
            {
                await DomainHttp.WriteFailureAsync(context, failure, ct);
                return;
            }
            if (mutation)
            {
                var policy = services.GetRequiredService<AuthRequestPolicy>();
                if (context.Request.Headers.Origin.Count != 1 || !policy.OriginAllowed(context, policy.Resolve(context)))
                {
                    await Error(context, "cross_origin_request_rejected", 403, ct);
                    return;
                }
            }

            var authentication = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
            if (!authentication.Succeeded)
            {
                await DomainHttp.WriteFailureAsync(context, authentication.Failure ?? new(401, "authentication_required"), ct);
                return;
            }
            var principal = authentication.Principal!;
            if (principal is not { Type: "session", Id: > 0 }
                || !(await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, ct)).IsOwner)
            {
                await Error(context, "platform_owner_required", 403, ct);
                return;
            }

            var client = services.GetRequiredService<BackupSettingsClient>();
            if (!mutation)
            {
                await WriteState(context, (await client.GetAsync(ct)).State ?? Unavailable, ct);
                return;
            }

            using var body = await AuthJsonBody.ReadAsync(context, ct, BodyLimit);
            if (BackupSettingsClient.ReadUpdate(body.RootElement) is not { } update)
            {
                await Error(context, BackupSettingsClient.Invalid, 400, ct);
                return;
            }
            var reply = await client.SetAsync(update, ct);
            if (reply.State is { } saved) await WriteState(context, saved, ct);
            else await Error(context, reply.Error ?? BackupSettingsClient.Unavailable,
                BackupSettingsClient.ErrorStatus(reply.Error) ?? 503, ct);
        }
        catch (AuthInputException error)
        {
            await Error(context, BackupSettingsClient.Invalid, error.StatusCode, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception error)
        {
            await DomainHttp.WriteUnexpectedAsync(context, services.GetRequiredService<ILoggerFactory>()
                .CreateLogger(nameof(BackupSettingsEndpoints)), error, ct, Path);
        }
    }

    private static Task WriteState(HttpContext context, BackupSettingsState state, CancellationToken ct) =>
        DomainHttp.WriteAsync(context, new
        {
            enabled = state.Values.Enabled,
            path = state.Values.Path,
            revision = state.Values.Revision,
            storage_status = state.StorageStatus,
        }, 200, ct);

    private static Task Error(HttpContext context, string code, int status, CancellationToken ct) =>
        DomainHttp.WriteAsync(context, new { error = code }, status, ct);
}
