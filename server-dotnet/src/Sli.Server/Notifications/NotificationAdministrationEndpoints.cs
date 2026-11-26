using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Compatibility;
using Sli.Server.Domains;
using Sli.Server.Problems;

namespace Sli.Server.Notifications;

public static class NotificationAdministrationEndpoints
{
    public const string Channels = "/api/v1/notification-channels";
    public const string Subscriptions = "/api/v1/notification-subscriptions";
    public static IServiceCollection AddNotificationAdministration(this IServiceCollection services)
    {
        services.TryAddScoped<IAccessFactsRepository, AccessFactsRepository>();
        services.TryAddScoped<INotificationRecipientAccess, NotificationRecipientAccess>();
        services.TryAddScoped<INotificationAdministrationRepository, NotificationAdministrationRepository>();
        services.TryAddSingleton<INotificationSetupClient, NotificationSetupClient>();
        services.TryAddScoped<NotificationAdministration>(); return services;
    }
    public static IEndpointRouteBuilder MapNotificationAdministration(this IEndpointRouteBuilder routes)
    {
        routes.MapGet(Channels, HandleAsync); routes.MapGet(Channels + "/workspace", HandleAsync);
        routes.MapPost(Channels + "/{kind}", HandleAsync);
        foreach (var action in new[] { "status", "save" }) routes.MapPost(Channels + "/smtp/setup/" + action, HandleAsync);
        foreach (var action in new[] { "status", "token", "chats", "bind", "test" }) routes.MapPost(Channels + "/telegram/setup/" + action, HandleAsync);
        routes.MapGet(Subscriptions, HandleAsync); routes.MapPost(Subscriptions, HandleAsync);
        routes.MapPost(Subscriptions + "/{id}/test", HandleAsync);
        // A malformed subscription UUID has the same 400 as the reference, while
        // schedules belongs to the separately registered report scheduling routes.
        routes.MapPost(Subscriptions + "/{id:regex(^(?!schedules$).+)}", HandleAsync);
        return routes;
    }
    public static async Task HandleAsync(HttpContext context)
    {
        var ct = context.RequestAborted; var services = context.RequestServices;
        bool channel = context.Request.Path.StartsWithSegments(Channels); bool mutation = HttpMethods.IsPost(context.Request.Method);
        string denied = channel ? "notification_channels_access_denied" : "notifications_access_denied";
        string unavailable = channel ? "notification_channels_unavailable" : "notifications_unavailable";
        try
        {
            var failure = services.GetRequiredService<TransportGate>().CheckTransport(context);
            if (failure is not null) { await DomainHttp.WriteFailureAsync(context, failure, ct); return; }
            var policy = services.GetRequiredService<AuthRequestPolicy>();
            if (mutation && !policy.OriginAllowed(context, policy.Resolve(context))) throw new NotificationException("cross_origin_request_rejected", 403);
            Principal principal;
            if (policy.AuthRequired)
            {
                var authentication = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
                if (!authentication.Succeeded) { await DomainHttp.WriteFailureAsync(context, authentication.Failure ?? new(401, "authentication_required"), ct); return; }
                principal = authentication.Principal!;
                if (TransportGate.CheckViewerRole(principal) is not null || mutation && principal.Role != "admin") throw new NotificationException("insufficient_permissions", 403);
            }
            else
            {
                string expected = (services.GetRequiredService<IConfiguration>()["Sli:OperatorToken"] ?? Environment.GetEnvironmentVariable("ADLOG_OPERATOR_TOKEN") ?? "").Trim();
                if (mutation && expected.Length > 0 && !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(expected)), SHA256.HashData(Encoding.UTF8.GetBytes(context.Request.Headers["X-ADLog-Operator-Token"].ToString()))))
                    throw new NotificationException("operator_token_required", 401);
                principal = new("", 0, "operator");
            }
            var facts = await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, ct);
            var access = new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts));
            if (!mutation)
            {
                var capability = access.Capabilities.Decide("access.manage");
                if (!capability.Allowed)
                {
                    await DomainHttp.WriteAsync(context, new { error = capability.Reason, required_capability = "access.manage" }, 403, ct);
                    return;
                }
            }
            if (!NotificationAccess.Allowed(access, action: mutation ? "configure_channel" : "view")) throw new NotificationException(denied, 403);
            var repository = services.GetRequiredService<INotificationAdministrationRepository>();
            string path = context.Request.Path.Value!;
            JsonNode result;
            if (!mutation)
            {
                if (path == Channels + "/workspace")
                {
                    if (!NotificationAccess.Allowed(access, "notifications.deliveries")) throw new NotificationException(denied, 403);
                    var query = NotificationWorkspaceQuery.Parse(context.Request.Query); bool links = NotificationAccess.Queue(access);
                    if (query.Finding is not null && !links) throw new NotificationException(denied, 403);
                    result = await repository.WorkspaceAsync(principal, query, links ? new ProblemAccess(access) : null,
                        NotificationAccess.Allowed(access, action: "configure_channel"), context.Request.Headers.AcceptLanguage.ToString(), ct);
                }
                else result = new JsonObject { ["items"] = channel ? await repository.ChannelsAsync(ct) : await repository.SubscriptionsAsync(ct) };
            }
            else
            {
                bool setupRoute = path.StartsWith(Channels + "/smtp/setup/", StringComparison.Ordinal) || path.StartsWith(Channels + "/telegram/setup/", StringComparison.Ordinal);
                if (setupRoute && (principal.Type != "session" || principal.Id <= 0) || !channel && !path.EndsWith("/test", StringComparison.Ordinal) && principal.Type != "session")
                    throw new NotificationException(denied, 403);
                using var document = await AuthJsonBody.ReadAsync(context, ct);
                var body = PythonJson.FromElement(document.RootElement)!.AsObject();
                if (path.StartsWith(Channels + "/smtp/setup/", StringComparison.Ordinal)) result = await services.GetRequiredService<NotificationAdministration>().SmtpAsync(principal, path.Split('/')[^1], body, ct);
                else if (path.StartsWith(Channels + "/telegram/setup/", StringComparison.Ordinal)) result = await services.GetRequiredService<NotificationAdministration>().TelegramAsync(principal, path.Split('/')[^1], body, ct);
                else if (channel)
                {
                    string kind = path[(Channels.Length + 1)..]; NotificationInput.Channel(kind, body);
                    result = new JsonObject { ["item"] = await repository.UpdateChannelAsync(principal, kind, body, ct) };
                }
                else if (path.EndsWith("/test", StringComparison.Ordinal))
                {
                    string id = path[(Subscriptions.Length + 1)..^5]; NotificationInput.Id(id); NotificationInput.Keys(body, "problem_id");
                    result = new JsonObject { ["item"] = await repository.EnqueueAsync(principal, id, NotificationInput.Id(NotificationInput.Text(body, "problem_id")), ct) };
                }
                else
                {
                    if (principal.Type != "session") throw new NotificationException(denied, 403);
                    string? id = path == Subscriptions ? null : path[(Subscriptions.Length + 1)..]; NotificationInput.Subscription(id, body);
                    result = new JsonObject { ["item"] = await repository.SaveSubscriptionAsync(principal, id, body, ct) };
                }
            }
            await DomainHttp.WriteAsync(context, result, 200, ct);
        }
        catch (NotificationException ex)
        {
            if (ex.Code.StartsWith("smtp_setup_", StringComparison.Ordinal))
            {
                string key = "notifications.smtp.setup." + ex.Code[11..];
                string locale = DomainHttp.SelectEnglish(context.Request.Headers.AcceptLanguage.ToString()) ? "en" : "ru";
                using var stream = typeof(NotificationAdministrationEndpoints).Assembly.GetManifestResourceStream("Sli.Server.Access.Administration.server." + locale + ".json")!;
                var catalog = JsonSerializer.Deserialize<Dictionary<string, string>>(stream)!;
                await DomainHttp.WriteAsync(context, new { error = ex.Code, message = new { code = key, @params = new { }, text = catalog.GetValueOrDefault(key, key) } }, ex.Status, ct);
            }
            else await AuthResponse.ErrorAsync(context, ex.Code, ex.Status, ct, login: false);
        }
        catch (AuthInputException ex) { await DomainHttp.WriteAsync(context, new { error = ex.Code }, ex.StatusCode, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch { if (context.Response.HasStarted) throw; await DomainHttp.WriteAsync(context, new { error = unavailable }, 503, ct); }
    }
}
