using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Entities;

public static class EntityReadEndpoints
{
    public static IServiceCollection AddEntityReads(this IServiceCollection services)
    {
        services.TryAddScoped<IEntityReadStore, EntityReadStore>();
        services.TryAddScoped<EntityDirectoryReader>();
        services.TryAddScoped<EntityReader>();
        return services;
    }
    public static IEndpointRouteBuilder MapEntityReads(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v1/objects", HandleAsync);
        endpoints.MapGet("/api/v1/objects/{objectType}/{objectId}", HandleAsync);
        endpoints.MapGet("/api/v1/objects/{**objectPath}", HandleAsync).WithOrder(1);
        endpoints.MapGet("/api/v1/entities", HandleAsync);
        endpoints.MapGet("/api/v1/entities/{id}", HandleAsync);
        endpoints.MapGet("/api/v1/entities/{id}/vpn-sessions", HandleAsync);
        endpoints.MapGet("/api/v1/entities/{**entityPath}", HandleAsync).WithOrder(1);
        return endpoints;
    }
    public static async Task HandleAsync(HttpContext context)
    {
        var ct = context.RequestAborted;
        try
        {
            var services = context.RequestServices;
            if (services.GetRequiredService<TransportGate>().CheckTransport(context) is { } transport) { await DomainHttp.WriteFailureAsync(context, transport, ct); return; }
            Principal principal;
            if (services.GetRequiredService<AuthRequestPolicy>().AuthRequired)
            {
                var auth = await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context, ct);
                if (!auth.Succeeded) { await DomainHttp.WriteFailureAsync(context, auth.Failure ?? new(401, "authentication_required"), ct); return; }
                principal = auth.Principal!;
                if (TransportGate.CheckViewerRole(principal) is { } failure) { await DomainHttp.WriteFailureAsync(context, failure, ct); return; }
            }
            else principal = new("", 0, "operator");
            var facts = await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal, ct);
            var caps = new CapabilityComposer().Compose(facts);
            string path = context.Request.Path.Value ?? ""; var query = context.Request.Query;
            var admission = caps.Decide("objects.view");
            bool exactObject = path.StartsWith("/api/v1/entities/", StringComparison.Ordinal) || path.StartsWith("/api/v1/objects/", StringComparison.Ordinal);
            bool objectListCandidate = path == "/api/v1/objects"
                && (caps.Capabilities.Contains("objects.view") || caps.ResourceCapabilities.Contains("objects.view"));
            // A scoped decision needs the object's minimal resource preflight. The
            // object list applies scoped grants/denials to each candidate instead.
            // Both resource checks run before protected object metadata is read.
            if (!admission.Allowed && !((exactObject || objectListCandidate) && admission.Reason == "resource_context_required"))
            { await DomainHttp.WriteAsync(context, new { error = admission.Reason, required_capability = "objects.view" }, 403, ct); return; }
            var reader = services.GetRequiredService<EntityReader>();
            if (path == "/api/v1/objects") { await DomainHttp.WriteAsync(context, await reader.Objects(query, caps, ct), 200, ct); return; }
            if (path == "/api/v1/entities") { await DomainHttp.WriteAsync(context, await reader.Entities(query, ct), 200, ct); return; }
            bool objects = path.StartsWith("/api/v1/objects/", StringComparison.Ordinal), vpn = !objects && path.EndsWith("/vpn-sessions", StringComparison.Ordinal);
            string? type = null; long id; int eventLimit = 30; EntityReadOptions? options = null;
            if (objects)
            {
                var parts = path["/api/v1/objects/".Length..].Split('/', 2);
                if (parts.Length != 2) throw new EntityInputException("invalid_object_path");
                string rawLimit = EntityReadInput.First(query, "event_limit", "30")!;
                eventLimit = EntityReadInput.Limit(rawLimit, 30, $"invalid literal for int() with base 10: '{rawLimit}'", emptyDefault: false);
                type = parts[0].Trim().ToLowerInvariant(); EntityReader.ValidateObjectType(type);
                id = EntityReadInput.Integer(parts[1], "invalid_object_id");
            }
            else
            {
                string raw = path["/api/v1/entities/".Length..]; if (vpn) raw = raw[..^"/vpn-sessions".Length];
                id = EntityReadInput.Integer(raw.Trim('/'), "invalid_entity_id"); if (id <= 0) throw new EntityInputException("invalid_entity_id");
                options = EntityReadInput.Detail(query, vpn);
            }
            var entity = await reader.Preflight(id, ct);
            if (entity is null || !EntityReader.Allows(caps, "objects.view", entity) || vpn && entity["server_id"] is null && entity["domain_id"] is null)
            { await Missing(context, id, objects, ct); return; }
            var access = new ReportEligibility().Compose(facts, caps);
            var payload = objects ? await reader.Object(entity, type!, eventLimit, caps, ct)
                : vpn ? await reader.Vpn(entity, options!, caps, access, ct)
                : await reader.Detail(entity, options!, caps, false, ct);
            if (payload is null) { await Missing(context, id, objects, ct); return; }
            if (!objects && !vpn) await reader.Interpretation(payload, entity, options!, caps, access, ct);
            await DomainHttp.WriteAsync(context, payload, 200, ct);
        }
        catch (Sli.Server.Storage.Lifecycle.LifecycleBlocked)
        { await DomainHttp.WriteAsync(context, new { error = "entity_history_unavailable", state = "unavailable", message = "История сущности временно недоступна. Повторите запрос позже." }, 503, ct); }
        catch (EntityInputException error)
        {
            var body = new System.Text.Json.Nodes.JsonObject { ["error"] = error.Message };
            if (error.UnknownTypes is not null) body["unknown_types"] = error.UnknownTypes;
            await DomainHttp.WriteAsync(context, body, 400, ct);
        }
        catch (Exception error) when (EntityReader.TimedOut(error) && !ct.IsCancellationRequested)
        { await DomainHttp.WriteAsync(context, new { error = "report_read_timeout", state = "unavailable" }, 503, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception error) { if (context.Response.HasStarted) throw; await AuthResponse.UnexpectedAsync(context, error, ct, login: false); }
    }
    static Task Missing(HttpContext context, long id, bool objects, CancellationToken ct) => objects
        ? DomainHttp.WriteAsync(context, new { error = "object_not_found" }, 404, ct)
        : DomainHttp.WriteAsync(context, new { error = "entity_not_found", entity_id = id }, 404, ct);
}
