using System.Text.Json.Nodes;
using System.Globalization;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Storage.EventReports;

public interface IEventReadService
{
    Task<IReadOnlyList<AccessResource>> ResourcesAsync(long id,CancellationToken ct);
    Task<Dictionary<long,JsonObject>> DetailsAsync(long[] ids,bool exact,Func<long,CancellationToken,Task<bool>> admitted,CancellationToken ct);
    Task<JsonObject> RelationsAsync(long id,Func<long,CancellationToken,Task<bool>> admitted,CancellationToken ct);
    Task<JsonObject> RelationsPageAsync(long id,int limit,string? cursor,Func<long,CancellationToken,Task<bool>> admitted,CancellationToken ct) =>
        cursor is null ? RelationsAsync(id,admitted,ct) : throw new InvalidDataException("invalid_cursor");
}

public static class EventReadEndpoints
{
    public static IServiceCollection AddEventReads(this IServiceCollection services)
    {
        services.TryAddScoped<IAccessFactsRepository,AccessFactsRepository>();
        services.TryAddScoped<IEventReadService,EventReadService>();
        EventQueryEndpoints.Add(services);
        return services;
    }
    public static IEndpointRouteBuilder MapEventReads(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/v1/events/{id}",HandleAsync);
        endpoints.MapGet("/api/v1/events/{id}/relations",HandleAsync);
        endpoints.MapGet("/api/v1/events/batch",HandleAsync);
        EventQueryEndpoints.Map(endpoints);
        return endpoints;
    }
    public static async Task HandleAsync(HttpContext context)
    {
        var ct=context.RequestAborted;
        var requestCancellation=ct;
        try
        {
            var services=context.RequestServices;
            var transport=services.GetRequiredService<TransportGate>().CheckTransport(context);
            if(transport is not null) { await DomainHttp.WriteFailureAsync(context,transport,ct); return; }
            Principal principal;
            if(services.GetRequiredService<AuthRequestPolicy>().AuthRequired)
            {
                var auth=await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context,ct);
                if(!auth.Succeeded) { await DomainHttp.WriteFailureAsync(context,auth.Failure??new(401,"authentication_required"),ct); return; }
                principal=auth.Principal!;
                if(TransportGate.CheckViewerRole(principal) is {} failure) { await DomainHttp.WriteFailureAsync(context,failure,ct); return; }
            }
            else principal=new("",0,"operator");
            var facts=await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal,ct);
            var caps=new CapabilityComposer().Compose(facts);
            // Scoped grants need a resource check below; global/invalid denies have
            // already removed the capability from both sets during composition.
            if(!caps.IsOwner && !caps.Capabilities.Contains("evidence.exact") && !caps.ResourceCapabilities.Contains("evidence.exact"))
            {
                await DomainHttp.WriteAsync(context,new {error=caps.Decide("evidence.exact").Reason,required_capability="evidence.exact"},403,ct); return;
            }
            var access=new ReportEligibility().Compose(facts,caps);
            string path=context.Request.Path.Value??"";
            bool batch=path=="/api/v1/events/batch", relations=path.EndsWith("/relations",StringComparison.Ordinal);
            long[] ids;
            if(batch)
            {
                ids=BatchIds(context.Request.Query["event_db_id"]);
                if(ids.Length==0) { await DomainHttp.WriteAsync(context,new {error="event_db_id_required"},400,ct); return; }
            }
            else
            {
                string raw=context.Request.RouteValues["id"]?.ToString()??"";
                if(!long.TryParse(raw,NumberStyles.Integer,CultureInfo.InvariantCulture,out long id))
                { await DomainHttp.WriteAsync(context,new {error="invalid_event_db_id"},400,ct); return; }
                ids=[id];
            }
            var reader=services.GetRequiredService<IEventReadService>();
            var decisions=new Dictionary<long,bool>();
            async Task<bool> Admitted(long id,CancellationToken token)
            {
                if(decisions.TryGetValue(id,out bool cached)) return cached;
                if(id<=0) return decisions[id]=false;
                var resources=await reader.ResourcesAsync(id,token);
                if(resources.Count==0) return decisions[id]=false;
                IReadOnlyList<IReadOnlyList<AccessResource>> groups=[resources];
                bool allowed=ResourceAccessDecisions.Capability(caps,"evidence.exact",groups).Allowed;
                if(principal.RestrictedReportKey)
                    allowed &= ResourceAccessDecisions.ReportAction(access,"events.explorer","view",groups,new HashSet<string>{"raw_evidence","technical","security"}).Allowed;
                return decisions[id]=allowed;
            }
            var permitted=new List<long>();
            foreach(long id in ids) if(await Admitted(id,ct)) permitted.Add(id);
            if(!batch && permitted.Count==0)
            { await DomainHttp.WriteAsync(context,new {error="event_not_found",event_db_id=ids[0]},404,ct); return; }
            if(relations)
            {
                await DomainHttp.WriteAsync(context,await reader.RelationsAsync(ids[0],Admitted,ct),200,ct); return;
            }
            var rows=permitted.Count==0 ? [] : await reader.DetailsAsync(permitted.ToArray(),!batch,Admitted,ct);
            // Do not allow an adapter to release an ID outside the admitted request.
            if(rows.Keys.Any(id=>!permitted.Contains(id))) throw new InvalidDataException("unauthorized_hydration_result");
            foreach(var (id,row) in rows) row["event_db_id"]=id;
            if(batch)
                await DomainHttp.WriteAsync(context,new {api_version="v1",items=ids.Where(rows.ContainsKey).Select(id=>rows[id]).ToArray(),requested_event_db_ids=ids,missing_event_db_ids=ids.Where(id=>!rows.ContainsKey(id)).ToArray(),limit=100},200,ct);
            else if(rows.TryGetValue(ids[0],out var item))
                await DomainHttp.WriteAsync(context,new {api_version="v1",item},200,ct);
            else await DomainHttp.WriteAsync(context,new {error="event_not_found",event_db_id=ids[0]},404,ct);
        }
        catch(PostgresException error) when(error.SqlState=="57014") { await Timeout(context,requestCancellation); }
        catch(TimeoutException) { await Timeout(context,requestCancellation); }
        catch(OperationCanceledException) when(requestCancellation.IsCancellationRequested) { }
        catch(OperationCanceledException) { await Timeout(context,requestCancellation); }
        catch(InvalidOperationException error) when(error.Message is "source_normalizer_bundle_unsupported" or "plugin_generation_unavailable" or "plugin_update_draining")
        { await DomainHttp.WriteAsync(context,new {error=error.Message,state="unavailable"},503,ct); }
        catch(EventReadConfigurationException error) { await DomainHttp.WriteAsync(context,new {error=error.Message,state="unavailable"},503,ct); }
        catch(Exception error) { if(context.Response.HasStarted) throw; await AuthResponse.UnexpectedAsync(context,error,ct,login:false); }
    }
    static Task Timeout(HttpContext context,CancellationToken ct) => DomainHttp.WriteAsync(context,new {error="report_read_timeout",state="unavailable"},503,ct);
    internal static long[] BatchIds(IEnumerable<string?> values)
    {
        var ids=new List<long>();
        foreach(string? raw in values) foreach(string part in (raw??"").Replace(';',',').Split(','))
        {
            if(long.TryParse(part,NumberStyles.Integer,CultureInfo.InvariantCulture,out long id) && id>0 && !ids.Contains(id)) ids.Add(id);
            if(ids.Count==100) return ids.ToArray();
        }
        return ids.ToArray();
    }
}
