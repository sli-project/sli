using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;

namespace Sli.Server.Storage.EventReports;

internal static class EventQueryEndpoints
{
    internal static void Add(IServiceCollection services)
    {
        services.TryAddScoped<IEventQueryStore,EventReadService>();
        services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        services.TryAddSingleton<EventSearchRuntime>();
    }
    internal static void Map(IEndpointRouteBuilder routes)
    {
        routes.MapGet("/api/v1/events",HandleAsync);
        routes.MapGet("/api/v1/events/{id}/entities",HandleAsync);
        foreach(string operation in new[]{"query","page","members","summary"}) routes.MapPost("/api/v1/event-search/"+operation,HandleAsync);
    }
    internal static async Task HandleAsync(HttpContext context)
    {
        var requestCt=context.RequestAborted;
        // The caller owns cancellation. Do not replace its lifetime with a
        // fixed report deadline (Q500: live work has no elapsed-time cutoff).
        var ct=requestCt;
        bool search=context.Request.Method=="POST",entities=context.Request.Path.Value?.EndsWith("/entities",StringComparison.Ordinal)==true;
        try
        {
            var services=context.RequestServices; var policy=services.GetRequiredService<AuthRequestPolicy>();
            if(services.GetRequiredService<TransportGate>().CheckTransport(context) is {} transport) { await DomainHttp.WriteFailureAsync(context,transport,ct); return; }
            if(search && !policy.OriginAllowed(context,policy.Resolve(context))) { await AuthResponse.ErrorAsync(context,"cross_origin_request_rejected",403,ct,login:false); return; }
            Principal principal;
            if(policy.AuthRequired)
            {
                var auth=await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context,ct);
                if(!auth.Succeeded) { await DomainHttp.WriteFailureAsync(context,auth.Failure??new(401,"authentication_required"),ct); return; }
                principal=auth.Principal!;
                if(TransportGate.CheckViewerRole(principal) is {} failure) { await DomainHttp.WriteFailureAsync(context,failure,ct); return; }
            }
            else principal=new("",0,"operator");
            if(search && (principal.Type!="session" || principal.Id<=0)) { await AuthResponse.ErrorAsync(context,principal.Type==""?"authentication_required":"insufficient_permissions",principal.Type==""?401:403,ct,login:false); return; }
            var facts=await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal,ct); var caps=new CapabilityComposer().Compose(facts);
            string capability=entities?"evidence.exact":"events.view";
            if(!caps.IsOwner && (search?!caps.Decide(capability).Allowed:!caps.Capabilities.Contains(capability) && !caps.ResourceCapabilities.Contains(capability)))
            { await DomainHttp.WriteAsync(context,new {error=caps.Decide(capability).Reason,required_capability=capability},403,ct); return; }
            var store=services.GetRequiredService<IEventQueryStore>();
            if(entities)
            {
                if(!long.TryParse(context.Request.RouteValues["id"]?.ToString(),NumberStyles.Integer,CultureInfo.InvariantCulture,out long id) || id<=0) { await DomainHttp.WriteAsync(context,new {error="invalid_event_db_id"},400,ct); return; }
                var resources=await services.GetRequiredService<IEventReadService>().ResourcesAsync(id,ct);
                if(resources.Count>0 && !ResourceAccessDecisions.Capability(caps,"evidence.exact",[resources]).Allowed)
                { await DomainHttp.WriteAsync(context,new {error="event_not_found",event_db_id=id},404,ct); return; }
                if(resources.Count==0 && !caps.Decide("evidence.exact").Allowed)
                { await DomainHttp.WriteAsync(context,new {error="event_not_found",event_db_id=id},404,ct); return; }
                await DomainHttp.WriteAsync(context,await store.EntitiesAsync(id,ct),200,ct); return;
            }
            if(!search)
            {
                var input=EventListInput.Parse(context.Request.Query,services.GetRequiredService<TimeProvider>().GetUtcNow());
                await DomainHttp.WriteAsync(context,await store.ListAsync(input,caps,ct),200,ct); return;
            }
            using var body=await AuthJsonBody.ReadAsync(context,ct,16*1024);
            var raw=JsonNode.Parse(body.RootElement.GetRawText()) as JsonObject??throw new EventSearchException("invalid_request");
            var access=new ReportEligibility().Compose(facts,caps); string operation=context.Request.Path.Value!.Split('/')[^1];
            var runtime=services.GetRequiredService<EventSearchRuntime>();
            var output=await runtime.RunAsync(async ()=>
            {
                string? id=null; EventSearchRuntime.Execution? entry=null; EventSearchInput input;
                if(operation=="query") input=EventSearchInput.Parse(raw,services.GetRequiredService<TimeProvider>().GetUtcNow());
                else
                {
                    EventSearchInput.Keys(raw,operation=="members"?["execution_id","cursor","page_size","group_key"]:operation=="summary"?["execution_id","cursor","page_size","blocks","facet_field","facet_query","histogram_buckets"]:["execution_id","cursor","page_size"]);
                    id=EventSearchInput.String(raw["execution_id"]);
                    if(id is null || id.Length is <1 or >128) throw new EventSearchException("invalid_request");
                    if(raw.ContainsKey("cursor") && (EventSearchInput.String(raw["cursor"]) is not {} cursor || cursor.Length is <1 or >2048)) throw new EventSearchException("invalid_cursor");
                    _=EventSearchInput.Size(raw); entry=runtime.Get(id,principal.Id); input=entry.Input;
                }
                try
                {
                    store.AdmitSearch();
                    var searchPolicy=EventSearchPolicy.Authorize(facts,access,input);
                    if(id is null)
                    {
                        var rows=await store.CaptureAsync(input,searchPolicy,ct); ct.ThrowIfCancellationRequested();
                        id=runtime.Start(principal.Id,input,searchPolicy,rows,store.RetentionBoundary,ct); entry=runtime.Get(id,principal.Id);
                    }
                    else runtime.Reauthorize(id,entry!,searchPolicy);
                    return operation=="summary"?runtime.Summary(id,entry!,raw,searchPolicy,ct):runtime.Page(id,entry!,raw,operation=="members");
                }
                catch { if(id is not null) runtime.Remove(id); throw; }
            });
            ct.ThrowIfCancellationRequested();
            if(JsonSerializer.SerializeToUtf8Bytes(output).Length>16*1024*1024) throw new EventSearchException("snapshot_limit_exceeded");
            await DomainHttp.WriteAsync(context,output,200,ct);
        }
        catch(EventSearchException error)
        {
            if(search) await SearchFailure(context,error.Code,error.Status,requestCt);
            else await DomainHttp.WriteAsync(context,new {error=error.Code[9..]},error.Status,requestCt);
        }
        catch(AuthInputException error) { await AuthResponse.ErrorAsync(context,error.Code,error.StatusCode,requestCt,login:false); }
        catch(OperationCanceledException) when(requestCt.IsCancellationRequested) { }
        catch(Exception e) when(e is TimeoutException or OperationCanceledException || e is PostgresException { SqlState:"57014" }) { await Timeout(context,search,entities,requestCt); }
        catch(InvalidDataException)
        { if(search) await SearchFailure(context,"evsearch.history_integrity_error",503,requestCt); else await DomainHttp.WriteAsync(context,new {error="event_read_unavailable",state="unavailable"},503,requestCt); }
        catch(Exception e) when(e is EventReadConfigurationException or IOException or HttpRequestException)
        { if(search) await SearchFailure(context,"evsearch.history_unavailable",503,requestCt); else await DomainHttp.WriteAsync(context,new {error="event_read_unavailable",state="unavailable"},503,requestCt); }
        catch(Exception e) { if(context.Response.HasStarted) throw; await AuthResponse.UnexpectedAsync(context,e,requestCt,login:false); }
    }
    static Task SearchFailure(HttpContext context,string code,int status,CancellationToken ct)
    {
        string locale=DomainHttp.SelectEnglish(context.Request.Headers.AcceptLanguage.ToString())?"en":"ru";
        using var stream=typeof(EventQueryEndpoints).Assembly.GetManifestResourceStream("Sli.Server.Access.Administration.server."+locale+".json")!;
        var catalog=JsonSerializer.Deserialize<Dictionary<string,string>>(stream)!;
        return DomainHttp.WriteAsync(context,new {error=code,message=catalog.GetValueOrDefault(code,code)},status,ct);
    }
    static Task Timeout(HttpContext context,bool search,bool entities,CancellationToken ct)
    {
        if(search) return SearchFailure(context,"evsearch.snapshot_timeout",503,ct);
        if(entities) return DomainHttp.WriteAsync(context,new {api_version="v1",event_db_id=long.TryParse(context.Request.RouteValues["id"]?.ToString(),out long id)?id:0,event_found=(bool?)null,evidence_status="timeout",items=Array.Empty<object>(),limit=30,warning="Связанные сущности временно недоступны: превышено время запроса. Это не означает, что связей нет."},200,ct);
        return DomainHttp.WriteAsync(context,new {api_version="v1",items=Array.Empty<object>(),has_more=false,next_cursor=(string?)null,query_status="timeout",warning="Превышено время запроса.",category_counts=(object?)null},200,ct);
    }
}
