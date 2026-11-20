using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
namespace Sli.Server.Investigations;
public static class InvestigationEventEndpoints
{
    public static IServiceCollection AddInvestigationEvents(this IServiceCollection services)
    {services.TryAddScoped<IInvestigationRepository,InvestigationRepository>();services.TryAddScoped<IInvestigationEventRepository,InvestigationEventRepository>();services.TryAddScoped<IAccessFactsRepository,AccessFactsRepository>();return services;}
    public static IEndpointRouteBuilder MapInvestigationEvents(this IEndpointRouteBuilder endpoints)
    {endpoints.MapPost("/api/v1/investigations/{**tail:regex((^|.*/)events$)}",InvestigationEndpoints.HandleDisabledAsync);endpoints.MapPost("/api/v1/investigations/{**tail:regex((^|.*/)events/remove$)}",InvestigationEndpoints.HandleDisabledAsync);return endpoints;}
    public static Task AddAsync(HttpContext context)=>HandleAsync(context,true);
    public static Task RemoveAsync(HttpContext context)=>HandleAsync(context,false);
    private static async Task HandleAsync(HttpContext context,bool add)
    {
        var ct=context.RequestAborted;
        try {
            var services=context.RequestServices;var failure=services.GetRequiredService<TransportGate>().CheckTransport(context);
            if(failure is not null){await AuthResponse.ErrorAsync(context,failure.Code,failure.StatusCode,ct,login:false);return;}
            var policy=services.GetRequiredService<AuthRequestPolicy>();var request=policy.Resolve(context);
            if(!policy.OriginAllowed(context,request)){await AuthResponse.ErrorAsync(context,"cross_origin_request_rejected",403,ct,login:false);return;}
            Principal principal;
            if(policy.AuthRequired) {
                var auth=await services.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context,ct);
                if(!auth.Succeeded){await AuthResponse.ErrorAsync(context,auth.Failure?.Code??"authentication_required",auth.Failure?.StatusCode??401,ct,login:false);return;}
                principal=auth.Principal!;
                if(TransportGate.CheckViewerRole(principal) is not null){await AuthResponse.ErrorAsync(context,"insufficient_permissions",403,ct,login:false);return;}
            } else {
                string expected=AssignmentValidation.Strip(services.GetRequiredService<IConfiguration>()["Sli:OperatorToken"]??Environment.GetEnvironmentVariable("ADLOG_OPERATOR_TOKEN")??"");
                if(expected.Length>0 && !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(expected)),SHA256.HashData(Encoding.UTF8.GetBytes(context.Request.Headers["X-ADLog-Operator-Token"].ToString())))) {await AuthResponse.ErrorAsync(context,"operator_token_required",401,ct,login:false);return;}
                principal=new("",0,"operator");
            }
            string raw=context.Features.Get<IHttpRequestFeature>()?.RawTarget is {Length:>0} target?target.Split('?',2)[0]:context.Request.Path.Value??"";
            string[] parts=raw.Split('/',StringSplitOptions.RemoveEmptyEntries);
            if(parts.Length<=3){await AuthResponse.ErrorAsync(context,"invalid_investigation_id",400,ct,login:false);return;}
            var facts=await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal,ct);var caps=new CapabilityComposer().Compose(facts);var access=new ReportEligibility().Compose(facts,caps);
            string? report=InvestigationAccess.ReportKey(access);
            if(report is null){await DomainHttp.WriteAsync(context,new {error="report_not_assigned",required_report="investigations.workspace",required_action=InvestigationAccess.Action},403,ct);return;}
            if(!caps.Capabilities.Contains(InvestigationAccess.Capability) && !caps.ResourceCapabilities.Contains(InvestigationAccess.Capability)){await DomainHttp.WriteAsync(context,new {error="insufficient_capability",required_capability=InvestigationAccess.Capability},403,ct);return;}
            var events=services.GetRequiredService<IInvestigationEventRepository>();
            InvestigationIdentity identity;InvestigationEventInput input;
            if(add) {
                using var body=await AuthJsonBody.ReadAsync(context,ct);input=InvestigationEventInput.Parse(body.RootElement,false);
                identity=InvestigationIdentity.Parse(parts[3]);
                var groups=(await services.GetRequiredService<IInvestigationRepository>().ResourceGroupsAsync(identity,ct)).ToList();groups.Add(await events.EventResourcesAsync(input.EventId,ct));
                if(!InvestigationAccess.Allowed(access,report,groups))throw new InvestigationException("not_found","Investigation resource was not found",404);
                input=InvestigationEventInput.Parse(body.RootElement,true);
            } else {
                identity=InvestigationIdentity.Parse(parts[3]);
                var groups=await services.GetRequiredService<IInvestigationRepository>().ResourceGroupsAsync(identity,ct);
                if(!InvestigationAccess.Allowed(access,report,groups))throw new InvestigationException("not_found","Investigation resource was not found",404);
                using var body=await AuthJsonBody.ReadAsync(context,ct);input=InvestigationEventInput.Parse(body.RootElement,false);
            }
            string actor=InvestigationAccess.Actor(principal);
            if(add) {
                var result=await events.AddAsync(identity,input,actor,CancellationToken.None);var row=result.Row;
                var value=new Dictionary<string,object?>{{"event_db_id",row.EventDbId},{"relation_status",row.RelationStatus},{"added_by",row.AddedBy},{"added_at",row.AddedAt}};
                if(result.Replay)value["idempotent_replay"]=true;
                await DomainHttp.WriteAsync(context,new {status="ok",@event=value},201,ct);
            } else {
                await events.RemoveAsync(identity,input.EventId,actor,CancellationToken.None);
                await DomainHttp.WriteAsync(context,new {status="ok",@event=new {event_db_id=(long)input.EventId,removed=true}},200,ct);
            }
        }
        catch(InvestigationException error) {
            if(error.Code=="invalid_event_db_id")await DomainHttp.WriteAsync(context,new {error="invalid_event_db_id"},400,ct);
            else await DomainHttp.WriteAsync(context,new {error=error.Code,message=error.Message},error.Status,ct);
        }
        catch(AuthInputException error){await AuthResponse.ErrorAsync(context,error.Code,error.StatusCode,ct,login:false);}
        catch(OperationCanceledException) when(ct.IsCancellationRequested){}
        catch(Exception error){if(context.Response.HasStarted)throw;await AuthResponse.UnexpectedAsync(context,error,ct,login:false);}
    }
}
