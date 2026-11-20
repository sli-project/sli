using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
namespace Sli.Server.Investigations;
public static class InvestigationCreateEndpoints
{
    public static IServiceCollection AddInvestigationCreate(this IServiceCollection services)
    {services.TryAddScoped<IAccessFactsRepository,AccessFactsRepository>();services.TryAddScoped<IInvestigationEventRepository,InvestigationEventRepository>();services.TryAddScoped<IInvestigationCreateRepository,InvestigationCreateRepository>();services.TryAddScoped<IInvestigationVpnEvidence,InvestigationVpnEvidence>();return services;}
    public static IEndpointRouteBuilder MapInvestigationCreate(this IEndpointRouteBuilder endpoints){endpoints.MapPost("/api/v1/investigations",InvestigationEndpoints.HandleDisabledAsync);return endpoints;}
    public static async Task HandleAsync(HttpContext context)
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
            var facts=await services.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal,ct);var caps=new CapabilityComposer().Compose(facts);var access=new ReportEligibility().Compose(facts,caps);
            string? report=InvestigationAccess.ReportKey(access);
            if(report is null){await DomainHttp.WriteAsync(context,new {error="report_not_assigned",required_report="investigations.workspace",required_action=InvestigationAccess.Action},403,ct);return;}
            if(!caps.Capabilities.Contains(InvestigationAccess.Capability) && !caps.ResourceCapabilities.Contains(InvestigationAccess.Capability)){await DomainHttp.WriteAsync(context,new {error="insufficient_capability",required_capability=InvestigationAccess.Capability},403,ct);return;}
            using var body=await AuthJsonBody.ReadAsync(context,ct);
            var eventId=InvestigationCreateInput.ParseEvent(body.RootElement);
            IReadOnlyList<IReadOnlyList<AccessResource>> groups=eventId is {} ev ? [await services.GetRequiredService<IInvestigationEventRepository>().EventResourcesAsync(ev,ct)] : [];
            if(!InvestigationAccess.Allowed(access,report,groups))throw new InvestigationException("not_found","Investigation resource was not found",404);
            var input=InvestigationCreateInput.Parse(body.RootElement);input.Validate();
            var result=await services.GetRequiredService<IInvestigationCreateRepository>().CreateAsync(input,InvestigationAccess.Actor(principal),CancellationToken.None);
            var rendered=InvestigationCaseRenderer.Render(new(result,false),access,services.GetRequiredService<IInvestigationVpnEvidence>());
            string locale=DomainHttp.SelectEnglish(context.Request.Headers.AcceptLanguage.ToString())?"en":"ru";
            using var stream=typeof(InvestigationCreateEndpoints).Assembly.GetManifestResourceStream("Sli.Server.Access.Administration.server."+locale+".json")??throw new InvalidOperationException("Presentation catalog missing");
            var catalog=JsonSerializer.Deserialize<Dictionary<string,string>>(stream)??throw new InvalidOperationException("Invalid presentation catalog");
            string code="investigations.caseStatus."+rendered["status"]!.GetValue<string>();
            if(catalog.TryGetValue(code,out var label))rendered["status_message"]=new JsonObject { ["code"]=code,["params"]=new JsonObject(),["text"]=label };
            await DomainHttp.WriteAsync(context,rendered,201,ct);
        }
        catch(InvestigationException error){if(error.Code=="invalid_event_db_id")await DomainHttp.WriteAsync(context,new {error="invalid_event_db_id"},400,ct);else await DomainHttp.WriteAsync(context,new {error=error.Code,message=error.Message},error.Status,ct);}
        catch(AuthInputException error){await AuthResponse.ErrorAsync(context,error.Code,error.StatusCode,ct,login:false);}
        catch(OperationCanceledException) when(ct.IsCancellationRequested){}
        catch(Exception error){if(context.Response.HasStarted)throw;await AuthResponse.UnexpectedAsync(context,error,ct,login:false);}
    }
}
