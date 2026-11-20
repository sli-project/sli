using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
namespace Sli.Server.Notifications;

public interface IReportScheduleRepository
{
    Task<IReadOnlyList<JsonObject>> ListAsync(bool runs,CancellationToken ct);
    Task<JsonObject> SaveAsync(Principal actor,Guid? id,ReportScheduleInput input,CancellationToken ct);
}
public static class ReportScheduleEndpoints
{
    public static IServiceCollection AddReportSchedules(this IServiceCollection s)
    {s.TryAddScoped<IAccessFactsRepository,AccessFactsRepository>();s.TryAddScoped<IReportScheduleRepository,ReportScheduleRepository>();return s;}
    public static IEndpointRouteBuilder MapReportSchedules(this IEndpointRouteBuilder e)
    {
        const string prefix="/api/v1/notification-subscriptions/";
        e.MapGet(prefix+"schedules",HandleAsync);e.MapGet(prefix+"runs",HandleAsync);
        e.MapPost(prefix+"schedules",HandleAsync);e.MapPost(prefix+"schedules/{**scheduleId}",HandleAsync);return e;
    }
    public static async Task HandleAsync(HttpContext context)
    {
        var ct=context.RequestAborted;
        try {
            var s=context.RequestServices;var transport=s.GetRequiredService<TransportGate>().CheckTransport(context);
            if(transport is not null){await DomainHttp.WriteAsync(context,new {error=transport.Code},transport.StatusCode,ct);return;}
            bool write=HttpMethods.IsPost(context.Request.Method);
            var policy=s.GetRequiredService<AuthRequestPolicy>();
            if(write && !policy.OriginAllowed(context,policy.Resolve(context))){await DomainHttp.WriteAsync(context,new {error="cross_origin_request_rejected"},403,ct);return;}
            var auth=await s.GetRequiredService<IPrincipalAuthenticator>().AuthenticateAsync(context,ct);
            if(!auth.Succeeded){await DomainHttp.WriteAsync(context,new {error=auth.Failure?.Code??"authentication_required"},auth.Failure?.StatusCode??401,ct);return;}
            var principal=auth.Principal!;
            if(write && principal.Role!="admin"){await DomainHttp.WriteAsync(context,new {error="insufficient_permissions"},403,ct);return;}
            if(write && principal.Type!="session")throw new ReportScheduleException("notifications_access_denied");
            var facts=await s.GetRequiredService<IAccessFactsRepository>().LoadAsync(principal,ct);var caps=new CapabilityComposer().Compose(facts);var access=new ReportEligibility().Compose(facts,caps);
            if(!ReportScheduleAccess.Configure(access,write?"configure_channel":"view"))throw new ReportScheduleException("notifications_access_denied");
            var repository=s.GetRequiredService<IReportScheduleRepository>();
            if(!write){var items=await repository.ListAsync(context.Request.Path.Value!.EndsWith("/runs",StringComparison.Ordinal),ct);await DomainHttp.WriteAsync(context,new {items},200,ct);return;}
            string? raw=context.Request.RouteValues["scheduleId"]?.ToString();Guid? id=string.IsNullOrEmpty(raw)?null:ReportScheduleInput.Identifier(raw);
            using var body=await AuthJsonBody.ReadAsync(context,ct);var input=ReportScheduleInput.Parse(body.RootElement,id.HasValue);
            var item=await repository.SaveAsync(principal,id,input,CancellationToken.None);await DomainHttp.WriteAsync(context,new {item},200,ct);
        }
        catch(ReportScheduleException e){await DomainHttp.WriteAsync(context,new {error=e.Code},e.Status,ct);}
        catch(Exception e) when(e is AuthInputException or JsonException){await DomainHttp.WriteAsync(context,new {error="invalid_notification_request"},400,ct);}
        catch(OperationCanceledException) when(ct.IsCancellationRequested){}
        catch {if(context.Response.HasStarted)throw;await DomainHttp.WriteAsync(context,new {error="notifications_unavailable"},503,ct);}
    }
}
