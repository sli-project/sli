using System.Globalization;
using System.Text.Json;
namespace Sli.Server.Notifications;
public sealed record NotificationJob(Guid Id,Guid Subscription,long Revision,string Kind,Guid ObjectId,long Recipient,int Attempts,Guid Lease,DateTime Created,string? Severity,string Reason,int Delay)
{
    public string? Channel {get;init;}
    public JsonElement? ReportRun {get;init;}
    public long? ReportChannelRevision {get;init;}
}
public static class NotificationMessage
{
    private static readonly IReadOnlyDictionary<string,string> Russian=Load();
    private static IReadOnlyDictionary<string,string> Load()
    {
        using var stream=typeof(NotificationMessage).Assembly.GetManifestResourceStream("Sli.Server.Access.Administration.server.ru.json") ?? throw new InvalidOperationException();
        return JsonSerializer.Deserialize<Dictionary<string,string>>(stream) ?? throw new InvalidOperationException();
    }
    public static string Format(NotificationJob job,string baseUrl,long? finding,string? kind)
    {
        if(job.Kind=="report_schedule")return ReportScheduleDelivery.Digest(job,baseUrl);
        string body,target,identity;
        if(job.Kind=="test_problem") {body="Category: simulated test problem\nSeverity: informational\n";target="/report/notifications.deliveries";identity=job.ObjectId.ToString();}
        else if(job.Kind=="semantic_finding" && finding is >0) {
            string suffix=kind is "remote_access" or "account_decoy" or "file_decoy" or "account_watch" ? "."+kind : "";
            body=Russian["notifications.problem"+suffix+".what"]+"\n"+Russian["notifications.problem"+suffix+".action"]+"\n";
            if(job.Severity is not null) {if(job.Severity is not ("info" or "low" or "medium" or "high" or "critical"))throw new FormatException();body+=$"Severity: {job.Severity}\n";}
            if(job.Reason=="pipeline_delay") {if(job.Delay<15)throw new FormatException();body+=("delayed by "+job.Delay.ToString(CultureInfo.InvariantCulture)+" min")+"\n";}
            identity=finding.Value.ToString(CultureInfo.InvariantCulture);target="/report/security.problems?id="+identity;
        } else throw new FormatException();
        // Python str(datetime) omits fractional seconds only when exactly zero.
        var time=job.Created.ToUniversalTime();string stamp=time.ToString("yyyy-MM-dd HH:mm:ss",CultureInfo.InvariantCulture);
        if(time.Ticks%TimeSpan.TicksPerSecond!=0)stamp+="."+(time.Ticks%TimeSpan.TicksPerSecond/10).ToString("D6",CultureInfo.InvariantCulture);
        return body+$"Time: {stamp}+00:00\nProblem: {identity}\nJob: {job.Id}\n{baseUrl.TrimEnd('/')}{target}\n";
    }
}
