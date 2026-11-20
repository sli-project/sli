using System.Net.Sockets;
using MailKit;
using MailKit.Net.Proxy;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
namespace Sli.Server.Notifications;
public interface ISmtpSession : IDisposable
{
    Task ConnectAsync(SmtpSettings settings,string tls,CancellationToken ct);
    Task AuthenticateAsync(SmtpSettings settings,CancellationToken ct);
    Task SendAsync(MimeMessage message,CancellationToken ct);
}
public interface ISmtpSessionFactory {ISmtpSession Create(Action progress);}
public sealed class MailKitSmtpSessionFactory:ISmtpSessionFactory {public ISmtpSession Create(Action progress)=>new MailKitSmtpSession(progress);}
public sealed class SmtpResponseBudget(Action? progress=null):IProtocolLogger
{
    private long count;
    public IAuthenticationSecretDetector? AuthenticationSecretDetector {get;set;}
    public void LogConnect(Uri uri){}
    public void LogClient(byte[] buffer,int offset,int count){progress?.Invoke();}
    public void LogServer(byte[] buffer,int offset,int count){progress?.Invoke();this.count+=count;if(this.count>65536)throw new IOException("smtp_response_limit");}
    public void Dispose(){}
}
internal sealed class MailKitSmtpSession(Action progress):ISmtpSession
{
    private readonly SmtpClient client=new(new SmtpResponseBudget(progress)){Timeout=5000};
    public async Task ConnectAsync(SmtpSettings settings,string tls,CancellationToken ct)
    {
        client.LocalDomain=settings.Sender[(settings.Sender.LastIndexOf('@')+1)..];
        if(settings.Proxy.Length>0){var proxy=new Uri(settings.Proxy);client.ProxyClient=new HttpProxyClient(proxy.Host,proxy.Port);}
        await client.ConnectAsync(settings.Host,settings.Port,tls=="tls"?SecureSocketOptions.SslOnConnect:SecureSocketOptions.StartTls,ct);
    }
    public Task AuthenticateAsync(SmtpSettings settings,CancellationToken ct)=>client.AuthenticateAsync(settings.User,settings.Password,ct);
    public async Task SendAsync(MimeMessage message,CancellationToken ct)=>await client.SendAsync(message,ct);
    public void Dispose()=>client.Dispose();
}
internal sealed class SmtpSessionCleanup(ISmtpSession session):IDisposable
{
    public void Dispose(){try {session.Dispose();} catch {}}
}
public sealed record SmtpResult(string Code,bool InternalError=false);
public sealed class SmtpSender(ISmtpSessionFactory factory)
{
    public async Task<SmtpResult> SendAsync(SmtpSettings settings,string tls,NotificationJob job,string text,CancellationToken ct)
    {
        MimeMessage message;
        try {
            var sender=MailboxAddress.Parse(settings.Sender);var recipient=MailboxAddress.Parse(settings.Recipient);
            message=new MimeMessage();message.From.Add(sender);message.To.Add(recipient);
            message.Subject=job.Kind=="report_schedule"?"SLI: "+ReportScheduleDelivery.Title(job.ReportRun??throw new FormatException()):job.Kind=="test_problem"?"SLI: simulated test problem":"SLI: security problem"+(job.Reason=="pipeline_delay"?" (delayed by "+job.Delay+" min)":"");
            message.MessageId=job.Id+"@notifications.sli.invalid";message.Date=DateTimeOffset.UtcNow;
            message.Body=new TextPart("plain"){Text=text};
        } catch(Exception e) when(e is ParseException or ArgumentException or FormatException) {
            return new("smtp_not_configured");
        }
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ct);deadline.CancelAfter(TimeSpan.FromSeconds(30));
        using var idle=CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);idle.CancelAfter(TimeSpan.FromSeconds(5));
        var client=factory.Create(()=>idle.CancelAfter(TimeSpan.FromSeconds(5)));
        using var cleanup=new SmtpSessionCleanup(client);
        try {
            await client.ConnectAsync(settings,tls,idle.Token);
            await client.AuthenticateAsync(settings,idle.Token);
        } catch(MailKit.Security.AuthenticationException e) {return new(e.InnerException is SmtpCommandException sc?SmtpOutcome.Reply((int)sc.StatusCode,true):"smtp_auth_failed");}
        catch(SmtpCommandException e){return new(SmtpOutcome.Reply((int)e.StatusCode,false));}
        catch(Exception e) when(e is IOException or SocketException or SmtpProtocolException or OperationCanceledException or SslHandshakeException or NotSupportedException or System.Security.Authentication.AuthenticationException){return new("smtp_unavailable");}
        try {await client.SendAsync(message,idle.Token);return new("accepted");}
        catch(SmtpCommandException e){return new(SmtpOutcome.Reply((int)e.StatusCode,false));}
        catch(Exception e) when(e is IOException or SmtpProtocolException or OperationCanceledException){return new("smtp_outcome_unknown");}
        catch {return new("smtp_outcome_unknown",InternalError:true);}
    }
}
