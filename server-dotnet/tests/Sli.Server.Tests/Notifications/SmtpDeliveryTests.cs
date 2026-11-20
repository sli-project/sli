using System.Text;
using Sli.Server.Notifications;
using Xunit;
namespace Sli.Server.Tests.Notifications;
public class SmtpDeliveryTests
{
    [Fact] public void SnapshotRequiresExactRevisionAndDigest()
    {
        const string config="{\"host\":\"mail.invalid\",\"port\":465,\"username\":\"svc\",\"sender\":\"svc@example.com\",\"recipients\":{\"7\":\"test@example.com\"},\"base_url\":\"https://sli.invalid\"}";
        var env=new Dictionary<string,string>{{"SLI_NOTIFICATION_SMTP_CONFIG_FILE","/private/smtp.json"},{"SLI_NOTIFICATION_SMTP_PASSWORD_FILE",Path.Combine(Path.GetDirectoryName("/private/smtp.json")!,"notification_smtp_password")}};
        var files=new Dictionary<string,string>{{"/private/smtp.json",config},{"/private/notification_smtp_password","password"},{"/private/smtp.ready","{\"revision\":3,\"digest\":\"d0ce54ca360d8eb65390516c2dc089645c1344325df1c0d5736b29e5e1fd520c\"}"}};
        byte[] Read(string p)=>Encoding.UTF8.GetBytes(files[p.Replace('\\','/')]);
        var settings=SmtpSettingsReader.Read(7,3,k=>env.GetValueOrDefault(k),Read);
        Assert.Equal("test@example.com",settings.Recipient);
        Assert.Throws<FormatException>(()=>SmtpSettingsReader.Read(7,4,k=>env.GetValueOrDefault(k),Read));
        files["/private/notification_smtp_password"]="other";
        Assert.Throws<FormatException>(()=>SmtpSettingsReader.Read(7,3,k=>env.GetValueOrDefault(k),Read));
        files["/private/notification_smtp_password"]="password";
        env["SLI_NOTIFICATION_SMTP_PASSWORD"]="forbidden";
        Assert.Throws<FormatException>(()=>SmtpSettingsReader.Read(7,3,k=>env.GetValueOrDefault(k),Read));
        env.Remove("SLI_NOTIFICATION_SMTP_PASSWORD");
        Assert.Throws<FormatException>(()=>SmtpSettingsReader.Read(8,3,k=>env.GetValueOrDefault(k),Read));
    }
    [Theory] [InlineData(450,"smtp_unavailable")] [InlineData(550,"smtp_rejected")]
    public void RepliesDistinguishTransientAndPermanent(int status,string expected)=>Assert.Equal(expected,SmtpOutcome.Reply(status,false));
    [Theory] [InlineData(454,"smtp_unavailable")] [InlineData(535,"smtp_auth_failed")]
    public void AuthRepliesDistinguishTransientAndPermanent(int status,string expected)=>Assert.Equal(expected,SmtpOutcome.Reply(status,true));
    [Fact] public void UncertainSubmissionIsNeverSuccessOrRetry()
    {Assert.Equal("delivery_unknown",SmtpOutcome.State("smtp_outcome_unknown"));Assert.Equal("failed",SmtpOutcome.State("smtp_rejected"));}
    [Fact] public void ClaimKeepsSmtpChannelAndIncludesReports()
    {Assert.Contains("channel='smtp'",SmtpWorker.ClaimSql);Assert.Contains("'test_problem','semantic_finding'",SmtpWorker.ClaimSql);Assert.Contains("report_schedule",SmtpWorker.ClaimSql);Assert.DoesNotContain("telegram",SmtpWorker.ClaimSql);}

    [Fact] public void ResponseBudgetCountsBytesAcrossTheSession()
    {
        using var budget=new SmtpResponseBudget();var block=new byte[65536];
        budget.LogClient(block,0,block.Length);budget.LogServer(block,0,block.Length);
        Assert.Throws<IOException>(()=>budget.LogServer(block,0,1));
    }
    [Fact] public void SettingsStringNeverExposesCredentials()
    {
        var settings=new SmtpSettings("mail.invalid",465,"user-secret","sender@example.com","target@example.com","https://sli.invalid","password-secret","");
        Assert.DoesNotContain("secret",settings.ToString());Assert.DoesNotContain("example.com",settings.ToString());
    }
    [Theory]
    [InlineData("connect", "smtp_unavailable")]
    [InlineData("send", "smtp_outcome_unknown")]
    [InlineData("auth-temp", "smtp_unavailable")]
    [InlineData("auth-perm", "smtp_auth_failed")]
    [InlineData("send-temp", "smtp_unavailable")]
    [InlineData("send-perm", "smtp_rejected")]
    [InlineData("bug", "smtp_outcome_unknown")]
    [InlineData("ok", "accepted")]
    [InlineData("dispose-bug", "accepted")]
    public async Task SenderDistinguishesPreSendAndUncertainSubmission(string phase,string expected)
    {
        var session=new FakeSession(phase);
        var sender=new SmtpSender(new FakeFactory(session));
        var settings=new SmtpSettings("mail.invalid",465,"svc","svc@example.com","to@example.com","https://sli.invalid","synthetic","");
        var job=new NotificationJob(Guid.NewGuid(),Guid.NewGuid(),1,"test_problem",Guid.NewGuid(),7,1,Guid.NewGuid(),DateTime.UtcNow,null,"live",0);
        var result=await sender.SendAsync(settings,"tls",job,"synthetic",CancellationToken.None);
        Assert.Equal(expected,result.Code);Assert.Equal(phase=="bug",result.InternalError);
        Assert.Equal(phase!="connect" && !phase.StartsWith("auth-"),session.SendCalled);
        if(phase=="ok") {
            Assert.Equal("tls",session.Tls);Assert.Equal("SLI: simulated test problem",session.Message!.Subject);
            Assert.Equal(job.Id+"@notifications.sli.invalid",session.Message.MessageId);
            Assert.Equal("synthetic",session.Message.TextBody);
        }
        if(phase=="bug")Assert.Equal("delivery_unknown",SmtpOutcome.State(result.Code));
    }
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task InvalidMailboxPreparationBlocksBeforeSessionCreation(bool invalidSender)
    {
        var factory=new CountingFactory();var sender=new SmtpSender(factory);
        var settings=new SmtpSettings("mail.invalid",465,"svc",invalidSender?".synthetic@example.com":"svc@example.com",invalidSender?"to@example.com":".synthetic@example.com","https://sli.invalid","synthetic","");
        var job=new NotificationJob(Guid.NewGuid(),Guid.NewGuid(),1,"test_problem",Guid.NewGuid(),7,1,Guid.NewGuid(),DateTime.UtcNow,null,"live",0);
        var result=await sender.SendAsync(settings,"tls",job,"synthetic",CancellationToken.None);
        Assert.Equal("smtp_not_configured",result.Code);Assert.Equal("blocked",SmtpOutcome.State(result.Code));
        Assert.False(result.InternalError);Assert.Equal(0,factory.Calls);
    }
    [Fact]
    public async Task ParserFailureInsideSendRemainsUnknown()
    {
        var session=new ParseFailureSession();var sender=new SmtpSender(new ParseFailureFactory(session));
        var settings=new SmtpSettings("mail.invalid",465,"svc","svc@example.com","to@example.com","https://sli.invalid","synthetic","");
        var job=new NotificationJob(Guid.NewGuid(),Guid.NewGuid(),1,"test_problem",Guid.NewGuid(),7,1,Guid.NewGuid(),DateTime.UtcNow,null,"live",0);
        var result=await sender.SendAsync(settings,"tls",job,"synthetic",CancellationToken.None);
        Assert.True(session.SendCalled);Assert.Equal("smtp_outcome_unknown",result.Code);Assert.True(result.InternalError);
        Assert.Equal("delivery_unknown",SmtpOutcome.State(result.Code));
    }
    private sealed class CountingFactory:ISmtpSessionFactory
    {
        public int Calls {get;private set;}
        public ISmtpSession Create(Action progress){Calls++;throw new InvalidOperationException();}
    }
    private sealed class ParseFailureFactory(ParseFailureSession session):ISmtpSessionFactory {public ISmtpSession Create(Action progress)=>session;}
    private sealed class ParseFailureSession:ISmtpSession
    {
        public bool SendCalled {get;private set;}
        public Task ConnectAsync(SmtpSettings settings,string tls,CancellationToken ct)=>Task.CompletedTask;
        public Task AuthenticateAsync(SmtpSettings settings,CancellationToken ct)=>Task.CompletedTask;
        public Task SendAsync(MimeKit.MimeMessage message,CancellationToken ct){SendCalled=true;MimeKit.MailboxAddress.Parse(".synthetic@example.com");return Task.CompletedTask;}
        public void Dispose(){}
    }
    private sealed class FakeFactory(FakeSession session):ISmtpSessionFactory {public ISmtpSession Create(Action progress)=>session;}
    private sealed class FakeSession(string phase):ISmtpSession
    {
        public bool SendCalled {get;private set;}
        public string? Tls {get;private set;}
        public MimeKit.MimeMessage? Message {get;private set;}
        public Task ConnectAsync(SmtpSettings settings,string tls,CancellationToken ct){Tls=tls;return phase=="connect"?Task.FromException(new IOException()):Task.CompletedTask;}
        public Task AuthenticateAsync(SmtpSettings settings,CancellationToken ct)
        {
            if(phase.StartsWith("auth-"))return Task.FromException(new MailKit.Security.AuthenticationException("synthetic",Reply(phase=="auth-temp"?454:535)));
            return Task.CompletedTask;
        }
        private static MailKit.Net.Smtp.SmtpCommandException Reply(int code)=>new(MailKit.Net.Smtp.SmtpErrorCode.UnexpectedStatusCode,(MailKit.Net.Smtp.SmtpStatusCode)code,"synthetic");
        public Task SendAsync(MimeKit.MimeMessage message,CancellationToken ct){SendCalled=true;Message=message;return phase=="send"?Task.FromException(new IOException()):phase=="bug"?Task.FromException(new InvalidOperationException()):phase.StartsWith("send-")?Task.FromException(Reply(phase=="send-temp"?450:550)):Task.CompletedTask;}
        public void Dispose(){if(phase=="dispose-bug")throw new IOException();}
    }
}
