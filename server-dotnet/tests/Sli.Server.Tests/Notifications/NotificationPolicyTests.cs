using System.Text;
using System.Text.Json.Nodes;
using Sli.Server.Notifications;
using Sli.Server.Problems;
using Sli.Server.Tests.Problems;
using Xunit;
namespace Sli.Server.Tests.Notifications;
public class NotificationPolicyTests
{
    [Theory] [InlineData(1,0,"retry",60)] [InlineData(2,600,"retry",600)] [InlineData(4,0,"retry",3600)] [InlineData(5,0,"failed",3600)]
    public void RetryScheduleAndLimit(int attempt,int provider,string expected,int delay)
    {Assert.Equal((expected,delay),TelegramWorker.Completion("retry",attempt,provider));}
    [Theory] [InlineData("accepted","accepted")] [InlineData("telegram_unavailable","retry")] [InlineData("telegram_outcome_unknown","delivery_unknown")] [InlineData("telegram_auth_failed","blocked")]
    public void OutcomesNeverGuessProviderAcceptance(string code,string state)=>Assert.Equal(state,TelegramWorker.OutcomeState(code));
    [Fact] public void ClaimIncludesReportsAndKeepsTelegramFencing()
    {
        Assert.Contains("channel='telegram'",TelegramWorker.ClaimSql);Assert.Contains("'test_problem','semantic_finding'",TelegramWorker.ClaimSql);
        Assert.Contains("for update skip locked",TelegramWorker.ClaimSql);Assert.Contains("lease_token=@token",TelegramWorker.ClaimSql);Assert.Contains("60 seconds",TelegramWorker.ClaimSql);
        Assert.Contains("report_schedule",TelegramWorker.ClaimSql);Assert.DoesNotContain("smtp",TelegramWorker.ClaimSql);
    }
    [Fact] public void SyntheticFileSettingsRequireSecretFileAndUserMapping()
    {
        var values=new Dictionary<string,string>{{"SLI_NOTIFICATION_TELEGRAM_CONFIG_FILE","config"},{"SLI_NOTIFICATION_TELEGRAM_TOKEN_FILE","token"}};
        byte[] Read(string key)=>Encoding.UTF8.GetBytes(key=="config"?"{\"base_url\":\"https://sli.invalid\",\"recipients\":{\"7\":\"-123\"}}":"1:synthetic\n");
        var setting=TelegramSettingsReader.Read(7,k=>values.GetValueOrDefault(k),Read);
        Assert.Equal("-123",setting.Chat);Assert.Equal("1:synthetic",setting.Token);
        values["SLI_NOTIFICATION_TELEGRAM_TOKEN"]="synthetic";
        Assert.Throws<FormatException>(()=>TelegramSettingsReader.Read(7,k=>values.GetValueOrDefault(k),Read));
    }
    [Fact] public void TestMessageContainsOnlyFixedReferences()
    {
        var j=new NotificationJob(Guid.Parse("00000000-0000-0000-0000-000000000001"),Guid.Empty,1,"test_problem",Guid.Parse("00000000-0000-0000-0000-000000000002"),7,1,Guid.Empty,new DateTime(2026,1,1,0,0,0,DateTimeKind.Utc),null,"live",0);
        Assert.Equal("SLI test message: alerts work.\nhttps://sli.invalid/app/report/notifications.deliveries",NotificationMessage.Format(j,"https://sli.invalid",null,null,"en"));
    }
    [Theory]
    [InlineData("en", "High", "First seen", "delivered 15 min late")]
    [InlineData("ru", "Высокая", "Впервые", "доставлено с задержкой на 15 мин")]
    public void BruteForceAlertUsesTheQueueTitleAndAction(string language, string severity, string firstSeen, string delay)
    {
        var j=new NotificationJob(Guid.Parse("00000000-0000-0000-0000-000000000001"),Guid.Empty,1,"semantic_finding",Guid.Parse("00000000-0000-0000-0000-000000000002"),7,1,Guid.Empty,new DateTime(2026,1,1,0,0,0,DateTimeKind.Utc),"high","pipeline_delay",15);
        var finding = JsonNode.Parse("""
            {"id":42,"rule_code":"semantic.qw.password-brute-force","severity":"high",
             "first_seen_utc":"2026-11-21T20:00:15.331082+00:00","occurrence_count":12,
             "presentation_facts":{"account":"Administrator","source":"192.0.2.10","count":12}}
            """)!.AsObject();
        var access = ProblemLifecycleTests.Access("security.queue", fields: ["security", "identity_basic", "technical"]);
        var queue = ProblemPresentation.Finding(finding, access, language, queue: true, includeDescription: true);
        string text = NotificationMessage.Format(j, "https://sli.invalid/app", finding, access, language, TimeZoneInfo.FindSystemTimeZoneById("Asia/Bangkok"));
        var lines = text.Split('\n');
        Assert.Equal(4, lines.Length);
        Assert.Equal($"{severity} · {queue["title_text"]}", lines[0]);
        Assert.Contains("Administrator", lines[1]); Assert.Contains("192.0.2.10", lines[1]); Assert.Contains("12", lines[1]);
        Assert.Contains($"{firstSeen}: 22.11 03:00", lines[1]); Assert.Contains(delay, lines[1]);
        Assert.Equal(queue["next_text"]!.ToString(), lines[2]);
        Assert.Equal("https://sli.invalid/app/report/security.problems?id=42", lines[3]);
        Assert.DoesNotContain(j.Id.ToString(), text); Assert.DoesNotContain(j.ObjectId.ToString(), text);
        Assert.DoesNotContain("+00:00", text);
        var restricted = ProblemLifecycleTests.Access("security.queue", fields: ["security"]);
        var redacted = NotificationMessage.Format(j, "https://sli.invalid/app", finding, restricted, language);
        Assert.DoesNotContain("Administrator", redacted); Assert.DoesNotContain("192.0.2.10", redacted);
    }
    [Fact] public void RecipientRequiresAtomicGlobalSecurityQueueGrant()
    {
        var caps=new Sli.Server.Access.CapabilityDecisionSet(false,new HashSet<string>(),new HashSet<string>(),[],new Dictionary<string,System.Text.Json.JsonElement>());
        Sli.Server.Access.AccessDecision Decision(string scope,string field) => new("viewer",caps,[new("security.queue",true,[new(System.Text.Json.JsonSerializer.SerializeToElement(new {kind=scope}),new HashSet<string>{field},new HashSet<string>{"view"},1,1)])]);
        var fields=new HashSet<string>{"security"};
        Assert.True(Sli.Server.Access.ResourceAccessDecisions.ReportAction(Decision("all","security"),"security.queue","view",null,fields).Allowed);
        Assert.False(Sli.Server.Access.ResourceAccessDecisions.ReportAction(Decision("all","technical"),"security.queue","view",null,fields).Allowed);
        Assert.False(Sli.Server.Access.ResourceAccessDecisions.ReportAction(Decision("domain","security"),"security.queue","view",null,fields).Allowed);
    }
    [Theory] [InlineData("http://proxy.invalid:80",true)] [InlineData("http://999.1.1.1:80",false)] [InlineData("http://name_with_underscore:80",false)] [InlineData("http://proxy.invalid:80/",false)]
    public void ProxyMustMatchFrozenCredentialFreeContract(string proxy,bool valid)
    {
        var e=Record.Exception(()=>TelegramSettingsReader.ValidateProxy(proxy));Assert.Equal(valid,e is null);
    }}
