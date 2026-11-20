using System.Text;
using Sli.Server.Notifications;
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
        Assert.Equal("Category: simulated test problem\nSeverity: informational\nTime: 2026-01-01 00:00:00+00:00\nProblem: 00000000-0000-0000-0000-000000000002\nJob: 00000000-0000-0000-0000-000000000001\nhttps://sli.invalid/report/notifications.deliveries\n",NotificationMessage.Format(j,"https://sli.invalid",null,null));
    }
    [Fact] public void SemanticMessageMatchesFrozenPythonVector()
    {
        var j=new NotificationJob(Guid.Parse("00000000-0000-0000-0000-000000000001"),Guid.Empty,1,"semantic_finding",Guid.Parse("00000000-0000-0000-0000-000000000002"),7,1,Guid.Empty,new DateTime(2026,1,1,0,0,0,DateTimeKind.Utc),"high","pipeline_delay",15);
        string text=NotificationMessage.Format(j,"https://sli.invalid",42,"remote_access");
        Assert.Equal("6ed35ada4d03fbccdcee4ea07a6d7c0681c4768b3b1006dbc80cbc9bceb14b3e",Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(text))));
    }    [Fact] public void RecipientRequiresAtomicGlobalSecurityQueueGrant()
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
