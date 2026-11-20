using Sli.Server.Notifications;
using Xunit;
namespace Sli.Server.Tests.Notifications;
public class TelegramContractTests
{
    [Theory]
    [InlineData(200,"{\"ok\":true,\"result\":{\"message_id\":1}}","accepted",0)]
    [InlineData(200,"{\"ok\":true}","telegram_outcome_unknown",0)]
    [InlineData(429,"{\"ok\":false,\"error_code\":429,\"parameters\":{\"retry_after\":90}}","telegram_rate_limited",90)]
    [InlineData(403,"{\"ok\":false,\"error_code\":403}","telegram_chat_denied",0)]
    [InlineData(500,"garbage","telegram_outcome_unknown",0)]
    public void ProviderResponsesAreNeverGuessed(int status,string body,string code,int seconds)
    {
        var outcome=TelegramTransport.ParseResponse(status,body,0);
        Assert.Equal(code,outcome.Code); Assert.Equal(seconds,outcome.RetryAfter);
    }
}
