using System.Net;
using System.Text.Json;
using Sli.Server.Notifications;
using Xunit;
namespace Sli.Server.Tests.Notifications;
public class TelegramSenderTests
{
    private sealed class Factory(HttpMessageHandler handler):IHttpClientFactory {public HttpClient CreateClient(string name)=>new(handler,false);}
    private sealed class Fake(Func<HttpRequestMessage,Task<HttpResponseMessage>> action):HttpMessageHandler
    {protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)=>action(request);}
    [Fact] public async Task AcceptedOnlyAfterProviderConfirmationAndJsonUsesReferenceOnly()
    {
        var state=new TelegramRequestState();
        var fake=new Fake(async request=>{
            Assert.Equal("api.telegram.org",request.RequestUri!.Host);Assert.Equal(HttpMethod.Post,request.Method);
            using var body=JsonDocument.Parse(await request.Content!.ReadAsStringAsync());
            Assert.Equal("-123",body.RootElement.GetProperty("chat_id").GetString());
            Assert.Equal("reference only",body.RootElement.GetProperty("text").GetString());
            Assert.True(body.RootElement.GetProperty("protect_content").GetBoolean());
            Assert.True(body.RootElement.GetProperty("link_preview_options").GetProperty("is_disabled").GetBoolean());
            Assert.False(body.RootElement.TryGetProperty("parse_mode",out _));state.MarkConnected();
            return new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent("{\"ok\":true,\"result\":{\"message_id\":1}}")};
        });
        var sender=new TelegramSender(new Factory(fake),state);
        Assert.Equal("accepted",(await sender.SendAsync(new("https://example.invalid","-123","1:synthetic",""),"reference only",CancellationToken.None)).Code);
    }
    [Theory] [InlineData(false,"telegram_unavailable")] [InlineData(true,"telegram_outcome_unknown")]
    public async Task FailedSubmissionIsNeverAcknowledged(bool connected,string expected)
    {
        var state=new TelegramRequestState();var fake=new Fake(_=>{if(connected)state.MarkConnected();throw new HttpRequestException();});
        Assert.Equal(expected,(await new TelegramSender(new Factory(fake),state).SendAsync(new("https://example.invalid","-123","1:synthetic",""),"reference",CancellationToken.None)).Code);
    }
    [Fact] public async Task OversizedBodyIsUnknownEvenIfItBeginsWithAcceptedResponse()
    {
        var state=new TelegramRequestState();var fake=new Fake(_=>{state.MarkConnected();return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(new string('x',32769))});});
        Assert.Equal("telegram_outcome_unknown",(await new TelegramSender(new Factory(fake),state).SendAsync(new("https://example.invalid","-123","1:synthetic",""),"reference",CancellationToken.None)).Code);
    }}
