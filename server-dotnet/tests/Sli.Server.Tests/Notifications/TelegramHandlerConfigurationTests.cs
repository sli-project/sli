using System.Net;
using Sli.Server.Notifications;
using Xunit;

namespace Sli.Server.Tests.Notifications;

public class TelegramHandlerConfigurationTests
{
    [Fact]
    public void ProductionHandlerDisablesPersistentCookies()
    {
        var state = new TelegramRequestState();
        using var handler = TelegramWorkerCommand.CreateHandler(state);
        Assert.False(handler.UseCookies);
        Assert.False(handler.AllowAutoRedirect);
        Assert.Equal(DecompressionMethods.None, handler.AutomaticDecompression);
        Assert.Equal(32, handler.MaxResponseHeadersLength);
        Assert.Equal(TimeSpan.FromSeconds(5), handler.ConnectTimeout);
        Assert.True(handler.UseProxy);
        Assert.Same(state, handler.Proxy);
        Assert.NotNull(handler.PlaintextStreamFilter);
    }
}
