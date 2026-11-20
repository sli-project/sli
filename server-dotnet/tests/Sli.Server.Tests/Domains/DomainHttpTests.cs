using System.Text;
using System.Text.Json;
using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Sli.Server.Auth;
using Sli.Server.Domains;
using Xunit;

namespace Sli.Server.Tests.Domains;

public sealed class DomainHttpTests
{
    [Theory]
    [InlineData("ru", "Необходимо войти в систему.")]
    [InlineData("en-US,en;q=0.9", "Sign in to continue.")]
    [InlineData("ru;q=0.2,en;q=0.9", "Sign in to continue.")]
    [InlineData("zz-ZZ", "Необходимо войти в систему.")]
    public async Task AuthenticationMessageFollowsLanguageWeights(string language, string expected)
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.AcceptLanguage = language;
        context.Response.Body = new MemoryStream();
        await DomainHttp.WriteFailureAsync(context, new AuthenticationFailure(401, "authentication_required"), CancellationToken.None);
        byte[] bytes = ((MemoryStream)context.Response.Body).ToArray();
        using var json = JsonDocument.Parse(bytes);
        Assert.Equal(expected, json.RootElement.GetProperty("message").GetProperty("text").GetString());
        Assert.DoesNotContain("\r\n", Encoding.UTF8.GetString(bytes));
        Assert.Equal(bytes.Length, context.Response.ContentLength);
    }

    [Theory]
    [InlineData("http", null, "127.0.0.1", false)]
    [InlineData("https", null, "127.0.0.1", true)]
    [InlineData("http", "https", "127.0.0.1", true)]
    [InlineData("http", "https", "192.0.2.3", false)]
    [InlineData("https", "http", "127.0.0.1", false)]
    [InlineData("http", "duplicate", "127.0.0.1", false)]
    public async Task HstsUsesTheSameTrustedExternalScheme(string scheme, string? forwarded, string peer, bool expected)
    {
        IConfiguration config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Sli:TrustedProxies"] = "127.0.0.1/32"
        }).Build();
        using var services = new ServiceCollection().AddSingleton(new TransportGate(config)).BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services };
        context.Connection.RemoteIpAddress = IPAddress.Parse(peer);
        context.Request.Scheme = scheme;
        if (forwarded is not null)
        {
            context.Request.Headers["X-Forwarded-Proto"] = forwarded == "duplicate"
                ? new StringValues(["https", "http"]) : forwarded;
        }
        context.Response.Body = new MemoryStream();
        await DomainHttp.WriteAsync(context, new { ok = true }, 200, CancellationToken.None);
        if (expected)
            Assert.Equal("max-age=15552000; includeSubDomains", context.Response.Headers.StrictTransportSecurity.ToString());
        else
            Assert.False(context.Response.Headers.ContainsKey("Strict-Transport-Security"));
    }

    [Fact]
    public async Task FailureLogUsesResponseIdWithoutExceptionSecrets()
    {
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        var logger = new RecordingLogger();
        await DomainHttp.WriteUnexpectedAsync(context, logger, new InvalidOperationException("secret-cookie-synthetic"), CancellationToken.None);
        using var json = JsonDocument.Parse(((MemoryStream)context.Response.Body).ToArray());
        string? id = json.RootElement.GetProperty("internal_error_id").GetString();
        Assert.Single(logger.Messages);
        Assert.Contains(id!, logger.Messages[0]);
        Assert.Contains("InvalidOperationException", logger.Messages[0]);
        Assert.DoesNotContain("secret-cookie-synthetic", logger.Messages[0]);
        Assert.Equal(500, context.Response.StatusCode);
    }

    private sealed class RecordingLogger : ILogger
    {
        public List<string> Messages { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => Messages.Add(formatter(state, exception));
    }
}
