using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Sli.Server.Auth;
using Xunit;

namespace Sli.Server.Tests.Domains;

public sealed class ProgramFailureTests
{
    [Fact]
    public async Task UnexpectedDependencyFailureHasOneSafeCorrelatedLog()
    {
        var events = new ConcurrentQueue<string>();
        using var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(SafeTestEnvironment.ConfigureApiHost).WithWebHostBuilder(builder =>
        {
            builder.ConfigureLogging(logging => logging.AddProvider(new RecordingProvider(events)));
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IPrincipalAuthenticator>();
                services.AddSingleton<IPrincipalAuthenticator, FailingAuthenticator>();
                services.AddTransient<IStartupFilter, TestRawTargetFilter>();
            });
        });
        using HttpClient client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/domains");
        request.Headers.TryAddWithoutValidation("Cookie", "adlog_session=synthetic-secret-do-not-log");
        using HttpResponseMessage response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken));
        string? id = body.RootElement.GetProperty("internal_error_id").GetString();
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("internal_server_error", body.RootElement.GetProperty("error").GetString());
        string[] errors = events.Where(message => message.Contains("request_failed", StringComparison.Ordinal)).ToArray();
        Assert.Single(errors);
        Assert.Contains(id!, errors[0]);
        Assert.Contains("InvalidOperationException", errors[0]);
        Assert.DoesNotContain("synthetic-secret-do-not-log", errors[0]);
    }

    private sealed class FailingAuthenticator : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context, CancellationToken ct) =>
            throw new InvalidOperationException("synthetic-secret-do-not-log");
    }

    private sealed class TestRawTargetFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, runNext) =>
            {
                context.Features.Get<IHttpRequestFeature>()!.RawTarget = context.Request.Path + context.Request.QueryString;
                await runNext(context);
            });
            next(app);
        };
    }

    private sealed class RecordingProvider(ConcurrentQueue<string> events) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new Recorder(events);
        public void Dispose() { }
    }

    private sealed class Recorder(ConcurrentQueue<string> events) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => events.Enqueue(formatter(state, exception));
    }
}
