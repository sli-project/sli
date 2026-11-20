using System.Net;
using System.Text;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Xunit;

namespace Sli.Server.Tests.Domains;

public sealed class IngressHostingTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SaturationRejectsBeforeBodyAndReleasesPermit(bool kestrel)
    {
        var blocker = new BlockingLogin();
        using var factory = Factory(blocker);
        if (kestrel) factory.UseKestrel(options => options.Listen(IPAddress.Loopback, 0));
        using var client = factory.CreateClient();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var requests = Enumerable.Range(0, 4).Select(i => client.PostAsync("/api/auth/login",
            new StringContent($"{{\"username\":\"synthetic{i}\",\"password\":\"p\"}}", Encoding.UTF8, "application/json"), timeout.Token)).ToArray();
        try
        {
            await blocker.Entered.Task.WaitAsync(timeout.Token);
            using var rejected = await client.PostAsync("/api/auth/login", new StringContent("{", Encoding.UTF8, "application/json"), timeout.Token);
            Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
            Assert.Contains("server_busy", await rejected.Content.ReadAsStringAsync(timeout.Token));
            Assert.Equal(4, blocker.Count);
            Assert.Equal("no-store, max-age=0", rejected.Headers.CacheControl!.ToString());
        }
        finally { blocker.Release.TrySetResult(); await Task.WhenAll(requests); }
        using var after = await client.GetAsync("/api/auth/me", timeout.Token);
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    [Fact]
    public async Task DynamicApiRateIsBoundedButLoginUsesItsSeparateBucket()
    {
        var blocker = new BlockingLogin();
        blocker.Release.SetResult();
        using var factory = Factory(blocker);
        using var client = factory.CreateClient();
        var ct = TestContext.Current.CancellationToken;
        for (int i = 0; i < 60; i++)
        {
            using var response = await client.GetAsync("/api/auth/me", ct);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
        using var limited = await client.GetAsync("/api/auth/me", ct);
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.Equal("60", Assert.Single(limited.Headers.GetValues("Retry-After")));
        using var login = await client.PostAsync("/api/auth/login", new StringContent("{\"username\":\"x\",\"password\":\"p\"}", Encoding.UTF8, "application/json"), ct);
        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
        Assert.Equal(1, blocker.Count);
    }

    private static WebApplicationFactory<Program> Factory(BlockingLogin blocker) => new WebApplicationFactory<Program>()
            .WithWebHostBuilder(SafeTestEnvironment.ConfigureApiHost).WithWebHostBuilder(builder =>
    {
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?> {
            ["Sli:AuthRequired"] = "1", ["Sli:AuthAllowInsecureHttp"] = "1", ["Sli:HttpMaxConcurrentRequests"] = "4", ["Sli:HttpRatePerMinute"] = "60" }));
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<ILoginService>(); services.AddSingleton<ILoginService>(blocker);
            services.RemoveAll<IPrincipalAuthenticator>(); services.AddSingleton<IPrincipalAuthenticator, DeniedAuthenticator>();
        });
    });

    private sealed class BlockingLogin : ILoginService
    {
        private int count;
        public int Count => Volatile.Read(ref count);
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task<LoginResult> LoginAsync(LoginCommand command, RequestIdentity identity, CancellationToken ct)
        {
            if (Interlocked.Increment(ref count) >= 4) Entered.TrySetResult();
            await Release.Task.WaitAsync(ct);
            return new(null, null);
        }
    }
    private sealed class DeniedAuthenticator : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(Microsoft.AspNetCore.Http.HttpContext context, CancellationToken ct) =>
            ValueTask.FromResult(AuthenticationResult.Denied(401, "authentication_required"));
    }
}
