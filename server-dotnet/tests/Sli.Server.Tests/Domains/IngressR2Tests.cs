using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Xunit;

namespace Sli.Server.Tests.Domains;

public sealed class IngressR2Tests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ForwardedClientsAreIsolatedOnlyForTrustedProxy(bool trustPeer)
    {
        var blocker = new BlockingLogin();
        using var factory = Factory(blocker, trustPeer ? "127.0.0.1,10.0.0.1" : "");
        factory.UseKestrel(o => o.Listen(IPAddress.Loopback, 0));
        using var client = factory.CreateClient();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        async Task<HttpStatusCode> Get(string xff)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/auth/me");
            request.Headers.TryAddWithoutValidation("X-Forwarded-For", xff);
            request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
            using var response = await client.SendAsync(request, deadline.Token);
            return response.StatusCode;
        }
        for (int i = 0; i < 60; i++) Assert.Equal(HttpStatusCode.Unauthorized, await Get("203.0.113.1, 198.51.100.7, 10.0.0.1"));
        Assert.Equal(trustPeer ? HttpStatusCode.Unauthorized : HttpStatusCode.TooManyRequests,
            await Get("203.0.113.2, 198.51.100.8, 10.0.0.1"));
        Assert.Equal(HttpStatusCode.TooManyRequests, await Get("203.0.113.3, 198.51.100.7, 10.0.0.1"));
    }

    [Fact]
    public async Task BusyLoginHasLocalizedEnvelopeAndOtherRoutesKeepPlainError()
    {
        var blocker = new BlockingLogin();
        using var factory = Factory(blocker, "");
        factory.UseKestrel(o => o.Listen(IPAddress.Loopback, 0));
        using var client = factory.CreateClient();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var inflight = Enumerable.Range(0, 4).Select(i => client.PostAsync("/api/auth/login",
            new StringContent($"{{\"username\":\"test{i}\",\"password\":\"p\"}}", Encoding.UTF8, "application/json"), deadline.Token)).ToArray();
        try
        {
            await blocker.Entered.Task.WaitAsync(deadline.Token);
            foreach (var (lang, text) in new[] { ("en", "The sign-in service is temporarily unavailable. Try again later."),
                ("ru", "Сервис входа временно недоступен. Повторите попытку позже.") })
            {
                using var req = new HttpRequestMessage(HttpMethod.Post, "/api/auth/login") { Content = new StringContent("{", Encoding.UTF8, "application/json") };
                req.Headers.TryAddWithoutValidation("Accept-Language", lang);
                using var response = await client.SendAsync(req, deadline.Token);
                Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
                using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(deadline.Token));
                Assert.Equal("server_busy", body.RootElement.GetProperty("error").GetString());
                var message = body.RootElement.GetProperty("message");
                Assert.Equal("login.error.unavailable", message.GetProperty("code").GetString());
                Assert.Equal(text, message.GetProperty("text").GetString());
                Assert.Equal(JsonValueKind.Object, message.GetProperty("params").ValueKind);
                Assert.Equal("no-store, max-age=0", response.Headers.CacheControl!.ToString());
            }
            using var other = await client.GetAsync("/api/auth/me", deadline.Token);
            Assert.Equal(HttpStatusCode.TooManyRequests, other.StatusCode);
            using var bodyOther = JsonDocument.Parse(await other.Content.ReadAsStringAsync(deadline.Token));
            Assert.Equal("server_busy", bodyOther.RootElement.GetProperty("error").GetString());
            Assert.False(bodyOther.RootElement.TryGetProperty("message", out _));
            Assert.Equal(4, blocker.Count);
        }
        finally { blocker.Release.TrySetResult(); await Task.WhenAll(inflight); }
    }
    private static WebApplicationFactory<Program> Factory(BlockingLogin blocker, string proxies) => new WebApplicationFactory<Program>().WithWebHostBuilder(Sli.Server.Tests.Domains.SafeTestEnvironment.ConfigureApiHost).WithWebHostBuilder(builder =>
    {
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?> {
            ["Sli:AuthRequired"] = "1", ["Sli:AuthAllowInsecureHttp"] = "1", ["Sli:HttpMaxConcurrentRequests"] = "4",
            ["Sli:HttpRatePerMinute"] = "60", ["Sli:TrustedProxies"] = proxies }));
        builder.ConfigureServices(services => {
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
        { if (Interlocked.Increment(ref count) >= 4) Entered.TrySetResult(); await Release.Task.WaitAsync(ct); return new(null, null); }
    }
    private sealed class DeniedAuthenticator : IPrincipalAuthenticator
    {
        public ValueTask<AuthenticationResult> AuthenticateAsync(Microsoft.AspNetCore.Http.HttpContext context, CancellationToken ct) =>
            ValueTask.FromResult(AuthenticationResult.Denied(401, "authentication_required"));
    }
}
