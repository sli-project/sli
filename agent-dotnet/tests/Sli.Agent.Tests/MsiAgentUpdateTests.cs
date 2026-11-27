using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Service;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class MsiAgentUpdateTests : IDisposable
{
    private readonly string _state = Helpers.TempDirectory();
    private readonly TestClock _clock = new();
    private readonly UpdateHandler _handler = new();

    [Fact]
    public async Task HashMismatchIsRefusedAndBackoffSurvivesRestart()
    {
        using var authority = new TestAuthority();
        var store = AgentRuntime.CreateIdentityStore(new AgentOptions { StateDir = _state });
        store.Prepare();
        using var before = store.Accept(authority.Issue(store), _clock.Now);
        using var http = Http();
        var offer = Offer();
        offer["format"] = "msi";

        await Updater().CheckAsync(offer, http, CancellationToken.None);
        Assert.Equal("agent_update_verification_failed", Assert.Single(_handler.Results)["reason"]!.GetValue<string>());
        Assert.Empty(Directory.GetFiles(_state, "*.msi", SearchOption.AllDirectories));
        // A fresh instance reads the same journal after an agent restart.
        await Updater().CheckAsync(offer, http, CancellationToken.None);
        Assert.Equal(1, _handler.Downloads);
        _clock.Now = _clock.Now.AddMinutes(2);
        await Updater().CheckAsync(offer, http, CancellationToken.None);
        Assert.Equal(2, _handler.Downloads);
        using var after = store.Load()!;
        Assert.Equal(before.AgentId, after.AgentId);
        Assert.Equal(before.Certificate.RawData, after.Certificate.RawData);
    }

    [Fact]
    public async Task LegacyZipOfferIsRejectedWithoutDownloading()
    {
        using var http = Http();
        await Updater().CheckAsync(Offer(), http, CancellationToken.None);
        var result = Assert.Single(_handler.Results);
        Assert.Equal("rejected", result["status"]!.GetValue<string>());
        Assert.Equal("agent_update_msi_required", result["reason"]!.GetValue<string>());
        Assert.Equal(typeof(AgentRuntime).Assembly.GetName().Version!.ToString(3), result["version"]!.GetValue<string>());
        Assert.Equal(0, _handler.Downloads);
    }

    private MsiAgentUpdate Updater() => new(_state, AgentRuntime.CreateFiles(), _clock);
    private AgentHttpClient Http() => new(new HttpClient(_handler) { BaseAddress = new Uri("https://core.example.test/") });
    private static JsonObject Offer() => new() { ["sha256"] = new string('a', 64), ["version"] = "26.0.185" };
    public void Dispose() => Directory.Delete(_state, recursive: true);

    private sealed class UpdateHandler : HttpMessageHandler
    {
        internal int Downloads { get; private set; }
        internal List<JsonObject> Results { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.Method == HttpMethod.Get && request.RequestUri!.AbsolutePath == "/api/v1/agent/package")
            {
                Downloads++;
                Assert.Equal("?sha256=" + new string('a', 64), request.RequestUri.Query);
                return new(HttpStatusCode.OK) { Content = new ByteArrayContent([1, 2, 3]) };
            }
            Assert.Equal("/api/v1/agent/update-result", request.RequestUri!.AbsolutePath);
            Results.Add(JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))!.AsObject());
            return new(HttpStatusCode.OK) { Content = new StringContent("{}", Encoding.UTF8, "application/json") };
        }
    }
}
