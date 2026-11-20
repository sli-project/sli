using Sli.Server.Agents.Consumer;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Sli.Server.Tests.Agents.M4;

public sealed class AgentImportLoopTests
{
    [Fact]
    public void WorkerConfigurationRejectsMissingAndMalformedBeforeHostConstruction()
    {
        static IConfiguration Config(string? value) => new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string,string?> { ["ConnectionStrings:Sli"] = value }).Build();
        Assert.False(AgentImportCommand.TryCreateFactory(Config(null), out var missing)); Assert.Null(missing);
        Assert.False(AgentImportCommand.TryCreateFactory(Config("not-a-connection-string"), out var malformed)); Assert.Null(malformed);
        Assert.True(AgentImportCommand.TryCreateFactory(Config("Host=127.0.0.1;Database=synthetic;Username=synthetic"), out var valid));
        Assert.NotNull(valid);
        Assert.True(AgentImportCommand.TryCreateFactory(Config("Host=127.0.0.1;Database=synthetic;Username=synthetic;Multiplexing=false"), out var explicitOff));
        Assert.NotNull(explicitOff);
        Assert.False(AgentImportCommand.TryCreateFactory(Config("Host=127.0.0.1;Database=synthetic;Username=synthetic;Multiplexing=true"), out var multiplexed));
        Assert.Null(multiplexed);
    }

    [Fact]
    public async Task FullBatchContinuesAndPartialBatchWaitsUntilCancellation()
    {
        using var cancel = new CancellationTokenSource();
        var scans = new Queue<int>([16, 3]); int calls = 0, delays = 0;
        int result = await AgentImportLoop.RunAsync(new(false, 30), (limit, _) =>
        {
            Assert.Equal(16, limit); calls++;
            return Task.FromResult(new AgentInboxBatchResult(scans.Dequeue(), 0, new Dictionary<string,int>()));
        }, (interval, _) =>
        {
            Assert.Equal(TimeSpan.FromSeconds(30), interval); delays++; cancel.Cancel(); return Task.CompletedTask;
        }, cancel.Token);
        Assert.Equal(0, result); Assert.Equal(2, calls); Assert.Equal(1, delays);
    }

    [Fact]
    public async Task OnceReturnsFailureOnlyForProjectionFailure()
    {
        async Task<int> Run(string reason) => await AgentImportLoop.RunAsync(new(true, 10), (_, _) =>
            Task.FromResult(new AgentInboxBatchResult(1, 0, new Dictionary<string,int> { [reason] = 1 })),
            (_, _) => throw new InvalidOperationException("once must not delay"), CancellationToken.None);
        Assert.Equal(1, await Run("agent_projection_failed"));
        Assert.Equal(1, await Run("agent_ad_dc_projection_failed"));
        Assert.Equal(0, await Run("dc_importer_unavailable"));
    }
}
