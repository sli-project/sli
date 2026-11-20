using Microsoft.Extensions.Configuration;
using Sli.Server.Infrastructure;
using Sli.Server.Legacy;
using Npgsql;
using Xunit;

namespace Sli.Server.Tests.Legacy;

public sealed class AdaptivePlanPostgresTests
{
    sealed class NoDatabase : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => throw new Exception("database accessed");
    }
    [Theory]
    [InlineData("0")]
    [InlineData("1")]
    public async Task Retired_collector_does_not_read_lag_or_write_a_cursor(string enable)
    {
        var settings=new LegacySettings(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["Sli:Legacy:ADLOG_ENABLE_POSTGRES_COLLECTION"]=enable }).Build());
        var collector=new LegacyAdaptiveCollector(new NoDatabase(),settings);
        var error=await Assert.ThrowsAsync<InvalidOperationException>(()=>collector.PlanAsync("dc.example.test",TestContext.Current.CancellationToken));
        Assert.Equal("module_disabled",error.Message);
        var write=await Assert.ThrowsAsync<InvalidOperationException>(()=>collector.RecordAsync(null!,null,"update",TestContext.Current.CancellationToken));
        Assert.Equal("module_disabled",write.Message);
    }
}
