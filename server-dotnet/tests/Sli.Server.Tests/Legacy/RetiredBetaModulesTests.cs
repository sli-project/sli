using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Legacy;
using Sli.Server.Semantic;
using Sli.Server.Storage.EventReports;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Legacy;

public sealed class RetiredBetaModulesTests
{
    sealed class NoStorage : IPostgresConnectionFactory, ISemanticDatabase, ISemanticSession
    {
        public int Calls;
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) { Calls++; throw new Exception("database accessed"); }
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct) { Calls++; throw new Exception("database accessed"); }
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values) { Calls++; throw new Exception("database accessed"); }
        public Task CommitAsync(CancellationToken ct) { Calls++; throw new Exception("database accessed"); }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static LegacySettings Settings => new(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
        ["Sli:Legacy:SLI_LEGACY_COLLECTION_DISABLED"]="0",
        ["Sli:Legacy:ADLOG_ENABLE_INPROCESS_COLLECTION_SCHEDULER"]="1",
        ["Sli:Legacy:ADLOG_ENABLE_INPROCESS_POST_COLLECTION"]="1",
        ["Sli:Legacy:ADLOG_ENABLE_POSTGRES_COLLECTION"]="1",
        ["Sli:Legacy:ADLOG_NPS_EVENTLOG_ENABLED"]="1"
    }).Build());

    [Fact]
    public async Task Retired_pipeline_cannot_read_events_or_commit_cursors()
    {
        var db=new NoStorage();
        var pipeline=new CollectionRuntimePipeline(db);
        foreach(var action in new Func<Task>[] {
            ()=>pipeline.GetCollectionPlanAsync("dc.example.test",["Security"],Ct),
            ()=>pipeline.UpdateCollectionStateAsync("dc.example.test","",new(),new(),Ct),
            ()=>LegacyCollectionState.UpdateAsync(db,new("dc.example.test","",new(),new()),null,null,Ct),
            ()=>new LegacyPartialTimeoutWatermark(db).CommitAsync("dc.example.test","","",new(),1,0,Ct),
            ()=>new LegacyStorageSnapshot(db,Settings).RecordAsync(null!,Ct),
            ()=>new LegacyAnalysis(db,null!).RenderAsync(1,["dc.example.test"],Ct),
            ()=>new PostgresVpnStore(db).OpenAsync(Ct)
        }) {
            var error=await Assert.ThrowsAsync<InvalidOperationException>(action);
            Assert.Equal("module_disabled",error.Message);
        }
        Assert.Equal(0,db.Calls);
    }
    [Fact]
    public async Task Enabled_Nps_flags_cannot_start_acquisition_or_read_a_cursor()
    {
        var db=new NoStorage();
        var result=await new NpsWorkerRuntime(db,Settings,null!,null!,null!).CompleteAsync(new(),null!,"fixture",Ct);
        Assert.Equal("disabled",result["status"]!.ToString()); Assert.Equal("module_disabled",result["reason"]!.ToString());
        Assert.Equal(0,db.Calls);
    }
    [Fact]
    public async Task Web_host_does_not_start_retired_workers_even_with_old_enable_flags()
    {
        var builder=Host.CreateApplicationBuilder(Array.Empty<string>());
        var db=new NoStorage();
        builder.Services.AddSingleton(Settings);
        builder.Services.AddSingleton<IPostgresConnectionFactory>(db);
        builder.Services.AddLegacyJobs();
        using var host=builder.Build();
        await host.StartAsync(Ct); await host.StopAsync(Ct);
        Assert.Equal(0,db.Calls);
    }
    [Fact]
    public async Task Legacy_collection_command_exits_without_runtime_configuration()
    {
        Assert.Equal(0,await LegacyWorkerCommand.RunAsync("collection-worker",["--once"]));
    }
    [Theory]
    [InlineData(null)] [InlineData("false")] [InlineData("0")] [InlineData("invalid")]
    public void Retired_setting_cannot_reenable_old_event_reads(string? value)
    {
        Assert.True(EventReadService.ShortReadsSetting(value));
    }
}
