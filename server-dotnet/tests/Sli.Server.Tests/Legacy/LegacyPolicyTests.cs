using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Sli.Server.Legacy;
using Xunit;

namespace Sli.Server.Tests.Legacy;

public sealed class LegacyPolicyTests
{
    [Theory]
    [InlineData(null, 30)]
    [InlineData("invalid", 30)]
    [InlineData("0", 1)]
    [InlineData("-5", 1)]
    [InlineData("7", 7)]
    public void PostCollectionRetentionMatchesConfiguredOperationalPolicy(string? value, int days)
    { Assert.Equal(days, LegacyPostStore.RetentionDays(_ => value)); }

    private static LegacySettings Settings(params (string Key,string Value)[] settings)
    {
        var values = new Dictionary<string,string?> { ["Sli:Legacy:SLI_LEGACY_COLLECTION_DISABLED"]="0",
            ["Sli:Legacy:ADLOG_ENABLE_INPROCESS_COLLECTION_SCHEDULER"]="0" };
        foreach (var (key,value) in settings) values["Sli:Legacy:"+key]=value;
        return new(new ConfigurationBuilder().AddInMemoryCollection(values).Build());
    }
    [Fact] public async Task DefaultSchedulerNeverResolvesDatabaseOrStartsWork()
    {
        using var services=new ServiceCollection().BuildServiceProvider();
        using var scheduler=new LegacyScheduler(services.GetRequiredService<IServiceScopeFactory>(),Settings(),NullLogger<LegacyScheduler>.Instance);
        await scheduler.StartAsync(TestContext.Current.CancellationToken);
        await scheduler.ExecuteTask!.WaitAsync(TestContext.Current.CancellationToken);
        await scheduler.StopAsync(TestContext.Current.CancellationToken);
        Assert.NotNull(scheduler.ExecuteTask); Assert.True(scheduler.ExecuteTask.IsCompletedSuccessfully);
    }
    [Theory] [InlineData("1")] [InlineData("yes")] [InlineData("")] [InlineData("garbage")]
    public void LegacyCutoverAcceptsOnlyDocumentedZero(string value)
    {
        var settings=Settings(("SLI_LEGACY_COLLECTION_DISABLED",value));
        Assert.True(settings.Disabled); Assert.Equal("legacy_collection_disabled",settings.SchedulerBlock);
    }
    [Fact] public async Task DefaultInprocessPostCollectionNeverConnectsToDatabase()
    {
        using var services=new ServiceCollection().BuildServiceProvider();
        using var worker=new LegacyPostCollectionHostedService(services.GetRequiredService<IServiceScopeFactory>(),
            Settings(("ADLOG_ENABLE_INPROCESS_POST_COLLECTION","0"),("ADLOG_EXTERNAL_POST_COLLECTION_WORKER","0")),NullLogger<LegacyPostCollectionHostedService>.Instance);
        await worker.StartAsync(TestContext.Current.CancellationToken);
        await worker.ExecuteTask!.WaitAsync(TestContext.Current.CancellationToken);
        await worker.StopAsync(TestContext.Current.CancellationToken);
        Assert.NotNull(worker.ExecuteTask); Assert.True(worker.ExecuteTask.IsCompletedSuccessfully);
    }
    [Theory]
    [InlineData(20L,100L,10L,true,"none")]
    [InlineData(12L,100L,10L,true,"warning_only")]
    [InlineData(8L,100L,1L,false,"free_percent_below_stop")]
    [InlineData(20L,100L,21L,false,"free_bytes_below_stop")]
    [InlineData(8L,100L,10L,false,"free_bytes_and_percent_below_stop")]
    [InlineData(10L,100L,10L,true,"warning_only")]
    public void CollectionStopsForEitherDiskThresholdIncludingBoundary(long free,long total,long minimum,bool allowed,string condition)
    {
        var result=LegacyEnvironment.DiskDecision(free,total,15,10,5,minimum,true);
        Assert.Equal(allowed,result["collection_allowed"]!.GetValue<bool>());
        Assert.Equal(condition,result["blocking_threshold"]!["condition"]!.GetValue<string>());
    }
    [Fact] public void PythonFalseValuesSelectCollectDefaults()
    {
        using var body=JsonDocument.Parse("{\"server\":false,\"hours\":0,\"max_events_per_channel\":{}}");
        var input=LegacyJobInput.Parse(body.RootElement,true); Assert.Empty(input.Servers); Assert.Equal(1,input.Hours); Assert.Equal(200,input.MaxEvents);
    }
    [Fact] public void AnalysisIgnoresCollectionOnlyParameters()
    {
        using var body=JsonDocument.Parse("{\"server\":\"ALL\",\"hours\":\"invalid\",\"max_events_per_channel\":[]} ");
        var input=LegacyJobInput.Parse(body.RootElement,false); Assert.Empty(input.Servers); Assert.Equal(0,input.Hours); Assert.Equal(0,input.MaxEvents);
    }
    [Fact] public async Task AuditIsBoundedJsonAndContainsNoJobErrorsOrOutputs()
    {
        string directory=Path.Combine(Path.GetTempPath(),"sli-legacy-audit-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        try {
            var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:DataDirectory"]=directory }).Build();
            var audit=new LegacyAudit(new(config));
            await audit.AppendAsync("manual_collection_start","skipped",new() { ["id"]=7,["servers"]=new JsonArray("dc.example.test"),
                ["hours"]=1,["max_events_per_channel"]=200,["mode"]="runtime_guard",["skipped_reason"]="acquisition_disabled",
                ["errors"]=new JsonArray("test-only-private-diagnostic"),["stdout_tail"]="test-only-private-output" },TestContext.Current.CancellationToken);
            string text=await File.ReadAllTextAsync(Path.Combine(directory,"logs","audit-actions.log"),TestContext.Current.CancellationToken);
            using var row=JsonDocument.Parse(text); Assert.Equal("operator_action",row.RootElement.GetProperty("event").GetString());
            Assert.Equal(7,row.RootElement.GetProperty("job_id").GetInt32()); Assert.Equal("acquisition_disabled",row.RootElement.GetProperty("runtime_guard").GetString());
            Assert.DoesNotContain("private",text); Assert.Single(text.Split('\n',StringSplitOptions.RemoveEmptyEntries));
        }
        finally { Directory.Delete(directory,true); }
    }
    [Fact] public void ReportNameCannotEscapeDirectory()
    {
        Assert.Equal(".._.._server.example.test",LegacyAnalysis.SafeName("../../server.example.test"));
        Assert.Equal("сервер.example.test",LegacyAnalysis.SafeName("сервер.example.test"));
    }
}
