using System.Text;
using System.Text.Json.Nodes;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Ad;
using Sli.Server.Compatibility;
using Sli.Server.Gpo;
using Sli.Server.Storage.EventReports;
using Sli.Server.Storage.History;
using Sli.Server.Workstations;
using Sli.Server.Reporting.V2;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class HistoryConfigurationTests
{
    sealed class Fixture : IDisposable
    {
        internal readonly string DirectoryPath=Path.Combine(Path.GetTempPath(),"history-fixture-"+Guid.NewGuid().ToString("N"));
        internal readonly Dictionary<string,string?> Values;
        internal Fixture()
        {
            Directory.CreateDirectory(DirectoryPath);
            File.WriteAllText(Path.Combine(DirectoryPath,"password")," fixture-password \r\n");
            File.WriteAllText(Path.Combine(DirectoryPath,"user")," fixture-user \n");
            Values=new() { ["CREDENTIALS_DIRECTORY"]=DirectoryPath,["ADLOG_HISTORY_READ_MODE"]="primary",
                ["ADLOG_HISTORY_CLICKHOUSE_HOST"]="192.0.2.11",["ADLOG_HISTORY_CLICKHOUSE_PORT"]="8123",
                ["ADLOG_HISTORY_CLICKHOUSE_USER_FILE"]="%d/user",["ADLOG_HISTORY_CLICKHOUSE_PASSWORD_FILE"]="%d/password" };
        }
        internal IConfiguration Config()=>new ConfigurationBuilder().AddInMemoryCollection(Values).Build();
        public void Dispose() {File.Delete(Path.Combine(DirectoryPath,"password"));File.Delete(Path.Combine(DirectoryPath,"user"));Directory.Delete(DirectoryPath);}
    }
    [Fact] public void History_clients_share_systemd_paths_host_and_one_secret_snapshot()
    {
        using var fixture=new Fixture();var config=fixture.Config();
        var settings=HistoryConfiguration.For(config);
        Assert.True(settings.Primary);
        using var first=settings.CreateClient();
        Assert.Equal("http://192.0.2.11:8123/",settings.Endpoint.AbsoluteUri);
        Assert.Equal("fixture-user: fixture-password ",Encoding.UTF8.GetString(Convert.FromBase64String(first.DefaultRequestHeaders.Authorization!.Parameter!)));
        // Subsequent report scopes must not reopen either file.
        File.Delete(Path.Combine(fixture.DirectoryPath,"password"));File.Delete(Path.Combine(fixture.DirectoryPath,"user"));
        Assert.Same(settings,HistoryConfiguration.For(config));
        using var second=settings.CreateClient();
        Assert.Equal(first.DefaultRequestHeaders.Authorization,second.DefaultRequestHeaders.Authorization);
    }
    [Theory]
    [InlineData("%d/../password")][InlineData("%d/..\\password")][InlineData("%d//password")][InlineData("%d/C:/password")][InlineData("%d/")]
    public void Invalid_credential_paths_fail_with_only_a_code(string file)
    {
        using var fixture=new Fixture();fixture.Values["ADLOG_HISTORY_CLICKHOUSE_PASSWORD_FILE"]=file;
        var settings=HistoryConfiguration.For(fixture.Config());
        var error=Assert.Throws<EventReadConfigurationException>(()=>settings.CreateClient());
        Assert.Equal("history_clickhouse_secret_invalid",error.Message);Assert.Null(error.InnerException);
        Assert.DoesNotContain(fixture.DirectoryPath,error.ToString());
    }
    [Fact] public async Task Invalid_secret_failure_is_cached_and_configuration_fails_before_database_work()
    {
        using var fixture=new Fixture();fixture.Values["ADLOG_HISTORY_CLICKHOUSE_PASSWORD"]="fixture-conflict";
        var config=fixture.Config();var settings=HistoryConfiguration.For(config);
        Assert.Throws<EventReadConfigurationException>(()=>settings.CreateClient());
        File.Delete(Path.Combine(fixture.DirectoryPath,"password"));
        Assert.Equal("history_clickhouse_secret_invalid",Assert.Throws<EventReadConfigurationException>(()=>settings.CreateClient()).Message);
        var reader=new EventReadService(null!,config,null!);
        Assert.Empty(await reader.DetailsAsync([1],false,(_,_)=>Task.FromResult(false),TestContext.Current.CancellationToken));
        await reader.DisposeAsync();
    }
    sealed class BrokenHistory : IEventReadService
    {
        public Task<IReadOnlyList<Sli.Server.Access.AccessResource>> ResourcesAsync(long id,CancellationToken ct)=>throw new InvalidOperationException("must_not_open_database");
        public Task<Dictionary<long,JsonObject>> DetailsAsync(long[] ids,bool exact,Func<long,CancellationToken,Task<bool>> admitted,CancellationToken ct)=>throw new EventReadConfigurationException("history_clickhouse_secret_invalid");
        public Task<JsonObject> RelationsAsync(long id,Func<long,CancellationToken,Task<bool>> admitted,CancellationToken ct)=>throw new NotSupportedException();
    }
    [Fact] public async Task Security_events_degrade_configuration_failure_as_reference_archive_state()
    {
        var rows=new List<JsonObject>{new(){["event_db_id"]=1}};
        await AdSecurityHydration.HydrateAsync(rows,1,new BrokenHistory(),TestContext.Current.CancellationToken);
        Assert.Equal("partial_archive_unavailable",(string?)rows[0]["archive_field_state"]);
    }
}
