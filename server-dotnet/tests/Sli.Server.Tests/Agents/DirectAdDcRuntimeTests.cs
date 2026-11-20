using Npgsql;
using Sli.Server.Agents.Consumer;
using Xunit;
namespace Sli.Server.Tests.Agents;
public class DirectAdDcRuntimeTests
{
    [Theory]
    [InlineData("host=localhost port=5432 dbname=sli user=worker options='-c application_name=source'")]
    [InlineData("Host=localhost;Port=5432;Database=sli;Username=worker;No Reset On Close=true")]
    public async Task Source_dsn_and_separate_secret_create_private_resetting_pool_without_execution_deadlines(string dsn)
    {
        var env=new Dictionary<string,string?> {
            ["ADLOG_STORAGE_V2_WORKER_DSN"]=dsn,
            ["ADLOG_STORAGE_V2_WORKER_PASSWORD_FILE"]="synthetic-file",
            ["ADLOG_PG_CONNECT_TIMEOUT_SECONDS"]="4",["ADLOG_PG_STATEMENT_TIMEOUT_MS"]="9000",["ADLOG_PG_LOCK_TIMEOUT_MS"]="12000"
        };
        await using var runtime=DirectAdDcRuntime.TryCreate(k=>env.GetValueOrDefault(k),_=>System.Text.Encoding.UTF8.GetBytes("synthetic-password\n"),Path.GetFullPath("catalog.json"));
        Assert.NotNull(runtime); var b=new NpgsqlConnectionStringBuilder(runtime.Worker.ConnectionString);
        Assert.Equal("worker",b.Username);Assert.True(b.Pooling);Assert.False(b.NoResetOnClose);Assert.False(b.Multiplexing);Assert.Equal(4,b.Timeout);Assert.Equal(0,b.CommandTimeout);
        Assert.Contains("-c statement_timeout=0 -c lock_timeout=0",b.Options);
    }
    [Fact]
    public void Missing_conflicting_or_implicit_configuration_never_uses_owner()
    {
        var env=new Dictionary<string,string?>();
        Assert.Null(DirectAdDcRuntime.TryCreate(k=>env.GetValueOrDefault(k),_=>[],Path.GetFullPath("catalog.json")));
        env["ADLOG_STORAGE_V2_WORKER_DSN"]="host=localhost dbname=sli user=worker password=first";
        env["ADLOG_STORAGE_V2_WORKER_PASSWORD"]="second";
        Assert.Null(DirectAdDcRuntime.TryCreate(k=>env.GetValueOrDefault(k),_=>[],Path.GetFullPath("catalog.json")));
        env.Remove("ADLOG_STORAGE_V2_WORKER_PASSWORD");
        Assert.Null(DirectAdDcRuntime.TryCreate(k=>env.GetValueOrDefault(k),_=>[],"relative-catalog"));
        env["ADLOG_STORAGE_V2_WORKER_DSN"]="dbname=sli user=worker";
        Assert.Null(DirectAdDcRuntime.TryCreate(k=>env.GetValueOrDefault(k),_=>[],Path.GetFullPath("catalog.json")));
    }
}
