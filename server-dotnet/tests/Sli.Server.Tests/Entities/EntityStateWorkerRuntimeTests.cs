using Npgsql;
using Sli.Server.Entities.State;
using Xunit;
namespace Sli.Server.Tests.Entities;
public class EntityStateWorkerRuntimeTests
{
    [Fact] public async Task Uses_source_worker_profile_without_pooling() {
        var env=new Dictionary<string,string?> { ["ADLOG_STORAGE_V2_WORKER_DSN"]="host=localhost port=5432 dbname=sli user=worker",["ADLOG_STORAGE_V2_WORKER_PASSWORD_FILE"]="synthetic",["ADLOG_PG_CONNECT_TIMEOUT_SECONDS"]="4",["ADLOG_PG_STATEMENT_TIMEOUT_MS"]="9000",["ADLOG_PG_LOCK_TIMEOUT_MS"]="12000" };
        await using var runtime=EntityStateWorkerRuntime.TryCreate(k=>env.GetValueOrDefault(k),_=>System.Text.Encoding.UTF8.GetBytes("synthetic-password\n"));
        Assert.NotNull(runtime);var b=new NpgsqlConnectionStringBuilder(runtime.DataSource.ConnectionString);
        Assert.Equal("worker",b.Username);Assert.Equal("adlog_entity_state_projector",b.ApplicationName);Assert.False(b.Pooling);Assert.False(b.Multiplexing);Assert.Equal(4,b.Timeout);Assert.Equal(9,b.CommandTimeout);
        Assert.Contains("-c statement_timeout=9000 -c lock_timeout=9000",b.Options);
    }
    [Fact] public void No_admin_fallback_and_conflicting_passwords_fail_closed() {
        var env=new Dictionary<string,string?> { ["ADLOG_PG_ADMIN_USER"]="owner",["ADLOG_PG_ADMIN_PASSWORD"]="synthetic" };
        Assert.Null(EntityStateWorkerRuntime.TryCreate(k=>env.GetValueOrDefault(k),_=>[]));
        env["ADLOG_STORAGE_V2_WORKER_DSN"]="host=localhost dbname=sli user=worker password=first";env["ADLOG_STORAGE_V2_WORKER_PASSWORD"]="second";
        Assert.Null(EntityStateWorkerRuntime.TryCreate(k=>env.GetValueOrDefault(k),_=>[]));
    }
}
