using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticHeartbeatPostgresTests
{
    [Fact]
    public async Task Occupied_worker_lock_exits_with_failure_and_next_start_can_process()
    {
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        // Include isolated schema installation and the worker's bounded lock wait.
        timeout.CancelAfter(TimeSpan.FromSeconds(120)); var ct=timeout.Token;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var old=new NpgsqlConnection(fixture.Pg.ConnectionString); await old.OpenAsync(ct);
        await PostCollectionPostgres.Sql(old,"select pg_advisory_lock(hashtextextended('ad_log_reports_runtime_semantic_production_worker',0))",ct);
        async Task<(int Code,string Output,string Errors)> Start() {
            var info=SemanticRuntimePostgresTests.NativeProcess(fixture,false,true); info.ArgumentList.Add("--once");
            using var process=Process.Start(info)!;
            var stdout=process.StandardOutput.ReadToEndAsync(ct); var stderr=process.StandardError.ReadToEndAsync(ct);
            try { await process.WaitForExitAsync(ct); return (process.ExitCode,await stdout,await stderr); }
            finally { if(!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); } }
        }
        var busy=await Start();
        Assert.Equal(1,busy.Code); Assert.Empty(busy.Output); Assert.Contains("semantic_production_worker_already_running",busy.Errors);
        await PostCollectionPostgres.Sql(old,"select pg_advisory_unlock_all()",ct);
        var restarted=await Start();
        Assert.Equal(0,restarted.Code); Assert.Empty(restarted.Errors);
        Assert.Equal("ok",JsonNode.Parse(restarted.Output.Trim()).Text("status"));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
