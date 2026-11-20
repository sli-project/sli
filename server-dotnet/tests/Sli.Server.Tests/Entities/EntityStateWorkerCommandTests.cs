using System.Text.Json.Nodes;
using Sli.Server.Entities.State;
using Xunit;

namespace Sli.Server.Tests.Entities;
public class EntityStateWorkerCommandTests
{
    [Fact] public async Task Once_dispatches_clamped_source_options_and_returns_actual_status()
    {
        using var output=new StringWriter();using var error=new StringWriter();EntityStateWorkerOptions? observed=null;
        int exit=await EntityStateWorkerCommand.RunCoreAsync(["--once","--poll-seconds","999","--limit","0"],(options,emit,_)=> {
            observed=options;emit(new JsonObject { ["status"]="partial",["failed"]=1 });return Task.FromResult(1);
        },output,error,TestContext.Current.CancellationToken);
        Assert.Equal(1,exit);Assert.Equal(new EntityStateWorkerOptions(true,300,1),observed);Assert.Contains("partial",output.ToString());Assert.Equal("",error.ToString());
    }
    [Fact] public async Task Continuous_mode_passes_defaults_and_cancels_host()
    {
        using var output=new StringWriter();using var error=new StringWriter();using var cancel=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        EntityStateWorkerOptions? observed=null;
        int exit=await EntityStateWorkerCommand.RunCoreAsync([],async (options,_,ct)=> {
            observed=options;cancel.Cancel();await Task.Delay(Timeout.Infinite,ct);return 1;
        },output,error,cancel.Token);
        Assert.True(cancel.IsCancellationRequested);Assert.Equal(new EntityStateWorkerOptions(false,30,16),observed);Assert.Equal(0,exit);Assert.Equal("",error.ToString());
    }
    [Fact] public async Task Unsupported_supervisor_profile_fails_without_starting_worker()
    {
        using var output=new StringWriter();using var error=new StringWriter();bool called=false;
        int exit=await EntityStateWorkerCommand.RunCoreAsync(["--load-supervisor-environment"],(_,_,_)=>{called=true;return Task.FromResult(0);},output,error,TestContext.Current.CancellationToken);
        Assert.Equal(1,exit);Assert.False(called);Assert.Contains("entity_state_supervisor_environment_unavailable",error.ToString());
    }
    [Fact] public async Task Missing_worker_configuration_reports_failure()
    {
        using var output=new StringWriter();using var error=new StringWriter();
        int exit=await EntityStateWorkerCommand.RunCoreAsync(["--once"],(_,_,_)=>throw new InvalidOperationException("server_configuration_invalid"),output,error,TestContext.Current.CancellationToken);
        Assert.Equal(1,exit);Assert.Equal("",output.ToString());Assert.Contains("server_configuration_invalid",error.ToString());
    }
}
