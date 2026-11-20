using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sli.Agent.Core;
using Sli.Agent.Service;
using Sli.Agent.Windows;

// `SliAgent prepare` prints the public identity (host id, key fingerprint) for an administrator to bind a token to.
// Anything else runs the agent: as a Windows service under the SCM, or in a console for diagnostics.
if (args.Length > 0 && args[0] == "prepare")
{
    return PrepareCommand.Run(args);
}

var builder = Host.CreateApplicationBuilder(args);
var agentConfiguration = AgentConfiguration.Load(args);
builder.Configuration.AddConfiguration(agentConfiguration);
builder.Services.AddWindowsService(options => options.ServiceName = AgentWorker.ServiceName);
if (OperatingSystem.IsWindows()) AgentLogging.AddWindowsEventLog(builder.Logging);
builder.Services.Configure<AgentOptions>(agentConfiguration.GetSection(AgentOptions.Section));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<AgentRuntime>();
builder.Services.AddHostedService<AgentWorker>();
await builder.Build().RunAsync();
return 0;
