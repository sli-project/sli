using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;
using Microsoft.Extensions.Options;
using Sli.Agent.Service;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class AgentLoggingTests
{
    [WindowsFact]
    public void TheServiceEventLogProviderAcceptsWorkerWarningsUnderTheServiceSource()
    {
        if (!OperatingSystem.IsWindows()) return;
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { ApplicationName = "SliAgent" });
        builder.Logging.ClearProviders();
        builder.Services.AddWindowsService(options => options.ServiceName = AgentWorker.ServiceName);
        AgentLogging.AddWindowsEventLog(builder.Logging);
        using var host = builder.Build();
        var settings = host.Services.GetRequiredService<IOptions<EventLogSettings>>().Value;
        Assert.Equal("SLIAgentNet", settings.SourceName);
        Assert.Equal("Application", settings.LogName);
        Assert.IsType<EventLogLoggerProvider>(Assert.Single(host.Services.GetServices<ILoggerProvider>()));
        // Checking enabled levels creates no SCM service or Event Log source and writes no events.
        var logger = host.Services.GetRequiredService<ILogger<AgentWorker>>();
        Assert.True(logger.IsEnabled(LogLevel.Warning));
        Assert.False(logger.IsEnabled(LogLevel.Information));
    }

    [WindowsFact]
    public void EventLogInformationConfigurationAddedAfterServiceRegistrationIsHonored()
    {
        if (!OperatingSystem.IsWindows()) return;
        var builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        builder.Services.AddWindowsService(options => options.ServiceName = AgentWorker.ServiceName);
        AgentLogging.AddWindowsEventLog(builder.Logging);
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        { ["Logging:EventLog:LogLevel:Default"] = "Information" });
        using var host = builder.Build();
        var logger = host.Services.GetRequiredService<ILogger<AgentWorker>>();
        Assert.True(logger.IsEnabled(LogLevel.Information));
        Assert.True(logger.IsEnabled(LogLevel.Warning));
    }
}
