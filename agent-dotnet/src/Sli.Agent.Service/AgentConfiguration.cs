using Microsoft.Extensions.Configuration;
using Sli.Agent.Windows;

namespace Sli.Agent.Service;

/// <summary>Identical settings and precedence for interactive prepare and the service, independent of the working directory.</summary>
public static class AgentConfiguration
{
    public static string MachineSettingsPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SLI", "AgentNet", "agent.json");

    public static IConfigurationRoot Load(string[] args)
    {
        var configuration = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: true)
            .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT") ?? "Production"}.json", optional: true);
        if (OperatingSystem.IsWindows()) configuration.AddInMemoryCollection(MsiConfiguration.ReadSettings());
        return configuration.AddJsonFile(MachineSettingsPath, optional: true)
            .AddEnvironmentVariables().AddCommandLine(args).Build();
    }
}
