using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;

namespace Sli.Agent.Service;

public static class AgentLogging
{
    [SupportedOSPlatform("windows")]
    public static void AddWindowsEventLog(ILoggingBuilder logging) => logging.AddEventLog(settings =>
    {
        // AddWindowsService defaults to the assembly name (SliAgent), not the SCM service name.
        settings.SourceName = AgentWorker.ServiceName;
        settings.LogName = "Application";
    });
}
