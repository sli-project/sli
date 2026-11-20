using System.Globalization;
using System.Runtime.InteropServices;
using Sli.Server.Hosting;
using Sli.Server.Infrastructure;

namespace Sli.Server.Agents.Control;

internal static class AgentCommandConsole
{
    private const string Usage = "Usage: sudo sli-agent-command [--count N] [--server-url URL] [--no-audit]";

    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEffectiveUserId();

    public static Task<int> RunAsync(string[] args) => RunAsync(args,
        OperatingSystem.IsLinux() && GetEffectiveUserId() == 0, Console.Out, Console.Error);

    internal static async Task<int> RunAsync(string[] args, bool isRoot, TextWriter output, TextWriter error,
        ConfigurationManager? configuration = null)
    {
        if (!isRoot)
        {
            await error.WriteLineAsync("host_root_required");
            return 1;
        }

        if (args is ["--help"] or ["-h"])
        {
            await output.WriteLineAsync(Usage);
            return 0;
        }

        int? count = null;
        string? address = null;
        bool manageWindowsAudit = true;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--count" when count is null && i + 1 < args.Length
                    && int.TryParse(args[i + 1], NumberStyles.None, CultureInfo.InvariantCulture, out int limit)
                    && limit is >= 1 and <= AgentManagementService.ConsoleHostLimit:
                    count = limit;
                    i++;
                    break;
                case "--server-url" when address is null && i + 1 < args.Length
                    && !args[i + 1].StartsWith("--", StringComparison.Ordinal):
                    address = args[++i];
                    break;
                case "--no-audit" when manageWindowsAudit:
                    manageWindowsAudit = false;
                    break;
                default:
                    await error.WriteLineAsync(Usage);
                    return 2;
            }
        }

        try
        {
            if (configuration is null)
            {
                configuration = new ConfigurationManager();
                configuration.AddEnvironmentVariables();
            }
            configuration.AddInstalledEnvironment();
            var factory = new PostgresConnectionFactory(configuration);
            var management = new AgentManagementService(new AgentControlAudit());
            var ct = CancellationToken.None;
            await using var db = await factory.OpenAsync(ct);
            await using var tx = await db.BeginTransactionAsync(ct);
            var issued = await management.IssueConsoleTokenAsync(db, tx, count ?? 1, manageWindowsAudit,
                address, "host_admin:root", configuration, saveAddress: false, fallbackAddress: null, ct);
            await tx.CommitAsync(ct);
            await output.WriteLineAsync(issued.Command);
            return 0;
        }
        catch (AgentControlException failure)
        {
            await error.WriteLineAsync(failure.Message == "agent_console_server_url_required"
                ? "No agent server address is saved. Specify --server-url https://HOST[:PORT]."
                : failure.Message);
        }
        catch (Exception)
        {
            await error.WriteLineAsync("agent_command_failed");
        }
        return 1;
    }
}
