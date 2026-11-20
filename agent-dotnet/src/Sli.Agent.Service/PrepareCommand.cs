using Microsoft.Extensions.Configuration;
using Sli.Agent.Core;

namespace Sli.Agent.Service;

public static class PrepareCommand
{
    /// <summary>Creates the host id and key if absent and prints only public values as JSON.</summary>
    public static int Run(string[] args)
    {
        try
        {
            var options = new AgentOptions();
            AgentConfiguration.Load(args.Skip(1).ToArray()).GetSection(AgentOptions.Section).Bind(options);
            if (!Path.IsPathFullyQualified(options.StateDir)) throw new AgentException("agent_state_path_invalid");
            var store = AgentRuntime.CreateIdentityStore(options);
            var prepared = store.Prepare(options.HostId);
            Console.Error.WriteLine("agent_prepare_state_directory=" + Path.GetFullPath(options.StateDir));
            if (!string.Equals(Path.GetFullPath(options.StateDir).TrimEnd(Path.DirectorySeparatorChar),
                Path.GetFullPath(new AgentOptions().StateDir).TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
                Console.Error.WriteLine("agent_prepare_custom_state_directory_service_must_match");
            Console.WriteLine($"{{\"host_id\":\"{prepared.HostId}\",\"key_fingerprint\":\"{prepared.KeyFingerprint}\"}}");
            return 0;
        }
        catch (AgentException exception)
        {
            Console.Error.WriteLine(exception.Code);
            return 1;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            Console.Error.WriteLine("agent_identity_store_unavailable_run_prepare_as_administrator");
            return 1;
        }
    }
}
