using System.Runtime.InteropServices;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Sli.Server.Auth.Recovery;

public sealed class OwnerRecoveryTerminal
{
    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEffectiveUserId();
    [DllImport("libc", EntryPoint = "isatty")]
    private static extern int IsATty(int descriptor);

    public void RequireRootInteractiveTerminal()
    {
        if (!OperatingSystem.IsLinux() || GetEffectiveUserId() != 0)
            throw new UnauthorizedAccessException("host_root_required");
        if (Console.IsInputRedirected || Console.IsOutputRedirected || IsATty(0) != 1 || IsATty(1) != 1)
            throw new UnauthorizedAccessException("terminal_required");
    }

    internal void WriteCode(string code)
    {
        RequireRootInteractiveTerminal();
        Console.Out.WriteLine("Single-use owner recovery code (expires in 10 minutes; password also required):");
        Console.Out.WriteLine(code);
    }
}

public sealed class OwnerRecoveryConsole(OwnerRecoveryService recovery, OwnerRecoveryTerminal terminal) : IOwnerRecoveryConsole
{
    public sealed record Arguments(string? Username, bool Help, bool Valid);

    public static Arguments ParseArguments(string[] args)
    {
        if (args.Length == 0 || args[0] != "owner-recovery") return new(null, false, false);
        if (args.Skip(1).Any(arg => arg is "--help" or "-h")) return new(null, true, true);
        if (args.Length == 3 && args[1] == "--username" && !args[2].StartsWith('-')) return new(args[2], false, true);
        if (args.Length == 2 && args[1].StartsWith("--username=", StringComparison.Ordinal))
            return new(args[1]["--username=".Length..], false, true);
        return new(null, false, false);
    }

    // Program invokes this before root/TTY checks or DI, matching argparse's non-issuance path.
    public static bool TryHandleNonIssuance(string[] args, out int exitCode)
    {
        Arguments parsed = ParseArguments(args);
        exitCode = parsed.Valid ? 0 : 2;
        if (parsed.Valid && !parsed.Help) return false;
        if (parsed.Help)
        {
            Console.Out.WriteLine("usage: owner-recovery --username USERNAME");
            Console.Out.WriteLine("Root console only: issue a single-use owner code (10 minutes)");
            Console.Out.WriteLine("  --username USERNAME, --username=USERNAME\n  -h, --help");
        }
        else Console.Error.WriteLine("usage: owner-recovery --username USERNAME");
        return true;
    }

    public async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        if (TryHandleNonIssuance(args, out int exitCode)) return exitCode;
        string username = ParseArguments(args).Username!;
        try
        {
            terminal.RequireRootInteractiveTerminal();
            string code = await recovery.IssueAsync(username, ct);
            terminal.WriteCode(code);
            return 0;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { return 130; }
        catch (UnauthorizedAccessException error) when (error.Message is "host_root_required" or "terminal_required")
        { Console.Error.WriteLine(error.Message); return 1; }
        catch (InvalidOperationException error) when (error.Message == "active_platform_owner_required")
        { Console.Error.WriteLine("active_platform_owner_required"); return 1; }
        // Provider exceptions may include parameters; print only a stable secret-free code.
        catch (Exception) { Console.Error.WriteLine("owner_recovery_issue_failed"); return 1; }
    }
}

public static class OwnerRecoveryServices
{
    public static IServiceCollection AddOwnerRecovery(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton<OwnerRecoveryAdmission>();
        services.AddSingleton<OwnerRecoveryTerminal>();
        services.AddScoped<OwnerRecoveryService>();
        services.AddScoped<IOwnerRecoveryService>(provider => provider.GetRequiredService<OwnerRecoveryService>());
        services.AddScoped<IOwnerRecoveryConsole, OwnerRecoveryConsole>();
        return services;
    }
}
