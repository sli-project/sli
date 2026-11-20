using System.CommandLine;
using System.Diagnostics;
using System.Text.Json.Nodes;

namespace Sli.Server.Semantic;

public static class SemanticDispatchRecoveryCommand
{
    public static async Task<int> RunAsync(string[] args)
    {
        var planFile = new Option<string>("--plan-file") { DefaultValueFactory = _ => "artifacts/stage8/evidence/semantic-dispatch-partition-recovery-plan.json" };
        var auditFile = new Option<string>("--audit-file") { DefaultValueFactory = _ => "artifacts/stage8/evidence/semantic-dispatch-partition-recovery-audit.json" };
        var digest = new Option<string>("--plan-digest") { DefaultValueFactory = _ => "" };
        var confirm = new Option<string>("--confirm") { DefaultValueFactory = _ => "" };
        var root = new RootCommand("Recover only the sealed historic semantic dispatch partitions.");
        var plan = new Command("plan"); var apply = new Command("apply"); root.Subcommands.Add(plan); root.Subcommands.Add(apply);
        foreach (var command in new[] { plan, apply }) { command.Options.Add(planFile); command.Options.Add(auditFile); command.Options.Add(digest); command.Options.Add(confirm); }
        plan.SetAction((parse, ct) => ExecuteAsync(false, parse.GetValue(planFile)!, parse.GetValue(auditFile)!, parse.GetValue(digest)!, parse.GetValue(confirm)!, Environment.GetEnvironmentVariable, Console.Out, Console.Error, ct));
        apply.SetAction((parse, ct) => ExecuteAsync(true, parse.GetValue(planFile)!, parse.GetValue(auditFile)!, parse.GetValue(digest)!, parse.GetValue(confirm)!, Environment.GetEnvironmentVariable, Console.Out, Console.Error, ct));
        return await root.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null }).InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false });
    }
    internal static Task<int> ExecuteAsync(bool apply, string planPath, string auditPath, string digest, string confirmation, Func<string, string?> get, TextWriter output, TextWriter error, CancellationToken ct) =>
        SemanticDispatchRecovery.ReportAsync(async () => {
            // This must precede even configuration loading, not just the first write.
            JsonObject? sealedPlan = apply ? SemanticDispatchRecovery.LoadApplyPlan(planPath, digest, confirmation) : null;
            string dsn = get("ConnectionStrings__Sli") ?? get("Sli__PostgresConnectionString") ?? throw new InvalidOperationException("semantic recovery admin database configuration required");
            var runtime = new SemanticDispatchRecoveryRuntime(dsn);
            return apply ? await runtime.Apply(sealedPlan!, () => GuardAsync(runtime, ct), auditPath, ct) : SemanticDispatchRecovery.WriteAtomicAudit(planPath, await runtime.Plan(ct));
        }, output, error);

    internal static async Task<int?> GuardAsync(SemanticDispatchRecoveryRuntime runtime, CancellationToken ct)
    {
        // A successful, complete OS inventory is mandatory. Never infer a stopped worker from a failed query.
        bool IsWorker(string command) => command.Contains("semantic-production-worker", StringComparison.OrdinalIgnoreCase) || command.Contains("semantic_production_worker.py", StringComparison.OrdinalIgnoreCase);
        bool live;
        if (OperatingSystem.IsWindows()) {
            var info = new ProcessStartInfo("powershell.exe") { UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; @(Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(python.*|dotnet|Sli.Server)(\\.exe)?$' } | ForEach-Object { if ($null -eq $_.CommandLine) { throw 'process_inventory_unavailable' }; $_.CommandLine }) | ConvertTo-Json -Compress" }) info.ArgumentList.Add(arg);
            using var process = Process.Start(info) ?? throw new InvalidOperationException("process inventory unavailable");
            var stdout = process.StandardOutput.ReadToEndAsync(ct); var stderr = process.StandardError.ReadToEndAsync(ct); await process.WaitForExitAsync(ct);
            string text = await stdout; await stderr;
            if (process.ExitCode != 0) return null;
            var payload = string.IsNullOrWhiteSpace(text) ? new JsonArray() : JsonNode.Parse(text);
            live = payload is JsonArray list ? list.Any(x => IsWorker(x!.GetValue<string>())) : payload is JsonValue value && IsWorker(value.GetValue<string>());
        }
        else if (OperatingSystem.IsLinux()) {
            live = false;
            foreach (string directory in Directory.EnumerateDirectories("/proc").Where(x => int.TryParse(Path.GetFileName(x), out _))) {
                ct.ThrowIfCancellationRequested();
                try { if (IsWorker(await File.ReadAllTextAsync(Path.Combine(directory, "cmdline"), ct))) live = true; }
                catch (Exception e) when (e is FileNotFoundException or DirectoryNotFoundException) { /* Process exited during inventory. */ }
            }
        }
        else return null;
        // Also require a successful authoritative DB read before claiming safety.
        await runtime.Snapshot(ct);
        return live ? 1 : 0;
    }
}
