using System.CommandLine;
using System.Text.Json.Nodes;

namespace Sli.Server.Storage.Lifecycle;

public static class StorageLifecycleCommand
{
    public static Task<int> RunAsync(string[] args) => RunCoreAsync(args, RunWorker, Console.Out, Console.Error);
    internal static async Task<int> RunCoreAsync(string[] args, Func<LifecycleOptions, Action<JsonObject>, CancellationToken, Task<int>> run, TextWriter output, TextWriter error, CancellationToken ct = default)
    {
        var once = new Option<bool>("--once"); var interval = new Option<int>("--interval-seconds") { DefaultValueFactory = _ => 21600 };
        var size = new Option<int>("--delete-batch-size") { DefaultValueFactory = _ => 1000 };
        var root = new RootCommand("Automatic partition and queue retention.");
        root.Options.Add(once); root.Options.Add(interval); root.Options.Add(size);
        root.SetAction(async (parse, token) => {
            var options = new LifecycleOptions(parse.GetValue(once), Math.Clamp(parse.GetValue(interval), 900, 86400), Math.Clamp(parse.GetValue(size), 1, 1000));
            var builder = Host.CreateApplicationBuilder([]); builder.Logging.ClearProviders();
            builder.Services.AddSingleton(new LifecycleRun(run, options, output, error)); builder.Services.AddSingleton<LifecycleService>(); builder.Services.AddHostedService(sp => sp.GetRequiredService<LifecycleService>());
            using var host = builder.Build(); var service = host.Services.GetRequiredService<LifecycleService>();
            try { await host.RunAsync(token); return service.ExitCode; } catch (OperationCanceledException) when (token.IsCancellationRequested) { return 0; }
        });
        var parsed = root.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null });
        return await parsed.InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false, Output = output, Error = error }, ct);
    }
    static async Task<int> RunWorker(LifecycleOptions options, Action<JsonObject> output, CancellationToken ct)
    {
        string root = LifecycleConfiguration.FindRoot(); var config = new LifecycleConfiguration(root, Environment.GetEnvironmentVariable);
        var files = new LifecycleFiles(config.DataRoot(root));
        await using var runtime = new LifecycleRuntime(config.Get, files);
        var operations = new Operations.OperationsFiles(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:ProjectRoot"] = root }).Build());
        return await new StorageLifecycleWorker(runtime, files, readVolume: operations.PostgresVolume).RunAsync(options, output, ct);
    }
    sealed record LifecycleRun(Func<LifecycleOptions, Action<JsonObject>, CancellationToken, Task<int>> Runner, LifecycleOptions Options, TextWriter Output, TextWriter Error);
    sealed class LifecycleService(LifecycleRun run, IHostApplicationLifetime lifetime) : BackgroundService
    {
        internal int ExitCode { get; private set; } = 2;
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            try { ExitCode = await run.Runner(run.Options, value => run.Output.WriteLine(LifecycleJson.Canonical(value)), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { ExitCode = 0; }
            catch (Exception error) { await run.Error.WriteLineAsync(LifecycleJson.Canonical(LifecycleJson.Result("failed", LifecycleJson.Failure(error)))); }
            finally { lifetime.StopApplication(); }
        }
    }
}
