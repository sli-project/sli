using System.CommandLine;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.SnapshotPublication;

namespace Sli.Server.Entities;

internal sealed record WhatWhereWhenOptions(bool Once, int Batch, int Retention, Microsoft.Extensions.Configuration.IConfiguration? Configuration = null);
internal delegate Task<int> WhatWhereWhenRunner(WhatWhereWhenOptions options, Action<JsonObject> output, CancellationToken ct);
public static class WhatWhereWhenCommand
{
    public static Task<int> RunAsync(string[] args) => RunCore(args, RunWorker, Console.Out, Console.Error);
    internal static async Task<int> RunCore(string[] args, WhatWhereWhenRunner runner, TextWriter output, TextWriter error, CancellationToken cancellationToken = default)
    {
        var once = new Option<bool>("--once");
        var batch = new Option<int>("--batch-limit") { DefaultValueFactory = _ => 2000 };
        var retention = new Option<int>("--retention-limit") { DefaultValueFactory = _ => 10000 };
        var supervisor = new Option<bool>("--load-supervisor-environment");
        var command = new RootCommand("Project bounded domain-user logon observations.");
        command.Options.Add(once); command.Options.Add(batch); command.Options.Add(retention); command.Options.Add(supervisor);
        command.SetAction(async (parse, ct) =>
        {
            if (parse.GetValue(supervisor)) { await error.WriteLineAsync("what_where_when_supervisor_environment_unavailable"); return 1; }
            var host = Host.CreateApplicationBuilder(Array.Empty<string>());
            host.Logging.ClearProviders();
            // The console owns only cancellation and configuration. The worker
            // owns both source-compatible advisory locks and its transaction.
            var options = new WhatWhereWhenOptions(parse.GetValue(once), Math.Clamp(parse.GetValue(batch), 1, 10000), Math.Clamp(parse.GetValue(retention), 1, 50000), host.Configuration);
            host.Services.AddSingleton(options); host.Services.AddSingleton(runner); host.Services.AddSingleton(new WhatWhereWhenOutput(output, error));
            host.Services.AddSingleton<WhatWhereWhenHostedService>(); host.Services.AddHostedService(sp => sp.GetRequiredService<WhatWhereWhenHostedService>());
            using var application = host.Build(); var service = application.Services.GetRequiredService<WhatWhereWhenHostedService>();
            try { await application.RunAsync(ct); return service.ExitCode; }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return 0; }
        });
        return await command.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null }).InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false }, cancellationToken);
    }
    static async Task<int> RunWorker(WhatWhereWhenOptions options, Action<JsonObject> output, CancellationToken ct)
    {
        if (!GpoWorkerConfiguration.TryCreateNamed(Environment.GetEnvironmentVariable, ReadBounded, "ADLOG_PG_DSN", "ADLOG_PG_PASSWORD", "ad_log_reports_runtime", 900, out var dsn))
            throw new InvalidOperationException("server_configuration_invalid");
        await using var source = NpgsqlDataSource.Create(dsn!);
        return await new WhatWhereWhenWorker(source, options.Configuration).Run(options.Once, options.Batch, options.Retention, output, ct);
    }
    static byte[] ReadBounded(string path)
    {
        using var stream = File.OpenRead(path); byte[] bytes = new byte[65537]; int count = 0, read;
        while (count < bytes.Length && (read = stream.Read(bytes, count, bytes.Length - count)) != 0) count += read;
        if (count > 65536) throw new InvalidDataException("secret_file_too_large"); return bytes[..count];
    }
}
internal sealed record WhatWhereWhenOutput(TextWriter Output, TextWriter Error);
internal sealed class WhatWhereWhenHostedService(WhatWhereWhenOptions options, WhatWhereWhenRunner runner, WhatWhereWhenOutput streams, IHostApplicationLifetime lifetime) : BackgroundService
{
    internal int ExitCode { get; private set; } = 1;
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { ExitCode = await runner(options, row => streams.Output.WriteLine(row.ToJsonString()), stoppingToken); }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { ExitCode = 0; }
        catch (Exception) { await streams.Error.WriteLineAsync("what_where_when_worker_unavailable"); }
        finally { lifetime.StopApplication(); }
    }
}
