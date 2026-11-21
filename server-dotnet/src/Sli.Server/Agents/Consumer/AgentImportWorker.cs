using System.CommandLine;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Agents.Radius;
using Sli.Server.Legacy;
using Sli.Server.Hosting;
using Sli.Server.Storage.Lifecycle;

namespace Sli.Server.Agents.Consumer;

// Separate process, matching post_collection_worker.py's agent inbox poll and lock.
public static class AgentImportCommand
{
    public static async Task<int> RunAsync(string[] args)
    {
        var once = new Option<bool>("--once");
        var poll = new Option<int>("--poll-seconds") { DefaultValueFactory = _ => 10 };
        var limit = new Option<int>("--limit") { DefaultValueFactory = _ => 1 };
        var root = new RootCommand("Run agent post-collection imports under one process lock.");
        root.Options.Add(once); root.Options.Add(poll); root.Options.Add(limit);
        root.SetAction(async (parse, ct) =>
        {
            int interval = Math.Clamp(parse.GetValue(poll), 1, 300);
            var builder = Host.CreateApplicationBuilder(Array.Empty<string>());
            builder.Configuration.AddInstalledEnvironment();
            if (!TryCreateFactory(builder.Configuration, out var connections))
            {
                Console.Error.WriteLine("server_configuration_invalid:ConnectionStrings:Sli:invalid");
                return 1;
            }
            builder.Services.AddSingleton<IPostgresConnectionFactory>(connections!);
            await using var direct = DirectAdDcRuntime.TryCreate(builder.Configuration, out var issue);
            builder.Services.AddSingleton(new AgentWorkstationInboxConsumer(connections!, direct) { DirectConfigurationIssue = issue });
            builder.Services.AddSingleton(new AgentImportOptions(parse.GetValue(once), interval, Math.Clamp(parse.GetValue(limit), 1, 10)));
            builder.Services.AddSingleton<AgentImportWorker>();
            builder.Services.AddHostedService(sp => sp.GetRequiredService<AgentImportWorker>());
            using var host = builder.Build();
            var worker = host.Services.GetRequiredService<AgentImportWorker>();
            await host.RunAsync(ct);
            return worker.ExitCode;
        });
        var parsed = root.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null });
        try { return await parsed.InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false }); }
        catch (Exception error) when (error is InvalidOperationException or ArgumentException or FormatException)
        { Console.Error.WriteLine(WorkerFailure.Describe(error, "post_collection_startup")); return 1; }
    }

    public static bool TryCreateFactory(IConfiguration config, out IPostgresConnectionFactory? factory)
    {
        try
        {
            var value = config.GetConnectionString("Sli") ?? config["Sli:PostgresConnectionString"];
            if (string.IsNullOrWhiteSpace(value) || new NpgsqlConnectionStringBuilder(value).Multiplexing)
            { factory = null; return false; }
            var worker = new NpgsqlConnectionStringBuilder(value) { Pooling = true, NoResetOnClose = false, CommandTimeout = 0 };
            worker.Options = (worker.Options ?? "") + " -c statement_timeout=0 -c lock_timeout=0";
            var workerConfig = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
                ["ConnectionStrings:Sli"] = worker.ConnectionString
            }).Build();
            factory = new PostgresConnectionFactory(workerConfig); return true;
        }
        catch (Exception error) when (error is InvalidOperationException or ArgumentException or FormatException)
        { factory = null; return false; }
    }
}

public sealed record AgentImportOptions(bool Once, int PollSeconds, int Limit = 1);

public static class AgentImportLoop
{
    public static async Task<int> RunAsync(AgentImportOptions options,
        Func<int, CancellationToken, Task<AgentInboxBatchResult>> poll,
        Func<TimeSpan, CancellationToken, Task> delay, CancellationToken ct)
    {
        do
        {
            var batch = await poll(16, ct);
            if (options.Once) return batch.PendingReasons.Keys.Any(k => k is "agent_projection_failed" or "agent_ad_dc_projection_failed") ? 1 : 0;
            if (batch.Scanned != 16) await delay(TimeSpan.FromSeconds(options.PollSeconds), ct);
        } while (!ct.IsCancellationRequested);
        return 0;
    }
}

public sealed class AgentImportWorker(IPostgresConnectionFactory connections, AgentWorkstationInboxConsumer consumer,
    AgentImportOptions options, IHostApplicationLifetime lifetime) : BackgroundService
{
    public int ExitCode { get; private set; }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            // A dedicated autocommit session uses the very same source lock as the Python process.
            await using var connection = await connections.OpenAsync(stoppingToken);
            await using var command = new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_post_collection_process'))", connection);
            if (await command.ExecuteScalarAsync(stoppingToken) is not true) {
                Console.WriteLine("{\"status\":\"skipped\",\"reason\":\"post_collection_process_lock_held\"}");
                ExitCode = 9; return;
            }
            try
            {
                consumer.ReportDirectConfigurationIssue(stoppingToken);
                ExitCode = await new PostCollectionRuntime(connection, connections, consumer)
                    .RunAsync(options, stoppingToken);
            }
            finally
            {
                await using var unlock = new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_post_collection_process'))", connection);
                await unlock.ExecuteScalarAsync(CancellationToken.None);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        catch (Exception error) { ExitCode = 1; Console.Error.WriteLine("agent_consumer_unavailable:" + WorkerFailure.Describe(error, "post_collection_process")); }
        finally { lifetime.StopApplication(); }
    }
}
