using System.CommandLine;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Hosting;
using Sli.Server.Infrastructure;

namespace Sli.Server.Semantic;

public static partial class SemanticRetainedCommand
{
    public static Task<int> RunAsync(string[] args) => RunCore(args, Execute, Console.Out, Console.Error);
    internal static async Task<int> RunCore(string[] args, Func<string, long[], string?, string?, CancellationToken, Task<JsonObject>> execute, TextWriter output, TextWriter error, CancellationToken ct = default, Action<string, bool>? loadEnvironment = null)
    {
        var action = new Argument<string>("action"); var ids = new Option<long[]>("--event-id") { AllowMultipleArgumentsPerToken = true };
        var digest = new Option<string?>("--plan-digest"); var confirm = new Option<string?>("--confirm"); var profile = new Option<string?>("--environment-file");
        var root = new RootCommand("Plan, resume and reconcile retained semantic work."); root.Arguments.Add(action); root.Options.Add(ids); root.Options.Add(digest); root.Options.Add(confirm); root.Options.Add(profile);
        root.SetAction(async (parse, token) => {
            string command = parse.GetValue(action)!; string? confirmation = parse.GetValue(confirm), plan = parse.GetValue(digest); var events = parse.GetValue(ids) ?? [];
            try {
                if (command is not ("facts-poll" or "facts-check-plan" or "facts-check" or "security-history-plan" or "security-history-poll" or "security-history-check-plan" or "security-history-check" or "security-history-supersede-plan" or "security-history-supersede")) throw new InvalidOperationException("semantic_retained_action_invalid");
                if (command == "facts-poll" && confirmation != "POLL-STAGE8-RETAINED-FACTS") throw new InvalidOperationException("retained facts poll confirmation required");
                if (command is "facts-check" or "facts-check-plan") _ = SemanticRetainedControl.ExactIds(events);
                string? prefix = command switch { "facts-check" => SemanticRetainedControl.ExactPrefix, "security-history-poll" => SemanticRetainedControl.PollPrefix, "security-history-check" => SemanticRetainedControl.CheckPrefix, "security-history-supersede" => SemanticRetainedControl.SupersedePrefix, _ => null };
                if (prefix is not null && (command != "security-history-poll" && string.IsNullOrEmpty(plan) || confirmation is null || !confirmation.StartsWith(prefix, StringComparison.Ordinal) || command != "security-history-poll" && confirmation != prefix + plan)) throw new InvalidOperationException("semantic retained exact confirmation required");
                if (parse.GetValue(profile) is { } path) (loadEnvironment ?? SemanticRetainedEnvironment.Load)(Path.GetFullPath(path), true);
                await output.WriteLineAsync((await execute(command, events, plan, confirmation, token)).ToJsonString()); return 0;
            }
            catch (InvalidOperationException e) { await error.WriteLineAsync(e.Message); return 1; }
            catch (Exception e) when (e is not OperationCanceledException) { await error.WriteLineAsync("semantic_retained_failed:" + WorkerFailure.Describe(e, "retained_control")); return 1; }
        });
        return await root.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null }).InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false, Output = output, Error = error }, ct);
    }
    private sealed class Connections(NpgsqlDataSource source) : IPostgresConnectionFactory
    { public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => await source.OpenConnectionAsync(ct); }
    internal static string ConnectionString(Func<string, string?> get)
    {
        string? dsn = get("ConnectionStrings__Sli") ?? get("Sli__PostgresConnectionString"); bool legacy = dsn is null;
        dsn ??= GpoWorkerConfiguration.CreateNamed(get, Storage.Lifecycle.LifecycleRuntime.ReadSecret, "ADLOG_PG_DSN", "ADLOG_PG_PASSWORD", "sli_semantic_control", 0);
        var builder = new NpgsqlConnectionStringBuilder(dsn) { Pooling = false, Multiplexing = false, CommandTimeout = 0, IncludeErrorDetail = false };
        if (legacy) {
            string? user = Storage.Lifecycle.LifecycleRuntime.Secret(get, "ADLOG_PG_ADMIN_USER"), password = Storage.Lifecycle.LifecycleRuntime.Secret(get, "ADLOG_PG_ADMIN_PASSWORD");
            if (string.IsNullOrWhiteSpace(user) || string.IsNullOrEmpty(password)) throw new InvalidOperationException("protected PostgreSQL migration credentials are required");
            builder.Username = user; builder.Password = password;
        }
        if (string.IsNullOrWhiteSpace(builder.Host) || string.IsNullOrWhiteSpace(builder.Database) || string.IsNullOrWhiteSpace(builder.Username)) throw new ServerConfigurationException("semantic_control_database_identity");
        return builder.ConnectionString;
    }
    private static async Task<JsonObject> Execute(string action, long[] ids, string? digest, string? confirmation, CancellationToken ct)
    {
        await using var source = NpgsqlDataSource.Create(ConnectionString(Environment.GetEnvironmentVariable)); var connections = new Connections(source);
        string data = Environment.GetEnvironmentVariable("ADLOG_DATA_DIR") ?? Environment.GetEnvironmentVariable("SLI_DATA_DIR") ?? Path.Combine(Directory.GetCurrentDirectory(), "data");
        var controller = new SemanticRetainedControl(new SemanticDatabase(connections), Path.Combine(data, "runtime"));
        return action switch {
            "facts-poll" => await controller.FactsPoll(ct), "facts-check-plan" => await controller.ExactPlan(ids, ct),
            "facts-check" => await controller.ExactCheck(ids, digest!, confirmation, ct, (exact, token) => WithWorkerLogin(connections, (dsn, cancel) => SemanticRetainedControl.ConsumeExactWithDsn(exact, dsn, cancel), token)),
            "security-history-plan" => await controller.HistoryPlan(ct), "security-history-poll" => await controller.HistoryPoll(confirmation!, ct),
            "security-history-check-plan" => await controller.HistoryCheckPlan(ct), "security-history-check" => await controller.HistoryCheck(digest!, confirmation!, ct),
            "security-history-supersede-plan" => await controller.SupersedePlan(ct), "security-history-supersede" => await controller.Supersede(digest!, confirmation!, ct),
            _ => throw new InvalidOperationException("semantic_retained_action_invalid") };
    }
}
