using System.CommandLine;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.SnapshotPublication;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Operations;

public static class OperationsStorageSnapshotCommand
{
    public static Task<int> RunAsync(string[] args) => RunCoreAsync(args, BuildAsync, Console.Out, Console.Error);

    internal static async Task<int> RunCoreAsync(string[] args, Func<StorageSnapshotOptions, CancellationToken, Task<JsonObject>> build,
        TextWriter output, TextWriter error, CancellationToken ct = default)
    {
        var path = new Option<string?>("--output"); var external = new Option<string?>("--external-archive"); var evidence = new Option<string?>("--evidence-root");
        var warm = new Option<string>("--clickhouse-container") { DefaultValueFactory = _ => "sli-warm-tier-step1" };
        var history = new Option<string?>("--clickhouse-history-container") { DefaultValueFactory = _ => "sli-history" };
        var deps = new Option<string?>("--platform-deps"); var pgData = new Option<string?>("--postgres-data"); var pgBin = new Option<string?>("--postgres-bin");
        var data = new Option<string?>("--sli-data"); var pnpm = new Option<string?>("--pnpm-store"); var skip = new Option<bool>("--skip-docker");
        var command = new RootCommand("Create one read-only, deduplicated storage footprint snapshot for Operations.");
        foreach (Option option in new Option[] { path, external, evidence, warm, history, deps, pgData, pgBin, data, pnpm, skip }) command.Options.Add(option);
        command.SetAction(async (parse, token) =>
        {
            var files = new OperationsFiles(new ConfigurationBuilder().Build());
            string sibling = Directory.GetParent(files.Root)!.FullName;
            static string? Existing(string directory) => Directory.Exists(directory) ? directory : null;
            var options = new StorageSnapshotOptions {
                ExternalArchive = parse.GetValue(external), EvidenceRoot = parse.GetValue(evidence), ClickHouseContainer = parse.GetValue(warm)!, HistoryContainer = parse.GetValue(history), IncludeDocker = !parse.GetValue(skip),
                PlatformDependencies = parse.GetValue(deps) ?? (OperatingSystem.IsWindows() ? Existing(@"D:\SLI_platform_deps") : null),
                PostgresData = parse.GetValue(pgData) ?? (OperatingSystem.IsWindows() ? Existing(@"D:\postgresql-data-official") : null),
                PostgresBin = parse.GetValue(pgBin) ?? (OperatingSystem.IsWindows() ? Existing(@"D:\PostgreSQL") : null),
                SliData = parse.GetValue(data) ?? Existing(Path.Combine(sibling, "sli_data")), PnpmStore = parse.GetValue(pnpm) ?? Existing(Path.Combine(sibling, ".pnpm-store")) };
            string destination = parse.GetValue(path) ?? Path.Combine(files.Root, "artifacts/operations/project-storage-latest.json");
            try
            {
                var result = await build(options, token); OperationsStorageSnapshot.WriteAtomic(destination, result);
                await output.WriteLineAsync(new JsonObject { ["status"] = Copy(result["status"]), ["output"] = destination, ["totals"] = Copy(result["totals"]), ["warnings"] = Copy(result["warnings"]) }.ToJsonString());
                return S(result["status"]) is "ok" or "partial" ? 0 : 1;
            }
            catch (Exception e) when (!token.IsCancellationRequested) { await error.WriteLineAsync(Unavailable(e).ToJsonString()); return 1; }
        });
        return await command.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null }).InvokeAsync(
            new InvocationConfiguration { EnableDefaultExceptionHandler = false, Output = output, Error = error }, ct);
    }

    static Task<JsonObject> BuildAsync(StorageSnapshotOptions options, CancellationToken ct)
    {
        var files = new OperationsFiles(new ConfigurationBuilder().Build());
        return new OperationsStorageSnapshot(files, PostgresAsync).BuildAsync(options, DateTimeOffset.UtcNow, ct);
    }
    static async Task<JsonObject> PostgresAsync(CancellationToken ct)
    {
        // Reuse the worker's strict DSN/credential parsing. Do not copy secrets to
        // the snapshot, inherited Docker arguments, logs, or failure messages.
        string connection = GpoWorkerConfiguration.CreateNamed(Environment.GetEnvironmentVariable, File.ReadAllBytes,
            "ADLOG_PG_DSN", "ADLOG_PG_PASSWORD", "sli_operations_storage_snapshot", 0);
        await using var db = new NpgsqlConnection(connection); await db.OpenAsync(ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        await using (var readOnly = new NpgsqlCommand("set transaction read only", db, tx) { CommandTimeout = 0 }) await readOnly.ExecuteNonQueryAsync(ct);
        await using var query = new NpgsqlCommand("select current_database(),pg_database_size(current_database()),now()", db, tx) { CommandTimeout = 0 };
        await using var reader = await query.ExecuteReaderAsync(ct); await reader.ReadAsync(ct);
        return new() { ["available"] = true, ["status"] = "ok", ["database"] = new JsonObject { ["database_name"] = reader.GetString(0),
            ["database_bytes"] = reader.GetInt64(1), ["database_human"] = Human(reader.GetInt64(1)), ["checked_at"] = Stamp(reader.GetFieldValue<DateTime>(2)) } };
    }
}
