using System.CommandLine;
using System.Text.Json;
using Npgsql;
using Sli.Server.Agents.Consumer;
using Sli.Server.Infrastructure;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic;
using Sli.Server.Sources;

namespace Sli.Server.Legacy;

public static class LegacyWorkerCommand
{
    public static Task<int> RunAsync(string role, string[] args) => RunAsync(role, args, null);
    internal static async Task<int> RunAsync(string role, string[] args, Func<SemanticProductionOptions, CancellationToken, Task<int>>? semanticRun)
    {
        // Compatibility entry point: there is one owner and one complete cycle,
        // rather than a legacy-only process competing with the inbox worker.
        if (role == "legacy-post-collection-worker") return await AgentImportCommand.RunAsync(args);
        var once = new Option<bool>("--once");
        var poll = new Option<int>("--poll-seconds") { DefaultValueFactory = _ => 30 };
        var limit = new Option<int>("--limit") { DefaultValueFactory = _ => role == "semantic-worker" ? 128 : 1 };
        var hours = new Option<int>("--hours") { DefaultValueFactory = _ => 1 };
        var events = new Option<int>("--max-events", "--max-events-per-channel") { DefaultValueFactory = _ => 50_000 };
        var preflight = new Option<string>("--preflight-server") { DefaultValueFactory = _ => Environment.GetEnvironmentVariable("ADLOG_COLLECTION_PREFLIGHT_SERVER") ?? "" };
        var command = new RootCommand("Run an isolated legacy/manual worker. Retired workers are never started.");
        foreach (var option in new Option[] { once, poll, limit, hours, events, preflight }) command.Options.Add(option);
        command.SetAction(async (parse, ct) => {
            if (role != "semantic-worker") {
                Output(new { status = "disabled", reason = "module_disabled" }); return 0;
            }
            if (role == "semantic-worker" && semanticRun is not null)
                return await semanticRun(new(parse.GetValue(once), parse.GetValue(poll), parse.GetValue(limit)), ct);
            var settings = new LegacySettings(Host.CreateApplicationBuilder(Array.Empty<string>()).Configuration);
            return await SemanticAsync(parse.GetValue(once), Math.Clamp(parse.GetValue(poll), 5, 300),
                Math.Clamp(parse.GetValue(limit), 1, 128), settings, ct);
        });
        try {
            return await command.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null })
                .InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false });
        }
        catch (OperationCanceledException) { return 130; }
        catch (InvalidOperationException error) when (error.Message is "semantic_normalization_must_be_explicitly_enabled"
            or "semantic_directory_state_forbidden" or "semantic_finding_creation_forbidden" or "semantic_development_scope_required")
        { Console.Error.WriteLine(error.Message); return 1; }
        catch { Console.Error.WriteLine("legacy_worker_failed"); return 1; }
    }

    private static void Output<T>(T result) => Console.WriteLine(JsonSerializer.Serialize(result));

    internal static Task<System.Text.Json.Nodes.JsonObject> RunCollectionCycleAsync(
        IServiceProvider services, string worker, int hours, int maxEvents, CancellationToken ct,
        Func<LegacyWork, CancellationToken, Task>? execute = null)
    {
        throw new InvalidOperationException("module_disabled");
    }

    private static async Task<int> SemanticAsync(bool once, int poll, int limit, LegacySettings settings, CancellationToken ct)
    {
        DevelopmentSemanticGuard.ValidateSettings(settings);
        await using var runtime = PasswordProducerRuntime.TryCreate();
        if (runtime is null) { Console.Error.WriteLine("semantic_worker_configuration_invalid"); return 1; }
        await using var db = await runtime.OpenAsync(ct);
        await DevelopmentSemanticGuard.ValidateDatabaseAsync(db, ct);
        await using var acquire = new NpgsqlCommand("select pg_try_advisory_lock(hashtext('ad_log_reports_runtime_semantic_development_worker'))", db);
        if (await acquire.ExecuteScalarAsync(ct) is not true) { Output(new { status = "skipped", reason = "semantic_worker_lock_held" }); return 0; }
        Guid worker = Guid.NewGuid();
        try {
            return await SemanticProduction.RunCyclesAsync(new(once, poll, limit), async token => {
                DevelopmentSemanticGuard.ValidateSettings(settings);
                await DevelopmentSemanticGuard.ValidateDatabaseAsync(db, token);
                var pipeline = new SemanticProduction(runtime, SemanticRuntimeSettings.Read(settings.Get),
                    SemanticProduction.DevelopmentMode, limit, development: true);
                return await pipeline.RunDevelopmentOnceAsync(db, token);
            }, (status, result) => SemanticProduction.Heartbeat(db, worker, SemanticProduction.DevelopmentMode,
                status == "error" ? "failed" : status, poll, ct, result, development: true), () => false, Task.Delay, ct, development: true);
        }
        finally {
            await using var release = new NpgsqlCommand("select pg_advisory_unlock(hashtext('ad_log_reports_runtime_semantic_development_worker'))", db);
            await release.ExecuteScalarAsync(CancellationToken.None);
        }
    }
}

public static class DevelopmentSemanticGuard
{
    public static void ValidateSettings(LegacySettings settings)
    {
        bool normalization = settings.Enabled("ADLOG_SEMANTIC_NORMALIZATION_ENABLED");
        bool assembly = normalization && settings.Enabled("ADLOG_SEMANTIC_ASSEMBLY_ENABLED");
        bool correlation = assembly && settings.Enabled("ADLOG_SEMANTIC_CORRELATION_ENABLED");
        bool risk = correlation && settings.Enabled("ADLOG_SEMANTIC_RISK_ENGINE_ENABLED");
        if (!normalization) throw new InvalidOperationException("semantic_normalization_must_be_explicitly_enabled");
        if (assembly && settings.Enabled("ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED")) throw new InvalidOperationException("semantic_directory_state_forbidden");
        if (risk && settings.Enabled("ADLOG_SEMANTIC_FINDING_CREATION_ENABLED")) throw new InvalidOperationException("semantic_finding_creation_forbidden");
    }
    public static async Task ValidateDatabaseAsync(NpgsqlConnection db, CancellationToken ct)
    {
        await using var check = new NpgsqlCommand("""
            select (select count(*)=2 from schema_migrations
               where (version=54 and name='semantic_worker_runtime_schema_guard')
                  or (version=71 and name='semantic_source_retention_decoupling'))
               and not exists(select 1 from semantic_risk_policies where lifecycle_status='enabled')
            """, db);
        if (await check.ExecuteScalarAsync(ct) is not true) throw new InvalidOperationException("semantic_development_scope_required");
    }
}
