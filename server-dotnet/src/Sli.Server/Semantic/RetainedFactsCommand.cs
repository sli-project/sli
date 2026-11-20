using System.CommandLine;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Semantic.Password;

namespace Sli.Server.Semantic;

public static class RetainedFactsCommand
{
    public static async Task<int> RunAsync(string[] args)
    {
        var checkpoint = new Option<string>("--checkpoint") { Required = true };
        var manifest = new Option<string>("--manifest");
        var ids = new Option<long[]>("--event-ids") { AllowMultipleArgumentsPerToken = true };
        var digest = new Option<string>("--plan-digest");
        var confirmation = new Option<string>("--confirmation");
        var operation = new Argument<string>("operation");
        var command = new RootCommand("Plan, publish or check retained semantic facts against the bound PostgreSQL target.");
        command.Arguments.Add(operation);
        command.Options.Add(checkpoint); command.Options.Add(manifest); command.Options.Add(ids); command.Options.Add(digest); command.Options.Add(confirmation);
        command.SetAction(async (parse, ct) => {
            try {
                string action = parse.GetValue(operation)!;
                if (action is not ("facts-plan" or "facts-poll" or "facts-check-plan" or "facts-check"))
                    throw new InvalidOperationException("retained facts operation is invalid");
                var config = Host.CreateApplicationBuilder([]).Configuration;
                var database = new SemanticDatabase(new PostgresConnectionFactory(config), config);
                var control = new RetainedFactsControl(database, parse.GetValue(checkpoint)!, RulesFingerprint(SemanticProduction.SourceBundleRoot(null, Directory.GetCurrentDirectory())));
                string manifestPath = parse.GetValue(manifest) ?? Path.Combine(Path.GetDirectoryName(Path.GetFullPath(parse.GetValue(checkpoint)!))!, "semantic-exact-facts-check.json");
                JsonObject result = action switch {
                    "facts-plan" => await control.PlanAsync(ct),
                    "facts-poll" => await control.PollAsync(ct),
                    "facts-check-plan" => await control.CheckPlanAsync(parse.GetValue(ids) ?? [], manifestPath, ct),
                    _ => await control.CheckAsync(parse.GetValue(ids) ?? [], manifestPath, parse.GetValue(digest) ?? "", parse.GetValue(confirmation) ?? "",
                        (exactIds, publish, token) => ExecuteAsync(database, exactIds, publish, token), ct)
                };
                Console.WriteLine(result.ToJsonString()); return 0;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return 0; }
            catch (InvalidOperationException error) { Console.Error.WriteLine(error.Message); return 1; }
            catch (Exception) { Console.Error.WriteLine("retained facts operation failed; check database availability, schema readiness and filesystem access"); return 1; }
        });
        return await command.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null }).InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false });
    }

    private static async Task<JsonObject> ExecuteAsync(ISemanticDatabase database, long[] ids, bool publish, CancellationToken ct)
    {
        // Existing least-privilege worker credentials and admission checks remain mandatory.
        await using var runtime = PasswordProducerRuntime.Create();
        await using var db = await runtime.OpenAsync(ct);
        await using (var command = new NpgsqlCommand("select pg_try_advisory_lock(hashtextextended($1,0)) and pg_try_advisory_lock(hashtext($1))", db) { CommandTimeout = 0 }) {
            command.Parameters.AddWithValue("ad_log_reports_runtime_semantic_production_worker");
            if (await command.ExecuteScalarAsync(ct) is not true)
                return new() { ["status"] = "blocked", ["reason"] = "semantic_production_worker_lock_held" };
        }
        var settings = new SemanticRuntimeSettings(true, true, false, false, false, false);
        await using (var tx = await db.BeginTransactionAsync(ct)) {
            await SemanticProduction.GuardAsync(new SemanticSession(db, tx), SemanticRuntimeSettings.FactsMode, ct);
            await tx.CommitAsync(ct);
        }
        JsonObject? producer = null;
        if (publish) {
            await using var session = await database.OpenAsync(true, ct);
            producer = await RetainedFactsControl.PublishAsync(session, ids, ct);
            await session.CommitAsync(ct);
        }
        var production = new SemanticProduction(runtime, settings, SemanticRuntimeSettings.FactsMode, ids.Length);
        var processing = await production.ProcessOutbox(db, ct, sourceEventIds: ids);
        return new() { ["status"] = "executed", ["producer"] = producer, ["runtime"] = new JsonObject { ["processing"] = processing } };
    }

    internal static string RulesFingerprint(string root)
    {
        string config = Path.GetFullPath(Path.Combine(root, "config"));
        var manifests = Directory.GetFiles(Path.Combine(config, "source_packs"), "*.json").Order(StringComparer.Ordinal).ToArray();
        var catalogs = new SortedSet<string>(StringComparer.Ordinal) { Path.Combine(config, "event_catalog.json") };
        foreach (string path in manifests) {
            var manifest = JsonNode.Parse(File.ReadAllText(path)) as JsonObject ?? throw new InvalidOperationException("semantic facts source-pack manifest is invalid");
            if (manifest["event_catalog"] is not { } catalog) continue;
            if (catalog is not JsonValue value || !value.TryGetValue<string>(out string? name) || string.IsNullOrWhiteSpace(name))
                throw new InvalidOperationException("semantic facts source-pack catalog is invalid");
            string target = Path.GetFullPath(Path.Combine(config, name));
            if (!string.Equals(Path.GetDirectoryName(target), config, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                throw new InvalidOperationException("semantic facts source-pack catalog escapes config");
            catalogs.Add(target);
        }
        var files = new JsonArray();
        foreach (string path in manifests.Concat(catalogs)) {
            byte[] raw = Encoding.UTF8.GetBytes(File.ReadAllText(path).Replace("\r\n", "\n"));
            files.Add(new JsonObject { ["path"] = Path.GetRelativePath(root, path).Replace('\\', '/'), ["sha256"] = Convert.ToHexStringLower(SHA256.HashData(raw)) });
        }
        return SemanticJson.Hash(new JsonObject {
            ["selector"] = new JsonObject { ["owner"] = "publish_semantic_candidates", ["source"] = "semantic_event_rows", ["ordered_by"] = "id_ascending", ["include_context"] = true, ["max_batch"] = SemanticProducer.MaxBatch },
            ["catalog"] = files,
            ["normalizer"] = new JsonObject { ["id"] = SemanticEvent.Normalizer, ["version"] = SemanticEvent.Version, ["semantic_contract_version"] = 1 },
            ["assemblers"] = new JsonArray(new JsonObject { ["id"] = "semantic-action-assembler", ["version"] = "1.1" }, new JsonObject { ["id"] = "process-episode-assembler", ["version"] = "1.0" })
        });
    }
}
