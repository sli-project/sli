using System.CommandLine;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Hosting;
using Sli.Server.Infrastructure;

namespace Sli.Server.Semantic;

public static class SemanticProductionControlCommand
{
    private const string Plan = "security-history-v2-quarantine-repair-plan", Apply = "security-history-v2-quarantine-repair";
    private static string ManifestPath(string root) => Path.Combine(root, "artifacts", "stage8", "evidence", "retained-security-history-vocabulary.json");
    public static Task<int> RunAsync(string[] args) => RunCoreAsync(args, Storage.Lifecycle.LifecycleConfiguration.FindRoot(), Run, Console.Out);
    internal static async Task<int> RunCoreAsync(string[] args, string root,
        Func<string,string,string,string,CancellationToken,Task<JsonObject>> run, TextWriter output, CancellationToken ct = default)
    {
        var action = new Argument<string>("action");
        var frozen = new Option<string?>("--frozen-security-history-manifest");
        var digest = new Option<string>("--plan-digest") { DefaultValueFactory = _ => "" };
        var confirm = new Option<string>("--confirm") { DefaultValueFactory = _ => "" };
        var command = new RootCommand("Plan or append exact frozen semantic v2 quarantine repair jobs.");
        command.Arguments.Add(action); command.Options.Add(frozen); command.Options.Add(digest); command.Options.Add(confirm);
        command.SetAction(async (parse, token) => {
            try {
                string selected = parse.GetValue(action)!, path = ManifestPath(root);
                if (parse.GetValue(frozen) is { Length: >0 } requested) {
                    if (selected is not (Plan or Apply)) throw new InvalidOperationException("frozen_security_history_manifest_requires_v2_quarantine_repair");
                    string main = new DirectoryInfo(root).Parent is { Name: ".worktrees", Parent: { } parent } ? parent.FullName : root;
                    path = ExactManifest(requested, ManifestPath(main));
                }
                if (selected is not (Plan or Apply)) {
                    await output.WriteLineAsync(new JsonObject { ["status"] = 501, ["error"] = "semantic_production_control_action_not_implemented" }.ToJsonString()); return 1;
                }
                await output.WriteLineAsync((await run(selected, path, parse.GetValue(digest)!, parse.GetValue(confirm)!, token)).ToJsonString());
                return 0;
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
            catch (Exception error) when (error is InvalidOperationException or IOException or UnauthorizedAccessException or System.Text.Json.JsonException or ServerConfigurationException or NpgsqlException) {
                string message = error switch {
                    NpgsqlException => "semantic_quarantine_repair_database_unavailable",
                    ServerConfigurationException => "semantic_quarantine_repair_configuration_invalid",
                    IOException or UnauthorizedAccessException => "security_history_manifest_unavailable",
                    System.Text.Json.JsonException => "security_history_manifest_invalid", _ => error.Message
                };
                await output.WriteLineAsync(new JsonObject { ["status"] = "error", ["error"] = message }.ToJsonString()); return 1;
            }
        });
        var parsed = command.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null });
        return await parsed.InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false, Output = output, Error = output }, ct);
    }
    private static string ExactManifest(string requested, string expected)
    {
        if (!Path.IsPathFullyQualified(requested)) throw new InvalidOperationException("frozen_security_history_manifest_must_be_absolute");
        if (!File.Exists(requested) || !File.Exists(expected)) throw new InvalidOperationException("frozen_security_history_manifest_is_not_an_existing_main_file");
        string resolved = Resolve(requested);
        if (!string.Equals(resolved, Resolve(expected), OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new InvalidOperationException("frozen_security_history_manifest_is_not_the_exact_main_file");
        return resolved;
    }
    private static string Resolve(string path)
    {
        string full = Path.GetFullPath(path), current = Path.GetPathRoot(full)!;
        foreach (string part in full[current.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries)) {
            current = Path.Combine(current, part);
            FileSystemInfo entry = Directory.Exists(current) ? new DirectoryInfo(current) : new FileInfo(current);
            if (entry.LinkTarget is not null) current = entry.ResolveLinkTarget(true)?.FullName ?? throw new InvalidOperationException("frozen_security_history_manifest_is_not_an_existing_main_file");
        }
        return current;
    }
    private static async Task<JsonObject> Run(string action, string path, string digest, string confirmation, CancellationToken ct)
    {
        string? Get(string key) => Environment.GetEnvironmentVariable(key);
        string user = Get("ADLOG_PG_ADMIN_USER")?.Trim() ?? "";
        if (user.Length == 0) throw new ServerConfigurationException("ADLOG_PG_ADMIN_USER", "missing");
        string dsn = GpoWorkerConfiguration.CreateNamed(Get, ReadSecret, "ADLOG_PG_DSN", "ADLOG_PG_ADMIN_PASSWORD", "sli_semantic_production_control", 0);
        var settings = new NpgsqlConnectionStringBuilder(dsn) { Username = user, Pooling = false, Multiplexing = false, CommandTimeout = 0 };
        if (string.IsNullOrEmpty(settings.Password)) throw new ServerConfigurationException("ADLOG_PG_ADMIN_PASSWORD", "missing");
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:PostgresConnectionString"] = settings.ConnectionString }).Build();
        var hot = Get("Sli:Storage:HotRetentionDays") ?? Get("Sli__Storage__HotRetentionDays");
        var history = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["Sli:Storage:HotRetentionDays"] = hot }).Build();
        var controller = new SemanticQuarantineRepairController(new SemanticDatabase(new PostgresConnectionFactory(configuration)),
            () => JsonNode.Parse(File.ReadAllText(path)) as JsonObject ?? throw new InvalidOperationException("security history manifest is invalid"), Get, null, history);
        return action == Plan ? await controller.PlanAsync(ct) : await controller.ApplyAsync(digest, confirmation, ct);
    }
    private static byte[] ReadSecret(string path)
    {
        using var file = File.OpenRead(path); byte[] bytes = new byte[65537]; int count = 0, read;
        while (count < bytes.Length && (read = file.Read(bytes, count, bytes.Length - count)) != 0) count += read;
        if (count > 65536) throw new ServerConfigurationException("ADLOG_PG_ADMIN_PASSWORD_FILE");
        return bytes[..count];
    }
}
