using System.Globalization;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Text.Json.Nodes;
using Sli.Server.Operations;

namespace Sli.Server.Hosting;

internal sealed record ReleaseMetadata(string? ProjectVersion, string? BaselineId, string? BuildId,
    string? GitCommit, string? ReleaseTag, DateTimeOffset? InstalledAtUtc)
{
    internal JsonObject ToJson() => new()
    {
        ["project_version"] = ProjectVersion,
        ["baseline_id"] = BaselineId,
        ["build_id"] = BuildId,
        ["git_commit"] = GitCommit,
        ["release_tag"] = ReleaseTag,
        ["installed_at_utc"] = InstalledAtUtc
    };

    internal static JsonObject Public(IConfiguration config) {
        var release = Read(config);
        using var reader = new StreamReader(typeof(ReleaseMetadata).Assembly.GetManifestResourceStream("Sli.Server.Hosting.release-version.py")!);
        string source = reader.ReadToEnd();
        string Declared(string name) => Regex.Match(source, "(?m)^" + name + " = \"([^\"]+)\"\\r?$").Groups[1].Value;
        string root = config["Sli:PackageRoot"] ?? new Sli.Server.Operations.OperationsFiles(config).Root;
        string schema = Path.Combine(root, "config", "postgres_schema.sql"), directory = Path.Combine(root, "config", "postgres_migrations");
        string[] migrations = Directory.Exists(directory) ? Directory.GetFiles(directory, "*.sql").Where(p => Regex.IsMatch(Path.GetFileName(p), @"\A[0-9]{3}_.*\.sql\z") && !p.EndsWith(".rollback.sql", StringComparison.Ordinal)).Order(StringComparer.Ordinal).ToArray() : [];
        var versions = migrations.Select(p => int.Parse(Path.GetFileName(p)[..3], System.Globalization.CultureInfo.InvariantCulture)).ToHashSet();
        if (File.Exists(schema)) foreach (Match match in Regex.Matches(File.ReadAllText(schema), @"\(\s*(\d+)\s*,\s*'[^']+'\s*\)")) versions.Add(int.Parse(match.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture));
        var schemaMetadata = new JsonObject { ["runtime_backend"] = "postgres", ["schema_file"] = schema, ["schema_file_exists"] = File.Exists(schema), ["schema_files"] = new JsonArray(new[] { schema }.Concat(migrations).Select(p => (JsonNode)JsonValue.Create(p)!).ToArray()), ["baseline_schema_migration_version"] = 37, ["schema_declared_max_version"] = versions.Count > 0 ? versions.Max() : 37 };
        if (versions.Count > 0) schemaMetadata["schema_migrations_declared"] = new JsonArray(versions.Order().Select(v => (JsonNode)JsonValue.Create(v)!).ToArray());
        var result = release.ToJson();
        result["project"] = Declared("PROJECT_NAME");
        result["project_slug"] = Declared("PROJECT_SLUG");
        result["baseline_label"] = Declared("BASELINE_LABEL");
        result["baseline_date_utc"] = Declared("BASELINE_DATE_UTC");
        result["generated_at_utc"] = DateTimeOffset.UtcNow;
        result["schema"] = schemaMetadata;
        return result;
    }
    internal static ReleaseMetadata Read(IConfiguration config)
    {
        static string? Present(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
        static string? Field(JsonObject? obj, string key) =>
            obj?[key] is JsonValue value && value.TryGetValue<string>(out var text) ? Present(text) : null;
        string? Setting(string name) => Present(config["Sli:Release:" + name]);

        var assembly = typeof(ReleaseMetadata).Assembly;
        using var version = assembly.GetManifestResourceStream("Sli.Server.Hosting.VERSION");
        using var reader = version is null ? null : new StreamReader(version);
        string? projectVersion = Present(reader?.ReadToEnd());
        string? buildCommit = Present(assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(a => a.Key == "GitCommit")?.Value);
        string? tag = null, commit = null;
        DateTimeOffset? installedAt = null;

        if (Setting("PackageRoot") is { } root)
        {
            var package = OperationsFiles.ReadJson(Path.Combine(root, "native-package.json"), 65536);
            var inventory = OperationsFiles.ReadJson(Path.Combine(root, "native-runtime.json"), 2097152);
            tag = Field(package, "release");
            commit = Field(inventory?["provenance"] as JsonObject, "source_commit");
            if (tag is not null && Present(config["CREDENTIALS_DIRECTORY"]) is { } directory)
            {
                // systemd supplies a read-only copy of the receipt for the selected release.
                var receipt = OperationsFiles.ReadJson(Path.Combine(directory, "sli-installation"), 2097152);
                if (Field(receipt, "release") == root &&
                    DateTimeOffset.TryParseExact(Field(receipt, "installed_at_utc"), "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK",
                        CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var timestamp))
                    installedAt = timestamp;
            }
        }

        return new(Setting("ProjectVersion") ?? projectVersion, Setting("BaselineId"),
            tag ?? Setting("BuildId") ?? Present(Environment.GetEnvironmentVariable("ADLOG_BUILD_ID")),
            commit ?? Setting("GitCommit") ?? Present(Environment.GetEnvironmentVariable("ADLOG_GIT_COMMIT")) ?? buildCommit,
            tag, installedAt);
    }
}
