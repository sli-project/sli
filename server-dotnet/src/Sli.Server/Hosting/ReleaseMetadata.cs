using System.Reflection;
using System.Text.RegularExpressions;
using System.Text.Json.Nodes;

namespace Sli.Server.Hosting;

internal sealed record ReleaseMetadata(string ProjectVersion,string BaselineId,string BuildId,string? GitCommit)
{
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
        return new() { ["project"] = Declared("PROJECT_NAME"), ["project_slug"] = Declared("PROJECT_SLUG"), ["project_version"] = release.ProjectVersion, ["baseline_id"] = release.BaselineId, ["baseline_label"] = Declared("BASELINE_LABEL"), ["baseline_date_utc"] = Declared("BASELINE_DATE_UTC"), ["build_id"] = release.BuildId, ["generated_at_utc"] = DateTimeOffset.UtcNow, ["git_commit"] = release.GitCommit, ["schema"] = schemaMetadata };
    }
    // Ship the canonical release declarations with the binary. No Python process,
    // working directory or Git executable is needed on an installed server.
    internal static ReleaseMetadata Read(IConfiguration config)
    {
        var assembly=typeof(ReleaseMetadata).Assembly;
        using var reader=new StreamReader(assembly.GetManifestResourceStream("Sli.Server.Hosting.release-version.py")!);
        string source=reader.ReadToEnd();
        string Declared(string name)
        {
            var match=Regex.Match(source,"(?m)^"+name+" = \"([^\"]+)\"\\r?$",RegexOptions.CultureInvariant);
            if(!match.Success) throw new ServerConfigurationException("ReleaseMetadata", "missing");
            return match.Groups[1].Value;
        }
        string? Value(string name)=>config["Sli:Release:"+name];
        string baseline=Value("BaselineId") ?? Declared("BASELINE_ID");
        string? git=Value("GitCommit") ?? Environment.GetEnvironmentVariable("ADLOG_GIT_COMMIT")
            ?? assembly.GetCustomAttributes<AssemblyMetadataAttribute>().FirstOrDefault(a=>a.Key=="GitCommit")?.Value;
        string? build=Value("BuildId") ?? Environment.GetEnvironmentVariable("ADLOG_BUILD_ID");
        return new(Value("ProjectVersion") ?? Declared("PROJECT_VERSION"),baseline,
            string.IsNullOrEmpty(build) ? baseline : build,string.IsNullOrWhiteSpace(git) ? null : git);
    }
}
