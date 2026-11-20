namespace Sli.Server.Storage.Lifecycle;

// Same two-level scalar YAML subset as app_config._read_simple_yaml. Only the
// existing storage policy, health and database keys are exposed; no values are logged.
internal sealed class LifecycleConfiguration
{
    internal static bool ShortReads(Func<string, string?> get) =>
        Sli.Server.Storage.EventReports.EventReadService.ShortReadsSetting(
            get("Sli:Storage:ShortEventReads") ?? get("Sli__Storage__ShortEventReads"));

    readonly Func<string, string?> environment;
    readonly Dictionary<string, string> fallback = new(StringComparer.Ordinal);
    internal LifecycleConfiguration(string root, Func<string, string?> environment)
    {
        this.environment = environment;
        string path = Path.Combine(root, "config", "adlog_config.yaml");
        if (!File.Exists(path)) return;
        if (new FileInfo(path).Length > 1024 * 1024) throw new LifecycleBlocked("storage_configuration_invalid");
        string section = "";
        foreach (string line in File.ReadLines(path)) {
            string clean = line.Split('#', 2)[0].TrimEnd();
            if (clean.Length == 0) continue;
            if (!char.IsWhiteSpace(line[0]) && clean.EndsWith(':')) { section = clean[..^1].Trim(); continue; }
            int colon = clean.IndexOf(':'); if (colon < 0) continue;
            string key = clean[..colon].Trim(), value = clean[(colon + 1)..].Trim().Trim('"', '\'');
            if (section == "retention" && !LifecyclePolicy.Fields.Contains(key) && key is not ("apply_by_default" or "storage_capacity_profile" or "storage_capacity_profile_overrides")) continue;
            string name = section == "database" ? key switch { "postgres_dsn" => "ADLOG_PG_DSN", "postgres_connect_timeout_seconds" => "ADLOG_PG_CONNECT_TIMEOUT_SECONDS", _ => "" } : section == "retention" ? key == "apply_by_default" ? "ADLOG_RETENTION_APPLY_BY_DEFAULT" : "ADLOG_" + key.ToUpperInvariant() : "";
            if (section == "storage" && key == "log_dir") name = "ADLOG_LOG_DIR";
            if (section == "health" && key == "lag_warn_minutes") name = "ADLOG_HEALTH_LAG_WARN_MINUTES";
            if (name.Length > 0 && value is not ("null" or "~" or "")) fallback[name] = value;
        }
    }
    internal string? Get(string name) => environment(name) is { Length: > 0 } value ? value : fallback.GetValueOrDefault(name);
    internal static string FindRoot()
    {
        foreach (string start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
            for (var dir = new DirectoryInfo(start); dir is not null; dir = dir.Parent)
                if (File.Exists(Path.Combine(dir.FullName, "config", "event_catalog.json"))) return dir.FullName;
        return Directory.GetCurrentDirectory();
    }
    internal string DataRoot(string root) => Path.GetFullPath(Get("ADLOG_DATA_DIR") ?? Get("SLI_DATA_DIR") ??
        (Directory.Exists(Path.Combine(Directory.GetParent(root)!.FullName, "sli_data")) ? Path.Combine(Directory.GetParent(root)!.FullName, "sli_data") : Path.Combine(root, "data")), root);
}
