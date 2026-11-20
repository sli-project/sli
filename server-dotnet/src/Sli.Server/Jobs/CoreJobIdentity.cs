using System.Text;
using Npgsql;

namespace Sli.Server.Jobs;

public static class CoreJobIdentity
{
    public static string PasswordName(string profile, string purpose)
    {
        if (!CoreJobRegistry.Profiles.ContainsKey(profile) || purpose is not ("dispatcher" or "executor" or "publisher")) throw new CoreJobContractException("executor_profile_invalid");
        return $"SLI_JOB_{purpose.ToUpperInvariant()}_{profile.ToUpperInvariant()}_PASSWORD";
    }
    public static NpgsqlConnectionStringBuilder Settings(string profile, string purpose, Func<string, string?> environment, Func<string, string> readSecret, bool child = false)
    {
        string name = PasswordName(profile, purpose);
        string? file = environment(name + "_FILE"), plain = environment(name);
        if (child && (string.IsNullOrEmpty(file) || !string.IsNullOrEmpty(plain))) throw new CoreJobContractException("executor_secret_file_required");
        if (file is not null && !string.IsNullOrEmpty(plain)) throw new CoreJobContractException("executor_secret_missing");
        string? password = file is not null ? readSecret(file) : plain;
        if (string.IsNullOrEmpty(password)) throw new CoreJobContractException("executor_secret_missing");
        return new NpgsqlConnectionStringBuilder
        {
            Host = environment("SLI_JOB_PG_HOST") ?? "postgres", Port = 5432, Database = "sli",
            Username = $"sli_job_{purpose}_{profile}", Password = password,
            ApplicationName = $"sli-core-job-{purpose}-{profile}-{Environment.ProcessId}",
            Timeout = 5, CommandTimeout = 0, Pooling = false, Multiplexing = false,
            Options = "-c statement_timeout=0 -c idle_in_transaction_session_timeout=0 -c lock_timeout=1000 -c search_path=pg_catalog,public"
        };
    }
    internal static string ReadSecret(string path)
    {
        try
        {
            using var input = File.OpenRead(path);
            byte[] bytes = new byte[65537]; int count = 0, read;
            while (count < bytes.Length && (read = input.Read(bytes, count, bytes.Length - count)) > 0) count += read;
            var value = new UTF8Encoding(false, true).GetString(bytes, 0, count).TrimEnd('\r', '\n');
            if (count > 65536 || value.Length == 0 || value.Contains('\0')) throw new CoreJobContractException("executor_secret_missing");
            return value;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException) { throw new CoreJobContractException("executor_secret_missing"); }
    }
    // Explicit allowlist; admin DSNs, other profiles and inline secrets never cross this boundary.
    public static Dictionary<string, string> ChildEnvironment(JsonObjectJobIdentity identity, Func<string, string?> environment)
    {
        if (identity.Purpose is not ("handler" or "publisher")) throw new CoreJobContractException("executor_purpose_invalid");
        string name = PasswordName(identity.Profile, identity.Purpose == "handler" ? "executor" : "publisher");
        string? file = environment(name + "_FILE");
        if (string.IsNullOrEmpty(file)) throw new CoreJobContractException("executor_secret_file_required");
        var result = new Dictionary<string, string>();
        foreach (string key in new[] { "PATH", "LANG", "SystemRoot", "WINDIR", "SLI_PLUGIN_RUNTIME_DIR", "SLI_PLUGIN_LOCK_DIR", "SLI_JOB_PG_HOST", "SLI_CORE_JOB_RADIUS_PILOT", "SLI_CORE_JOB_AD_GPO_PILOT", "SLI_CORE_JOB_WORKSTATIONS_RETENTION", "SLI_CORE_JOB_WORKSTATIONS_PROJECTION" })
            if (environment(key) is string value) result[key] = value;
        result[name + "_FILE"] = file;
        if (identity.Plugin == "sli.remote-access")
        {
            Sli.Server.Agents.Radius.RadiusChildEnvironment.ConfigureMode(result, identity.Handler, identity.Purpose, environment);
            if (identity.Purpose == "handler" && OperatingSystem.IsWindows())
                Sli.Server.Agents.Radius.RadiusChildEnvironment.ConfigureWindows(result, environment);
        }
        if (identity.Plugin == "sli.workstations" && identity.Handler != "workstations.overview-project")
        {
            var keys = new List<string> { "SLI_WORKSTATION_EVIDENCE_RETENTION_DAYS", "ADLOG_HISTORY_READ_MODE" };
            if (identity.Purpose == "publisher") keys.AddRange(["ADLOG_HISTORY_CLICKHOUSE_HOST", "ADLOG_HISTORY_CLICKHOUSE_PORT", "ADLOG_HISTORY_CLICKHOUSE_USER", "ADLOG_HISTORY_CLICKHOUSE_PASSWORD_FILE", "ADLOG_DATA_DIR"]);
            foreach (string key in keys) if (environment(key) is string value) result[key] = value;
        }
        return result;
    }
}

public sealed record JsonObjectJobIdentity(string Profile, string Purpose, string Plugin, string Handler);
