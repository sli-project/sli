using System.Globalization;
using System.Text;
using Npgsql;
using Sli.Server.Hosting;

namespace Sli.Server.Agents.SnapshotPublication;

// Source uses libpq keyword/value DSNs plus independent file-backed secrets.
// Only deployment-relevant options are accepted; unknown forms fail closed.
public static class GpoWorkerConfiguration
{
    public static bool TryCreate(Func<string, string?> get, Func<string, byte[]> read, out string? connectionString)
    {
        return TryCreateNamed(get, read, "ADLOG_AD_CONTEXT_WORKER_DSN", "ADLOG_AD_CONTEXT_WORKER_PASSWORD", "adlog_context_snapshot_import", 300, out connectionString);
    }
    internal static bool TryCreateNamed(Func<string,string?> get, Func<string,byte[]> read, string dsnName, string passwordName, string appName, int commandTimeout, out string? connectionString)
    {
        try { connectionString = CreateNamed(get, read, dsnName, passwordName, appName, commandTimeout); return true; }
        catch (ServerConfigurationException) { connectionString = null; return false; }
    }

    internal static string CreateNamed(Func<string,string?> get, Func<string,byte[]> read, string dsnName, string passwordName, string appName, int commandTimeout)
    {
        string setting = dsnName;
        try
        {
            string? dsn = Secret(dsnName, get, read);
            if (string.IsNullOrWhiteSpace(dsn)) throw new ServerConfigurationException(dsnName, "missing");
            setting = passwordName;
            string? password = Secret(passwordName, get, read);
            setting = dsnName;
            var b = new NpgsqlConnectionStringBuilder();
            bool native = false;
            if (dsn.Contains(';'))
            {
                try { b.ConnectionString = dsn; native = true; }
                catch (Exception error) when (error is ArgumentException or FormatException) { b = new NpgsqlConnectionStringBuilder(); }
            }
            if (!native)
                foreach (var (key, value) in Parse(dsn))
                    switch (key)
                {
                    case "host": b.Host = value; break;
                    case "port": b.Port = int.Parse(value, CultureInfo.InvariantCulture); break;
                    case "dbname": b.Database = value; break;
                    case "user": b.Username = value; break;
                    case "password": b.Password = value; break;
                    case "connect_timeout": b.Timeout = int.Parse(value, CultureInfo.InvariantCulture); break;
                    case "sslmode": b.SslMode = value switch
                    {
                        "disable" => SslMode.Disable, "prefer" => SslMode.Prefer, "require" => SslMode.Require,
                        "verify-ca" => SslMode.VerifyCA, "verify-full" => SslMode.VerifyFull,
                        _ => throw new ArgumentException()
                    }; break;
                    case "application_name": b.ApplicationName = value; break;
                    case "options" when dsnName == "ADLOG_STORAGE_V2_WORKER_DSN": b.Options = value; break;
                    default: throw new ServerConfigurationException(dsnName);
                }
            if (password is not null)
            {
                if (!string.IsNullOrEmpty(b.Password)) throw new ServerConfigurationException(passwordName, "conflict");
                b.Password = password;
            }
            if (string.IsNullOrWhiteSpace(b.Host) || string.IsNullOrWhiteSpace(b.Database) || string.IsNullOrWhiteSpace(b.Username) || b.Multiplexing) throw new ServerConfigurationException(dsnName);
            b.ApplicationName = appName;
            // Source uses an independent non-pooled role session; never return SET ROLE to a shared pool.
            b.Pooling = false;
            b.CommandTimeout = commandTimeout;
            return b.ConnectionString;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        { throw new ServerConfigurationException(get(setting + "_FILE") is null ? setting : setting + "_FILE", "unavailable"); }
        catch (Exception e) when (e is ArgumentException or FormatException or OverflowException)
        { throw new ServerConfigurationException(get(setting + "_FILE") is null ? setting : setting + "_FILE"); }
    }

    private static string? Secret(string name, Func<string,string?> get, Func<string,byte[]> read)
    {
        string? file = get(name + "_FILE"), value = get(name);
        if (file is null) return string.IsNullOrEmpty(value) ? null : value;
        if (value is { Length: > 0 } || file.Length == 0) throw new ArgumentException();
        byte[] raw = read(file);
        if (raw.Length > 65536) throw new ArgumentException();
        string result = new UTF8Encoding(false, true).GetString(raw).TrimEnd('\r', '\n');
        if (result.Length == 0 || result.Contains('\0')) throw new ArgumentException();
        return result;
    }

    internal static Dictionary<string,string> Parse(string input)
    {
        var values = new Dictionary<string,string>(StringComparer.Ordinal); int i = 0;
        while (true)
        {
            while (i < input.Length && char.IsWhiteSpace(input[i])) i++;
            if (i == input.Length) return values;
            int start = i;
            while (i < input.Length && !char.IsWhiteSpace(input[i]) && input[i] != '=') i++;
            string key = input[start..i];
            while (i < input.Length && char.IsWhiteSpace(input[i])) i++;
            if (key.Length == 0 || i == input.Length || input[i++] != '=') throw new ArgumentException();
            while (i < input.Length && char.IsWhiteSpace(input[i])) i++;
            var value = new StringBuilder(); bool quoted = i < input.Length && input[i] == '\'';
            if (quoted) i++;
            bool closed = !quoted;
            while (i < input.Length)
            {
                char c = input[i++];
                if (c == '\\') { if (i == input.Length) throw new ArgumentException(); value.Append(input[i++]); continue; }
                if (quoted && c == '\'') { closed = true; break; }
                if (!quoted && char.IsWhiteSpace(c)) break;
                value.Append(c);
            }
            if (!closed || (quoted && i < input.Length && !char.IsWhiteSpace(input[i]))) throw new ArgumentException();
            values[key] = value.ToString();
        }
    }
}
