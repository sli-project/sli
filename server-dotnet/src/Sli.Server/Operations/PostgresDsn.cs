using System.Globalization;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Compatibility;

namespace Sli.Server.Operations;

internal static class PostgresDsn
{
    // Diagnostic output only. Never return the original input on a parser failure.
    internal static string? Redact(string? input)
    {
        if (string.IsNullOrEmpty(input)) return null;
        try
        {
            Dictionary<string, string> fields;
            if (input.StartsWith("postgresql://", StringComparison.Ordinal) || input.StartsWith("postgres://", StringComparison.Ordinal))
            {
                if (Regex.IsMatch(input, @"%(?![0-9A-Fa-f]{2})") || !Uri.TryCreate(input, UriKind.Absolute, out var uri) || uri.Fragment.Length > 0)
                    throw new ArgumentException();
                fields = new(StringComparer.Ordinal);
                string[] user = uri.UserInfo.Split(':', 2);
                if (user[0].Length > 0) fields["user"] = Uri.UnescapeDataString(user[0]);
                if (user.Length == 2) fields["password"] = Uri.UnescapeDataString(user[1]);
                if (uri.Host.Length > 0) fields["host"] = uri.Host.Trim('[', ']');
                if (!uri.IsDefaultPort && uri.Port > 0) fields["port"] = uri.Port.ToString(CultureInfo.InvariantCulture);
                string database = uri.AbsolutePath.TrimStart('/');
                if (database.Contains('/')) throw new ArgumentException();
                if (database.Length > 0) fields["dbname"] = Uri.UnescapeDataString(database);
                foreach (string pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = pair.Split('=', 2);
                    if (parts.Length != 2) throw new ArgumentException();
                    fields[Uri.UnescapeDataString(parts[0])] = Uri.UnescapeDataString(parts[1]);
                }
            }
            else
            {
                if (input.Contains(';'))
                {
                    try
                    {
                        var native = new NpgsqlConnectionStringBuilder(input);
                        if (native.ContainsKey("Password")) native.Password = "***";
                        return native.ConnectionString;
                    }
                    catch (ArgumentException) { /* A libpq value may contain a semicolon. */ }
                }
                fields = LibpqKeywordDsn.Parse(input);
            }
            // Unknown options fail closed rather than becoming an unrecognised secret field.
            foreach (string key in fields.Keys)
                if (key is not ("host" or "hostaddr" or "port" or "dbname" or "user" or "password" or "sslpassword"
                    or "connect_timeout" or "application_name" or "fallback_application_name" or "options"
                    or "sslmode" or "sslcert" or "sslkey" or "sslrootcert" or "sslcrl" or "sslcrldir"
                    or "service" or "passfile" or "target_session_attrs" or "channel_binding" or "client_encoding"))
                    throw new ArgumentException();
            foreach (string key in new[] { "password", "sslpassword" })
                if (fields.ContainsKey(key)) fields[key] = "***";
            return string.Join(' ', fields.Select(p => p.Key + "='" + p.Value.Replace("\\", "\\\\").Replace("'", "\\'") + "'"));
        }
        catch (Exception) { return "<invalid PostgreSQL DSN>"; }
    }
}
