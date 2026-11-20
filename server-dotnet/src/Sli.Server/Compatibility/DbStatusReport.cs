using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.SnapshotPublication;
using Sli.Server.Operations;
using Sli.Server.Storage.Lifecycle;

namespace Sli.Server.Compatibility;

// The SQLite section describes a historical file only; PostgreSQL remains the runtime.
public sealed class DbStatusReport(IOperationsQueries queries, OperationsFiles files, IConfiguration configuration)
{
    internal static readonly string[] ExpectedTables = ["schema_migrations", "log_sources", "collection_channel_state", "collector_channel_runs", "collector_stage_metrics", "events", "findings", "ai_api_runs"];

    public async Task<JsonObject> ReadAsync(CancellationToken ct)
    {
        var started = Stopwatch.StartNew();
        string? native = configuration.GetConnectionString("Sli") ?? configuration["Sli:PostgresConnectionString"];
        var cfg = new LifecycleConfiguration(files.Root, name => files.Setting(name) is { Length: > 0 } value ? value : configuration[name]);
        string dsn = cfg.Get("ADLOG_PG_DSN") ?? "";
        bool configured = !string.IsNullOrEmpty(native) || dsn.Length > 0;
        string rawPath = files.Setting("ADLOG_DB_PATH").Trim();
        string path = Path.GetFullPath(rawPath.Length == 0 ? Path.Combine(files.DataRoot, "processed", "ad_logs.sqlite") : rawPath, files.Root);
        var file = new FileInfo(path);
        long bytes = file.Exists ? file.Length : 0;
        string timeout = cfg.Get("ADLOG_PG_CONNECT_TIMEOUT_SECONDS") ?? "3";
        int seconds = int.Parse(timeout.Length == 0 ? "3" : timeout, CultureInfo.InvariantCulture);
        var checks = new JsonObject();
        var result = new JsonObject {
            ["status"] = configured ? "ok" : "warn", ["active_backend"] = "postgres", ["duration_ms"] = 0,
            ["sqlite"] = new JsonObject { ["path"] = path, ["exists"] = file.Exists, ["size_human"] = OpsJson.Human(bytes) },
            ["postgres"] = new JsonObject { ["configured"] = configured, ["dsn"] = configured ? RedactDsn(dsn.Length > 0 ? dsn : native!, dsn.Length == 0) : null, ["connect_timeout_seconds"] = seconds },
            ["checks"] = checks
        };
        if (!configured)
            checks["dsn"] = new JsonObject { ["status"] = "warn", ["reason"] = "ADLOG_PG_DSN/config database.postgres_dsn is not set" };
        else
        {
            checks["dsn"] = new JsonObject { ["status"] = "ok" };
            // Keep the frozen report's check name and module label on the wire.
            checks["psycopg"] = new JsonObject { ["status"] = "ok", ["duration_ms"] = 0, ["module"] = "psycopg" };
            try
            {
                var identity = (await queries.ReadReadinessAsync("select version() as version,current_database() as database,current_user as user", ct)).OfType<JsonObject>().First();
                var tables = await queries.ReadReadinessAsync("select table_name from information_schema.tables where table_schema='public' order by table_name", ct);
                var names = tables.Select(t => (string?)t?["table_name"]).ToHashSet();
                string[] missing = ExpectedTables.Where(t => !names.Contains(t)).ToArray();
                var migrations = names.Contains("schema_migrations") ? await queries.ReadReadinessAsync("select version,name from schema_migrations order by version", ct) : new JsonArray();
                checks["connection"] = new JsonObject { ["status"] = "ok", ["database"] = identity["database"]?.DeepClone(), ["user"] = identity["user"]?.DeepClone(), ["version"] = identity["version"]?.DeepClone() };
                checks["schema"] = new JsonObject { ["status"] = missing.Length == 0 ? "ok" : "warn", ["tables_seen"] = tables.Count, ["missing_tables"] = new JsonArray(missing.Select(x => JsonValue.Create(x)).ToArray()), ["schema_migrations"] = migrations };
                if (missing.Length > 0) result["status"] = "warn";
            }
            catch (Exception error) when (!ct.IsCancellationRequested)
            {
                result["status"] = "failed";
                string message = error is PostgresException postgres ? postgres.MessageText : error.Message;
                foreach (string raw in new[] { dsn, native ?? "" })
                {
                    if (raw.Length == 0) continue;
                    message = message.Replace(raw, "[redacted]", StringComparison.Ordinal);
                    try
                    {
                        var secrets = DsnValues(raw, raw == native);
                        foreach (var pair in secrets.Where(p => p.Key is "password" or "sslpassword" && p.Value.Length > 0)) message = message.Replace(pair.Value, "[redacted]", StringComparison.Ordinal);
                    }
                    catch (ArgumentException) { message = "PostgreSQL connection failed"; }
                }
                string errorType = error switch {
                    PostgresException pg => typeof(PostgresErrorCodes).GetFields().FirstOrDefault(f => f.IsLiteral && (string?)f.GetRawConstantValue() == pg.SqlState)?.Name ?? "DatabaseError",
                    NpgsqlException => "OperationalError",
                    _ => error.GetType().Name
                };
                checks["connection"] = new JsonObject { ["status"] = "failed", ["error_type"] = errorType, ["error"] = OperationsFiles.Redact(message) };
            }
        }
        result["duration_ms"] = started.ElapsedMilliseconds;
        return result;
    }

    internal static string RedactDsn(string dsn, bool native = false)
    {
        try
        {
            var values = DsnValues(dsn, native);
            string[] options = ["service", "user", "password", "passfile", "channel_binding", "connect_timeout", "dbname", "host", "hostaddr", "port", "client_encoding", "options", "application_name", "fallback_application_name", "keepalives", "keepalives_idle", "keepalives_interval", "keepalives_count", "tcp_user_timeout", "sslmode", "requiressl", "sslcompression", "sslcert", "sslkey", "sslpassword", "sslrootcert", "sslcrl", "sslcrldir", "sslsni", "requirepeer", "ssl_min_protocol_version", "ssl_max_protocol_version", "gssencmode", "krbsrvname", "gsslib", "replication", "target_session_attrs", "load_balance_hosts"];
            if (values.Keys.Any(k => !options.Contains(k))) return "<invalid PostgreSQL DSN>";
            foreach (string key in new[] { "password", "sslpassword" }) if (values.ContainsKey(key)) values[key] = "***";
            static string Quote(string s) => s.Length == 0 ? "''" : s.Any(char.IsWhiteSpace) ? "'" + s.Replace("\\", "\\\\").Replace("'", "\\'") + "'" : s.Replace("\\", "\\\\").Replace("'", "\\'");
            return string.Join(" ", values.OrderBy(p => Array.IndexOf(options, p.Key)).Select(p => p.Key + "=" + Quote(p.Value)));
        }
        catch (Exception error) when (error is ArgumentException or FormatException or OverflowException) { return "<invalid PostgreSQL DSN>"; }
    }

    static Dictionary<string, string> DsnValues(string dsn, bool native)
    {
        if (native)
        {
            var b = new NpgsqlConnectionStringBuilder(dsn);
            var values = new Dictionary<string, string> { ["user"] = b.Username ?? "", ["dbname"] = b.Database ?? "", ["host"] = b.Host ?? "", ["port"] = b.Port.ToString(CultureInfo.InvariantCulture) };
            if (b.ContainsKey("Password")) values["password"] = b.Password ?? "";
            return values;
        }
        if (!dsn.StartsWith("postgresql://", StringComparison.Ordinal) && !dsn.StartsWith("postgres://", StringComparison.Ordinal)) return GpoWorkerConfiguration.Parse(dsn);
        var uri = new Uri(dsn);
        var result = new Dictionary<string, string>();
        string[] auth = uri.UserInfo.Split(':', 2);
        if (auth[0].Length > 0) result["user"] = Uri.UnescapeDataString(auth[0]);
        if (auth.Length > 1) result["password"] = Uri.UnescapeDataString(auth[1]);
        if (uri.AbsolutePath.Length > 1) result["dbname"] = Uri.UnescapeDataString(uri.AbsolutePath[1..]);
        if (uri.Host.Length > 0) result["host"] = uri.Host.Trim('[', ']');
        if (uri.Port >= 0) result["port"] = uri.Port.ToString(CultureInfo.InvariantCulture);
        foreach (var pair in Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query)) result[pair.Key] = pair.Value.ToString();
        return result;
    }

    internal static string Escape(string value) => value.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&#x27;");
    internal static string PythonString(JsonNode? node, bool repr = false) => node switch
    {
        null => "None",
        JsonObject obj => "{" + string.Join(", ", obj.Select(p => PythonQuote(p.Key) + ": " + PythonString(p.Value, true))) + "}",
        JsonArray array => "[" + string.Join(", ", array.Select(x => PythonString(x, true))) + "]",
        JsonValue value when value.TryGetValue<string>(out string? s) => repr ? PythonQuote(s) : s,
        JsonValue value when value.TryGetValue<bool>(out bool b) => b ? "True" : "False",
        _ => node.ToJsonString()
    };
    static string PythonQuote(string value)
    {
        char quote = value.Contains('\'') && !value.Contains('"') ? '"' : '\'';
        var result = new StringBuilder().Append(quote);
        foreach (var rune in value.EnumerateRunes())
        {
            int c = rune.Value;
            if (c == quote || c == '\\') result.Append('\\').Append((char)c);
            else if (c is '\n' or '\r' or '\t') result.Append(c == '\n' ? "\\n" : c == '\r' ? "\\r" : "\\t");
            else if (Rune.GetUnicodeCategory(rune) is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.Surrogate or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator || c != ' ' && Rune.GetUnicodeCategory(rune) == UnicodeCategory.SpaceSeparator)
                result.Append(c < 256 ? "\\x" + c.ToString("x2") : c < 65536 ? "\\u" + c.ToString("x4") : "\\U" + c.ToString("x8"));
            else result.Append(rune.ToString());
        }
        return result.Append(quote).ToString();
    }

    internal static string Render(JsonObject data)
    {
        var pg = data["postgres"] as JsonObject ?? new();
        var sqlite = data["sqlite"] as JsonObject ?? new();
        var checks = data["checks"] as JsonObject ?? new();
        string E(JsonNode? node) => Escape(PythonString(node));
        string rows = string.Concat(checks.Select(p => $"<tr><td>{Escape(p.Key)}</td><td>{E(p.Value?["status"])}</td><td><pre>{E(p.Value)}</pre></td></tr>"));
        return $$"""
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <title>DB Backend Status</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; background: #f7f7f7; color: #222; }
    .card { background: white; border: 1px solid #ddd; border-radius: 10px; padding: 16px; margin-bottom: 16px; }
    table { border-collapse: collapse; width: 100%; background: white; }
    th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
    th { background: #f0f0f0; }
    pre { white-space: pre-wrap; margin: 0; font-size: 12px; }
    .status { font-weight: 700; }
  </style>
</head>
<body>
  <h1>DB Backend Status</h1>
  <div class="card">
    <p>Stage: <b>DB-0.1 PostgreSQL readiness</b></p>
    <p>Status: <span class="status">{{E(data["status"])}}</span></p>
    <p>Active backend: <b>{{E(data["active_backend"])}}</b></p>
    <p>Duration: {{E(data["duration_ms"])}} ms</p>
  </div>
  <div class="card">
    <h2>SQLite</h2>
    <p>Path: <code>{{E(sqlite["path"])}}</code></p>
    <p>Exists: {{E(sqlite["exists"])}}</p>
    <p>Size: {{E(sqlite["size_human"])}}</p>
  </div>
  <div class="card">
    <h2>PostgreSQL</h2>
    <p>Configured: {{E(pg["configured"])}}</p>
    <p>DSN: <code>{{Escape(OpsJson.S(pg["dsn"]).Length == 0 ? "not set" : PythonString(pg["dsn"]))}}</code></p>
    <p>Timeout: {{E(pg["connect_timeout_seconds"])}} sec</p>
  </div>
  <h2>Checks</h2>
  <table><tr><th>Check</th><th>Status</th><th>Details</th></tr>{{rows}}</table>
</body>
</html>
""".Replace("\r\n", "\n");
    }
}
