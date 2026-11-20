using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Auth.Lifecycle;

namespace Sli.Server.InstallationSetup;

public sealed class BootstrapException(string code) : Exception(code);
public sealed record BootstrapMigration(int Version, string Name, string Path, string Sha256);
public sealed record BootstrapCluster(int ServerVersionNum, string DataDirectory, string ServerAddress,
    int ServerPort, bool DatabaseExists, bool RuntimeRoleExists, string CurrentUser = "postgres", bool AdminIsSuperuser = true);
public sealed record BootstrapBaseline(int Version, string RolesPath, string SchemaPath);
public sealed record BootstrapProcessResult(int ExitCode, string Output);
public delegate Task<object?[][]> BootstrapExecute(string sql, params object[] parameters);

// Port of existing_postgres_bootstrap.py. Only this explicit installation command
// can create cluster roles; the HTTP host never calls it.
public static class PostgresBootstrap
{
    public const string PgcryptoSql = "CREATE EXTENSION IF NOT EXISTS pgcrypto";
    public const string GrantSchemaSql = "GRANT USAGE, CREATE ON SCHEMA public TO adlog_user";
    public const string RevokeSchemaSql = "REVOKE CREATE ON SCHEMA public FROM adlog_user";
    public const string EmptyV2RouteSql = "update public.storage_v2_cutover_state set read_mode='v2', write_mode='v2', shadow_sample_rate=0 where singleton=true";
    private const RegexOptions SqlOptions = RegexOptions.IgnoreCase | RegexOptions.Singleline;
    private const string MarkerPrefix = @"insert\s+into\s+(?:public\.)?schema_migrations\s*\(\s*version\s*,\s*name\s*\)\s*values";
    private static readonly HashSet<int> AdminVersions = [20,43,44,45,47,48,49,77,111,113,114,115,118,119,120,121,122,123,124,125,127,128,129,130];

    public static string HashFile(string path, bool normalized = false) => Hash(normalized
        ? Encoding.UTF8.GetBytes(File.ReadAllText(path).Replace("\r\n", "\n")) : File.ReadAllBytes(path));
    private static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    public static BootstrapMigration[] ForwardInventory(string root)
    {
        var result = new List<BootstrapMigration>();
        foreach (string path in Directory.GetFiles(root, "*.sql").OrderBy(Path.GetFileName, StringComparer.Ordinal))
        {
            string file = Path.GetFileName(path);
            if (Regex.IsMatch(file, @"(?:\.|_)rollback\.sql$")) continue;
            var name = Regex.Match(file, @"^(\d{3})_([a-z0-9_]+)\.sql$");
            if (!name.Success) continue;
            var markers = Regex.Matches(File.ReadAllText(path), MarkerPrefix + @"\s*\(\s*(\d+)\s*,\s*'([^']+)'", SqlOptions);
            if (markers.Count == 0) throw new BootstrapException("migration_marker_missing");
            var marker = markers[^1]; int version = int.Parse(name.Groups[1].Value, CultureInfo.InvariantCulture);
            if (int.Parse(marker.Groups[1].Value, CultureInfo.InvariantCulture) != version) throw new BootstrapException("migration_marker_mismatch");
            result.Add(new(version, marker.Groups[2].Value, path, HashFile(path)));
        }
        if (result.Select(m => m.Version).Distinct().Count() != result.Count) throw new BootstrapException("migration_version_duplicate");
        return result.ToArray();
    }

    public static (int Version, string Name)[] BaseMarkers(string path)
    {
        var blocks = Regex.Matches(File.ReadAllText(path), MarkerPrefix + @"(.*?)on\s+conflict\s*\(\s*version\s*\)", SqlOptions);
        if (blocks.Count == 0) throw new BootstrapException("base_schema_markers_missing");
        var result = Regex.Matches(blocks[^1].Groups[1].Value, @"\(\s*(\d+)\s*,\s*'([^']+)'\s*\)")
            .Select(m => (int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture), m.Groups[2].Value)).ToArray();
        if (result.Length == 0 || result.Select(m => m.Item1).Distinct().Count() != result.Length) throw new BootstrapException("base_schema_markers_invalid");
        return result;
    }

    public static string SourceDomain(string path)
    {
        try
        {
            var controllers = JsonNode.Parse(File.ReadAllText(path))?["domain_controllers"] as JsonArray;
            if (controllers is not { Count: > 0 }) throw new BootstrapException("source_domain_config_invalid");
            var domains = new HashSet<string>(StringComparer.Ordinal);
            foreach (var controller in controllers)
            {
                if (controller is not JsonObject obj) throw new BootstrapException("source_domain_config_invalid");
                string address = Domain(obj["connect_address"]?.GetValue<string>() ?? "");
                if (address.Split('.').Length < 3) throw new BootstrapException("source_domain_config_invalid");
                domains.Add(address[(address.IndexOf('.') + 1)..]);
            }
            if (domains.Count != 1) throw new BootstrapException("source_domain_ambiguous");
            return domains.Single();
        }
        catch (BootstrapException) { throw; }
        catch { throw new BootstrapException("source_domain_config_invalid"); }
    }

    public static string Domain(string value)
    {
        try { return InstallationSettings.Dns(value); }
        catch { throw new BootstrapException("source_domain_config_invalid"); }
    }

    public static async Task SeedDomainAsync(BootstrapExecute execute, string domain)
    {
        domain = Domain(domain);
        var forest = await execute("insert into public.forests(name) values ($1) on conflict(name) do update set name=excluded.name returning id", domain);
        if (forest.Length != 1) throw new BootstrapException("source_domain_seed_failed");
        var row = await execute("insert into public.domains(forest_id,fqdn) values ($1,$2) on conflict(forest_id,fqdn) do update set fqdn=excluded.fqdn returning id", Convert.ToInt64(forest[0][0]), domain);
        var count = await execute("select count(*) from public.domains where lower(fqdn)=lower($1)", domain);
        if (row.Length != 1 || count.Length != 1 || Convert.ToInt64(count[0][0]) != 1) throw new BootstrapException("source_domain_seed_failed");
    }

    public static JsonObject BuildPlan(string database, string dataDirectory, BootstrapCluster snapshot,
        string schemaHash, string rolesHash, IReadOnlyList<BootstrapMigration> migrations) => new()
    {
        ["contract_version"] = 1, ["operation"] = "bootstrap_existing_postgresql_18", ["database"] = database,
        ["roles"] = new JsonObject { ["migration"] = "postgres", ["runtime"] = "adlog_user" },
        ["cluster"] = new JsonObject {
            ["server_version_num"] = snapshot.ServerVersionNum, ["data_directory"] = dataDirectory,
            ["server_address"] = snapshot.ServerAddress, ["server_port"] = snapshot.ServerPort,
            ["database_exists"] = snapshot.DatabaseExists, ["runtime_role_exists"] = snapshot.RuntimeRoleExists,
            ["current_user"] = snapshot.CurrentUser, ["admin_is_superuser"] = snapshot.AdminIsSuperuser },
        ["schema_sha256"] = schemaHash, ["roles_sha256"] = rolesHash,
        ["migrations"] = new JsonArray(migrations.Select(m => (JsonNode)new JsonObject {
            ["version"] = m.Version, ["name"] = m.Name, ["path"] = Path.GetFileName(m.Path), ["sha256"] = m.Sha256 }).ToArray())
    };

    // Match Python's sort_keys/ensure_ascii/separators, including Windows paths
    // and non-ASCII source roots, so the same plan has the same confirmation.
    public static string Canonical(JsonNode? value)
    {
        if (value is null) return "null";
        if (value is JsonObject obj) return "{" + string.Join(",", obj.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => Quote(p.Key) + ":" + Canonical(p.Value))) + "}";
        if (value is JsonArray array) return "[" + string.Join(",", array.Select(Canonical)) + "]";
        if (value is JsonValue scalar && scalar.TryGetValue<string>(out var text)) return Quote(text);
        return value.ToJsonString();
    }
    private static string Quote(string value)
    {
        var result = new StringBuilder("\"");
        foreach (char c in value) result.Append(c switch {
            '"' => "\\\"", '\\' => "\\\\", '\b' => "\\b", '\f' => "\\f", '\n' => "\\n", '\r' => "\\r", '\t' => "\\t",
            < ' ' or > '~' => "\\u" + ((int)c).ToString("x4", CultureInfo.InvariantCulture), _ => c.ToString() });
        return result.Append('"').ToString();
    }
    public static string Confirmation(JsonObject plan) => Hash(Encoding.UTF8.GetBytes(Canonical(plan)));

    public static void ValidateCluster(BootstrapCluster snapshot, string dataDirectory, int port, bool newTarget = true)
    {
        if (snapshot.ServerVersionNum / 10000 != 18) throw new BootstrapException("postgresql_18_required");
        if (snapshot.CurrentUser != "postgres" || !snapshot.AdminIsSuperuser) throw new BootstrapException("postgres_admin_required");
        string[] parts = snapshot.ServerAddress.Split('/');
        if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var address)
            || (parts.Length == 2 && (!int.TryParse(parts[1], out int mask) || mask < 0 || mask > (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128))))
            throw new BootstrapException("loopback_required");
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (!IPAddress.IsLoopback(address)) throw new BootstrapException("loopback_required");
        if (snapshot.ServerPort != port || !string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(snapshot.DataDirectory)), Path.TrimEndingDirectorySeparator(Path.GetFullPath(dataDirectory)),
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)) throw new BootstrapException("cluster_identity_mismatch");
        if (newTarget && snapshot.DatabaseExists) throw new BootstrapException("target_database_exists");
        if (newTarget && snapshot.RuntimeRoleExists) throw new BootstrapException("runtime_role_exists");
    }

    public static async Task<BootstrapCluster> ReadClusterAsync(BootstrapExecute execute, string database)
    {
        var rows = await execute("""
            select current_setting('server_version_num')::integer, current_setting('data_directory'),
              inet_server_addr()::text, inet_server_port(), exists(select 1 from pg_database where datname=$1),
              exists(select 1 from pg_roles where rolname=$2), current_user,
              coalesce((select rolsuper from pg_roles where rolname=current_user),false)
            """, database, "adlog_user");
        if (rows.Length != 1 || rows[0].Length != 8) throw new BootstrapException("cluster_readback_failed");
        var r = rows[0]; return new(Convert.ToInt32(r[0]), (string)r[1]!, (string)r[2]!, Convert.ToInt32(r[3]),
            (bool)r[4]!, (bool)r[5]!, (string)r[6]!, (bool)r[7]!);
    }

    public static Dictionary<string, string> ChildEnvironment(string psql, string password, IReadOnlyDictionary<string, string> source)
    {
        var folded = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in source) folded[pair.Key] = pair.Value;
        var result = new Dictionary<string, string>();
        foreach (string key in new[] { "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP" })
            if (folded.TryGetValue(key, out var value) && value.Length > 0) result[key] = value;
        result["PATH"] = Path.GetDirectoryName(psql)!; result["PGPASSWORD"] = password;
        if (folded.TryGetValue("ADLOG_REPORT_DOMAIN_FQDN", out var domain) && domain.Trim().Length > 0)
            result["PGOPTIONS"] = "-c sli.report_domain_fqdn=" + Domain(domain);
        return result;
    }

    public static Dictionary<string, string> EnvironmentValues() => Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>()
        .ToDictionary(p => (string)p.Key, p => (string)p.Value!);

    public static async Task<BootstrapProcessResult> RunProcessAsync(ProcessStartInfo start)
    {
        using var process = Process.Start(start) ?? throw new BootstrapException("migration_apply_failed");
        // Close stdin and continuously drain both pipes; no secret or SQL output
        // is forwarded to the console, receipt, or exception boundary.
        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync(); await stderr;
        return new(process.ExitCode, await stdout);
    }

    public static ProcessStartInfo ProcessStart(string executable, IEnumerable<string> args, IReadOnlyDictionary<string, string> environment)
    {
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string arg in args) start.ArgumentList.Add(arg);
        start.Environment.Clear(); foreach (var pair in environment) start.Environment[pair.Key] = pair.Value;
        return start;
    }

    public static async Task<JsonObject> RunFileAsync(string psql, string host, int port, string user, string database,
        string sqlPath, string password, Func<ProcessStartInfo, Task<BootstrapProcessResult>>? runner = null, IReadOnlyDictionary<string, string>? source = null)
    {
        // Function-body hashes in the reviewed migrations pin LF bytes. Windows
        // checkouts may contain CRLF; use the same normalization as the existing
        // PostgreSQL test/installation helpers, without editing the source SQL.
        string sql = File.ReadAllText(sqlPath), executionPath = sqlPath;
        bool normalized = sql.Contains("\r\n", StringComparison.Ordinal);
        if (normalized) {
            executionPath = Path.Combine(Path.GetTempPath(), "sli-bootstrap-sql-" + Guid.NewGuid().ToString("N") + ".sql");
            await File.WriteAllTextAsync(executionPath, sql.Replace("\r\n", "\n"), new UTF8Encoding(false));
        }
        try {
            var start = ProcessStart(psql, ["-X", "--host", host, "--port", port.ToString(CultureInfo.InvariantCulture), "--username", user,
                "--dbname", database, "--no-password", "--set", "ON_ERROR_STOP=1", "--file", executionPath], ChildEnvironment(psql, password, source ?? EnvironmentValues()));
            var result = await (runner ?? RunProcessAsync)(start);
            if (result.ExitCode != 0) throw new BootstrapException("migration_apply_failed");
            return new JsonObject { ["status"] = "ok" };
        } finally { if (normalized) File.Delete(executionPath); }
    }

    public static void VerifyLedger(IEnumerable<(int Version, string Name)> actual, IEnumerable<(int Version, string Name)> expected)
    {
        if (!actual.SequenceEqual(expected)) throw new BootstrapException("migration_ledger_mismatch");
    }

    public static void ValidateOwnerPassword(string password)
    {
        if (password.EnumerateRunes().Count() < 12 || password.EnumerateRunes().Count() > 4096 || password.Contains('\0'))
            throw new BootstrapException("platform_owner_password_invalid");
    }

    public static async Task CreateOwnerAsync(BootstrapExecute execute, string password)
    {
        ValidateOwnerPassword(password);
        await execute("""
            insert into public.auth_users(username,password_hash,role) select $1,$2,$3
            where not exists(select 1 from public.auth_users where lower(username)='platform-owner')
            """, "platform-owner", new PasswordCodec().Hash(password), "admin");
    }

    public static string Identifier(string value)
    {
        if (!Regex.IsMatch(value, @"\A[a-z_][a-z0-9_]{0,62}\z")) throw new BootstrapException("invalid_identifier");
        return '"' + value + '"';
    }

    public static async Task CreateTargetAsync(BootstrapExecute execute, string database, string runtimePassword)
    {
        string target = Identifier(database);
        await execute("SET password_encryption = 'scram-sha-256'");
        await execute("CREATE ROLE \"adlog_user\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION");
        await execute("select set_config('sli.bootstrap_runtime_password',$1,false)", runtimePassword);
        try { await execute("""
            do $bootstrap$ begin
              execute format('alter role "adlog_user" password %L',current_setting('sli.bootstrap_runtime_password'));
            end $bootstrap$
            """); }
        finally { await execute("reset sli.bootstrap_runtime_password"); }
        await execute($"CREATE DATABASE {target} OWNER \"postgres\" TEMPLATE template0 ENCODING 'UTF8'");
        await execute($"REVOKE ALL ON DATABASE {target} FROM PUBLIC");
        await execute($"GRANT CONNECT, TEMPORARY ON DATABASE {target} TO \"adlog_user\"");
    }

    public static bool RequiresAdmin(BootstrapMigration migration) => migration.Version >= 89 || AdminVersions.Contains(migration.Version)
        || Regex.IsMatch(File.ReadAllText(migration.Path), @"\bset\s+local\s+role\b|\bpg_has_role\s*\(\s*session_user\b|\b(?:create|alter)\s+role\b|\bowner\s+to\b", RegexOptions.IgnoreCase);

    public static async Task ApplySequenceAsync(string schema, string roles, IReadOnlyList<BootstrapMigration> migrations,
        string psql, string host, int port, string database, string adminPassword, string runtimePassword, string ownerPassword,
        BootstrapExecute execute, string? sourceDomain = null, Func<ProcessStartInfo, Task<BootstrapProcessResult>>? runner = null,
        IReadOnlyDictionary<string, string>? source = null)
    {
        await execute(PgcryptoSql); await execute(GrantSchemaSql);
        await RunFileAsync(psql, host, port, "adlog_user", database, schema, runtimePassword, runner, source);
        if (sourceDomain is not null) await SeedDomainAsync(execute, sourceDomain);
        await RunFileAsync(psql, host, port, "postgres", database, roles, adminPassword, runner, source);
        foreach (var migration in migrations)
        {
            if (migration.Version == 89) await execute(RevokeSchemaSql);
            if (migration.Version == 12) await execute(EmptyV2RouteSql);
            bool admin = RequiresAdmin(migration);
            await RunFileAsync(psql, host, port, admin ? "postgres" : "adlog_user", database, migration.Path,
                admin ? adminPassword : runtimePassword, runner, source);
            if (migration.Version == 14) await CreateOwnerAsync(execute, ownerPassword);
        }
    }

    public static BootstrapBaseline LoadBaseline(string root, IReadOnlyList<BootstrapMigration> migrations)
    {
        JsonObject manifest; int version; JsonObject files, covered;
        try {
            manifest = JsonNode.Parse(File.ReadAllText(Path.Combine(root, "manifest.json")))!.AsObject();
            version = manifest["baseline_version"]!.GetValue<int>(); files = manifest["files"]!.AsObject(); covered = manifest["migrations"]!.AsObject();
            if (manifest["domain_placeholder"]!.GetValue<string>() != "__SLI_REPORT_DOMAIN__") throw new FormatException();
        } catch { throw new BootstrapException("baseline_manifest_invalid"); }
        foreach (string name in new[] { "roles.sql", "baseline.sql" })
            if (!File.Exists(Path.Combine(root, name)) || HashFile(Path.Combine(root, name), true) != files[name]?.GetValue<string>()) throw new BootstrapException("baseline_file_mismatch");
        var current = migrations.Where(m => m.Version <= version).ToArray();
        if (current.Length != covered.Count || current.Any(m => covered[m.Version.ToString(CultureInfo.InvariantCulture)]?.GetValue<string>() != HashFile(m.Path, true)))
            throw new BootstrapException("baseline_migrations_mismatch");
        return new(version, Path.Combine(root, "roles.sql"), Path.Combine(root, "baseline.sql"));
    }

    public static async Task ApplyDatabaseAsync(BootstrapOptions opts, JsonObject plan, string adminPassword, string runtimePassword, string ownerPassword)
    {
        string root = plan["paths"]!["app_root"]!.GetValue<string>(), psql = plan["paths"]!["psql"]!.GetValue<string>();
        string domain = plan["source_identity"]?["domain_fqdn"]?.GetValue<string>() ?? throw new BootstrapException("plan_invalid");
        var migrations = ForwardInventory(Path.Combine(root, "config/postgres_migrations"));
        await using var db = await ConnectAsync(opts, opts.Database, adminPassword);
        BootstrapExecute execute = (sql, args) => ExecuteAsync(db, sql, args);
        string baselineRoot = Path.Combine(root, "config/postgres_baseline");
        if (File.Exists(Path.Combine(baselineRoot, "manifest.json")))
        {
            var baseline = LoadBaseline(baselineRoot, migrations);
            string temporary = Path.Combine(Path.GetTempPath(), "sli-baseline-" + Guid.NewGuid().ToString("N") + ".sql");
            try {
                await File.WriteAllTextAsync(temporary, File.ReadAllText(baseline.SchemaPath).Replace("__SLI_REPORT_DOMAIN__", Domain(domain)).Replace("\r\n", "\n"));
                await RunFileAsync(psql, opts.Host, opts.Port, "postgres", opts.Database, baseline.RolesPath, adminPassword);
                await RunFileAsync(psql, opts.Host, opts.Port, "postgres", opts.Database, temporary, adminPassword);
                await CreateOwnerAsync(execute, ownerPassword);
                foreach (var migration in migrations.Where(m => m.Version > baseline.Version)) {
                    bool admin = RequiresAdmin(migration);
                    await RunFileAsync(psql, opts.Host, opts.Port, admin ? "postgres" : "adlog_user", opts.Database, migration.Path, admin ? adminPassword : runtimePassword);
                }
            } finally { File.Delete(temporary); }
        }
        else await ApplySequenceAsync(Path.Combine(root, "config/postgres_schema_v8.sql"), Path.Combine(root, "config/postgres_migrations/storage_v2_roles.sql"),
            migrations, psql, opts.Host, opts.Port, opts.Database, adminPassword, runtimePassword, ownerPassword, execute, domain);
        await VerifyTargetAsync(execute, plan);
    }

    public static async Task VerifyTargetAsync(BootstrapExecute execute, JsonObject plan)
    {
        (int Version, string Name)[] expected;
        try { expected = plan["base_markers"]!.AsArray().Concat(plan["migrations"]!.AsArray()).Select(n => (n!["version"]!.GetValue<int>(), n["name"]!.GetValue<string>())).OrderBy(m => m.Item1).ToArray(); }
        catch { throw new BootstrapException("plan_invalid"); }
        var ledger = await execute("select version,name from public.schema_migrations order by version");
        VerifyLedger(ledger.Select(r => (Convert.ToInt32(r[0]), (string)r[1]!)), expected);
        var rows = await execute("""
            select current_database(),pg_get_userbyid(d.datdba),r.rolcanlogin,r.rolsuper,r.rolcreatedb,r.rolcreaterole,r.rolbypassrls,
              (select count(*) from public.schema_migrations)
            from pg_database d join pg_roles r on r.rolname='adlog_user' where d.datname=current_database()
            """);
        if (rows.Length != 1 || rows[0].Length != 8 || (string)rows[0][1]! != "postgres" || rows[0][2] is not true
            || rows[0].Skip(3).Take(4).Any(v => v is not false) || Convert.ToInt64(rows[0][7]) != expected.Length)
            throw new BootstrapException("target_readback_failed");
    }

    public static async Task<NpgsqlConnection> ConnectAsync(BootstrapOptions opts, string database, string password)
    {
        var db = new NpgsqlConnection(new NpgsqlConnectionStringBuilder { Host = opts.Host, Port = opts.Port, Database = database,
            Username = "postgres", Password = password, ApplicationName = "sli_existing_postgres_bootstrap", Pooling = false,
            Timeout = 0, CommandTimeout = 0 }.ConnectionString);
        try { await db.OpenAsync(); return db; }
        catch { await db.DisposeAsync(); throw new BootstrapException("postgres_admin_connection_failed"); }
    }
    public static async Task<object?[][]> ExecuteAsync(NpgsqlConnection db, string sql, params object[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, db) { CommandTimeout = 0 };
        foreach (object parameter in parameters) command.Parameters.Add(new NpgsqlParameter { Value = parameter });
        await using var reader = await command.ExecuteReaderAsync(); var rows = new List<object?[]>();
        while (await reader.ReadAsync()) { var values = new object[reader.FieldCount]; reader.GetValues(values); rows.Add(values.Select(v => v is DBNull ? null : v).ToArray()); }
        return rows.ToArray();
    }
}
