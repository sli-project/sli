using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.InstallationSetup;

public sealed record BootstrapOptions(string AppRoot, string BinDirectory, string DataDirectory, string Database,
    string Host = "127.0.0.1", int Port = 55433, bool Apply = false, bool ApplyAfterPlan = false, string? ConfirmPlan = null,
    string? StatusFile = null, bool AdminPasswordStdin = false, bool SaveAdminPassword = false, bool UseSavedAdminPassword = false,
    bool OwnerPasswordStdin = false, bool SaveOwnerPassword = false, bool UseSavedOwnerPassword = false);

public class PostgresBootstrapServices
{
    public virtual string ReadHiddenPassword(string prompt)
    {
        Console.Error.Write(prompt); var password = new StringBuilder();
        while (true) {
            var key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter) { Console.Error.WriteLine(); return password.ToString(); }
            if (key.Key == ConsoleKey.Backspace) { if (password.Length > 0) password.Length--; }
            else if (key.KeyChar != '\0') password.Append(key.KeyChar);
        }
    }
    public virtual string LoadPassword(string root, bool owner) => PostgresBootstrapCredentials.Load(root, owner);
    public virtual void SavePassword(string root, string password, bool owner) => PostgresBootstrapCredentials.Save(root, password, owner);
    public virtual async Task ValidateCredentialsAsync(BootstrapOptions opts, string password)
    {
        string data = ExistingDirectory(opts.DataDirectory);
        await using var db = await PostgresBootstrap.ConnectAsync(opts, "postgres", password);
        var snapshot = await PostgresBootstrap.ReadClusterAsync((sql, args) => PostgresBootstrap.ExecuteAsync(db, sql, args), opts.Database);
        PostgresBootstrap.ValidateCluster(snapshot, data, opts.Port, false);
    }
    internal static string ExistingDirectory(string path)
    {
        if (!Path.IsPathFullyQualified(path)) throw new BootstrapException("unsafe_path");
        path = Path.GetFullPath(path);
        if (!Directory.Exists(path)) throw new BootstrapException("required_path_missing");
        return path;
    }
    public virtual async Task<JsonObject> PreparePlanAsync(BootstrapOptions opts, string password)
    {
        string root = ExistingDirectory(opts.AppRoot), bin = ExistingDirectory(opts.BinDirectory), data = ExistingDirectory(opts.DataDirectory);
        string psql = Path.Combine(bin, OperatingSystem.IsWindows() ? "psql.exe" : "psql"), schema = Path.Combine(root, "config/postgres_schema_v8.sql"),
            roles = Path.Combine(root, "config/postgres_migrations/storage_v2_roles.sql"), controllers = Path.Combine(root, "config/domain_controllers.json");
        if (new[] { psql, schema, roles, controllers }.Any(p => !File.Exists(p))) throw new BootstrapException("required_path_missing");
        var version = await PostgresBootstrap.RunProcessAsync(PostgresBootstrap.ProcessStart(psql, ["--version"], PostgresBootstrap.ChildEnvironment(psql, "", PostgresBootstrap.EnvironmentValues())));
        if (version.ExitCode != 0 || !Regex.IsMatch(version.Output, @"PostgreSQL\) 18(?:\.\d+)*")) throw new BootstrapException("postgresql_18_required");
        var migrations = PostgresBootstrap.ForwardInventory(Path.Combine(root, "config/postgres_migrations"));
        var markers = PostgresBootstrap.BaseMarkers(schema); string domain = PostgresBootstrap.SourceDomain(controllers);
        await using var db = await PostgresBootstrap.ConnectAsync(opts, "postgres", password);
        var snapshot = await PostgresBootstrap.ReadClusterAsync((sql, args) => PostgresBootstrap.ExecuteAsync(db, sql, args), opts.Database);
        PostgresBootstrap.ValidateCluster(snapshot, data, opts.Port);
        string profile = Path.Combine(root, "data/runtime/local-postgres-18-official");
        if (Path.Exists(profile)) throw new BootstrapException("profile_target_exists");
        var plan = PostgresBootstrap.BuildPlan(opts.Database, data, snapshot, PostgresBootstrap.HashFile(schema), PostgresBootstrap.HashFile(roles), migrations);
        plan["paths"] = new JsonObject { ["app_root"] = root, ["psql"] = psql, ["profile_dir"] = profile };
        plan["isolated_rehearsal_required"] = true;
        plan["source_identity"] = new JsonObject { ["domain_fqdn"] = domain, ["forest_fqdn"] = domain, ["domain_sid"] = null, ["basis"] = "domain_controllers" };
        plan["base_markers"] = new JsonArray(markers.Select(m => (JsonNode)new JsonObject { ["version"] = m.Version, ["name"] = m.Name }).ToArray());
        plan["expected_marker_count"] = markers.Length + migrations.Length;
        plan["planned_actions"] = new JsonArray(new[] { "create_runtime_login_role", "create_runtime_owned_database", "apply_base_schema", "seed_configured_source_domain",
            "apply_role_bootstrap", "apply_exact_forward_inventory", "verify_exact_marker_name_ledger", "require_separate_isolated_cluster_rehearsal",
            "write_inactive_dpapi_runtime_candidate", "write_sanitized_receipt" }.Select(s => (JsonNode)JsonValue.Create(s)!).ToArray());
        plan["excluded_actions"] = new JsonArray(new[] { "source_contact", "worker_start", "report_start", "cursor_change", "existing_database_change", "plaintext_secret_storage" }
            .Select(s => (JsonNode)JsonValue.Create(s)!).ToArray());
        return plan;
    }
    public virtual async Task<string> ApplyAsync(BootstrapOptions opts, string password, string ownerPassword, JsonObject plan, string confirmation)
    {
        if (!OperatingSystem.IsWindows()) throw new BootstrapException("windows_dpapi_required");
        string root = plan["paths"]!["app_root"]!.GetValue<string>(), profile = plan["paths"]!["profile_dir"]!.GetValue<string>();
        string receiptPath = Path.Combine(root, "artifacts/operations/existing-postgres-bootstrap-latest.json"), sid = PostgresBootstrapCredentials.IdentitySid();
        var receipt = new JsonObject { ["contract_version"] = 1, ["operation"] = "bootstrap_existing_postgresql_18", ["status"] = "in_progress",
            ["confirmation_sha256"] = confirmation, ["database"] = opts.Database, ["isolated_rehearsal_required"] = true,
            ["runtime_role"] = "adlog_user", ["migration_role"] = "postgres", ["expected_marker_count"] = plan["expected_marker_count"]!.DeepClone(),
            ["last_completed_stage"] = "plan_revalidated", ["error_code"] = null, ["generated_at"] = DateTimeOffset.UtcNow.ToString("O"), ["credential_values_exposed"] = false };
        Directory.CreateDirectory(Path.GetDirectoryName(receiptPath)!);
        void Checkpoint(string stage) { receipt["last_completed_stage"] = stage; PostgresBootstrapCredentials.WriteJson(receiptPath, receipt); }
        Checkpoint("plan_revalidated");
        try {
            string runtimePassword = Convert.ToBase64String(RandomNumberGenerator.GetBytes(36)).Replace('+', '-').Replace('/', '_');
            await using (var db = await PostgresBootstrap.ConnectAsync(opts, "postgres", password)) {
                // Read back again immediately before the first cluster mutation.
                var snapshot = await PostgresBootstrap.ReadClusterAsync((sql, args) => PostgresBootstrap.ExecuteAsync(db, sql, args), opts.Database);
                PostgresBootstrap.ValidateCluster(snapshot, opts.DataDirectory, opts.Port);
                await PostgresBootstrap.CreateTargetAsync((sql, args) => PostgresBootstrap.ExecuteAsync(db, sql, args), opts.Database, runtimePassword);
            }
            Checkpoint("target_database_and_runtime_role_created");
            await PostgresBootstrap.ApplyDatabaseAsync(opts, plan, password, runtimePassword, ownerPassword);
            Checkpoint("target_schema_and_exact_ledger_verified");
            PostgresBootstrapCredentials.CreatePrivateDirectory(profile, sid);
            if (!PostgresBootstrapCredentials.VerifyPrivateDirectory(profile, sid)) throw new BootstrapException("acl_verification_failed");
            receipt["runtime_candidate"] = PostgresBootstrapCredentials.WriteRuntimeCandidate(profile, opts.Database, opts.Host, opts.Port, runtimePassword, sid,
                value => PostgresBootstrapCredentials.Protect(value, PostgresBootstrapCredentials.RuntimePurpose));
            receipt["status"] = "complete"; Checkpoint("runtime_candidate_written"); return receiptPath;
        }
        catch (Exception ex) {
            receipt["status"] = "partial_failure"; receipt["error_code"] = ex is BootstrapException ? PostgresBootstrapCommand.SafeCode(ex.Message) : "internal_error";
            PostgresBootstrapCredentials.WriteJson(receiptPath, receipt);
            if (ex is BootstrapException) throw;
            throw new BootstrapException("bootstrap_partial_failure");
        }
    }
}

public static class PostgresBootstrapCommand
{
    public static BootstrapOptions Parse(string[] args)
    {
        var values = new Dictionary<string, string>(); var flags = new HashSet<string>();
        string[] valueKeys = ["--app-root", "--bin-dir", "--data-dir", "--database", "--host", "--port", "--confirm-plan", "--status-file"];
        string[] flagKeys = ["--apply", "--apply-after-plan", "--admin-password-stdin", "--save-admin-password", "--use-saved-admin-password",
            "--platform-owner-password-stdin", "--save-platform-owner-password", "--use-saved-platform-owner-password"];
        for (int i = 0; i < args.Length; i++) {
            if (flagKeys.Contains(args[i])) flags.Add(args[i]);
            else if (valueKeys.Contains(args[i]) && i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal)) { string key = args[i]; values[key] = args[++i]; }
            else throw new BootstrapException("invalid_arguments");
        }
        if (valueKeys.Take(4).Any(k => !values.ContainsKey(k))) throw new BootstrapException("invalid_arguments");
        string database = values["--database"], host = values.GetValueOrDefault("--host", "127.0.0.1");
        if (!Regex.IsMatch(database, @"\Asli_[a-z0-9_]*\z") || database.Length > 63) throw new BootstrapException("invalid_database");
        if (host != "127.0.0.1") throw new BootstrapException("loopback_required");
        if (!int.TryParse(values.GetValueOrDefault("--port", "55433"), NumberStyles.Integer, CultureInfo.InvariantCulture, out int port)) throw new BootstrapException("invalid_arguments");
        if (port is < 1024 or > 65535) throw new BootstrapException("invalid_port");
        bool apply = flags.Contains("--apply"), after = flags.Contains("--apply-after-plan"); string? confirmation = values.GetValueOrDefault("--confirm-plan");
        if (after && (apply || !string.IsNullOrEmpty(confirmation))
            || flags.Contains("--use-saved-admin-password") && (flags.Contains("--admin-password-stdin") || flags.Contains("--save-admin-password"))
            || flags.Contains("--use-saved-platform-owner-password") && (flags.Contains("--platform-owner-password-stdin") || flags.Contains("--save-platform-owner-password")))
            throw new BootstrapException("invalid_arguments");
        if (!after && apply != !string.IsNullOrEmpty(confirmation)) throw new BootstrapException("confirmation_required");
        return new(values["--app-root"], values["--bin-dir"], values["--data-dir"], database, host, port, apply, after, confirmation,
            values.GetValueOrDefault("--status-file"), flags.Contains("--admin-password-stdin"), flags.Contains("--save-admin-password"), flags.Contains("--use-saved-admin-password"),
            flags.Contains("--platform-owner-password-stdin"), flags.Contains("--save-platform-owner-password"), flags.Contains("--use-saved-platform-owner-password"));
    }
    public static string SafeCode(string code) => Regex.IsMatch(code, @"\A[a-z][a-z0-9_]{0,63}\z") ? code : "internal_error";
    private static string ReadSecret(TextReader input, string error)
    {
        var result = new StringBuilder();
        while (input.Read() is int ch && ch != -1) {
            if (ch == '\n') break;
            result.Append((char)ch);
            if (result.Length > 8194) throw new BootstrapException(error);
        }
        string value = result.ToString().TrimEnd('\r', '\n');
        if (value.EnumerateRunes().Count() > 4096) throw new BootstrapException(error);
        return value;
    }
    private static void WriteStatus(string? path, JsonObject value)
    {
        if (path is null) return;
        if (!Path.IsPathFullyQualified(path)) throw new BootstrapException("unsafe_status_path");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!); PostgresBootstrapCredentials.WriteJson(path, value);
    }
    public static async Task<int> RunAsync(string[] args, PostgresBootstrapServices? services = null, TextReader? input = null, TextWriter? output = null, TextWriter? error = null)
    {
        services ??= new(); input ??= Console.In; output ??= Console.Out; error ??= Console.Error; BootstrapOptions? opts = null;
        try {
            opts = Parse(args);
            string password = opts.UseSavedAdminPassword ? services.LoadPassword(opts.AppRoot, false) : opts.AdminPasswordStdin
                ? ReadSecret(input, "postgres_admin_password_invalid") : services.ReadHiddenPassword("PostgreSQL administrator password: ");
            if (password.Length == 0) throw new BootstrapException("postgres_admin_password_required");
            string? ownerPassword = null;
            if (opts.Apply || opts.ApplyAfterPlan) {
                ownerPassword = opts.UseSavedOwnerPassword ? services.LoadPassword(opts.AppRoot, true) : opts.OwnerPasswordStdin
                    ? ReadSecret(input, "platform_owner_password_invalid") : services.ReadHiddenPassword("New platform-owner password: ");
                PostgresBootstrap.ValidateOwnerPassword(ownerPassword);
            }
            if (opts.SaveAdminPassword || opts.SaveOwnerPassword) await services.ValidateCredentialsAsync(opts, password);
            if (opts.SaveAdminPassword) services.SavePassword(opts.AppRoot, password, false);
            if (opts.SaveOwnerPassword) { if (ownerPassword is null) throw new BootstrapException("invalid_arguments"); services.SavePassword(opts.AppRoot, ownerPassword, true); }
            var plan = await services.PreparePlanAsync(opts, password); string confirmation = PostgresBootstrap.Confirmation(plan);
            if (!opts.Apply && !opts.ApplyAfterPlan) {
                await output.WriteLineAsync(PostgresBootstrap.Canonical(new JsonObject { ["confirmation_sha256"] = confirmation, ["mode"] = "plan", ["plan"] = plan }));
                WriteStatus(opts.StatusFile, new JsonObject { ["status"] = "planned", ["confirmation_sha256"] = confirmation }); return 0;
            }
            if (opts.Apply && !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(opts.ConfirmPlan ?? ""), Encoding.UTF8.GetBytes(confirmation))) throw new BootstrapException("confirmation_mismatch");
            string receipt = await services.ApplyAsync(opts, password, ownerPassword!, plan, confirmation);
            var envelope = new JsonObject { ["confirmation_sha256"] = confirmation, ["mode"] = "apply", ["receipt"] = receipt, ["status"] = "complete" };
            await output.WriteLineAsync(PostgresBootstrap.Canonical(envelope)); WriteStatus(opts.StatusFile, envelope); return 0;
        }
        catch (Exception ex) {
            var envelope = new JsonObject { ["status"] = "error", ["code"] = ex is BootstrapException ? SafeCode(ex.Message) : "internal_error" };
            try { WriteStatus(opts?.StatusFile, envelope); } catch { /* Preserve the original sanitized failure. */ }
            await error.WriteLineAsync(PostgresBootstrap.Canonical(envelope)); return 2;
        }
    }
}
