using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Npgsql;

namespace Sli.Server.Tests.Access;

// .NET counterpart of tests/access/bootstrap_cluster.py. This owns test clusters,
// never an installed service or a connection supplied by the caller's environment.
internal sealed class BootstrapCluster(
    Func<ProcessStartInfo, CancellationToken, Task<BootstrapCluster.ProcessResult>>? runner = null,
    bool? linux = null, uint? effectiveUserId = null)
{
    internal sealed record ProcessResult(int ExitCode, string Output);
    internal sealed record Cluster(string Data, string Host, string Psql, string Database)
    {
        internal int Port => 5432;
    }

    [DllImport("libc", EntryPoint = "geteuid")]
    private static extern uint GetEffectiveUserId();

    internal static string? Configuration(IReadOnlyDictionary<string, string?> environment)
    {
        string? Get(string key) => environment.GetValueOrDefault(key);
        if (Get("SLI_BOOTSTRAP_DISPOSABLE_CLUSTER") != "1")
        {
            if (new[] { "SLI_BOOTSTRAP_TEST_PG_DSN", "SLI_BOOTSTRAP_TEST_PSQL" }
                .Any(key => !string.IsNullOrWhiteSpace(Get(key))))
                throw new InvalidOperationException("legacy bootstrap configuration is unsupported; replace it with " +
                    "SLI_BOOTSTRAP_DISPOSABLE_CLUSTER=1 and SLI_BOOTSTRAP_TEST_PG_BIN; Linux/nonroot required");
            return null; // Unconfigured integration coverage, as in the Python fixture.
        }
        return !string.IsNullOrWhiteSpace(Get("SLI_BOOTSTRAP_TEST_PG_BIN"))
            ? Get("SLI_BOOTSTRAP_TEST_PG_BIN")
            : throw new InvalidOperationException("set SLI_BOOTSTRAP_TEST_PG_BIN; Linux/nonroot required");
    }

    internal async Task ExecuteAsync(string bin, IReadOnlyDictionary<string, string?> environment,
        Func<Cluster, Task> operation, CancellationToken ct)
    {
        if (environment.GetValueOrDefault("SLI_BOOTSTRAP_DISPOSABLE_CLUSTER") != "1")
            throw new InvalidOperationException("bootstrap_cluster_explicit_opt_in_required");
        if (!(linux ?? OperatingSystem.IsLinux()) ||
            (effectiveUserId ?? GetEffectiveUserId()) == 0)
            throw new InvalidOperationException("bootstrap_cluster_requires_linux_nonroot: use Linux as a non-root user");
        if (!Path.IsPathFullyQualified(bin))
            throw new InvalidOperationException("bootstrap_cluster_requires_absolute_pg18_bin_directory");
        bin = Path.GetFullPath(bin);
        if (!new[] { "initdb", "pg_ctl", "postgres", "psql" }.All(name => File.Exists(Path.Combine(bin, name))))
            throw new InvalidOperationException("bootstrap_cluster_requires_installed_pg18_binaries");

        string root = Path.Combine(Path.GetTempPath(), "sli-pg-" + Guid.NewGuid().ToString("N"));
        CreatePrivateDirectory(root);
        var cluster = new Cluster(Path.Combine(root, "data"), Path.Combine(root, "socket"),
            Path.Combine(bin, "psql"), "sli_test_bootstrap_" + Guid.NewGuid().ToString("N"));
        bool initAttempted = false, initReturned = false, startAttempted = false;

        async Task<ProcessResult> Run(string name, string stage, CancellationToken token, params string[] args)
        {
            var info = new ProcessStartInfo(Path.Combine(bin, name)) {
                UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden,
                WorkingDirectory = root,
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true
            };
            foreach (string arg in args) info.ArgumentList.Add(arg);
            info.Environment.Clear();
            info.Environment["PATH"] = bin + Path.PathSeparator + "/bin:/usr/bin";
            info.Environment["LC_ALL"] = "C";
            try { return await (runner ?? RunProcessAsync)(info, token); }
            catch (Exception error) when (error is System.ComponentModel.Win32Exception or IOException or
                OperationCanceledException or TimeoutException or InvalidOperationException)
            {
                // Commands, child output and inherited configuration can contain secrets.
                throw new InvalidOperationException($"bootstrap_cluster_{stage}_failed");
            }
        }

        try
        {
            CreatePrivateDirectory(cluster.Host);
            var version = await Run("initdb", "version", ct, "--version");
            if (version.ExitCode != 0 || !Regex.IsMatch(version.Output, @"\(PostgreSQL\) 18(?:\.|\b)"))
                throw new InvalidOperationException("bootstrap_cluster_requires_postgresql18");
            initAttempted = true;
            var initialized = await Run("initdb", "init", ct, "-D", cluster.Data, "--username=postgres",
                "--no-locale", "--encoding=UTF8", "--auth-local=trust", "--auth-host=reject");
            initReturned = true;
            if (initialized.ExitCode != 0) throw new InvalidOperationException("bootstrap_cluster_init_failed");
            string options = $"-c listen_addresses='' -c unix_socket_directories='{cluster.Host}' -c unix_socket_permissions=0700 -p 5432";
            startAttempted = true;
            var started = await Run("pg_ctl", "start", ct, "-D", cluster.Data, "-l", Path.Combine(root, "postgres.log"),
                "-o", options, "-w", "start");
            if (started.ExitCode != 0) throw new InvalidOperationException("bootstrap_cluster_start_failed");
            await operation(cluster);
        }
        finally
        {
            bool stopped = !startAttempted && (!initAttempted || initReturned);
            if (startAttempted)
            {
                try
                {
                    // Cleanup must still run when the operation's token was cancelled.
                    var stop = await Run("pg_ctl", "stop", CancellationToken.None, "-D", cluster.Data,
                        "-m", "immediate", "-w", "stop");
                    stopped = stop.ExitCode == 0;
                }
                catch (InvalidOperationException) { stopped = false; }
            }
            if (!stopped)
                throw new InvalidOperationException($"bootstrap_cluster_cleanup_incomplete_preserved:{root}");
            // root was freshly generated here; no caller-supplied path is deleted.
            Directory.Delete(root, recursive: true);
        }
    }

    internal const string IdentitySql = "select current_setting('data_directory'), " +
        "current_setting('server_version_num')::integer, inet_server_addr(), current_user";

    internal static async Task AssertOwnedConnectionAsync(NpgsqlConnection connection, Cluster cluster, CancellationToken ct)
    {
        await AssertOwnedConnectionAsync(async (sql, token) =>
        {
            await using var command = new NpgsqlCommand(sql, connection) { CommandTimeout = 0 };
            await using var reader = await command.ExecuteReaderAsync(token);
            if (!await reader.ReadAsync(token)) return null;
            var row = new object[reader.FieldCount];
            reader.GetValues(row);
            return row;
        }, cluster, ct);
    }

    internal static async Task AssertOwnedConnectionAsync(
        Func<string, CancellationToken, Task<object?[]?>> read, Cluster cluster, CancellationToken ct) =>
        AssertIdentity(await read(IdentitySql, ct), cluster);

    internal static void AssertIdentity(object?[]? row, Cluster cluster)
    {
        if (row is not [string data, int version, var address, "postgres"] || version / 10000 != 18 ||
            address is not (null or DBNull) || !Path.IsPathFullyQualified(data) ||
            Path.GetFullPath(data) != Path.GetFullPath(cluster.Data))
            throw new InvalidOperationException("bootstrap_cluster_connection_identity_mismatch");
    }

    private static void CreatePrivateDirectory(string path)
    {
        if (OperatingSystem.IsLinux()) Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        else Directory.CreateDirectory(path); // Offline lifecycle vectors also run on Windows.
    }

    private static async Task<ProcessResult> RunProcessAsync(ProcessStartInfo info, CancellationToken ct)
    {
        using var process = Process.Start(info) ?? throw new InvalidOperationException();
        process.StandardInput.Close();
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync(ct);
        await error; // Drain without including potentially private child diagnostics.
        return new ProcessResult(process.ExitCode, await output);
    }
}
