using System.Diagnostics;
using Xunit;

namespace Sli.Server.Tests.Access;

// Offline parity vectors from tests/access/test_bootstrap_cluster_guard.py.
// No process is launched and no PostgreSQL connection is opened by these tests.
public sealed class BootstrapClusterGuardTests
{
    [Fact]
    public async Task FailureAndRetryUseDistinctOwnedClustersAndIgnoreAmbientConfiguration()
    {
        using var fixture = new Fixture();
        var clusters = new List<BootstrapCluster.Cluster>();
        foreach (bool failSchema in new[] { true, false })
        {
            async Task Apply(BootstrapCluster.Cluster cluster)
            {
                clusters.Add(cluster);
                Assert.True(Directory.Exists(cluster.Data));
                Assert.Equal(Path.GetDirectoryName(cluster.Data), Path.GetDirectoryName(cluster.Host));
                Assert.NotEqual(fixture.Environment["PGHOST"], cluster.Host);
                Assert.Equal(5432, cluster.Port);
                Assert.Equal(Path.Combine(fixture.Bin, "psql"), cluster.Psql);
                Assert.StartsWith("sli_test_bootstrap_", cluster.Database);
                await BootstrapCluster.AssertOwnedConnectionAsync((sql, _) => {
                    Assert.Equal(BootstrapCluster.IdentitySql, sql);
                    return Task.FromResult<object?[]?>([cluster.Data, 180000, null, "postgres"]);
                }, cluster, TestContext.Current.CancellationToken);
                if (failSchema) throw new ArgumentException("synthetic migration failure");
                await Task.CompletedTask;
            }
            if (failSchema)
                Assert.Equal("synthetic migration failure", (await Assert.ThrowsAsync<ArgumentException>(() => fixture.Execute(Apply))).Message);
            else await fixture.Execute(Apply);
            Assert.False(Directory.Exists(Path.GetDirectoryName(clusters[^1].Data)));
            Assert.Empty(fixture.Running);
        }
        Assert.NotEqual(clusters[0].Data, clusters[1].Data);
        Assert.NotEqual(clusters[0].Database, clusters[1].Database);
        Assert.Equal(2, fixture.Calls.Count(c => c.ArgumentList.Contains("start")));
        foreach (var call in fixture.Calls)
        {
            Assert.Equal(new[] { "LC_ALL", "PATH" }, call.Environment.Keys.Order().ToArray());
            Assert.Equal("C", call.Environment["LC_ALL"]);
            Assert.StartsWith(fixture.Bin + Path.PathSeparator, call.Environment["PATH"]);
            Assert.False(call.UseShellExecute);
            Assert.True(call.CreateNoWindow);
            Assert.True(call.RedirectStandardInput);
        }
        var init = fixture.Calls.First(c => c.ArgumentList.Contains("--username=postgres"));
        Assert.Contains("--auth-local=trust", init.ArgumentList);
        Assert.Contains("--auth-host=reject", init.ArgumentList);
        foreach (var start in fixture.Calls.Where(c => c.ArgumentList.Contains("start")))
        {
            string options = Argument(start, "-o");
            Assert.Contains("listen_addresses=''", options);
            Assert.Contains("unix_socket_permissions=0700", options);
            Assert.Contains("unix_socket_directories='" + clusters.Single(c => c.Data == Argument(start, "-D")).Host + "'", options);
        }
        Assert.True(Directory.Exists(fixture.Foreign));
    }

    [Theory]
    [InlineData("start_exception")]
    [InlineData("start_failure")]
    public async Task PartialStartAlwaysStopsBeforeDeletingItsDirectory(string failure)
    {
        using var fixture = new Fixture { Failure = failure };
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Execute(_ => throw new Xunit.Sdk.XunitException("unexpected cluster")));
        Assert.Equal("bootstrap_cluster_start_failed", error.Message);
        Assert.Empty(fixture.Running);
        Assert.False(Directory.Exists(fixture.Root));
        Assert.Contains(fixture.Calls, c => c.ArgumentList.Contains("stop"));
    }

    [Theory]
    [InlineData("stop_failure")]
    [InlineData("stop_exception")]
    public async Task UncertainStopPreservesOwnedDirectoryAndReportsBlockerWithoutSecrets(string failure)
    {
        using var fixture = new Fixture { Failure = failure };
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Execute());
        Assert.Equal("bootstrap_cluster_cleanup_incomplete_preserved:" + fixture.Root, error.Message);
        Assert.DoesNotContain("synthetic-private-value-never-log", error.ToString());
        Assert.True(Directory.Exists(fixture.Root));
        Assert.Single(fixture.Running);
    }

    [Fact]
    public async Task ReturnedInitFailureRemovesOnlyNewDirectoryWithoutStartingOrStopping()
    {
        using var fixture = new Fixture { Failure = "init_failure" };
        Assert.Equal("bootstrap_cluster_init_failed", (await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Execute())).Message);
        Assert.False(Directory.Exists(fixture.Root));
        Assert.DoesNotContain(fixture.Calls, c => c.ArgumentList.Contains("start") || c.ArgumentList.Contains("stop"));
        Assert.True(Directory.Exists(fixture.Foreign));
    }

    [Theory]
    [InlineData("init_uncertain")]
    [InlineData("init_cancelled")]
    public async Task UncertainInitPreservesDirectoryWithoutStartingOrStopping(string failure)
    {
        using var fixture = new Fixture { Failure = failure };
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Execute());
        Assert.Equal("bootstrap_cluster_cleanup_incomplete_preserved:" + fixture.Root, error.Message);
        Assert.True(Directory.Exists(fixture.Root));
        Assert.DoesNotContain(fixture.Calls, c => c.ArgumentList.Contains("start") || c.ArgumentList.Contains("stop"));
    }

    [Theory]
    [InlineData("initdb (PostgreSQL) 17.6", 0)]
    [InlineData("initdb (PostgreSQL) 180.0", 0)]
    [InlineData("initdb (PostgreSQL) 18.0", 1)]
    public async Task WrongVersionOrFailedProbeNeverInitializes(string version, int exitCode)
    {
        using var fixture = new Fixture { Version = version, VersionExitCode = exitCode };
        Assert.Equal("bootstrap_cluster_requires_postgresql18", (await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Execute())).Message);
        Assert.Contains("--version", Assert.Single(fixture.Calls).ArgumentList);
        Assert.False(Directory.Exists(fixture.Root));
    }

    [Theory]
    [InlineData("initdb")]
    [InlineData("pg_ctl")]
    [InlineData("postgres")]
    [InlineData("psql")]
    public async Task MissingBinaryOrRelativePathFailsBeforeProcesses(string missing)
    {
        using var fixture = new Fixture();
        File.Delete(Path.Combine(fixture.Bin, missing));
        Assert.Equal("bootstrap_cluster_requires_installed_pg18_binaries", (await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Execute())).Message);
        Assert.Equal("bootstrap_cluster_requires_absolute_pg18_bin_directory", (await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Execute(bin: "relative/bin"))).Message);
        Assert.Empty(fixture.Calls);
    }

    [Fact]
    public async Task ReadOnlyIdentityGateRejectsForeignDataVersionTcpUserAndMalformedRows()
    {
        string data = Path.Combine(Path.GetTempPath(), "synthetic-owned", "data");
        var cluster = new BootstrapCluster.Cluster(data, "unused", "unused", "unused");
        Assert.Equal("select current_setting('data_directory'), current_setting('server_version_num')::integer, inet_server_addr(), current_user", BootstrapCluster.IdentitySql);
        object?[][] invalid = [
            [Path.Combine(Path.GetTempPath(), "foreign", "data"), 180000, null, "postgres"],
            [data, 170000, null, "postgres"],
            [data, 180000, "192.0.2.1", "postgres"],
            [data, 180000, null, "foreign"],
            [], [data, 180000, null], [data, 180000, null, "postgres", "extra"],
            [null, 180000, null, "postgres"], [data, "invalid-version", null, "postgres"]
        ];
        foreach (var row in invalid)
        {
            int calls = 0;
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() => BootstrapCluster.AssertOwnedConnectionAsync((sql, _) => {
                calls++;
                Assert.Equal(BootstrapCluster.IdentitySql, sql);
                return Task.FromResult<object?[]?>(row);
            }, cluster, TestContext.Current.CancellationToken));
            Assert.Equal("bootstrap_cluster_connection_identity_mismatch", error.Message);
            Assert.Equal(1, calls);
        }
        Assert.Throws<InvalidOperationException>(() => BootstrapCluster.AssertIdentity(null, cluster));
        BootstrapCluster.AssertIdentity([data, 180000, null, "postgres"], cluster);
        BootstrapCluster.AssertIdentity([Path.Combine(data, "..", "data"), 180006, DBNull.Value, "postgres"], cluster);
    }

    [Theory]
    [InlineData("0", true, 1000, "opt_in")]
    [InlineData("1", true, 0, "nonroot")]
    [InlineData("1", false, 1000, "nonroot")]
    public async Task OptInLinuxAndNonrootGuardsPrecedeProcesses(string optIn, bool linux, int uid, string code)
    {
        using var fixture = new Fixture();
        fixture.Environment["SLI_BOOTSTRAP_DISPOSABLE_CLUSTER"] = optIn;
        var helper = new BootstrapCluster(fixture.Run, linux, (uint)uid);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => helper.ExecuteAsync(fixture.Bin, fixture.Environment, _ => Task.CompletedTask, TestContext.Current.CancellationToken));
        Assert.Contains(code, error.Message);
        Assert.Empty(fixture.Calls);
    }

    [Theory]
    [InlineData("SLI_BOOTSTRAP_TEST_PG_DSN")]
    [InlineData("SLI_BOOTSTRAP_TEST_PSQL")]
    public void LegacySettingsFailWithMigrationGuidanceWithoutEchoingValues(string setting)
    {
        var environment = new Dictionary<string, string?> { [setting] = "synthetic-private-value-never-log" };
        var error = Assert.Throws<InvalidOperationException>(() => BootstrapCluster.Configuration(environment));
        Assert.Contains("SLI_BOOTSTRAP_DISPOSABLE_CLUSTER=1", error.Message);
        Assert.Contains("SLI_BOOTSTRAP_TEST_PG_BIN", error.Message);
        Assert.DoesNotContain(environment[setting]!, error.ToString());
    }

    [Fact]
    public void UnconfiguredRemainsUnconfiguredAndOptInRequiresBinaryDirectory()
    {
        Assert.Null(BootstrapCluster.Configuration(new Dictionary<string, string?>()));
        Assert.Null(BootstrapCluster.Configuration(new Dictionary<string, string?> { ["SLI_BOOTSTRAP_TEST_PG_DSN"] = " " }));
        var environment = new Dictionary<string, string?> { ["SLI_BOOTSTRAP_DISPOSABLE_CLUSTER"] = "1" };
        Assert.Contains("SLI_BOOTSTRAP_TEST_PG_BIN", Assert.Throws<InvalidOperationException>(() => BootstrapCluster.Configuration(environment)).Message);
        environment["SLI_BOOTSTRAP_TEST_PG_BIN"] = "synthetic-bin";
        Assert.Equal("synthetic-bin", BootstrapCluster.Configuration(environment));
    }

    [Fact]
    public async Task CancelledOperationStillStopsOwnedCluster()
    {
        using var fixture = new Fixture();
        using var cancellation = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.Execute(_ => {
            cancellation.Cancel();
            cancellation.Token.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }, ct: cancellation.Token));
        Assert.DoesNotContain("-t", Assert.Single(fixture.Calls, c => c.ArgumentList.Contains("stop")).ArgumentList);
        Assert.Empty(fixture.Running);
        Assert.False(Directory.Exists(fixture.Root));
    }

    private static string Argument(ProcessStartInfo info, string name) => info.ArgumentList[info.ArgumentList.IndexOf(name) + 1];

    private sealed class Fixture : IDisposable
    {
        internal readonly string Bin = Path.Combine(Path.GetTempPath(), "sli-bootstrap-binaries-" + Guid.NewGuid().ToString("N"));
        internal string Foreign => Path.Combine(Bin, "preexisting-data");
        internal readonly Dictionary<string, string?> Environment = new() {
            ["SLI_BOOTSTRAP_DISPOSABLE_CLUSTER"] = "1", ["PGHOST"] = "foreign.example.test",
            ["PGSERVICE"] = "foreign", ["PGDATA"] = "foreign-data", ["PGPASSWORD"] = "synthetic-private-value-never-log",
            ["SLI_BOOTSTRAP_TEST_PG_DSN"] = "host=foreign.example.test dbname=foreign",
            ["SLI_BOOTSTRAP_TEST_PSQL"] = "/foreign/psql", ["ADLOG_REPORT_DOMAIN_FQDN"] = "foreign.example.test"
        };
        internal readonly List<ProcessStartInfo> Calls = [];
        internal readonly HashSet<string> Running = [];
        private readonly HashSet<string> roots = [];
        internal string? Root { get; private set; }
        internal string? Failure { get; init; }
        internal string Version { get; init; } = "initdb (PostgreSQL) 18.0";
        internal int VersionExitCode { get; init; }

        internal Fixture()
        {
            Directory.CreateDirectory(Foreign);
            foreach (string name in new[] { "initdb", "pg_ctl", "postgres", "psql" }) File.WriteAllText(Path.Combine(Bin, name), "synthetic binary placeholder; never executed");
        }

        internal Task Execute(Func<BootstrapCluster.Cluster, Task>? operation = null, string? bin = null, CancellationToken? ct = null) =>
            new BootstrapCluster(Run, linux: true, effectiveUserId: 1000).ExecuteAsync(bin ?? Bin, Environment,
                operation ?? (_ => Task.CompletedTask), ct ?? TestContext.Current.CancellationToken);

        internal Task<BootstrapCluster.ProcessResult> Run(ProcessStartInfo info, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Calls.Add(info);
            Root = info.WorkingDirectory;
            roots.Add(Root);
            if (info.ArgumentList.Contains("--version"))
            {
                Assert.True(Directory.Exists(Path.Combine(Root, "socket")));
                if (OperatingSystem.IsLinux())
                    Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(Root));
                return Task.FromResult(new BootstrapCluster.ProcessResult(VersionExitCode, Version));
            }
            string data = Argument(info, "-D");
            Root = Path.GetDirectoryName(data)!;
            roots.Add(Root);
            if (Path.GetFileName(info.FileName) == "initdb")
            {
                Directory.CreateDirectory(data);
                if (Failure == "init_uncertain") throw new TimeoutException("synthetic-private-value-never-log");
                if (Failure == "init_cancelled") throw new OperationCanceledException("synthetic-private-value-never-log");
                if (Failure == "init_failure") return Task.FromResult(new BootstrapCluster.ProcessResult(1, "synthetic-private-value-never-log"));
            }
            if (info.ArgumentList.Contains("start"))
            {
                Running.Add(data);
                if (Failure == "start_exception") throw new TimeoutException("synthetic-private-value-never-log");
                if (Failure == "start_failure") return Task.FromResult(new BootstrapCluster.ProcessResult(1, "synthetic-private-value-never-log"));
            }
            if (info.ArgumentList.Contains("stop"))
            {
                if (Failure == "stop_exception") throw new IOException("synthetic-private-value-never-log");
                if (Failure == "stop_failure") return Task.FromResult(new BootstrapCluster.ProcessResult(1, "synthetic-private-value-never-log"));
                Assert.True(Directory.Exists(data));
                Running.Remove(data);
            }
            return Task.FromResult(new BootstrapCluster.ProcessResult(0, ""));
        }

        public void Dispose()
        {
            // Only synthetic initializers ran, so retained directories have no live children.
            foreach (string path in roots.Append(Bin))
            {
                string resolved = Path.GetFullPath(path);
                Assert.Equal(Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar), Path.GetDirectoryName(resolved));
                Assert.StartsWith("sli-", Path.GetFileName(resolved));
                if (Directory.Exists(resolved)) Directory.Delete(resolved, recursive: true);
            }
        }
    }
}
