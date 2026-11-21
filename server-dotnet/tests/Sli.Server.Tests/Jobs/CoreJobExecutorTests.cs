using System.Diagnostics;
using System.Text.Json.Nodes;
using Sli.Server.Jobs;
using Xunit;

namespace Sli.Server.Tests.Jobs;

public class CoreJobExecutorTests
{
    [Fact]
    public async Task Child_runtime_collects_within_budget_and_rejects_managed_and_native_overallocation()
    {
        const string probe = "SLI_TEST_JOB_MEMORY_PROBE";
        const long memory = 256L * 1024 * 1024;
        var budget = new JsonObject { ["memory_bytes"] = memory, ["max_result_bytes"] = 65536L };
        if (Environment.GetEnvironmentVariable(probe) is { } probeMode)
        {
            Assert.False(System.Runtime.GCSettings.IsServerGC);
            Assert.InRange(GC.GetGCMemoryInfo().TotalAvailableMemoryBytes, 1, memory / 2);
            CoreJobProcess.Limits(budget);
            if (probeMode == "managed")
            {
                // This must fail before the OS/process budget is exhausted, and
                // leave enough headroom to report the allocation failure.
                try { GC.KeepAlive(new byte[(int)memory]); }
                catch (OutOfMemoryException) { Environment.Exit(73); }
                throw new Exception("managed allocation escaped the heap budget");
            }
            if (probeMode == "native")
            {
                // mmap bypasses the managed heap. RLIMIT_DATA must still reject
                // writable anonymous mappings, even if they are never touched.
                var address = MapMemory(IntPtr.Zero, (nuint)(memory + 4096), 3, 0x22, -1, 0);
                if (address == new IntPtr(-1) && System.Runtime.InteropServices.Marshal.GetLastPInvokeError() == 12)
                    Environment.Exit(73); // ENOMEM, handled without SIGABRT
                if (address != new IntPtr(-1)) UnmapMemory(address, (nuint)(memory + 4096));
                throw new Exception("native allocation escaped the process budget");
            }
            var retained = new byte[32][];
            for (int i = 0; i < retained.Length; i++) retained[i] = new byte[1024 * 1024];
            long checksum = 0;
            for (int i = 0; i < 200000; i++)
            {
                var item = new byte[4096]; item[0] = (byte)i; checksum += item[0];
            }
            Assert.True(checksum > 0);
            Assert.True(GC.CollectionCount(0) > 0);
            using var current = Process.GetCurrentProcess();
            Assert.InRange(current.PeakWorkingSet64, 1, memory);
            GC.KeepAlive(retained);
            return;
        }
        var job = CoreJobTests.Job(); job["budget"] = budget.DeepClone();
        var environment = new Dictionary<string, string>
        {
            ["SLI_JOB_EXECUTOR_LIGHT_PASSWORD_FILE"] = "synthetic-unused",
            ["ADLOG_COLLECTION_PRINCIPAL"] = @"example.test\synthetic",
            ["ADLOG_COLLECTION_PRINCIPAL_SID"] = "S-1-5-21-100000001-200000002-300000003-1001",
            ["DOTNET_PROCESSOR_COUNT"] = "64", ["DOTNET_GCHeapHardLimitPercent"] = "64"
        };
        foreach (string key in new[] { "PATH", "SystemRoot", "WINDIR" })
            if (Environment.GetEnvironmentVariable(key) is { } value) environment[key] = value;
        foreach (string mode in OperatingSystem.IsLinux() ? new[] { "within", "managed", "native" } : new[] { "within", "managed" })
        {
            var start = CoreJobProcess.StartInfo(job, "handler", environment.GetValueOrDefault,
                Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet", false);
            start.ArgumentList.Clear();
            // Use the web executable's server-GC runtimeconfig, not the test
            // runner's default workstation config. This reproduces the real host.
            start.ArgumentList.Add("exec"); start.ArgumentList.Add("--runtimeconfig");
            start.ArgumentList.Add(Path.ChangeExtension(typeof(CoreJobProcess).Assembly.Location, ".runtimeconfig.json"));
            start.ArgumentList.Add(typeof(CoreJobExecutorTests).Assembly.Location);
            start.ArgumentList.Add("-method");
            start.ArgumentList.Add(typeof(CoreJobExecutorTests).FullName + "." + nameof(Child_runtime_collects_within_budget_and_rejects_managed_and_native_overallocation));
            start.Environment[probe] = mode;
            using var child = Process.Start(start)!;
            child.StandardInput.Close();
            var stdout = child.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
            var stderr = child.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
            await child.WaitForExitAsync(TestContext.Current.CancellationToken);
            string diagnostics = await stdout + await stderr;
            Assert.True(child.ExitCode == (mode == "within" ? 0 : 73), $"{mode}: exit={child.ExitCode}; {diagnostics}");
        }
    }

    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "mmap", SetLastError = true)]
    private static extern IntPtr MapMemory(IntPtr address, nuint length, int protection, int flags, int descriptor, long offset);
    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "munmap")]
    private static extern int UnmapMemory(IntPtr address, nuint length);

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, true)]
    [InlineData(true, false)]
    public async Task Failed_child_reports_exit_and_bounded_safe_stderr_even_when_stdout_is_empty(bool emptyOutput, bool knownMessage)
    {
        string message = knownMessage ? "Out of memory." : "synthetic-private-unrecognized";
        var start = new ProcessStartInfo(OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe") : "/bin/sh")
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        if (OperatingSystem.IsWindows())
        {
            start.ArgumentList.Add("-NoProfile"); start.ArgumentList.Add("-NonInteractive"); start.ArgumentList.Add("-Command");
            start.ArgumentList.Add("[void][Console]::In.ReadToEnd(); [Console]::Error.Write(('synthetic-private-password ' * 2000) + \"`n" + message + "`nsynthetic-private-row\"); "
                + (emptyOutput ? "" : "[Console]::Out.Write('{}'); ") + "exit 42");
        }
        else
        {
            start.ArgumentList.Add("-c");
            start.ArgumentList.Add("cat >/dev/null; i=0; while [ $i -lt 2000 ]; do printf '%s' 'synthetic-private-password ' >&2; i=$((i+1)); done; printf '\\n" + message + "\\nsynthetic-private-row' >&2; "
                + (emptyOutput ? "" : "printf '{}'; ") + "exit 42");
        }
        var budget = new JsonObject { ["max_result_bytes"] = 4096L, ["memory_bytes"] = 268435456L };
        var error = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => CoreJobProcess.RunAsync(start, budget,
            TimeSpan.FromSeconds(10), null, TestContext.Current.CancellationToken, new()));
        Assert.Equal("job_child_exited", CoreJobCommand.FailureCode(error));
        var diagnostic = CoreJobCommand.Diagnostic(error);
        Assert.Equal(42, diagnostic["child_exit_code"]?.GetValue<int>());
        Assert.Equal(knownMessage ? "Out of memory." : "[redacted]", diagnostic["child_stderr"]?.GetValue<string>());
        Assert.DoesNotContain("private", diagnostic.ToJsonString());
        Assert.True(diagnostic.ToJsonString().Length < 1024);
    }

    [Fact]
    public async Task Linux_signal_death_reports_exit_code_and_signal_candidate()
    {
        if (!OperatingSystem.IsLinux()) return;
        var start = new ProcessStartInfo("/bin/sh")
        { UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        start.ArgumentList.Add("-c"); start.ArgumentList.Add("cat >/dev/null; kill -KILL $$");
        var budget = new JsonObject { ["max_result_bytes"] = 4096L, ["memory_bytes"] = 268435456L };
        var error = await Assert.ThrowsAsync<CoreJobProcess.ExitFailure>(() => CoreJobProcess.RunAsync(start, budget,
            TimeSpan.FromSeconds(10), null, TestContext.Current.CancellationToken, new()));
        var diagnostic = CoreJobCommand.Diagnostic(error);
        Assert.Equal(137, diagnostic["child_exit_code"]!.GetValue<int>());
        Assert.Equal(9, diagnostic["child_signal_candidate"]!.GetValue<int>());
        Assert.Equal("", diagnostic["child_stderr"]!.GetValue<string>());
    }

    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "memfd_create", SetLastError = true)]
    private static extern int MemoryFile(string name, uint flags);
    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "ftruncate64", SetLastError = true)]
    private static extern int ResizeMemoryFile(int descriptor, long length);

    [Fact]
    public async Task Linux_runtime_backing_file_can_exceed_stdout_budget_but_not_memory_budget()
    {
        if (!OperatingSystem.IsLinux()) return;
        const string probe = "SLI_TEST_JOB_RUNTIME_FILE_PROBE";
        const long memory = 268435456;
        var budget = new JsonObject { ["max_result_bytes"] = 65536L, ["memory_bytes"] = memory };
        if (Environment.GetEnvironmentVariable(probe) is { } probeMode)
        {
            int descriptor = MemoryFile("synthetic-runtime-code", 1);
            Assert.True(descriptor >= 0);
            using var file = new Microsoft.Win32.SafeHandles.SafeFileHandle((IntPtr)descriptor, ownsHandle: true);
            CoreJobProcess.Limits(budget);
            // CLR 10 uses 192 KiB memfd templates for executable code. These
            // files are not stdout results; exceeding the file cap sends SIGXFSZ.
            Assert.Equal(0, ResizeMemoryFile(descriptor, probeMode == "within" ? 192 * 1024 : memory + 1));
            return;
        }
        foreach (string mode in new[] { "within", "beyond" })
        {
            var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            start.ArgumentList.Add(typeof(CoreJobExecutorTests).Assembly.Location);
            start.ArgumentList.Add("-method");
            start.ArgumentList.Add(typeof(CoreJobExecutorTests).FullName + "." + nameof(Linux_runtime_backing_file_can_exceed_stdout_budget_but_not_memory_budget));
            start.Environment[probe] = mode;
            start.Environment["DOTNET_GCHeapHardLimit"] = "8000000";
            start.Environment["DOTNET_GCHeapCount"] = "1";
            start.Environment["DOTNET_EnableDiagnostics"] = "0";
            using var child = Process.Start(start)!;
            var stdout = child.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
            var stderr = child.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
            await child.WaitForExitAsync(TestContext.Current.CancellationToken);
            await stdout; await stderr;
            Assert.Equal(mode == "within" ? 0 : 128 + 25, child.ExitCode); // SIGXFSZ
        }
    }

    [Fact]
    public void Child_preserves_Windows_network_provider_paths_without_inheriting_other_credentials()
    {
        var environment = new Dictionary<string,string>
        {
            ["SystemRoot"]="C:/Windows",["WINDIR"]="C:/Windows",
            ["SLI_JOB_EXECUTOR_LIGHT_PASSWORD_FILE"]="synthetic-owned-file",
            ["ADLOG_PG_DSN"]="synthetic-admin"
        };
        var child=CoreJobIdentity.ChildEnvironment(new("light","handler","sli.workstations","workstations.overview-project"),environment.GetValueOrDefault);
        Assert.Equal("C:/Windows",child["SystemRoot"]);Assert.Equal("C:/Windows",child["WINDIR"]);
        Assert.DoesNotContain("ADLOG_PG_DSN",child.Keys);
    }
    [Theory]
    [InlineData("57014", "job_statement_cancelled")]
    [InlineData("08006", "job_connection_lost")]
    [InlineData("55P03", "job_lock_unavailable")]
    public async Task Database_failure_is_recorded_and_the_next_job_can_execute(string state, string code)
    {
        var session = new CoreJobTests.Session(true, true, true, true);
        int calls = 0;
        var executor = new CoreJobExecutor(new(session), CoreJobTests.Registry(), (_, purpose, _, _, _) =>
        {
            if (++calls == 1) throw new Npgsql.PostgresException("synthetic-private", "ERROR", "ERROR", state);
            return Task.FromResult(new JsonObject { ["status"] = purpose == "handler" ? "success" : "committed" });
        });
        await executor.ExecuteAsync(CoreJobTests.Job(), TestContext.Current.CancellationToken);
        Assert.Equal(code, session.Calls.Single(c => c.Function == "fail_core_job_v1").Args[3]);
        await executor.ExecuteAsync(CoreJobTests.Job(), TestContext.Current.CancellationToken);
        Assert.Equal(3, calls);
    }

    [Fact]
    public void Job_connections_have_no_elapsed_query_or_idle_transaction_limit()
    {
        var settings = CoreJobIdentity.Settings("light", "dispatcher", k => k == "SLI_JOB_DISPATCHER_LIGHT_PASSWORD" ? "synthetic" : null, _ => "synthetic");
        Assert.Equal(0, settings.CommandTimeout);
        Assert.Contains("statement_timeout=0", settings.Options);
        Assert.Contains("idle_in_transaction_session_timeout=0", settings.Options);
        Assert.Contains("lock_timeout=1000", settings.Options);
    }
    [Theory] [InlineData("sli.ad", "ad-context-snapshot")] [InlineData("sli.gpo", "gpo-snapshot")]
    public void Retained_handler_does_not_install_a_plugin_without_its_package_manifest(string plugin, string handler)
    {
        string root = Path.Combine(Path.GetTempPath(), "sli-job-package-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var identity = new JsonObject { ["plugin_id"] = plugin, ["handler_id"] = handler };
            var available = new CoreJobPluginCatalog();
            available.Add(plugin, handler, new((_, _, _) => throw new Exception("not dispatched"), (_, _, _, _) => Task.CompletedTask));
            Assert.True(available.Contains(identity));
            Assert.False(CoreJobWorker.Installed(identity, root, available));
            string manifests = Path.Combine(root, "config", "plugin_packages", "v3");
            Directory.CreateDirectory(manifests);
            using var manifest = typeof(CoreJobWorker).Assembly.GetManifestResourceStream("Sli.Installation.plugin_packages.v3." + plugin + ".json")!;
            using (var output = File.Create(Path.Combine(manifests, plugin + ".json"))) manifest.CopyTo(output);
            Assert.True(CoreJobWorker.Installed(identity, root, available));
        }
        finally { Directory.Delete(root, true); }
    }
    [Theory]
    [InlineData("sli.ad", "1", false, true, false)]
    [InlineData("sli.gpo", "1", false, true, false)]
    [InlineData("sli.ad", "1", true, false, false)]
    [InlineData("sli.gpo", "1", true, false, false)]
    [InlineData("sli.ad", "0", true, true, false)]
    [InlineData("sli.gpo", "1", true, true, true)]
    [InlineData("sli.ad", "1", true, true, true)]
    public void Ad_gpo_worker_requires_pilot_installed_executable_and_navigation(string plugin, string pilot, bool present, bool navigation, bool expected)
    {
        var identity = new JsonObject { ["plugin_id"] = plugin };
        Assert.Equal(expected, CoreJobWorker.Enabled(identity, _ => pilot, navigation ? new HashSet<string> { plugin } : new HashSet<string>(), _ => present));
        identity["handler_id"] = "unregistered-handler";
        Assert.False(CoreJobWorker.Enabled(identity, _ => "1"));
    }
    [Theory]
    [InlineData("success")]
    [InlineData("partial")]
    [InlineData("blocked")]
    [InlineData("cancelled")]
    public async Task Stage_and_publish_are_separate_and_publisher_deadline_is_below_lease(string status)
    {
        var session = new CoreJobTests.Session(true, true); var calls = new List<string>();
        var executor = new CoreJobExecutor(new(session), CoreJobTests.Registry(), (job, purpose, timeout, heartbeat, ct) =>
        {
            calls.Add(purpose);
            if (purpose == "publisher") { Assert.Null(heartbeat); Assert.True(timeout <= TimeSpan.FromSeconds(20)); Assert.Equal(status, job["staged_result"]!.Text("status")); }
            return Task.FromResult(new JsonObject { ["status"] = purpose == "handler" ? status : "committed" });
        });
        await executor.ExecuteAsync(CoreJobTests.Job(), TestContext.Current.CancellationToken);
        Assert.Equal(new[] { "handler", "publisher" }, calls);
        Assert.Equal(2, session.Calls.Count);
    }

    [Fact]
    public async Task Draining_projection_renews_the_publisher_lease_while_process_is_alive()
    {
        var session=new CoreJobTests.Session(true,true,true);var job=CoreJobTests.Job("workstations.overview-project");
        job["source_instance_id"]="workstations:projection";bool renewed=false;
        await new CoreJobExecutor(new(session),CoreJobTests.Registry(),async (request,purpose,timeout,beat,ct)=>
        {
            Assert.NotNull(beat);
            if(purpose=="publisher"){await beat();renewed=true;}
            return new JsonObject{["status"]=purpose=="handler"?"partial":"committed"};
        }).ExecuteAsync(job,TestContext.Current.CancellationToken);
        Assert.True(renewed);Assert.Equal(3,session.Calls.Count);
        Assert.All(session.Calls,c=>Assert.Equal("heartbeat_core_job_v1",c.Function));
    }

    [Theory]
    [InlineData("timeout", false, "job_deadline_exceeded")]
    [InlineData("crash", false, "job_execution_failed")]
    [InlineData("retryable_error", false, "job_execution_failed")]
    [InlineData("invalid", true, "job_execution_failed")]
    [InlineData("permanent_error", true, "job_execution_failed")]
    public async Task Failed_stage_retries_or_quarantines_and_never_calls_publisher(string failure, bool permanent, string code)
    {
        var session = new CoreJobTests.Session(true, true); int children = 0;
        var executor = new CoreJobExecutor(new(session), CoreJobTests.Registry(), (job, purpose, timeout, beat, ct) =>
        {
            children++;
            if (failure == "timeout") throw new TimeoutException();
            if (failure == "crash") throw new InvalidOperationException("synthetic-private");
            return Task.FromResult(new JsonObject { ["status"] = failure });
        });
        await executor.ExecuteAsync(CoreJobTests.Job(), TestContext.Current.CancellationToken);
        Assert.Equal(1, children); Assert.Equal("fail_core_job_v1", session.Calls.Last().Function);
        Assert.Equal(code, session.Calls.Last().Args[3]); Assert.Equal(permanent, session.Calls.Last().Args[4]);
    }

    [Theory]
    [InlineData("heartbeat")]
    [InlineData("handler")]
    [InlineData("publisher")]
    public async Task Lost_lease_stops_without_failure_or_publication_effects(string phase)
    {
        var session = phase == "heartbeat" ? new CoreJobTests.Session(false) : new CoreJobTests.Session(true, true);
        var purposes = new List<string>();
        var executor = new CoreJobExecutor(new(session), CoreJobTests.Registry(), (job, purpose, timeout, beat, ct) =>
        { purposes.Add(purpose); return Task.FromResult(new JsonObject { ["status"] = phase == purpose ? "lease_lost" : "success" }); });
        await executor.ExecuteAsync(CoreJobTests.Job(), TestContext.Current.CancellationToken);
        Assert.DoesNotContain(session.Calls, c => c.Function == "fail_core_job_v1");
        if (phase == "heartbeat") Assert.Empty(purposes);
        if (phase == "handler") Assert.Equal(new[] { "handler" }, purposes);
    }

    [Theory]
    [InlineData("light")]
    [InlineData("heavy")]
    [InlineData("long")]
    public void Identities_connect_directly_and_child_receives_only_its_secret_file(string profile)
    {
        var env = new Dictionary<string, string> { ["SLI_JOB_PG_HOST"] = "synthetic-host", [CoreJobIdentity.PasswordName(profile, "executor") + "_FILE"] = "synthetic-file", ["ADLOG_PG_DSN"] = "synthetic-admin", ["SLI_JOB_PUBLISHER_HEAVY_PASSWORD"] = "synthetic-other" };
        var settings = CoreJobIdentity.Settings(profile, "executor", k => env.GetValueOrDefault(k), p => " synthetic password ", true);
        Assert.Equal($"sli_job_executor_{profile}", settings.Username); Assert.False(settings.Pooling); Assert.False(settings.Multiplexing);
        Assert.Equal(" synthetic password ", settings.Password); Assert.Equal("sli", settings.Database); Assert.Equal(5432, settings.Port);
        var child = CoreJobIdentity.ChildEnvironment(new(profile, "handler", "sli.ad", "ad-context-snapshot"), k => env.GetValueOrDefault(k));
        Assert.Equal(2, child.Count); Assert.DoesNotContain("ADLOG_PG_DSN", child.Keys); Assert.DoesNotContain("SLI_JOB_PUBLISHER_HEAVY_PASSWORD", child.Keys);
        env[CoreJobIdentity.PasswordName(profile, "executor")] = "synthetic-inline";
        Assert.Throws<CoreJobContractException>(() => CoreJobIdentity.Settings(profile, "executor", k => env.GetValueOrDefault(k), _ => throw new Exception("must not read"), true));
        env.Clear(); Assert.Throws<CoreJobContractException>(() => CoreJobIdentity.ChildEnvironment(new(profile, "handler", "sli.ad", "ad-context-snapshot"), k => env.GetValueOrDefault(k)));
    }

    [Theory]
    [InlineData("light")]
    [InlineData("heavy")]
    [InlineData("long")]
    public async Task Empty_catalog_runs_once_without_credentials_or_database(string profile)
    {
        using var output = new StringWriter(); using var errors = new StringWriter();
        Assert.Equal(0, await CoreJobCommand.RunAsync(["--profile", profile, "--once"], new(), new StringReader(""), output, errors, TestContext.Current.CancellationToken));
        Assert.Equal("", errors.ToString()); Assert.Equal("", output.ToString());
    }

    [Fact] public async Task Invalid_command_fails_closed_without_credentials_and_diagnostics_hide_private_text()
    {
        using var output = new StringWriter(); using var errors = new StringWriter();
        Assert.NotEqual(0, await CoreJobCommand.RunAsync(["--profile", "invalid", "--once"], new(), new StringReader(""), output, errors, TestContext.Current.CancellationToken));
        Assert.Contains("executor_profile_invalid", errors.ToString());
        Assert.DoesNotContain("private", CoreJobCommand.Diagnostic(new InvalidOperationException("synthetic-private-password")).ToJsonString());
        Assert.DoesNotContain("private", CoreJobCommand.Diagnostic(new CoreJobContractException("synthetic-private-password")).ToJsonString());
        var pg = new Npgsql.PostgresException("synthetic-private-row", "ERROR", "ERROR", "23514");
        Assert.Equal("23514", CoreJobCommand.Diagnostic(pg).Text("sqlstate"));
        Assert.DoesNotContain("private", CoreJobCommand.Diagnostic(pg).ToJsonString());
        Assert.Null(CoreJobCommand.Diagnostic(new Npgsql.PostgresException("private", "ERROR", "ERROR", "23514\nprivate"))["sqlstate"]);
    }

    [Fact] public async Task Stop_before_dispatch_does_not_open_database_or_claim_new_work()
    {
        using var stopping = new CancellationTokenSource(); stopping.Cancel();
        var catalog = new CoreJobPluginCatalog();
        catalog.Add("sli.ad", "ad-context-snapshot", new((_, _, _) => throw new Exception("unused"), (_, _, _, _) => Task.CompletedTask));
        Assert.Equal(0, await new CoreJobWorker(catalog).RunAsync("heavy", false, stopping.Token));
    }

    [Fact] public void Profile_switches_disable_workers_without_explicit_activation()
    {
        string? Off(string key) => null;
        Assert.False(CoreJobWorker.Enabled(new JsonObject { ["plugin_id"] = "sli.ad" }, Off));
        Assert.False(CoreJobWorker.Enabled(new JsonObject { ["plugin_id"] = "sli.remote-access" }, Off));
        Assert.False(CoreJobWorker.Enabled(new JsonObject { ["plugin_id"] = "sli.workstations", ["handler_id"] = "workstations.evidence-retention" }, Off));
        Assert.False(CoreJobWorker.Enabled(new JsonObject { ["plugin_id"] = "sli.workstations", ["handler_id"] = "workstations.overview-project" }, Off));
        Assert.True(CoreJobWorker.Enabled(new JsonObject { ["plugin_id"] = "sli.workstations", ["handler_id"] = "workstations.overview-project" }, key=>key=="SLI_CORE_JOB_WORKSTATIONS_PROJECTION"?"1":null));
    }

    [Fact] public void Child_launch_uses_argument_list_its_own_identity_and_bounded_managed_heap()
    {
        var job = CoreJobTests.Job();
        var env = new Dictionary<string, string> { ["SLI_JOB_EXECUTOR_LIGHT_PASSWORD_FILE"] = "synthetic-executor", ["SLI_JOB_PUBLISHER_LIGHT_PASSWORD_FILE"] = "synthetic-publisher", ["ADLOG_PG_DSN"] = "synthetic-admin",
            ["ADLOG_COLLECTION_PRINCIPAL"] = @"EXAMPLE\owner", ["ADLOG_COLLECTION_PRINCIPAL_SID"] = "S-1-5-21-100000001-200000002-300000003-1001" };
        foreach (string purpose in new[] { "handler", "publisher" })
        {
            var start = CoreJobProcess.StartInfo(job, purpose, k => env.GetValueOrDefault(k), "dotnet", false);
            Assert.False(start.UseShellExecute); Assert.True(start.RedirectStandardOutput);
            Assert.Equal(new[] { typeof(CoreJobProcess).Assembly.Location, "core-job-executor", "--profile", "light", "--child", purpose }, start.ArgumentList);
            Assert.False(start.Environment.ContainsKey("ADLOG_PG_DSN"));
            Assert.Equal(purpose == "handler" ? "synthetic-executor" : "synthetic-publisher", start.Environment["SLI_JOB_" + (purpose == "handler" ? "EXECUTOR" : "PUBLISHER") + "_LIGHT_PASSWORD_FILE"]);
            Assert.Equal("8000000", start.Environment["DOTNET_GCHeapHardLimit"]);
            Assert.Single(start.Environment.Keys, k => k.EndsWith("PASSWORD_FILE", StringComparison.Ordinal));
        }
    }

    [Theory]
    [InlineData("radius-session-observation", "light")]
    [InlineData("ad-context-snapshot", "heavy")]
    [InlineData("gpo-snapshot", "long")]
    public async Task Each_profile_dispatches_pinned_handler_and_rejects_changed_budget(string handler, string profile)
    {
        var job = CoreJobTests.Job(handler); var session = new CoreJobTests.Session(true, true); var purposes = new List<string>();
        await new CoreJobExecutor(new(session), CoreJobTests.Registry(), (request, purpose, timeout, beat, ct) =>
        {
            purposes.Add(purpose); Assert.Equal(profile, request.Text("resource_profile")); Assert.Equal(handler, request.Text("handler_id"));
            if(purpose=="handler")Assert.NotNull(beat);else Assert.Null(beat);
            return Task.FromResult(new JsonObject { ["status"] = purpose == "handler" ? "success" : "committed" });
        }).ExecuteAsync(job, TestContext.Current.CancellationToken);
        Assert.Equal(new[] { "handler", "publisher" }, purposes);
        session = new CoreJobTests.Session(true); job["budget"]!["max_db_connections"] = 2;
        await new CoreJobExecutor(new(session), CoreJobTests.Registry(), (_, _, _, _, _) => throw new Exception("invalid job executed")).ExecuteAsync(job, TestContext.Current.CancellationToken);
        Assert.Equal("fail_core_job_v1", Assert.Single(session.Calls).Function); Assert.Equal(true, session.Calls[0].Args[4]);
    }

    [Theory]
    [InlineData("success")]
    [InlineData("timeout")]
    [InlineData("oversized")]
    [InlineData("invalid")]
    [InlineData("crash")]
    [InlineData("memory")]
    [InlineData("cpu")]
    public async Task Disposable_process_observes_liveness_output_memory_and_cleanup(string mode)
    {
        string payload = mode == "oversized" ? new string('x', 5000) : mode == "invalid" ? "[]" : "{\"status\":\"success\"}";
        string executable = OperatingSystem.IsWindows() ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe") : "/bin/sh";
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        const string readyDirectory = "SLI_TEST_JOB_READY_DIRECTORY";
        string script;
        if (OperatingSystem.IsWindows())
        {
            start.ArgumentList.Add("-NoProfile"); start.ArgumentList.Add("-NonInteractive"); start.ArgumentList.Add("-Command");
            script = "[void][Console]::In.ReadToEnd(); " + (mode switch
            {
                "timeout" => "[void][IO.Directory]::CreateDirectory((Join-Path $env:" + readyDirectory + " $PID)); [Threading.Thread]::Sleep(-1)",
                "memory" => "[Threading.Thread]::Sleep(-1)",
                "crash" => "exit 1",
                "cpu" => "for ($i=0; $i -lt 100000; $i++) { }; [Console]::Out.Write('" + payload + "')",
                _ => "[Console]::Out.Write('" + payload + "')"
            });
        }
        else
        {
            start.ArgumentList.Add("-c");
            script = "cat >/dev/null; " + (mode switch
            {
                "timeout" => "mkdir \"$" + readyDirectory + "/$$\" && exec sleep infinity",
                "memory" => "exec sleep infinity",
                "crash" => "exit 1",
                "cpu" => "i=0; while [ $i -lt 100000 ]; do i=$((i+1)); done; printf '%s' '" + payload + "'",
                _ => "printf '%s' '" + payload + "'"
            });
        }
        start.ArgumentList.Add(script);
        var budget = JsonNode.Parse("{\"max_result_bytes\":4096,\"memory_bytes\":268435456,\"cpu_seconds\":30}")!.AsObject();
        if (mode == "memory") budget["memory_bytes"] = 1L;
        if (mode == "cpu") budget["cpu_seconds"] = 0L;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        Task<JsonObject> Run() => CoreJobProcess.RunAsync(start, budget, Timeout.InfiniteTimeSpan, null, deadline.Token, new());
        if (mode == "timeout")
        {
            var ready = Directory.CreateTempSubdirectory("sli-job-ready-");
            start.Environment[readyDirectory] = ready.FullName;
            var execution = Run();
            try
            {
                // Arm the caller's deadline after the child has consumed stdin and signaled readiness.
                string? childDirectory;
                while ((childDirectory = Directory.EnumerateDirectories(ready.FullName).SingleOrDefault()) is null)
                {
                    if (execution.IsCompleted) await execution;
                    await Task.Delay(20, deadline.Token);
                }
                using var child = Process.GetProcessById(int.Parse(Path.GetFileName(childDirectory)));
                Assert.False(child.HasExited);
                deadline.CancelAfter(TimeSpan.FromMilliseconds(150));
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => execution);
                Assert.True(child.HasExited);
            }
            finally
            {
                deadline.Cancel();
                try { await execution; }
                catch (OperationCanceledException) when (deadline.IsCancellationRequested) { }
                finally { ready.Delete(recursive: true); }
            }
            return;
        }
        if (mode is "invalid" or "oversized") await Assert.ThrowsAsync<CoreJobContractException>(Run);
        else if (mode == "crash") Assert.Equal("job_child_exited", (await Assert.ThrowsAsync<CoreJobProcess.ExitFailure>(Run)).Message);
        else if (mode == "memory") Assert.Equal("job_child_memory_exceeded", (await Assert.ThrowsAsync<InvalidOperationException>(Run)).Message);
        else { var result = await Run(); Assert.Equal("success", result.Text("status")); Assert.True(result["resource_usage"]!["wall_seconds"]!.Number() > 0); }
    }
}
