using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

internal static class Program
{
    private static int Main(string[] args)
    {
        var payload = args[0];
        var evidence = args[1];
        var result = new JsonObject();
        AssemblyLoadContext.Default.Resolving += (context, name) =>
        {
            var path = Path.Combine(payload, name.Name + ".dll");
            return File.Exists(path) ? context.LoadFromAssemblyPath(path) : null;
        };
        int status = 0;
        try
        {
            Read(payload, result);
        }
        catch (Exception error)
        {
            result["exception_type"] = error.GetType().Name;
            result["hresult"] = unchecked((uint)error.HResult);
            status = 1;
        }
        File.WriteAllText(evidence + ".pending", result.ToJsonString());
        File.Move(evidence + ".pending", evidence);
        return status;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Read(string payload, JsonObject result)
    {
        using var identity = WindowsIdentity.GetCurrent();
        result["account_sid"] = identity.User?.Value;
        if (identity.User?.Value != "S-1-5-18")
            throw new InvalidOperationException("The diagnostic account did not match the agent service account.");

        var windows = AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.Combine(payload, "Sli.Agent.Windows.dll"));
        var privilegeType = windows.GetType("Sli.Agent.Windows.WindowsAuditApi+SecurityPrivilege", throwOnError: true)!;
        using var privilege = (IDisposable)Activator.CreateInstance(privilegeType, nonPublic: true)!;
        using (var reader = new EventLogReader(new EventLogQuery("Security", PathType.LogName, "*")))
        using (var entry = reader.ReadEvent(TimeSpan.FromSeconds(3)))
            result["security_record_read"] = entry is not null;
        if (result["security_record_read"]?.GetValue<bool>() != true)
            throw new InvalidOperationException("The Security read did not return a test-runner record.");

        var random = Guid.NewGuid().ToByteArray();
        var sid = new SecurityIdentifier($"S-1-5-21-{BitConverter.ToUInt32(random, 0)}-{BitConverter.ToUInt32(random, 4)}-{BitConverter.ToUInt32(random, 8)}-48261");
        string user = $"/user:{{{sid.Value}}}";
        var baseline = Inspect(sid);
        result["baseline"] = baseline.Evidence;
        if (!baseline.Absent)
            throw new InvalidOperationException("Explicitly absent File SACL required before any configuration change.");

        try
        {
            result["stage"] = "set_one_test_ace";
            var set = AuditPol("/set", "/type:File", user, "/success", "/access:FR");
            result["set_exit"] = set.Exit;
            if (set.Exit != 0)
                throw new InvalidOperationException("Auditpol did not accept the synthetic ACE.");

            result["stage"] = "read_one_test_ace";
            var present = Inspect(sid);
            result["present"] = present.Evidence;
            if (!present.Success || present.Count != 1 || !present.SingleTestAuditAce || present.ViewExit != 0 || present.ViewSaysAbsent)
                throw new InvalidOperationException("The present state did not contain exactly one synthetic audit ACE.");
        }
        finally
        {
            result["cleanup_stage"] = "remove_only_test_sid";
            try
            {
                result["remove_exit"] = AuditPol("/remove", "/type:File", user).Exit;
            }
            finally
            {
                var restored = Inspect(sid);
                result["state_after_single_remove"] = restored.Evidence;
                if (restored.Success && restored.Count == 0 && restored.ViewExit == 0)
                {
                    result["cleanup_stage"] = "clear_verified_zero_entry_file_policy";
                    result["clear_empty_exit"] = AuditPol("/clear", "/type:File").Exit;
                    restored = Inspect(sid);
                }
                result["restored"] = restored.Evidence;
                result["original_absence_restored"] = restored.Absent;
                if (!restored.Absent)
                    throw new InvalidOperationException("The hosted runner did not verify restoration to the original absent state.");
            }
        }
        result["stage"] = "verified_pair";
    }

    private sealed record State(bool Success, int Error, int? Count, bool SingleTestAuditAce, int ViewExit, bool ViewSaysAbsent)
    {
        public bool Absent => !Success && Error == 2 && Count is null && ViewExit == 0 && ViewSaysAbsent;
        public JsonObject Evidence => new()
        {
            ["api_return"] = Success, ["api_last_error"] = Error,
            ["ace_count"] = Count is int count ? JsonValue.Create(count) : null,
            ["single_test_audit_ace"] = SingleTestAuditAce, ["auditpol_exit"] = ViewExit,
            ["auditpol_explicitly_absent"] = ViewSaysAbsent
        };
    }

    private static State Inspect(SecurityIdentifier testSid)
    {
        bool success = AuditQueryGlobalSacl("File", out var acl);
        int lastError = Marshal.GetLastPInvokeError();
        int? count = null;
        bool singleTestAuditAce = false;
        try
        {
            if (success)
            {
                if (acl == IntPtr.Zero)
                    count = 0;
                else
                {
                    int length = unchecked((ushort)Marshal.ReadInt16(acl, 2));
                    var bytes = new byte[length];
                    Marshal.Copy(acl, bytes, 0, bytes.Length);
                    var parsed = new RawAcl(bytes, 0);
                    count = parsed.Count;
                    singleTestAuditAce = count == 1 && parsed[0] is QualifiedAce ace &&
                        ace.AceQualifier == AceQualifier.SystemAudit && ace.SecurityIdentifier.Equals(testSid);
                }
            }
        }
        finally
        {
            if (acl != IntPtr.Zero) LocalFree(acl);
        }
        var view = AuditPol("/type:File", "/view");
        bool absent = Regex.IsMatch(view.Text, @"\bthere is no global SACL for this resource type\b", RegexOptions.IgnoreCase);
        return new(success, lastError, count, singleTestAuditAce, view.Exit, absent);
    }

    private static (int Exit, string Text) AuditPol(params string[] args)
    {
        var command = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "auditpol.exe"))
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        command.ArgumentList.Add("/resourceSACL");
        foreach (string arg in args) command.ArgumentList.Add(arg);
        using var process = Process.Start(command)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(15000))
        {
            process.Kill();
            process.WaitForExit();
            throw new TimeoutException("Auditpol did not complete.");
        }
        return (process.ExitCode, stdout.GetAwaiter().GetResult() + "\n" + stderr.GetAwaiter().GetResult());
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditQueryGlobalSacl(string type, out IntPtr acl);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr value);
}
