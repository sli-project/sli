using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
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
            throw new InvalidOperationException("The probe must run under the service account.");

        var windows = AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.Combine(payload, "Sli.Agent.Windows.dll"));
        var privilegeType = windows.GetType("Sli.Agent.Windows.WindowsAuditApi+SecurityPrivilege", throwOnError: true)!;
        using var privilege = (IDisposable)Activator.CreateInstance(privilegeType, nonPublic: true)!;
        try
        {
            using var reader = new EventLogReader(new EventLogQuery("Security", PathType.LogName, "*"));
            using var entry = reader.ReadEvent(TimeSpan.FromSeconds(3));
            result["security_read"] = true;
            result["security_record_returned"] = entry is not null;
        }
        catch (Exception error)
        {
            result["security_read"] = false;
            result["security_error_type"] = error.GetType().Name;
            result["security_hresult"] = unchecked((uint)error.HResult);
        }

        bool queried = AuditQueryGlobalSacl("File", out var acl);
        int lastError = Marshal.GetLastPInvokeError();
        try
        {
            result["global_sacl_api_return"] = queried;
            result["global_sacl_api_last_error"] = lastError;
            result["global_sacl_api_ace_count"] = queried
                ? JsonValue.Create(acl == IntPtr.Zero ? 0 : unchecked((ushort)Marshal.ReadInt16(acl, 4))) : null;
        }
        finally
        {
            if (acl != IntPtr.Zero) LocalFree(acl);
        }

        var command = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "auditpol.exe"))
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        command.ArgumentList.Add("/resourceSACL");
        command.ArgumentList.Add("/type:File");
        command.ArgumentList.Add("/view");
        using var process = Process.Start(command)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(15000))
        {
            process.Kill();
            result["auditpol_status"] = "timeout";
            return;
        }
        result["auditpol_exit"] = process.ExitCode;
        var lines = (stdout.GetAwaiter().GetResult() + "\n" + stderr.GetAwaiter().GetResult())
            .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Trim()).Where(line => line.Length > 0).ToArray();
        const string safe = @"^(?:No(?:\s|$)|There (?:is|are) no\b|The (?:global|policy|file) |Global |Resource |File system |Error\b|The system |Audit(?:ing)? |SACL\b)";
        var generic = lines.Where(line => Regex.IsMatch(line, safe, RegexOptions.IgnoreCase)
            && Regex.IsMatch(line, @"^[A-Za-z][A-Za-z0-9 .,:'()-]{0,180}$")).Take(12).ToArray();
        result["auditpol_description"] = new JsonArray(generic.Select(line => (JsonNode?)JsonValue.Create(line)).ToArray());
        result["auditpol_nonempty_line_count"] = lines.Length;
        result["auditpol_non_generic_line_count"] = lines.Length - generic.Length;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditQueryGlobalSacl(string type, out IntPtr acl);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr value);
}
