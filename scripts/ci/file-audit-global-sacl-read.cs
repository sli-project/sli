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
        using var stdout = new MemoryStream();
        using var stderr = new MemoryStream();
        var readStdout = process.StandardOutput.BaseStream.CopyToAsync(stdout);
        var readStderr = process.StandardError.BaseStream.CopyToAsync(stderr);
        if (!process.WaitForExit(15000))
        {
            process.Kill();
            result["auditpol_status"] = "timeout";
            return;
        }
        result["auditpol_exit"] = process.ExitCode;
        Task.WhenAll(readStdout, readStderr).GetAwaiter().GetResult();
        result["auditpol_stdout_bytes"] = stdout.Length;
        var lines = (Decode(stdout.ToArray()) + "\n" + Decode(stderr.ToArray()))
            .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Trim().TrimStart('\ufeff')).Where(line => line.Length > 0).ToArray();
        result["auditpol_nonempty_line_count"] = lines.Length;
        var description = string.Join(" ", lines.Select(line => Regex.Replace(line, @"[\u0000-\u001f\u007f\u200e\u200f\ufeff]", " ").Trim()));
        result["auditpol_explicitly_absent"] = Regex.IsMatch(description,
            @"\b(?:no\b.{0,55}\b(?:SACLs?|audit(?:ing)? (?:entries|rules))\b|(?:SACLs?|audit(?:ing)? entries)\b.{0,50}\b(?:does not exist|not configured|not defined|not present|(?:is|are) empty))", RegexOptions.IgnoreCase)
            || Regex.IsMatch(description, @"\b(?:global|resource)\b.{0,90}\bno (?:entries|records|rules)\b", RegexOptions.IgnoreCase);
        result["auditpol_ace_rows_present"] = lines.Any(line => Regex.IsMatch(line,
            @"(?i)(?:\bS-\d+(?:-\d+)+\b|[\p{L}\p{N}_.@$-]+\\[\p{L}\p{N}_.@$-]+).{0,90}\b(?:success|failure)\b"));
        var safeWords = new HashSet<string>((
            "access audit auditing auditpol all any are as at be been configured control current defined descriptor does " +
            "empty entries entry error exist exists failure file files filesystem for found global has have is key list mask masks " +
            "no none not object of on or permissions present registry resource resources resourcesacl rules records sacl sacls security " +
            "set specified status success system the there this to type user view was were which with without").Split(' '),
            StringComparer.OrdinalIgnoreCase);
        var publicLines = lines.Take(2).Select(line =>
        {
            string text = Regex.Replace(line, @"[\u0000-\u001f\u007f\u200e\u200f\ufeff]", " ").Trim();
            text = Regex.Replace(text, @"(?i)\bS-\d+(?:-\d+)+\b", "[SID]");
            text = Regex.Replace(text, @"""[^""]*[\\/][^""]*""|(?:[A-Za-z]:[\\/]|\\\\)[^\s]+", "[path]");
            text = Regex.Replace(text, @"\{[^}]*\}|[\p{L}\p{N}_.@$-]+\\[\p{L}\p{N}_.@$-]+|[\p{L}\p{N}_.-]+@[\p{L}\p{N}_.-]+", "[account]");
            if (Regex.IsMatch(text, @"(?i)(?:^|\s)[DGS]:\s*\("))
                return (JsonNode?)JsonValue.Create("[descriptor omitted]");
            text = Regex.Replace(text, @"\[(?:SID|path|account)\]|[\p{L}\p{N}\p{M}_@/\\$-]+",
                word => word.Value.StartsWith('[') || safeWords.Contains(word.Value) ? word.Value : "[masked]");
            return JsonValue.Create(text[..Math.Min(text.Length, 180)]);
        }).ToArray();
        result["auditpol_description"] = new JsonArray(publicLines);
    }

    private static string Decode(byte[] data)
    {
        bool littleEndianBom = data.Length >= 2 && data[0] == 0xff && data[1] == 0xfe;
        int pairs = data.Length / 2;
        int oddZeros = Enumerable.Range(0, pairs).Count(i => data[i * 2 + 1] == 0);
        return (littleEndianBom || pairs > 2 && oddZeros > pairs / 2
            ? System.Text.Encoding.Unicode : System.Text.Encoding.UTF8).GetString(data);
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditQueryGlobalSacl(string type, out IntPtr acl);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr value);
}
