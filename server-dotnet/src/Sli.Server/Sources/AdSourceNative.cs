using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Sli.Server.Sources;

internal static class AdSourceNative
{
    internal static string CommandLine(IReadOnlyList<string> command)
    {
        if (command.Count == 0 || command.Any(s => s is null || s.Contains('\0'))
            || !Path.IsPathFullyQualified(command[0])
            || !Path.GetFileName(command[0]).Equals("powershell.exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("ad_source_process_command_invalid");
        // Match subprocess.list2cmdline: Windows CRT quoting, including trailing
        // backslashes and embedded quotes. Never concatenate a shell script.
        string line = string.Join(" ", command.Select(Quote));
        if (line.Length >= 1024) throw new InvalidOperationException("ad_source_process_command_too_long");
        return line;
    }

    private static string Quote(string value)
    {
        bool quoted = value.Length == 0 || value.Contains(' ') || value.Contains('\t');
        var text = new StringBuilder(); if (quoted) text.Append('"');
        int slashes = 0;
        foreach (char ch in value) {
            if (ch == '\\') { slashes++; continue; }
            text.Append('\\', ch == '"' ? slashes * 2 + 1 : slashes); slashes = 0;
            text.Append(ch);
        }
        text.Append('\\', quoted ? slashes * 2 : slashes);
        if (quoted) text.Append('"');
        return text.ToString();
    }

    internal static Task<AdSourceProcessResult> RunAsync(IReadOnlyList<string> command, AdSourceLogin credentials,
        string cwd, CancellationToken ct, Func<Task>? heartbeat)
        => RunAsync(command, credentials, cwd, ct, heartbeat, null);

    internal static async Task<AdSourceProcessResult> RunAsync(IReadOnlyList<string> command, AdSourceLogin credentials,
        string cwd, CancellationToken ct, Func<Task>? heartbeat, Action? beforeAssign)
    {
        string line = CommandLine(command);
        if (!OperatingSystem.IsWindows()) throw new InvalidOperationException("ad_source_process_command_invalid");
        ct.ThrowIfCancellationRequested();
        using var child = new NativeChild();
        child.Start(command[0], line, credentials, cwd, AdSourceProcess.SourceEnvironment(Environment.GetEnvironmentVariable), beforeAssign);
        using var stdout = new MemoryStream(); using var stderr = new MemoryStream();
        var watch = Stopwatch.StartNew(); TimeSpan nextHeartbeat = TimeSpan.Zero;
        while (true) {
            ct.ThrowIfCancellationRequested();
            bool exited = child.Exited;
            if (exited) child.KillDescendants();
            bool pending = child.Drain(stdout, stderr);
            if (exited && !pending)
                return new(command.ToArray(), child.ExitCode, Encoding.UTF8.GetString(stdout.ToArray()), Encoding.UTF8.GetString(stderr.ToArray()));
            if (heartbeat is not null && watch.Elapsed >= nextHeartbeat) {
                await heartbeat(); nextHeartbeat = watch.Elapsed + TimeSpan.FromSeconds(10);
            }
            await Task.Delay(20, ct);
        }
    }

    // The child is suspended until assignment to a kill-on-close job succeeds.
    // This also contains descendants inheriting the output pipe handles.
    private sealed class NativeChild : IDisposable
    {
        private SafeFileHandle? job, process, thread, output, error;
        private bool assigned;
        internal bool Exited {
            get {
                uint status = WaitForSingleObject(process!, 0);
                if (status == uint.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error());
                return status == 0;
            }
        }
        internal int ExitCode { get { Check(GetExitCodeProcess(process!, out uint code)); return unchecked((int)code); } }

        internal void Start(string executable, string line, AdSourceLogin credentials, string cwd, Dictionary<string, string> environment, Action? beforeAssign)
        {
            using var input = Pipe(out var inputWriter); using var unusedWriter = inputWriter;
            output = Pipe(out var outputWriter); using var outWriter = outputWriter;
            error = Pipe(out var errorWriter); using var errWriter = errorWriter;
            // Parent readers must not be inherited; the stdin reader must be.
            Check(SetHandleInformation(input, 1, 1));
            inputWriter.Dispose();
            job = CreateJobObjectW(0, null); Check(!job.IsInvalid);
            var limits = new JobLimits { Basic = new BasicLimits { Flags = 0x2000 } }; // KILL_ON_JOB_CLOSE
            Check(SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<JobLimits>()));
            var startup = new Startup { Size = (uint)Marshal.SizeOf<Startup>(), Flags = 0x101,
                Input = input.DangerousGetHandle(), Output = outWriter.DangerousGetHandle(), Error = errWriter.DangerousGetHandle() };
            nint password = Marshal.StringToHGlobalUni(credentials.Password);
            nint block = Marshal.StringToHGlobalUni(string.Join('\0', environment.OrderBy(p => p.Key, StringComparer.OrdinalIgnoreCase)
                .Select(p => p.Key + "=" + p.Value)) + "\0\0");
            try {
                string user = credentials.Username; string? domain = null;
                int slash = user.IndexOf('\\');
                if (slash >= 0) { domain = user[..slash]; user = user[(slash + 1)..]; }
                bool created = CreateProcessWithLogonW(user, domain, password, 2, executable, new StringBuilder(line),
                    0x4 | 0x400 | 0x08000000, block, cwd, ref startup, out var info);
                int failure = Marshal.GetLastWin32Error();
                if (info.Process != 0) process = new(info.Process, true);
                if (info.Thread != 0) thread = new(info.Thread, true);
                if (!created) throw new Win32Exception(failure);
                beforeAssign?.Invoke();
                Check(AssignProcessToJobObject(job, process!)); assigned = true;
                if (ResumeThread(thread!) == uint.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally { Marshal.ZeroFreeGlobalAllocUnicode(password); Marshal.FreeHGlobal(block); }
        }

        internal void KillDescendants() => Check(TerminateJobObject(job!, 1));
        internal bool Drain(MemoryStream stdout, MemoryStream stderr) => DrainPipe(output!, stdout) | DrainPipe(error!, stderr);
        private static bool DrainPipe(SafeFileHandle pipe, MemoryStream target)
        {
            if (!PeekNamedPipe(pipe, 0, 0, 0, out uint available, 0)) {
                int code = Marshal.GetLastWin32Error(); if (code == 109) return false;
                throw new Win32Exception(code);
            }
            if (available == 0) return false;
            byte[] buffer = new byte[Math.Min(available, 65536)];
            Check(ReadFile(pipe, buffer, (uint)buffer.Length, out uint read, 0));
            // A hostile source cannot grow the server's capture buffer forever.
            if (target.Length + read > 1024 * 1024) throw new InvalidOperationException("ad_source_process_output_limit");
            target.Write(buffer, 0, (int)read); return true;
        }

        public void Dispose()
        {
            try {
                if (process is { IsInvalid: false }) {
                    if (assigned) TerminateJobObject(job!, 1);
                    else if (!Exited) TerminateProcess(process, 1);
                    job?.Dispose(); // Kill-on-close, even if explicit termination failed.
                    WaitForSingleObject(process, uint.MaxValue);
                }
            }
            finally { job?.Dispose(); thread?.Dispose(); process?.Dispose(); output?.Dispose(); error?.Dispose(); }
        }
    }

    private static SafeFileHandle Pipe(out SafeFileHandle writer)
    {
        var attributes = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Inherit = 1 };
        Check(CreatePipe(out var reader, out writer, ref attributes, 0));
        try { Check(SetHandleInformation(reader, 1, 0)); return reader; }
        catch { reader.Dispose(); writer.Dispose(); throw; }
    }
    private static void Check(bool success) { if (!success) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes { public int Length; public nint Descriptor; public int Inherit; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct Startup {
        public uint Size; public nint Reserved, Desktop, Title;
        public uint X, Y, XSize, YSize, XCount, YCount, Fill, Flags;
        public ushort Show, ReservedSize; public nint ReservedBytes, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInfo { public nint Process, Thread; public uint ProcessId, ThreadId; }
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimits {
        public long ProcessTime, JobTime; public uint Flags; public nuint MinWorkingSet, MaxWorkingSet;
        public uint ActiveProcessLimit; public nuint Affinity; public uint Priority, Scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] private struct JobLimits {
        public BasicLimits Basic; public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes;
        public nuint ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessWithLogonW(string user, string? domain, nint password, uint logonFlags,
        string application, StringBuilder command, uint flags, nint environment, string cwd, ref Startup startup, out ProcessInfo info);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CreatePipe(out SafeFileHandle read, out SafeFileHandle write, ref SecurityAttributes attributes, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetHandleInformation(SafeFileHandle handle, uint mask, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateJobObjectW(nint attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetInformationJobObject(SafeFileHandle job, int kind, ref JobLimits limits, uint length);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AssignProcessToJobObject(SafeFileHandle job, SafeFileHandle process);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(SafeFileHandle thread);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(SafeFileHandle handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(SafeFileHandle process, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateJobObject(SafeFileHandle job, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(SafeFileHandle process, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool PeekNamedPipe(SafeFileHandle pipe, nint buffer, uint length, nint read, out uint available, nint remaining);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool ReadFile(SafeFileHandle file, byte[] buffer, uint length, out uint read, nint overlapped);
}
