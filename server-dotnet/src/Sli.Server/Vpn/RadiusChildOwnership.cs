using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Sli.Server.Vpn;

// Own descendants as well as the child. No execution deadline or CPU limit.
internal static class RadiusChildOwnership
{
    internal static IDisposable? Attach(Process child)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var job = CreateJobObjectW(IntPtr.Zero, null);
        try {
            var limits = new ExtendedLimits { Basic = new BasicLimits { Flags = 0x2000 } }; // KILL_ON_JOB_CLOSE
            if (job.IsInvalid || !SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimits>()) || !AssignProcessToJobObject(job, child.Handle)) {
                if (!child.HasExited) child.Kill(entireProcessTree: true);
                throw new InvalidOperationException("plugin_child_ownership_failed");
            }
            return job;
        }
        catch { job.Dispose(); throw; }
    }
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimits { public long ProcessTime, JobTime; public uint Flags; public UIntPtr MinimumWorkingSet, MaximumWorkingSet; public uint ActiveProcesses; public UIntPtr Affinity; public uint Priority, Scheduling; }
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters { public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimits { public BasicLimits Basic; public IoCounters Io; public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory; }
    private sealed class JobHandle : SafeHandleZeroOrMinusOneIsInvalid { public JobHandle() : base(true) { } protected override bool ReleaseHandle() => CloseHandle(handle); }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern JobHandle CreateJobObjectW(IntPtr attributes, string? name);
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetInformationJobObject(JobHandle job, int kind, ref ExtendedLimits information, uint size);
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool AssignProcessToJobObject(JobHandle job, IntPtr process);
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr handle);
}
