namespace Sli.Server.Jobs;

public sealed class WindowsPluginJobError(string code) : InvalidOperationException(code);

// Validation contract from sources/windows_plugin_job.py. This does not apply
// resource limits to the server or change the core job executor's configuration.
public sealed record WindowsPluginJobLimits(
    int ActiveProcesses,
    long ProcessMemoryBytes,
    bool KillOnJobClose,
    int? CpuHardLimit = null)
{
    public void Validate()
    {
        if (ActiveProcesses is < 1 or > 8)
            throw new WindowsPluginJobError("job_active_process_limit_invalid");
        if (ProcessMemoryBytes is < 16 * 1024 * 1024 or > 4L * 1024 * 1024 * 1024)
            throw new WindowsPluginJobError("job_process_memory_limit_invalid");
        if (!KillOnJobClose)
            throw new WindowsPluginJobError("job_kill_on_close_required");
        if (CpuHardLimit is < 1 or > 100)
            throw new WindowsPluginJobError("job_cpu_hard_limit_invalid");
    }
}
