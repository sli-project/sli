using Sli.Server.Jobs;
using Xunit;

namespace Sli.Server.Tests.Jobs;

public class WindowsPluginJobTests
{
    // Both rejection vectors from tests/sources/test_windows_plugin_job.py.
    [Fact]
    public void Unsupported_cpu_or_unsafe_limits_fail_closed()
    {
        Assert.Equal("job_cpu_hard_limit_invalid", Assert.Throws<WindowsPluginJobError>(
            () => new WindowsPluginJobLimits(1, 128 * 1024 * 1024, true, 101).Validate()).Message);
        Assert.Equal("job_kill_on_close_required", Assert.Throws<WindowsPluginJobError>(
            () => new WindowsPluginJobLimits(1, 128 * 1024 * 1024, false).Validate()).Message);
    }

    [Theory]
    [InlineData(1, 16L * 1024 * 1024, null)]
    [InlineData(8, 4L * 1024 * 1024 * 1024, 100)]
    [InlineData(1, 128L * 1024 * 1024, 1)]
    [InlineData(1, 128L * 1024 * 1024, 20)]
    public void Valid_limits_include_reference_fixture_and_boundaries(int processes, long memory, int? cpu)
        => new WindowsPluginJobLimits(processes, memory, true, cpu).Validate();

    [Theory]
    [InlineData(0, 128L * 1024 * 1024, 20, "job_active_process_limit_invalid")]
    [InlineData(9, 128L * 1024 * 1024, 20, "job_active_process_limit_invalid")]
    [InlineData(1, 16L * 1024 * 1024 - 1, 20, "job_process_memory_limit_invalid")]
    [InlineData(1, 4L * 1024 * 1024 * 1024 + 1, 20, "job_process_memory_limit_invalid")]
    [InlineData(1, 128L * 1024 * 1024, 0, "job_cpu_hard_limit_invalid")]
    [InlineData(1, 128L * 1024 * 1024, 101, "job_cpu_hard_limit_invalid")]
    public void Invalid_limits_preserve_reference_error_codes(int processes, long memory, int? cpu, string code)
        => Assert.Equal(code, Assert.Throws<WindowsPluginJobError>(
            () => new WindowsPluginJobLimits(processes, memory, true, cpu).Validate()).Message);

    [Fact]
    public void Validation_preserves_reference_error_precedence()
    {
        var limits = new WindowsPluginJobLimits(0, 0, false, 101);
        Assert.Equal("job_active_process_limit_invalid", Assert.Throws<WindowsPluginJobError>(limits.Validate).Message);
        limits = limits with { ActiveProcesses = 1 };
        Assert.Equal("job_process_memory_limit_invalid", Assert.Throws<WindowsPluginJobError>(limits.Validate).Message);
        limits = limits with { ProcessMemoryBytes = 128 * 1024 * 1024 };
        Assert.Equal("job_kill_on_close_required", Assert.Throws<WindowsPluginJobError>(limits.Validate).Message);
    }
}
