using Sli.Server.Workstations;
using Xunit;

namespace Sli.Server.Tests.Workstations;

public sealed class WorkstationActivityTests
{
    private static readonly DateTimeOffset Start = new(2026, 10, 1, 12, 0, 0, TimeSpan.Zero);
    private const string Security = "Security";
    private const string Audit = "Microsoft-Windows-Security-Auditing";
    private const string Usb = @"USBSTOR\Disk&Ven_Example\Unit1";

    private static StationObservation Event(int code, int minute = 0, long id = 1) =>
        new(id, null, code, Security, Audit, Start.AddMinutes(minute), Start.AddMinutes(minute), 1);

    private static WorkstationActivity Read(params StationObservation[] rows) =>
        WorkstationActivity.Rank(rows, Start, Start.AddHours(1), "WS-EXAMPLE.example.test");

    [Theory]
    [InlineData(@"C:\Users\example\Downloads\example.exe", true)]
    [InlineData(@"D:\Users\example\Desktop\example.exe", true)]
    [InlineData(@"C:\Users\example\AppData\Local\example.exe", true)]
    [InlineData(@"C:\Windows\Temp\example.exe", true)]
    [InlineData(@"C:\Temp\example.exe", true)]
    [InlineData(@"C:\Program Files\Desktop\example.exe", false)]
    [InlineData(@"C:\Users\example\Downloads\..\Documents\example.exe", false)]
    public void Writable_program_paths_are_classified_by_directory(string path, bool writable)
    {
        var report = Read(Event(4688) with { Path = path });
        Assert.Equal(writable, Assert.Single(report.Programs).Writable);
        Assert.Equal(writable ? "high" : null, report.Importance(1, null));
    }

    [Theory]
    [InlineData(@"C:\Tools\service.exe -start", "high")]
    [InlineData("\"D:\\Program Files (x86)\\Example\\service.exe\" --start", "low")]
    [InlineData(@"C:\Windows\System32\service.exe", "low")]
    [InlineData(@"%SystemRoot%\System32\service.exe", "low")]
    [InlineData(@"C:\Windows\..\Tools\service.exe", "high")]
    [InlineData(@"C:\WindowsApps\service.exe", "high")]
    [InlineData(null, null)]
    public void Service_install_uses_the_binary_and_its_normalized_location(string? path, string? severity)
    {
        var report = Read(Event(7045) with { Channel = "System", Provider = "Service Control Manager", Path = path, Name = "Example service" });
        Assert.Equal(severity, report.Importance(1, null));
        if (severity is not null) Assert.Equal("Example service", Assert.Single(report.Notable).Object);
    }

    [Theory]
    [InlineData(4732, Audit, "S-1-5-32-544", null, "local_admin_added", "high")]
    [InlineData(4732, Audit, "S-1-5-32-545", null, null, null)]
    [InlineData(4719, Audit, null, null, "audit_policy_changed", "high")]
    [InlineData(1102, "Microsoft-Windows-Eventlog", null, null, "security_log_cleared", "high")]
    [InlineData(1102, Audit, null, null, null, null)]
    [InlineData(4720, Audit, null, "WS-EXAMPLE", "local_account_created", "low")]
    [InlineData(4720, Audit, null, "EXAMPLE", null, null)]
    public void Account_and_audit_facts_require_the_native_provider_and_expected_target(int code, string provider,
        string? group, string? domain, string? fact, string? severity)
    {
        var report = Read(Event(code) with { Provider = provider, GroupSid = group, TargetDomain = domain, Account = @"WS-EXAMPLE\example" });
        Assert.Equal(fact, report.Notable.SingleOrDefault()?.Fact);
        Assert.Equal(severity, report.Importance(1, null));
    }

    [Fact]
    public void Ranks_and_collapses_writable_launches_and_uses_a_seven_day_program_baseline()
    {
        const string known = @"C:\Tools\known.exe";
        const string novel = @"C:\Tools\novel.exe";
        const string writable = @"C:\Temp\example.exe";
        var report = Read(Event(4688, -7 * 1440, 2) with { Path = known },
            Event(4688, -60, 3) with { Path = known }, Event(4688, 1, 4) with { Path = known },
            Event(4688, 2, 5) with { Path = writable }, Event(4688, 3, 6) with { Path = writable },
            Event(4688, 4, 7) with { Path = novel }, Event(4688, 5, 8) with { Path = novel });

        Assert.Collection(report.Notable,
            row => { Assert.Equal("writable_program", row.Fact); Assert.Equal(2, row.Count); },
            row => { Assert.Equal("new_program", row.Fact); Assert.Equal(Start.AddMinutes(4), row.First); });
        Assert.Null(report.Importance(4, null));
        Assert.Equal("medium", report.Importance(7, null));
        Assert.Null(report.Importance(8, null));
        Assert.Empty(Read(Event(4688, -6 * 1440, 9) with { Path = known }, Event(4688, 0) with { Path = novel }).Notable);
    }

    [Fact]
    public void Programs_group_case_insensitively_and_keep_users_and_launch_times()
    {
        var report = Read(Event(4688, 1, 2) with { Path = @"C:\Tools\editor.exe", Account = "alex" },
            Event(4688, 3, 3) with { Path = @"c:\tools\EDITOR.exe", Account = "ALEX" },
            Event(4688, 4, 4) with { Path = @"C:\Tools\editor.exe", Account = "sam" },
            Event(4688, 2, 5) with { Path = @"C:\Temp\example.exe" });

        Assert.True(report.Programs[0].Writable);
        var editor = report.Programs[1];
        Assert.Equal("editor.exe", editor.Name);
        Assert.Equal(Start.AddMinutes(1), editor.First);
        Assert.Equal(Start.AddMinutes(4), editor.Last);
        Assert.Equal(3, editor.Count);
        Assert.Equal(["alex", "sam"], editor.Users);
    }

    [Fact]
    public void Logons_group_by_account_and_type_and_rank_a_successful_remote_logon()
    {
        var report = Read(Event(4624, 1, 2) with { Account = "alex", LogonType = "10" },
            Event(4625, 2, 3) with { Account = "ALEX", LogonType = "10" },
            Event(4624, 3, 4) with { Account = "alex", LogonType = "2" },
            Event(4624, 4, 5) with { Account = "alex", LogonType = "3" });

        Assert.Equal(2, report.Logons.Length);
        var remote = Assert.Single(report.Logons, row => row.Type == "10");
        Assert.Equal(2, remote.Count);
        Assert.Equal(1, remote.Failures);
        Assert.Equal(Start.AddMinutes(2), remote.Last);
        Assert.Equal("remote_logon", Assert.Single(report.Notable).Fact);
        Assert.Null(report.Importance(3, null));
    }

    [Fact]
    public void Failure_burst_uses_a_rolling_ten_minutes_for_the_same_account()
    {
        var failures = Enumerable.Range(0, 10).Select(i => Event(4625, 6 + i, i + 1) with { Account = "alex" }).ToArray();
        Assert.Empty(Read(failures[..9]).Notable);
        Assert.Empty(Read([..failures[..9], failures[9] with { Account = "sam" }]).Notable);
        var report = Read([..failures, Event(4625, 26, 11) with { Account = "alex" }]);
        var burst = Assert.Single(report.Notable);
        Assert.Equal("logon_failure_burst", burst.Fact);
        Assert.Equal(10, burst.Count);
        Assert.Equal(Start.AddMinutes(6), burst.First);
        Assert.Equal(Start.AddMinutes(15), burst.Last);
        Assert.Equal("medium", report.Importance(1, null));
        Assert.Null(report.Importance(11, null));
    }

    [Fact]
    public void Devices_group_by_device_identity_and_rank_only_the_first_recognition_of_usb_storage()
    {
        var first = Event(6416, 1, 2) with { DeviceId = Usb, DeviceClass = "DiskDrive", Name = "Example USB drive" };
        var mouse = Event(6416, 2, 3) with { DeviceId = @"USB\VID_0000&PID_0000", DeviceClass = "Mouse", Name = "Example mouse" };
        var again = first with { Id = 4, First = Start.AddMinutes(3), Last = Start.AddMinutes(3), DeviceId = Usb.ToLowerInvariant() };
        var report = Read(first, mouse, again);
        Assert.Equal(2, report.Devices.Length);
        var storage = Assert.Single(report.Devices, row => row.Class == "DiskDrive");
        Assert.Equal("Example USB drive", storage.Name);
        Assert.Equal(Start.AddMinutes(1), storage.First);
        Assert.Equal(Start.AddMinutes(3), storage.Last);
        Assert.Equal("new_usb_storage", Assert.Single(report.Notable).Fact);
        Assert.Null(report.Importance(4, null));
        Assert.Empty(Read(first with { Id = 5, First = Start.AddDays(-10), Last = Start.AddDays(-10) }, first, mouse, again).Notable);
    }
}
