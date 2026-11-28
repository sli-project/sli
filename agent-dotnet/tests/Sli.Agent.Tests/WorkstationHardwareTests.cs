using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class WorkstationHardwareTests
{
    [Fact]
    public void BuildsBoundedInventoryFromHardwareObservationsWithStableIdentity()
    {
        var data = JsonNode.Parse("""
            {
              "computer":[{"manufacturer":" Example ","model":"Synthetic\u0000PC","serial":"TEST-001","ignored":"local user"}],
              "bios":[{"version":"1.15","date":"2026-01-01"}],
              "security":[{"secure_boot":false,"tpm_enabled":true,"tpm_version":"2.0"}],
              "processor":[{"id":"CPU0","model":"Example CPU","cores":8,"threads":16}],
              "memory":[{"size":34359738368}],
              "memory_module":[{"id":"A1","slot":"A1","size":17179869184,"speed":5600,"manufacturer":"Example"}],
              "disk":[{"id":"TEST-DISK-2","model":"Example SSD","size":1000000000000,"type":"SSD","interface":"NVMe"},
                      {"id":"TEST-DISK-1","model":"Example SSD","type":"SSD"}],
              "volume":[{"id":"synthetic-volume","disk_id":"test-disk-2","mount":"C:","bitlocker":"on","system":true}],
              "video":[{"id":"synthetic-pci","model":"Example GPU"}],
              "network":[{"id":"02:00:00:00:00:01","name":"Example Ethernet","mac":"02:00:00:00:00:01","speed":1000000000}],
              "monitor":[{"id":"synthetic-display","model":"Example panel","serial":null}]
            }
            """)!.AsObject();
        var snapshot = WorkstationHardware.Build(data)!;
        Assert.True(WorkstationHardware.IsValid(snapshot));
        Assert.Equal("SyntheticPC", snapshot["computer"]![0]!["model"]!.GetValue<string>());
        Assert.False(snapshot["computer"]![0]!.AsObject().ContainsKey("ignored"));
        Assert.False(snapshot["security"]![0]!["secure_boot"]!.GetValue<bool>());
        Assert.Null(snapshot["monitor"]![0]!["serial"]);
        var disks = snapshot["disk"]!.AsArray();
        Assert.Equal(2, disks.Count);
        var systemDisk = Assert.Single(disks, disk => disk!["size"] is not null);
        Assert.Equal(systemDisk!["id"]!.ToString(), snapshot["volume"]![0]!["disk_id"]!.ToString());
        var first = data["disk"]![0]!.DeepClone();
        data["disk"]!.AsArray().RemoveAt(0);
        data["disk"]!.AsArray().Add(first);
        Assert.Equal(Packets.Digest(snapshot), Packets.Digest(WorkstationHardware.Build(data)!));
        data["monitor"]![0]!["model"] = new string('x', 400);
        Assert.Equal(128, WorkstationHardware.Build(data)!["monitor"]![0]!["model"]!.ToString().Length);
    }

    [Fact]
    public void OnlyAcknowledgedDigestSuppressesSendingAcrossQueueRestart()
    {
        var path = Helpers.TempDirectory();
        try
        {
            using var key = Helpers.NewKey();
            var snapshot = WorkstationHardware.Build(JsonNode.Parse("""{"computer":[{"model":"Example PC"}]}""")!.AsObject())!;
            var policy = WorkstationPolicy.Parse(new());
            using (var queue = Helpers.Queue(path))
            {
                var sample = WorkstationHardware.Collect(snapshot, null, Helpers.HostId, policy, null, Helpers.Now)!;
                Assert.Equal(sample.CursorBefore, sample.CursorAfter);
                var expired = queue.Capture(Helpers.Signer(key), Helpers.AgentId, sample, Helpers.Now);
                Assert.True(queue.Acknowledge(expired, Helpers.ExpiredReceipt(expired)));
                Assert.Null(queue.WorkstationHardwareDigest());
                var retry = queue.Capture(Helpers.Signer(key), Helpers.AgentId, sample, Helpers.Now);
                Assert.True(queue.Acknowledge(retry, Helpers.Receipt(retry, "duplicate")));
            }
            using var reopened = Helpers.Queue(path);
            var position = reopened.Captured(WorkstationsModule.ModuleId);
            Assert.Null(WorkstationHardware.Collect(snapshot, reopened.WorkstationHardwareDigest(), Helpers.HostId, policy, position, Helpers.Now.AddDays(1)));
            snapshot["computer"]![0]!["model"] = "Replacement PC";
            Assert.NotNull(WorkstationHardware.Collect(snapshot, reopened.WorkstationHardwareDigest(), Helpers.HostId, policy, position, Helpers.Now.AddDays(1)));
        }
        finally { Directory.Delete(path, true); }
    }
}
