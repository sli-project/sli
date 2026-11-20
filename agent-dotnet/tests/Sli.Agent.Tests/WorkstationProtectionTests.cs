using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Agent.Tests.Support;
using Xunit;

namespace Sli.Agent.Tests;

public sealed class WorkstationProtectionTests
{
    private sealed class EmptySource : IEventLogSource
    {
        public SourceBatch Read(string channel, ChannelProgress progress, int limit) => new([]);
    }

    private static JsonObject Available() => new()
    {
        ["state"] = "available",
        ["components"] = new JsonObject
        {
            ["antivirus_enabled"] = true, ["real_time_protection_enabled"] = false,
            ["behavior_monitor_enabled"] = true, ["ioav_protection_enabled"] = null,
            ["nis_enabled"] = true, ["tamper_protected"] = false,
        },
    };

    private static JsonNode Protection(Sample sample) => sample.Payload["context"]!["workstations"]!["protection_state"]!;

    [Theory]
    [InlineData(1, "{}")]
    [InlineData(0, "not-json")]
    [InlineData(0, "[]")]
    [InlineData(0, "{}")]
    [InlineData(0, "{\"antivirus_enabled\":\"false\"}")]
    [InlineData(0, "{\"antivirus_enabled\":true,\"antivirus_enabled\":false}")]
    public void NativeOutputFailureIsUnknownRatherThanHealthy(int exitCode, string output)
    {
        Assert.Equal(CanonicalJson.Serialize(ProtectionSnapshot.Unavailable()),
            CanonicalJson.Serialize(ProtectionSnapshot.FromDefenderOutput(exitCode, output)));
    }

    [Fact]
    public void NativeOutputRetainsFalseAndNullButRejectsExcessData()
    {
        var value = Available();
        Assert.Equal(CanonicalJson.Serialize(value),
            CanonicalJson.Serialize(ProtectionSnapshot.FromDefenderOutput(0, value["components"]!.ToJsonString())));
        value["components"]!["private_diagnostics"] = "not-allowed";
        Assert.Equal("unavailable", ProtectionSnapshot.FromDefenderOutput(0, value["components"]!.ToJsonString())["state"]!.GetValue<string>());
        Assert.Equal("unavailable", ProtectionSnapshot.FromDefenderOutput(0, new string(' ', 4097))["state"]!.GetValue<string>());
    }

    [Fact]
    public void IncludesValidatedSnapshotInDefenderPacketAndReusesItForSameInstant()
    {
        var calls = 0;
        var supplied = Available();
        var module = new WorkstationsModule(Helpers.HostId, WorkstationPolicy.Parse(new()), new EmptySource(),
            () => { calls++; return supplied; });
        var first = module.Collect(null, Helpers.Now, WorkstationPolicy.Channels[2]).Sample!;
        Assert.Equal(CanonicalJson.Serialize(Available()), CanonicalJson.Serialize(Protection(first)));
        supplied["components"]!["antivirus_enabled"] = false;
        Protection(first)["components"]!["nis_enabled"] = false;
        var second = module.Collect(null, Helpers.Now, WorkstationPolicy.Channels[2]).Sample!;
        Assert.Equal(CanonicalJson.Serialize(Available()), CanonicalJson.Serialize(Protection(second)));
        Assert.Equal(1, calls);
        var third = module.Collect(null, Helpers.Now.AddSeconds(1), WorkstationPolicy.Channels[2]).Sample!;
        Assert.False(Protection(third)["components"]!["antivirus_enabled"]!.GetValue<bool>());
        Assert.Equal(2, calls);
    }

    [Fact]
    public void OtherChannelsAndDisabledProtectionNeverReadSnapshot()
    {
        var calls = 0;
        var policy = WorkstationPolicy.Parse(new() { ["families"] = new JsonObject { ["protection"] = false } });
        var module = new WorkstationsModule(Helpers.HostId, policy, new EmptySource(), () => { calls++; return Available(); });
        var sample = module.Collect(null, Helpers.Now, "Security").Sample!;
        Assert.Null(sample.Payload["context"]!["workstations"]!["protection_state"]);
        Assert.Equal(0, calls);
    }

    [Theory]
    [InlineData("string_boolean")]
    [InlineData("unknown_key")]
    [InlineData("missing_component")]
    [InlineData("unavailable_true")]
    public void RejectsMalformedSnapshotWithoutAdvancingCursor(string change)
    {
        var value = Available();
        if (change == "string_boolean") value["components"]!["antivirus_enabled"] = "true";
        if (change == "unknown_key") value["secret"] = "must-not-escape";
        if (change == "missing_component") value["components"]!.AsObject().Remove("nis_enabled");
        if (change == "unavailable_true") value["state"] = "unavailable";
        var module = new WorkstationsModule(Helpers.HostId, WorkstationPolicy.Parse(new()), new EmptySource(), () => value);
        var error = Assert.Throws<AgentException>(() => module.Collect(null, Helpers.Now, WorkstationPolicy.Channels[2]));
        Assert.Equal("agent_workstations_protection_invalid", error.Code);
    }
}
