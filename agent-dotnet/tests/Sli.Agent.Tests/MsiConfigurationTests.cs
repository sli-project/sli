using System.Runtime.Versioning;
using Sli.Agent.Core;
using Sli.Agent.Windows;
using Xunit;

namespace Sli.Agent.Tests;

[SupportedOSPlatform("windows")]
public sealed class MsiConfigurationTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("a")]
    [InlineData("0")]
    [InlineData("dc_1-test")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public void ValidInstanceName(string? value) =>
        Assert.Equal(string.IsNullOrEmpty(value) ? null : value, MsiConfiguration.ValidateInstanceName(value));

    [Theory]
    [InlineData("DC")]
    [InlineData("_dc")]
    [InlineData("-dc")]
    [InlineData("dc ")]
    [InlineData("dc\n")]
    [InlineData("a/b")]
    [InlineData("a\\b")]
    [InlineData("é")]
    [InlineData("а")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public void InvalidInstanceName(string value) =>
        Assert.Equal("invalid_agent_instance_name", Assert.Throws<AgentException>(() => MsiConfiguration.ValidateInstanceName(value)).Code);
}
