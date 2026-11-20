using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Sli.Server.Auth.Lifecycle;
using Xunit;

namespace Sli.Server.Tests.Auth;

public sealed class AuthRequestPolicyTests
{
    [Theory]
    [InlineData("https://example.test", true)]
    [InlineData("https://example.test:443/", true)]
    [InlineData("http://example.test", false)]
    [InlineData("https://evil@example.test", false)]
    [InlineData("https://example.test/path", false)]
    [InlineData("null", false)]
    public void OriginChecksEffectiveCanonicalAuthority(string origin, bool expected)
    {
        var policy = new AuthRequestPolicy(new ConfigurationBuilder().Build());
        var context = new DefaultHttpContext();
        context.Request.Headers.Origin = origin;
        Assert.Equal(expected, policy.OriginAllowed(context, new("127.0.0.1", "https", "example.test")));
    }

    [Fact]
    public void ForwardingRequiresTrustedSocketPeerAndStopsAtFirstUntrustedHop()
    {
        var policy = new AuthRequestPolicy(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:TrustedProxies"] = "127.0.0.1/32" }).Build());
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.5");
        context.Request.Host = new HostString("internal.test");
        context.Request.Headers["X-Forwarded-Host"] = "external.test";
        context.Request.Headers["X-Forwarded-Proto"] = "https";
        context.Request.Headers["X-Forwarded-For"] = "203.0.113.6, 192.0.2.9";
        Assert.Equal(new("192.0.2.5", "http", "internal.test"), policy.Resolve(context));
        context.Connection.RemoteIpAddress = IPAddress.Loopback;
        Assert.Equal(new("192.0.2.9", "https", "external.test"), policy.Resolve(context));
        context.Request.Headers.Append("X-Forwarded-For", "invalid");
        Assert.Equal("127.0.0.1", policy.Resolve(context).Address);
    }

    [Theory]
    [InlineData("null", false)]
    [InlineData("false", false)]
    [InlineData("0", false)]
    [InlineData("[]", false)]
    [InlineData("{}", false)]
    [InlineData("\"\"", false)]
    [InlineData("\"false\"", true)]
    [InlineData("[0]", true)]
    [InlineData("{\"value\":0}", true)]
    public void RememberUsesPythonTruthiness(string json, bool expected)
    {
        using var doc = JsonDocument.Parse(json);
        Assert.Equal(expected, AuthJsonBody.Truthy(doc.RootElement));
    }

    [Theory]
    [InlineData("{\"password\":1.0}", "1.0")]
    [InlineData("{\"password\":true}", "True")]
    [InlineData("{\"password\":0}", "")]
    [InlineData("{\"password\":null}", "")]
    public void CredentialsRetainObservedPythonScalarCoercion(string json, string expected)
    {
        using var doc = JsonDocument.Parse(json);
        Assert.Equal(expected, AuthJsonBody.CredentialString(doc.RootElement, "password"));
    }
}
