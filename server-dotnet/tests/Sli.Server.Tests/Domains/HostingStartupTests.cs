using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Sli.Server.Hosting;
using Xunit;

namespace Sli.Server.Tests.Domains;

public sealed class HostingStartupTests
{
    [Theory]
    [InlineData("--Sli:AgentMtlsCaFile","server_configuration_invalid:Sli:AgentMtlsCaFile:invalid")]
    [InlineData("--Sli:HttpMaxConnections","server_configuration_invalid:Sli:HttpMaxConnections:invalid")]
    [InlineData("--Sli:HttpMaxConcurrentRequests","server_configuration_invalid:Sli:HttpMaxConcurrentRequests:invalid")]
    [InlineData("--contentRoot","server_startup_failed")]
    [InlineData("--Kestrel:Certificates:Default:Path","server_startup_failed")]
    public async Task Startup_errors_print_only_safe_code_and_identify_the_failed_setting(string setting,string expected)
    {
        var start=new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") is { Length: > 0 } host ? host : "dotnet") {
            UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true,CreateNoWindow=true };
        SafeTestEnvironment.Apply(start);
        start.ArgumentList.Add(typeof(Program).Assembly.Location);
        start.ArgumentList.Add(setting);
        start.ArgumentList.Add("synthetic-private-invalid-value");
        if(setting.StartsWith("--Kestrel",StringComparison.Ordinal))
        { start.ArgumentList.Add("--urls"); start.ArgumentList.Add("https://127.0.0.1:0"); }
        using var process=Process.Start(start)!;
        var stdout=process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        var stderr=process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken); deadline.CancelAfter(TimeSpan.FromSeconds(15));
        try { await process.WaitForExitAsync(deadline.Token); }
        finally { if(!process.HasExited) { process.Kill(entireProcessTree:true); await process.WaitForExitAsync(TestContext.Current.CancellationToken); } }
        Assert.NotEqual(0,process.ExitCode); Assert.Equal(expected,(await stderr).Trim());
        string output=await stdout+await stderr;
        Assert.DoesNotContain("synthetic-private-invalid-value",output); Assert.DoesNotContain("   at ",output); Assert.DoesNotContain("Now listening on:",output);
    }
    [Theory]
    [InlineData("http://127.0.0.1:0", "", true)]
    [InlineData("http://[::1]:0", "", true)]
    [InlineData("https://0.0.0.0:8443", "", true)]
    [InlineData("http://0.0.0.0:8080", "127.0.0.1", true)]
    [InlineData("http://0.0.0.0:8080", "", false)]
    public void BindSecurityUsesDeclaredEndpointAndProxyPolicy(string url, string proxy, bool allowed)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        { ["urls"] = url, ["Sli:TrustedProxies"] = proxy }).Build();
        if (allowed) IngressHosting.ValidateBindSecurity(config);
        else Assert.Equal("server_configuration_invalid:Kestrel:Endpoints:tls_or_trusted_proxies_required",
            Assert.Throws<ServerConfigurationException>(() => IngressHosting.ValidateBindSecurity(config)).Message);
    }

    [Fact]
    public void PreferredHostingUrlsCannotBypassBindSecurity()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["Kestrel:Endpoints:Local:Url"] = "http://127.0.0.1:0", ["urls"] = "http://0.0.0.0:8080", ["preferHostingUrls"] = "true" }).Build();
        Assert.Equal("server_configuration_invalid:Kestrel:Endpoints:tls_or_trusted_proxies_required",
            Assert.Throws<ServerConfigurationException>(() => IngressHosting.ValidateBindSecurity(config)).Message);
    }
    [Theory]
    [InlineData("invalid", "1", "")]
    [InlineData("0", "0", "")]
    [InlineData("1", "0", "not-a-cidr")]
    public void InvalidAuthOrProxyConfigurationFailsBeforeStartup(string required, string allow, string proxy)
    {
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            { ["Sli:AuthRequired"] = required, ["Sli:AllowUnauthenticated"] = allow, ["Sli:TrustedProxies"] = proxy })));
        Assert.ThrowsAny<Exception>(() => factory.CreateClient());
    }

    [Theory]
    [InlineData("invalid", "1", "", false)]
    [InlineData("0", "0", "", false)]
    [InlineData("1", "0", "not-a-cidr", false)]
    [InlineData("1", "0", "", true)]
    public async Task InvalidSettingsExitWithoutOpeningKestrel(string required, string allow, string proxy, bool external)
    {
        using var reservation = new TcpListener(IPAddress.Loopback, 0);
        reservation.Start();
        int port = ((IPEndPoint)reservation.LocalEndpoint).Port;
        reservation.Stop();
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") is { Length: > 0 } host ? host : "dotnet")
        { UseShellExecute = false, RedirectStandardError = true, RedirectStandardOutput = true, CreateNoWindow = true };
        SafeTestEnvironment.Apply(start);
        foreach (string arg in new[] { typeof(Program).Assembly.Location, "--urls", $"http://{(external ? "0.0.0.0" : "127.0.0.1")}:{port}",
            "--Sli:AuthRequired", required, "--Sli:AllowUnauthenticated", allow, "--Sli:TrustedProxies", proxy }) start.ArgumentList.Add(arg);
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        var error = process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(15));
        bool listened = false;
        try
        {
            while (!process.HasExited)
            {
                using var socket = new TcpClient();
                using var connectDeadline = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
                connectDeadline.CancelAfter(TimeSpan.FromMilliseconds(100));
                try { await socket.ConnectAsync(IPAddress.Loopback, port, connectDeadline.Token); listened = true; }
                catch (SocketException) { }
                catch (OperationCanceledException) when (!deadline.IsCancellationRequested) { }
                await Task.Delay(25, deadline.Token);
            }
            await process.WaitForExitAsync(deadline.Token);
            Assert.NotEqual(0, process.ExitCode);
            Assert.False(listened);
            Assert.DoesNotContain("Now listening on:", await output);
            Assert.Contains("server_configuration_invalid", await error);
        }
        finally { if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(TestContext.Current.CancellationToken); } }
    }
}
