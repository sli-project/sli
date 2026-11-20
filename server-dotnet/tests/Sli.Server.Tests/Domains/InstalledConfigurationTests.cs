using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Hosting;
using Sli.Server.Infrastructure;
using Xunit;

namespace Sli.Server.Tests.Domains;

[CollectionDefinition("Installed API environment", DisableParallelization = true)]
public sealed class InstalledApiEnvironmentCollection { }

[Collection("Installed API environment")]
public sealed class InstalledConfigurationTests
{
    // tests/core/test_pg_stable_runtime_backend.py: selection must fail before DB access.
    [Theory]
    [InlineData("sqlite")]
    [InlineData("unknown")]
    [InlineData("")]
    [InlineData("   ")]
    public void UnsupportedRuntimeBackendIsRejectedBeforeConfigurationOrConnection(string backend)
    {
        var config = new ConfigurationManager();
        config["ADLOG_DB_BACKEND"] = backend;
        config["ConnectionStrings:Sli"] = "Host=192.0.2.1;Database=fixture;Username=fixture";
        var error = Assert.Throws<ServerConfigurationException>(() => config.AddInstalledEnvironment());
        Assert.Equal("server_configuration_invalid:ADLOG_DB_BACKEND:postgres_required", error.Message);
        error = Assert.Throws<ServerConfigurationException>(() => new PostgresConnectionFactory(config));
        Assert.Equal("server_configuration_invalid:ADLOG_DB_BACKEND:postgres_required", error.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("postgres")]
    [InlineData(" POSTGRES ")]
    public void AbsentBackendDefaultsToPostgresAndConfiguredPostgresIsAccepted(string? backend)
    {
        var config = new ConfigurationManager();
        config["ADLOG_DB_BACKEND"] = backend;
        config["ConnectionStrings:Sli"] = "Host=192.0.2.1;Database=fixture;Username=fixture";
        config.AddInstalledEnvironment();
        _ = new PostgresConnectionFactory(config);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void PostgresRuntimeRequiresNonemptyConnectionString(string? connection)
    {
        var config = new ConfigurationManager();
        config["ADLOG_DB_BACKEND"] = "postgres";
        config["ConnectionStrings:Sli"] = connection;
        var error = Assert.Throws<ServerConfigurationException>(() => new PostgresConnectionFactory(config));
        Assert.Equal("server_configuration_invalid:ConnectionStrings:Sli:missing", error.Message);
    }

    [Theory]
    [InlineData("CERT")]
    [InlineData("KEY")]
    public void Tls_path_and_file_are_mutually_exclusive(string part)
    {
        using var fixture = new InstalledApi();
        var config = new ConfigurationManager();
        config.AddInMemoryCollection(fixture.Settings.Select(p => KeyValuePair.Create<string, string?>(p.Key, p.Value)));
        config["ADLOG_TLS_" + part + "_PATH"] = " conflicting-path ";
        Assert.Equal("server_configuration_invalid:ADLOG_TLS_" + part + "_FILE:conflict",
            Assert.Throws<ServerConfigurationException>(config.AddInstalledEnvironment).Message);
    }

    [Fact] public void Tls_paths_are_trimmed_and_empty_paths_disable_tls()
    {
        using var fixture = new InstalledApi();
        var config = new ConfigurationManager();
        foreach (string part in new[] { "CERT", "KEY" })
            config["ADLOG_TLS_" + part + "_PATH"] = " \t" + fixture.Settings["ADLOG_TLS_" + part + "_FILE"] + " \r\n";
        config.AddInstalledEnvironment();
        Assert.Equal(fixture.Settings["ADLOG_TLS_CERT_FILE"], config["Kestrel:Certificates:Default:Path"]);
        var empty = new ConfigurationManager();
        empty["ADLOG_TLS_CERT_PATH"] = " \t"; empty["ADLOG_TLS_KEY_PATH"] = "";
        empty.AddInstalledEnvironment();
        Assert.Null(empty["Kestrel:Certificates:Default:Path"]);
        var emptyFile = new ConfigurationManager(); emptyFile["ADLOG_TLS_CERT_FILE"] = " ";
        Assert.Throws<ServerConfigurationException>(emptyFile.AddInstalledEnvironment);
    }
    [Theory]
    [InlineData("%d/../outside")]
    [InlineData("%d/nested/../../outside")]
    [InlineData("%d//absolute")]
    [InlineData("%d/C:/absolute")]
    [InlineData("%d/\\absolute")]
    [InlineData("%d/nested\\..\\outside")]
    [InlineData("%d/")]
    public void Credential_expansion_rejects_escape_before_file_access(string path)
    {
        var config=new ConfigurationManager();
        config["CREDENTIALS_DIRECTORY"]=Path.GetTempPath();
        config["SLI_AGENT_MTLS_CA_FILE"]=path;
        var error=Assert.Throws<ServerConfigurationException>(()=>config.AddInstalledEnvironment());
        Assert.Equal("server_configuration_invalid:Sli:AgentMtlsCaFile:invalid",error.Message);
        Assert.Null(error.InnerException);
    }
    [Fact] public void Credential_expansion_keeps_relative_path_inside_directory()
    {
        var config=new ConfigurationManager();
        config["CREDENTIALS_DIRECTORY"]=Path.GetTempPath();
        config["SLI_AGENT_MTLS_CA_FILE"]="%d/nested/certificate";
        config.AddInstalledEnvironment();
        Assert.Equal(Path.Combine(Path.GetTempPath(),"nested/certificate"),config["Sli:AgentMtlsCaFile"]);
    }

    private const string Password = " synthetic;password='private' ";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InstalledApiEnvironmentStartsHostAndHealthWithoutExposingSecrets(bool explicitSettings)
    {
        using var fixture = new InstalledApi();
        // Keep startup's optional warmup on an isolated, unused loopback port.
        using var unusedDatabase = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        unusedDatabase.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        int databasePort = ((IPEndPoint)unusedDatabase.LocalEndPoint!).Port;
        fixture.Settings["ADLOG_PG_DSN"] = $"host=127.0.0.1 port={databasePort} dbname=sli user=adlog_user";
        fixture.Settings["Logging__LogLevel__Microsoft.Hosting.Lifetime"] = "Information";
        fixture.Settings["Logging__Console__FormatterName"] = "simple";
        if (explicitSettings)
        {
            fixture.Settings["ConnectionStrings__Sli"] = $"Host=127.0.0.1;Port={databasePort};Database=explicit;Username=explicit";
            fixture.Settings["ADLOG_PG_PASSWORD_FILE"] = Path.Combine(fixture.Directory, "missing");
            fixture.Settings["Kestrel__Certificates__Default__Path"] = fixture.Settings["ADLOG_TLS_CERT_FILE"];
            fixture.Settings["Kestrel__Certificates__Default__KeyPath"] = fixture.Settings["ADLOG_TLS_KEY_FILE"];
            fixture.Settings["ADLOG_TLS_CERT_FILE"] = "missing";
            fixture.Settings["ADLOG_TLS_KEY_FILE"] = "missing";
        }
        var config = new ConfigurationManager();
        config.AddInMemoryCollection(fixture.Settings.Select(pair => KeyValuePair.Create(
            pair.Key.Replace("__", ":", StringComparison.Ordinal), (string?)pair.Value)));
        config.AddInstalledEnvironment();
        string certificatePath = Path.Combine(fixture.Directory, "tls_certificate");
        Assert.Equal(certificatePath, config["Kestrel:Certificates:Default:Path"]);
        Assert.Equal(Path.Combine(fixture.Directory, "tls_key"), config["Kestrel:Certificates:Default:KeyPath"]);
        Assert.Equal(fixture.Url, config["urls"]);
        var postgres = new NpgsqlConnectionStringBuilder(config.GetConnectionString("Sli"));
        Assert.Equal(explicitSettings ? "explicit" : "sli", postgres.Database);
        Assert.Equal(databasePort, postgres.Port);
        Assert.True(explicitSettings ? string.IsNullOrEmpty(postgres.Password) : postgres.Password == Password,
            "Unexpected installed PostgreSQL credential selection");

        using var certificate = X509CertificateLoader.LoadCertificateFromFile(certificatePath);
        using var handler = new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false };
        handler.SslOptions.CertificateChainPolicy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust };
        handler.SslOptions.CertificateChainPolicy.CustomTrustStore.Add(certificate);
        using var client = new HttpClient(handler);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(20));
        using var process = fixture.Start();
        var listening = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var stdout = ReadHostOutput(process.StandardOutput, listening);
        var stderr = process.StandardError.ReadToEndAsync();
        try
        {
            string? address = await listening.Task.WaitAsync(deadline.Token);
            Assert.True(Uri.TryCreate(address, UriKind.Absolute, out var endpoint), "The installed API did not publish its listener");
            Assert.Equal(Uri.UriSchemeHttps, endpoint.Scheme);
            Assert.Equal(IPAddress.Loopback.ToString(), endpoint.Host);
            Assert.True(endpoint.Port > 0);
            using var response = await client.GetAsync(new Uri(endpoint, "/health"), deadline.Token);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var body = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync(deadline.Token));
            Assert.Equal("ok", body.RootElement.GetProperty("status").GetString());
        }
        finally { await Stop(process); }
        string output = await stdout + await stderr;
        Assert.Equal(1, output.Split('\n').Count(line => line.Contains(ListeningOn, StringComparison.Ordinal)));
        Assert.False(output.Contains(Password, StringComparison.Ordinal), "The installed API logged its database credential");
        Assert.False(output.Contains("BEGIN PRIVATE KEY", StringComparison.Ordinal), "The installed API logged its TLS private key");
    }

    private const string ListeningOn = "Now listening on: ";

    private static async Task<string> ReadHostOutput(StreamReader reader, TaskCompletionSource<string?> listening)
    {
        var output = new StringBuilder();
        while (await reader.ReadLineAsync() is { } line)
        {
            output.AppendLine(line);
            if (line.TrimStart().StartsWith(ListeningOn, StringComparison.Ordinal))
                listening.TrySetResult(line.Trim()[ListeningOn.Length..]);
        }
        listening.TrySetResult(null);
        return output.ToString();
    }

    [Theory]
    [InlineData("missing", "server_configuration_invalid:ADLOG_PG_PASSWORD_FILE:unavailable")]
    [InlineData("empty", "server_configuration_invalid:ADLOG_PG_PASSWORD_FILE:invalid")]
    [InlineData("absent", "server_configuration_invalid:ADLOG_PG_PASSWORD:missing")]
    [InlineData("dsn", "server_configuration_invalid:ADLOG_PG_DSN:invalid")]
    [InlineData("tls", "server_configuration_invalid:ADLOG_TLS_KEY_FILE:missing")]
    [InlineData("no-dsn", "server_configuration_invalid:ADLOG_PG_DSN:missing")]
    [InlineData("connections", "server_configuration_invalid:Sli:HttpMaxConnections:invalid")]
    [InlineData("requests", "server_configuration_invalid:Sli:HttpMaxConcurrentRequests:invalid")]
    public async Task InvalidInstalledSettingExitsWithSafeSettingCode(string failure, string expected)
    {
        using var fixture = new InstalledApi();
        if (failure == "missing") fixture.Settings["ADLOG_PG_PASSWORD_FILE"] = Path.Combine(fixture.Directory, "missing");
        if (failure == "empty") File.WriteAllText(Path.Combine(fixture.Directory, "runtime_password"), "\r\n");
        if (failure == "absent") fixture.Settings.Remove("ADLOG_PG_PASSWORD_FILE");
        if (failure == "dsn") fixture.Settings["ADLOG_PG_DSN"] = "host='" + Password;
        if (failure == "tls") fixture.Settings.Remove("ADLOG_TLS_KEY_FILE");
        if (failure == "no-dsn") fixture.Settings.Remove("ADLOG_PG_DSN");
        if (failure == "connections") fixture.Settings["ADLOG_HTTP_MAX_CONNECTIONS"] = "invalid";
        if (failure == "requests") fixture.Settings["ADLOG_HTTP_MAX_CONCURRENT_REQUESTS"] = "invalid";
        using var process = fixture.Start();
        var stdout = process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        var stderr = process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(15));
        try { await process.WaitForExitAsync(deadline.Token); }
        finally { await Stop(process); }
        Assert.NotEqual(0, process.ExitCode);
        Assert.Equal(expected, (await stderr).Trim());
        Assert.DoesNotContain("Now listening on:", await stdout);
        Assert.DoesNotContain(Password, await stdout + await stderr);
    }

    [Fact]
    public void InvalidNewConnectionStringDoesNotRetainParserExceptionOrPassword()
    {
        var config = new ConfigurationManager();
        config["ConnectionStrings:Sli"] = "Host=localhost;Port=" + Password;
        var error = Assert.Throws<ServerConfigurationException>(() => new PostgresConnectionFactory(config));
        Assert.Equal("server_configuration_invalid:ConnectionStrings:Sli:invalid", error.Message);
        Assert.Null(error.InnerException);
        Assert.DoesNotContain(Password, error.ToString());
    }

    [Fact]
    public void NativeDsnPasswordAndAliasesReachServerConfiguration()
    {
        using var fixture = new InstalledApi();
        var config = new ConfigurationManager();
        config.AddInMemoryCollection(fixture.Settings.Select(kv => new KeyValuePair<string, string?>(kv.Key, kv.Value)));
        config.AddInstalledEnvironment();
        var pg = new NpgsqlConnectionStringBuilder(config.GetConnectionString("Sli"));
        Assert.Equal("127.0.0.1", pg.Host);
        Assert.Equal(5432, pg.Port);
        Assert.Equal("sli", pg.Database);
        Assert.Equal("adlog_user", pg.Username);
        Assert.Equal(Password, pg.Password);
        Assert.False(pg.IncludeErrorDetail);
        _ = new PostgresConnectionFactory(config);
        Assert.Equal("1", config["Sli:AuthRequired"]);
        Assert.Equal(fixture.Directory, config["Sli:ReactRoot"]);
        Assert.Equal(fixture.Url, config["urls"]);
    }

    [Theory]
    [InlineData("0.0.0.0", "https://0.0.0.0:8443")]
    [InlineData("::", "https://[::]:8443")]
    [InlineData("192.0.2.10", "https://192.0.2.10:8443")]
    public void BindAddressIsTheListenerAndHealthUrlOnlySuppliesSchemeAndPort(string bind, string expected)
    {
        var config = new ConfigurationManager();
        config.AddInMemoryCollection(new Dictionary<string, string?> { ["SLI_BIND"] = bind, ["SLI_HEALTH_URL"] = "https://127.0.0.1:8443/api/health/ready" });
        config.AddInstalledEnvironment();
        Assert.Equal(expected, config["urls"]);
    }

    [Fact]
    public void InvalidBindAddressIsRefused()
    {
        var config = new ConfigurationManager();
        config.AddInMemoryCollection(new Dictionary<string, string?> { ["SLI_BIND"] = "not-an-ip", ["SLI_HEALTH_URL"] = "https://127.0.0.1:8443/api/health/ready" });
        Assert.Equal("server_configuration_invalid:SLI_BIND:invalid", Assert.Throws<ServerConfigurationException>(config.AddInstalledEnvironment).Message);
    }

    [Theory]
    [InlineData("ConnectionStrings:Sli")]
    [InlineData("Sli:PostgresConnectionString")]
    public void ExplicitConnectionAndAliasesWinWithoutReadingInstalledSecrets(string connectionSetting)
    {
        var config = new ConfigurationManager();
        const string connection = "Host=localhost;Database=explicit;Username=explicit;Password=synthetic-explicit";
        config.AddInMemoryCollection(new Dictionary<string, string?> {
            [connectionSetting] = connection, ["ADLOG_PG_DSN"] = "invalid", ["ADLOG_PG_PASSWORD_FILE"] = "missing",
            ["Sli:AuthRequired"] = "0", ["ADLOG_AUTH_REQUIRED"] = "1", ["Sli:ReactRoot"] = "explicit", ["ADLOG_REACT_WEB_DIR"] = "legacy",
            ["urls"] = "http://127.0.0.1:9000", ["SLI_HEALTH_URL"] = "https://127.0.0.1:8443/api/health/ready"
        });
        config.AddInstalledEnvironment();
        Assert.Equal(connection, config[connectionSetting]);
        _ = new PostgresConnectionFactory(config);
        Assert.Equal("0", config["Sli:AuthRequired"]);
        Assert.Equal("explicit", config["Sli:ReactRoot"]);
        Assert.Equal("http://127.0.0.1:9000", config["urls"]);
    }

    private static async Task Stop(Process process)
    {
        if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(TestContext.Current.CancellationToken); }
    }

    // CI has no DOTNET_HOST_PATH but has dotnet on PATH.
    private static string DotnetHost => Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") is { Length: > 0 } path ? path : "dotnet";

    private sealed class InstalledApi : IDisposable
    {
        public string Directory { get; } = Path.Combine(Path.GetTempPath(), "sli-installed-api-" + Guid.NewGuid().ToString("N"));
        public Dictionary<string, string> Settings { get; } = new();
        public string Url { get; } = "https://127.0.0.1:0";
        public InstalledApi()
        {
            System.IO.Directory.CreateDirectory(Directory);
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); request.CertificateExtensions.Add(san.Build());
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
            File.WriteAllText(Path.Combine(Directory, "tls_certificate"), cert.ExportCertificatePem());
            File.WriteAllText(Path.Combine(Directory, "tls_key"), key.ExportPkcs8PrivateKeyPem());
            File.WriteAllText(Path.Combine(Directory, "runtime_password"), Password + "\r\n");
            File.WriteAllText(Path.Combine(Directory, "history_password"), "synthetic-history-password\n");
            foreach (var (name, value) in new Dictionary<string, string> {
                ["ADLOG_PG_DSN"] = "host=127.0.0.1 port=5432 dbname=sli user=adlog_user",
                ["ADLOG_PG_PASSWORD_FILE"] = "%d/runtime_password", ["CREDENTIALS_DIRECTORY"] = Directory,
                ["ADLOG_HISTORY_CLICKHOUSE_HOST"] = "127.0.0.1", ["ADLOG_HISTORY_CLICKHOUSE_PORT"] = "8123",
                ["ADLOG_HISTORY_CLICKHOUSE_USER"] = "sli_history", ["ADLOG_HISTORY_CLICKHOUSE_PASSWORD_FILE"] = Path.Combine(Directory, "history_password"),
                ["ADLOG_TLS_CERT_FILE"] = Path.Combine(Directory, "tls_certificate"), ["ADLOG_TLS_KEY_FILE"] = Path.Combine(Directory, "tls_key"),
                ["SLI_TLS_CA_FILE"] = Path.Combine(Directory, "tls_certificate"), ["SLI_AGENT_MTLS_CA_FILE"] = Path.Combine(Directory, "tls_certificate"),
                ["SLI_AGENT_CA_ROOT_CERT_FILE"] = Path.Combine(Directory, "tls_certificate"),
                ["SLI_AGENT_CA_ISSUER_CERT_FILE"] = Path.Combine(Directory, "tls_certificate"), ["SLI_AGENT_CA_ISSUER_KEY_FILE"] = Path.Combine(Directory, "tls_key"),
                ["ADLOG_DATA_DIR"] = Directory, ["ADLOG_LOG_DIR"] = Directory, ["ADLOG_AUTH_REQUIRED"] = "1",
                ["SLI_PLUGIN_RUNTIME_DIR"] = Directory, ["SLI_PLUGIN_LOCK_DIR"] = Directory, ["SLI_DEPLOYMENT_MODE"] = "native",
                ["ADLOG_REACT_WEB_DIR"] = Directory, ["SLI_HEALTH_URL"] = Url + "/api/health/ready"
            }) Settings.Add(name, value);
        }
        public Process Start(params string[] args)
        {
            var start = new ProcessStartInfo(DotnetHost) {
                UseShellExecute = false, RedirectStandardError = true, RedirectStandardOutput = true, CreateNoWindow = true,
                WorkingDirectory = AppContext.BaseDirectory
            };
            string[] listenerOverrides = ["URLS", "HTTP_PORTS", "HTTPS_PORTS", "DOTNET_URLS", "DOTNET_HTTP_PORTS", "DOTNET_HTTPS_PORTS"];
            foreach (string name in start.Environment.Keys.Where(k => k.StartsWith("SLI", StringComparison.OrdinalIgnoreCase)
                || k.StartsWith("ADLOG", StringComparison.OrdinalIgnoreCase) || k.StartsWith("ConnectionStrings", StringComparison.OrdinalIgnoreCase)
                || k.StartsWith("Kestrel", StringComparison.OrdinalIgnoreCase) || k.StartsWith("ASPNETCORE", StringComparison.OrdinalIgnoreCase)
                || listenerOverrides.Contains(k, StringComparer.OrdinalIgnoreCase)).ToArray()) start.Environment.Remove(name);
            foreach (var (name, value) in Settings) start.Environment[name] = value;
            start.ArgumentList.Add(typeof(Program).Assembly.Location);
            foreach (string arg in args) start.ArgumentList.Add(arg);
            return Process.Start(start)!;
        }
        public void Dispose() => System.IO.Directory.Delete(Directory, recursive: true);
    }
}
