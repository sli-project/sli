using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Security;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using System.Text;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Npgsql;
using Sli.Server.Agents.Certificates;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.Registry;
using Sli.Server.Hosting;
using Xunit;

namespace Sli.Server.Tests.Agents;

[Collection("Agent CA environment")]
public sealed class AgentTlsTests
{
    [Fact]
    public async Task OptionalClientCertificateAcceptsLeafOnlyFromTrustedIssuerAndRejectsForeignBeforeDispatch()
    {
        var ct = TestContext.Current.CancellationToken;
        using var rootKey = RSA.Create(2048);
        using var otherKey = RSA.Create(2048);
        using var secondKey = RSA.Create(2048);
        using var issuerKey = RSA.Create(2048);
        using var foreignIssuerKey = RSA.Create(2048);
        using var serverKey = RSA.Create(2048);
        using var clientKey = RSA.Create(2048);
        using var foreignKey = RSA.Create(2048);
        using var secondClientKey = RSA.Create(2048);
        using var root = Root(rootKey, "CN=Owned listener root");
        using var foreignRoot = Root(otherKey, "CN=Foreign listener root");
        using var secondRoot = Root(secondKey, "CN=Second listener root");
        using var issuer = Issuer(root, issuerKey);
        using var foreignIssuer = Issuer(foreignRoot, foreignIssuerKey);
        using var server = Leaf(root, serverKey, "CN=localhost", server: true);
        using var valid = Leaf(issuer, clientKey, "CN=valid client", server: false);
        using var invalid = Leaf(foreignIssuer, foreignKey, "CN=foreign client", server: false);
        using var validSecond = Leaf(secondRoot, secondClientKey, "CN=second client", server: false);
        string temp = Path.Combine(Path.GetTempPath(), "sli-agent-listener-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        string path = Path.Combine(temp, "listener-ca.pem");
        string issuerPath = Path.Combine(temp, "issuer.pem");
        await File.WriteAllTextAsync(path, root.ExportCertificatePem() + "\n" + secondRoot.ExportCertificatePem(), ct);
        await File.WriteAllTextAsync(issuerPath, issuer.ExportCertificatePem(), ct);
        await File.WriteAllTextAsync(Path.Combine(temp, "login.html"), "<html>synthetic login</html>", ct);
        string? priorCa = Environment.GetEnvironmentVariable("SLI_AGENT_MTLS_CA_FILE");
        string? priorIssuer = Environment.GetEnvironmentVariable("SLI_AGENT_CA_ISSUER_CERT_FILE");
        var warnings = new RejectionLogger();
        try
        {
            Environment.SetEnvironmentVariable("SLI_AGENT_MTLS_CA_FILE", path);
            Environment.SetEnvironmentVariable("SLI_AGENT_CA_ISSUER_CERT_FILE", issuerPath);
            using var host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
                builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Sli:AgentMtlsCaFile"] = path, ["Sli:WebRoot"] = temp, ["urls"] = "http://127.0.0.1:0", ["Sli:TrustedProxies"] = "",
                    ["Sli:AuthRequired"] = "1", ["Sli:OwnerSetup"] = "0", ["ConnectionStrings:Sli"] = ""
                }))).WithWebHostBuilder(b => b.ConfigureLogging(logging => logging.ClearProviders()).ConfigureServices(services => {
            services.AddSingleton<ILogger<AgentCertificateRejections>>(warnings);
            foreach (var worker in services.Where(d => d.ServiceType == typeof(Microsoft.Extensions.Hosting.IHostedService)
                && (d.ImplementationType == typeof(Sli.Server.Workspace.DashboardWarmupService)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyJobWorker)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyScheduler)
                    || d.ImplementationType == typeof(Sli.Server.Legacy.LegacyPostCollectionHostedService))).ToArray())
                services.Remove(worker);
        }));
            host.UseKestrel(options => options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(server)));
            host.StartServer();
            string address = Assert.Single(host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
            using var noCert = Client(address, null);
            Assert.Contains("synthetic login", await noCert.GetStringAsync("/login", ct));
            using var enrollmentBody = new StringContent("{}", Encoding.UTF8, "application/json");
            using var enrollment = await noCert.PostAsync("/api/v1/agent/enroll", enrollmentBody, ct);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, enrollment.StatusCode);
            using var noIdentity = await noCert.GetAsync("/api/v1/agent/identity", ct);
            Assert.Equal(HttpStatusCode.Unauthorized, noIdentity.StatusCode);
            using var trusted = Client(address, valid);
            using var identity = await trusted.GetAsync("/api/v1/agent/identity", ct);
            // The peer certificate reached the endpoint. This fixture has no PostgreSQL connection.
            Assert.Equal(HttpStatusCode.ServiceUnavailable, identity.StatusCode);
            using var trustedSecond = Client(address, validSecond);
            Assert.Equal(HttpStatusCode.OK, (await trustedSecond.GetAsync("/login", ct)).StatusCode);
            using var untrusted = Client(address, invalid);
            await Assert.ThrowsAsync<HttpRequestException>(() => untrusted.GetAsync("/login", ct));
            using var invalidBody = new StringContent("{}", Encoding.UTF8, "application/json");
            await Assert.ThrowsAsync<HttpRequestException>(() => untrusted.PostAsync("/api/v1/agent/enroll", invalidBody, ct));
            var line = Assert.Single(warnings.Messages);
            Assert.Contains("CN=foreign client", line, StringComparison.Ordinal);
            Assert.Contains(invalid.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant(), line, StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SLI_AGENT_CA_ISSUER_CERT_FILE", priorIssuer);
            Environment.SetEnvironmentVariable("SLI_AGENT_MTLS_CA_FILE", priorCa);
            Directory.Delete(temp, recursive: true);
        }
    }

    [Fact]
    public void ListenerPolicyBuildsTheLeafChainAndStartupRefusesAnUntrustedIssuer()
    {
        using var rootKey = RSA.Create(2048);
        using var foreignRootKey = RSA.Create(2048);
        using var issuerKey = RSA.Create(2048);
        using var foreignIssuerKey = RSA.Create(2048);
        using var leafKey = RSA.Create(2048);
        using var foreignLeafKey = RSA.Create(2048);
        using var root = Root(rootKey, "CN=Owned listener root");
        using var foreignRoot = Root(foreignRootKey, "CN=Foreign listener root");
        using var issuer = Issuer(root, issuerKey);
        using var foreignIssuer = Issuer(foreignRoot, foreignIssuerKey);
        using var leaf = Leaf(issuer, leafKey, "CN=valid client", server: false);
        using var foreignLeaf = Leaf(foreignIssuer, foreignLeafKey, "CN=foreign client", server: false);
        var temp = Directory.CreateTempSubdirectory("sli-agent-listener-");
        try
        {
            string rootPath = Path.Combine(temp.FullName, "root.pem");
            string issuerPath = Path.Combine(temp.FullName, "issuer.pem");
            File.WriteAllText(rootPath, root.ExportCertificatePem());
            File.WriteAllText(issuerPath, issuer.ExportCertificatePem());
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sli:AgentMtlsCaFile"] = rootPath,
                ["SLI_AGENT_CA_ISSUER_CERT_FILE"] = issuerPath
            }).Build();
            Assert.True(AgentTlsTrust.TryLoad(config, out var trust));
            Assert.NotNull(trust);
            using (trust)
            {
                var https = new HttpsConnectionAdapterOptions();
                var ssl = new SslServerAuthenticationOptions();
                trust.Configure(https, new AgentCertificateRejections(new RejectionLogger()));
                https.OnAuthenticate!(null!, ssl);
                using var chain = new X509Chain { ChainPolicy = ssl.CertificateChainPolicy! };
                Assert.True(chain.Build(leaf));
                Assert.False(chain.Build(foreignLeaf));
            }

            File.WriteAllText(issuerPath, foreignIssuer.ExportCertificatePem());
            Assert.False(AgentTlsTrust.TryLoad(config, out var rejected));
            Assert.Null(rejected);
        }
        finally { temp.Delete(recursive: true); }
    }

    [Fact]
    public void RejectedChainsLogTheirReasonAndPublicIdentityOnce()
    {
        using var rootKey = RSA.Create(2048);
        using var foreignRootKey = RSA.Create(2048);
        using var issuerKey = RSA.Create(2048);
        using var leafKey = RSA.Create(2048);
        using var root = Root(rootKey, "CN=Owned listener root");
        using var foreignRoot = Root(foreignRootKey, "CN=Foreign listener root");
        using var issuer = Issuer(root, issuerKey);
        using var foreign = Leaf(foreignRoot, leafKey, "CN=foreign client", server: false);
        using var incomplete = Leaf(issuer, leafKey, "CN=incomplete client", server: false);
        using var wrongUsage = Leaf(root, leafKey, "CN=wrong usage", server: true);
        using var expired = Leaf(root, leafKey, "CN=expired client", server: false, expired: true);
        var temp = Directory.CreateTempSubdirectory("sli-agent-listener-");
        try
        {
            string rootPath = Path.Combine(temp.FullName, "root.pem");
            File.WriteAllText(rootPath, root.ExportCertificatePem());
            using var trust = new AgentTlsTrust(rootPath);
            var logger = new RejectionLogger();
            var rejections = new AgentCertificateRejections(logger);
            var https = new HttpsConnectionAdapterOptions();
            trust.Configure(https, rejections);

            Check(foreign, "untrusted_root", "untrusted root", foreignRoot);
            Check(incomplete, "unexpected_chain_length", "unexpected chain length");
            Check(wrongUsage, "wrong_eku", "wrong extended key usage");
            Check(expired, "expired", "expired");
            Assert.Equal(4, logger.Messages.Count);

            void Check(X509Certificate2 cert, string reason, string detail, X509Certificate2? extra = null)
            {
                var ssl = new SslServerAuthenticationOptions();
                https.OnAuthenticate!(null!, ssl);
                using var chain = new X509Chain { ChainPolicy = ssl.CertificateChainPolicy! };
                if (extra is not null) chain.ChainPolicy.ExtraStore.Add(extra);
                Assert.False(chain.Build(cert));
                for (int attempt = 0; attempt < 2; attempt++)
                    Assert.False(https.ClientCertificateValidation!(cert, chain, SslPolicyErrors.RemoteCertificateChainErrors));
                string thumbprint = cert.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant();
                Assert.Equal(reason, rejections.Snapshot()[thumbprint].Reason);
                string warning = Assert.Single(logger.Messages, message => message.Contains(thumbprint, StringComparison.Ordinal));
                Assert.Contains($"({detail})", warning, StringComparison.Ordinal);
                Assert.Contains(cert.Subject, warning, StringComparison.Ordinal);
                Assert.DoesNotContain("PRIVATE KEY", warning, StringComparison.Ordinal);
                Assert.DoesNotContain(cert.ExportCertificatePem(), warning, StringComparison.Ordinal);
                Assert.DoesNotContain(temp.FullName, warning, StringComparison.Ordinal);
            }
        }
        finally { temp.Delete(recursive: true); }
    }

    [Fact]
    public async Task File_audit_catalog_accepts_the_registered_https_peer_and_projects_its_saved_scope()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        var ownerToken = await fixture.SeedOwnerAsync(ct);
        using var certificates = new WriteSqlPostgresTests.Certificates();
        using var serverRootKey = RSA.Create(2048);
        using var serverKey = RSA.Create(2048);
        using var clientKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var serverRoot = Root(serverRootKey, "CN=Catalog test server root");
        using var server = Leaf(serverRoot, serverKey, "CN=localhost", server: true);

        string trust = Path.Combine(fixture.Pg.Root, "catalog-listener-root.pem");
        string issuer = Path.Combine(fixture.Pg.Root, "catalog-listener-issuer.pem");
        await File.WriteAllTextAsync(trust, certificates.Root.ExportCertificatePem(), ct);
        await File.WriteAllTextAsync(issuer, certificates.Issuer.ExportCertificatePem(), ct);
        const string mtlsSetting = "SLI_AGENT_MTLS_CA_FILE";
        const string issuerSetting = "SLI_AGENT_CA_ISSUER_CERT_FILE";
        string? priorTrust = Environment.GetEnvironmentVariable(mtlsSetting);
        string? priorIssuer = Environment.GetEnvironmentVariable(issuerSetting);
        try
        {
            Environment.SetEnvironmentVariable(mtlsSetting, trust);
            Environment.SetEnvironmentVariable(issuerSetting, issuer);
            using var host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder => builder
                .ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Sli:AgentMtlsCaFile"] = trust,
                    ["Sli:TrustedProxies"] = "",
                    ["Sli:AuthRequired"] = "1",
                    ["Sli:AllowUnauthenticated"] = "0",
                    ["Sli:OwnerSetup"] = "0",
                    ["Sli:ProjectRoot"] = PostCollectionPostgres.Repository(),
                    ["Sli:Storage:ArchiveRoot"] = fixture.Pg.Root,
                    ["Sli:Storage:HistoryReadMode"] = "primary",
                    ["Sli:DataDirectory"] = Path.Combine(fixture.Pg.Root, "catalog-data"),
                    ["Sli:LogDirectory"] = Path.Combine(fixture.Pg.Root, "catalog-logs"),
                    ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user"),
                    ["urls"] = "http://127.0.0.1:0"
                }))
                .ConfigureLogging(logging => logging.ClearProviders())
                .ConfigureServices(services =>
                {
                    services.RemoveAll<IHostedService>();
                    services.AddSingleton(certificates.Ca);
                }));
            host.UseKestrel(options => options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(server)));
            host.StartServer();
            var address = Assert.Single(host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
            Assert.Equal("https", new Uri(address).Scheme);

            async Task<JsonObject> Get(HttpClient client, string route)
            {
                using var response = await client.GetAsync(route, ct);
                return await Read(response, HttpStatusCode.OK);
            }
            async Task<JsonObject> Post(HttpClient client, string route, object payload, HttpStatusCode expected = HttpStatusCode.OK)
            {
                using var response = await client.PostAsJsonAsync(route, payload, ct);
                return await Read(response, expected);
            }
            async Task<JsonObject> Read(HttpResponseMessage response, HttpStatusCode expected)
            {
                string body = await response.Content.ReadAsStringAsync(ct);
                Assert.True(response.StatusCode == expected, $"Expected {(int)expected}, got {(int)response.StatusCode} {body}");
                return JsonNode.Parse(body)!.AsObject();
            }

            using var admin = Client(address, null, server);
            admin.DefaultRequestHeaders.Add("Cookie", "adlog_session=" + ownerToken);
            using var noCert = Client(address, null, server);
            string source = Guid.NewGuid().ToString("D");
            var csr = new CertificateRequest("CN=" + source, clientKey, HashAlgorithmName.SHA256);
            var token = await Post(admin, "/api/v1/admin/agent-tokens", new
            {
                host_id = source,
                key_fingerprint = Convert.ToHexStringLower(SHA256.HashData(clientKey.ExportSubjectPublicKeyInfo()))
            });
            var enrolled = await Post(noCert, "/api/v1/agent/enroll", new
            {
                token = token["token"]!.GetValue<string>(), csr_pem = csr.CreateSigningRequestPem(),
                reported_hostname = "catalog.example.test"
            });
            string agentId = enrolled["agent_id"]!.GetValue<string>();
            using var issued = X509Certificate2.CreateFromPem(enrolled["certificate_pem"]!.GetValue<string>());
            using var peer = issued.CopyWithPrivateKey(clientKey);
            using var agent = Client(address, peer, server);
            agent.DefaultRequestHeaders.Add("X-SLI-File-Audit-Catalog", "1");
            const string identityRoute = "/api/v1/agent/identity";
            var initial = await Get(agent, identityRoute);
            var revision = initial["policy_revision"]!.GetValue<long>();
            const string scope = "scope:catalog-https";
            var check = await Post(admin, "/api/v1/admin/agents/file-audit", new
            {
                agent_id = agentId, expected_revision = revision,
                config = new
                {
                    source_name = "catalog.example.test", source_kind = "server",
                    roots = new[] { new { collection_scope_id = scope, share_name = "Pilot$", path = @"C:\Pilot",
                        important = false, sacl = new { trustee_sids = new[] { "S-1-1-0" }, inherit_files = true, inherit_directories = true } } }
                },
                command = new { contract_id = "sli.file-audit.audit-command.v1", command_id = "catalog-https-check",
                    action = "check", policy_revision = (revision + 1).ToString(System.Globalization.CultureInfo.InvariantCulture),
                    collection_scope_ids = new[] { scope } }
            });
            Assert.Equal("pending", check["state"]!.GetValue<string>());

            const string catalogRoute = "/api/v1/admin/agents/file-audit/catalog";
            const string reportRoute = "/api/v1/agent/file-audit-catalog-report";
            string catalogPath = catalogRoute + "?agent_id=" + agentId;
            Assert.Equal("pending", (await Post(admin, catalogRoute, new { agent_id = agentId }))["state"]!.GetValue<string>());
            var identity = await Get(agent, identityRoute);
            string requestId = identity["file_audit_catalog_request"]!["request_id"]!.GetValue<string>();
            var report = new { request_id = requestId, status = "ready", shares = new[] { new { share_name = "Pilot$", path = @"C:\Pilot" } } };
            Assert.Equal("agent_mtls_required", (await Post(noCert, reportRoute, report, HttpStatusCode.Unauthorized))["error"]!.GetValue<string>());
            var stillPending = await Get(admin, catalogPath);
            Assert.Equal("pending", stillPending["state"]!.GetValue<string>());
            Assert.Empty(stillPending["items"]!.AsArray());

            Assert.Equal("accepted", (await Post(agent, reportRoute, report))["status"]!.GetValue<string>());
            var ready = await Get(admin, catalogPath);
            Assert.Equal("ready", ready["state"]!.GetValue<string>());
            var share = Assert.IsType<JsonObject>(Assert.Single(ready["items"]!.AsArray()));
            Assert.Equal("Pilot$", share["share_name"]!.GetValue<string>());
            Assert.Equal(@"C:\Pilot", share["path"]!.GetValue<string>());
            Assert.Equal(scope, share["collection_scope_id"]!.GetValue<string>());
            Assert.Equal("catalog-https-check", ready["saved_command"]!["command_id"]!.GetValue<string>());
            var key = JsonNode.Parse(ready["saved_report_share_key"]!.GetValue<string>())!.AsArray();
            Assert.Equal(new[] { agentId, source, scope }, key.Select(item => item!.GetValue<string>()).ToArray());
        }
        finally
        {
            Environment.SetEnvironmentVariable(mtlsSetting, priorTrust);
            Environment.SetEnvironmentVariable(issuerSetting, priorIssuer);
        }
    }

    [Fact]
    public async Task InventoryMatchesOnlyRegisteredFingerprintsAndClearsAfterContact()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var db = new NpgsqlConnection(fixture.Dsn("adlog_user"));
        await db.OpenAsync(ct);
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var now = DateTimeOffset.UtcNow;
        using var root = SigningCa("CN=Synthetic root", rootKey, 1).CreateSelfSigned(now.AddDays(-2), now.AddYears(2));
        using var issuer = SigningCa("CN=Synthetic issuer", issuerKey, 0).Create(root, now.AddDays(-1), now.AddYears(1), RandomNumberGenerator.GetBytes(16));
        using var ca = new AgentIssuingCa(new X509Certificate2(root), issuer.CopyWithPrivateKey(issuerKey));
        var id = Guid.NewGuid();
        var host = Guid.NewGuid();
        var csr = new CertificateRequest($"CN={host}", leafKey, HashAlgorithmName.SHA256);
        var validatedCsr = AgentCertificateAuthority.ParseCsr(csr.CreateSigningRequestPem(), host);
        using var revoked = ca.Issue(validatedCsr, id, host);
        using var registered = ca.Issue(validatedCsr, id, host);
        using var unknown = ca.Issue(validatedCsr, id, host);
        var logger = new RejectionLogger();
        var rejections = new AgentCertificateRejections(logger);
        var identity = new AgentIdentityService(ca, rejections: rejections);
        var management = new AgentManagementService(new AgentControlAudit(), rejections);
        await using var tx = await db.BeginTransactionAsync(ct);
        await using (var insert = new NpgsqlCommand("insert into sli_agents(id,host_id,key_fingerprint) values(@id,@host,@key)", db, tx))
        {
            insert.Parameters.AddWithValue("id", id);
            insert.Parameters.AddWithValue("host", host);
            insert.Parameters.AddWithValue("key", Convert.ToHexStringLower(SHA256.HashData(csr.PublicKey.ExportSubjectPublicKeyInfo())));
            await insert.ExecuteNonQueryAsync(ct);
        }
        await Save(revoked, true);
        await Save(registered, false);
        var rejection = await Assert.ThrowsAsync<AgentCertificateException>(() => identity.AuthenticateAsync(db, tx, revoked, false, ct));
        Assert.Equal(401, rejection.Status);
        Assert.Contains("(revoked)", Assert.Single(logger.Messages), StringComparison.Ordinal);
        rejections.Record(unknown, "wrong_eku");
        var row = (await management.ListAgentsAsync(db, tx, id.ToString(), "synthetic", ct)).GetProperty("items")[0];
        Assert.Equal("revoked", row.GetProperty("certificate_rejection_reason").GetString());
        Assert.All(row.GetProperty("certificates").EnumerateArray(), cert => Assert.False(cert.TryGetProperty("fingerprint", out _)));
        await identity.AuthenticateAsync(db, tx, registered, false, ct);
        row = (await management.ListAgentsAsync(db, tx, id.ToString(), "synthetic", ct)).GetProperty("items")[0];
        Assert.False(row.TryGetProperty("certificate_rejection_reason", out _));
        await tx.RollbackAsync(ct);

        static CertificateRequest SigningCa(string subject, ECDsa key, int pathLength)
        {
            var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, pathLength, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, true));
            return request;
        }

        async Task Save(X509Certificate2 cert, bool isRevoked)
        {
            await using var insert = new NpgsqlCommand("""
                insert into sli_agent_certificates(agent_id,serial,fingerprint,not_before,not_after,revoked_at)
                values(@id,@serial,@fingerprint,@before,@after,case when @revoked then clock_timestamp() end)
                """, db, tx);
            insert.Parameters.AddWithValue("id", id);
            insert.Parameters.AddWithValue("serial", cert.SerialNumber.TrimStart('0').ToLowerInvariant());
            insert.Parameters.AddWithValue("fingerprint", cert.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant());
            insert.Parameters.AddWithValue("before", cert.NotBefore.ToUniversalTime());
            insert.Parameters.AddWithValue("after", cert.NotAfter.ToUniversalTime());
            insert.Parameters.AddWithValue("revoked", isRevoked);
            await insert.ExecuteNonQueryAsync(ct);
        }
    }

    private sealed class RejectionLogger : ILogger<AgentCertificateRejections>
    {
        public ConcurrentQueue<string> Messages { get; } = new();
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Assert.Equal(LogLevel.Warning, logLevel);
            Assert.Null(exception);
            Messages.Enqueue(formatter(state, exception));
        }
    }

    private static HttpClient Client(string address, X509Certificate2? cert, X509Certificate2? expectedServer = null)
    {
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, presented, _, _) =>
                expectedServer is null || presented is not null && presented.RawData.AsSpan().SequenceEqual(expectedServer.RawData)
        };
        if (cert is not null) handler.ClientCertificates.Add(cert);
        return new HttpClient(handler) { BaseAddress = new Uri(address) };
    }

    private static X509Certificate2 Root(RSA key, string name)
    {
        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(2));
    }

    private static X509Certificate2 Issuer(X509Certificate2 root, RSA key)
    {
        var request = new CertificateRequest("CN=Test agent issuer", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        using var issuer = request.Create(root, DateTimeOffset.UtcNow.AddMinutes(-3), DateTimeOffset.UtcNow.AddDays(1.5), RandomNumberGenerator.GetBytes(16));
        return issuer.CopyWithPrivateKey(key);
    }

    private static X509Certificate2 Leaf(X509Certificate2 issuer, RSA key, string name, bool server, bool expired = false)
    {
        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var purposes = new OidCollection { new Oid(server ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(purposes, true));
        if (server) { var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("localhost"); request.CertificateExtensions.Add(san.Build()); }
        var now = DateTimeOffset.UtcNow;
        using var leaf = request.Create(issuer, now.AddMinutes(-2), expired ? now.AddMinutes(-1) : now.AddDays(1), RandomNumberGenerator.GetBytes(16));
        return leaf.CopyWithPrivateKey(key);
    }
}
