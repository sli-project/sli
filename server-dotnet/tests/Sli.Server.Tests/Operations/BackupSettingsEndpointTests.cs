using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Operations;
using Xunit;

namespace Sli.Server.Tests.Operations;

public sealed class BackupSettingsEndpointTests
{
    private const string Endpoint = "/api/v1/admin/backup-settings";
    private const string Origin = "https://sli.example.test";
    private const string Empty = """{"ok":true,"enabled":false,"path":null,"revision":"r1","storage_status":"unconfigured"}""";
    private const string Configured = """{"ok":true,"enabled":true,"path":"/mounted/backup","revision":"r2","storage_status":"ready"}""";
    private const string Update = """{"enabled":true,"path":"/mounted/backup","revision":"r1"}""";

    [Fact]
    public async Task ReadsAndUpdatesWithoutLeakingTheNativeEnvelope()
    {
        await using var fixture = new Fixture { Reply = Empty + "\n" };
        using var get = await fixture.Send(HttpMethod.Get);
        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        Assert.True(get.Headers.CacheControl?.NoStore);
        Assert.Equal("{\"action\":\"get\"}\n", fixture.Wire);
        Assert.Equal(4, (await Json(get)).Count);
        Assert.Equal("unconfigured", (await Json(get))["storage_status"]!.GetValue<string>());

        fixture.Reply = Configured + "\n";
        using var put = await fixture.Send(HttpMethod.Put, Update);
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);
        Assert.EndsWith("\n", fixture.Wire);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"action":"set","enabled":true,"path":"/mounted/backup","revision":"r1"}"""),
            JsonNode.Parse(fixture.Wire)));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"enabled":true,"path":"/mounted/backup","revision":"r2","storage_status":"ready"}"""),
            await Json(put)));
    }

    [Theory]
    [InlineData("GET", false, "session", false, 401, "authentication_required")]
    [InlineData("PUT", false, "session", false, 401, "authentication_required")]
    [InlineData("GET", true, "session", false, 403, "platform_owner_required")]
    [InlineData("PUT", true, "session", false, 403, "platform_owner_required")]
    [InlineData("GET", true, "api_key", true, 403, "platform_owner_required")]
    [InlineData("PUT", true, "api_key", true, 403, "platform_owner_required")]
    public async Task RequiresAnAuthenticatedOwnerSession(string method, bool authenticated, string kind, bool owner, int status, string code)
    {
        await using var fixture = new Fixture { Authenticated = authenticated, PrincipalType = kind, Owner = owner };
        using var response = await fixture.Send(new HttpMethod(method), "{");
        await ExpectError(response, status, code);
        Assert.Equal(0, fixture.Connections);
    }

    [Fact]
    public async Task RejectsBothInsecureTransportAndMissingOrForeignMutationOrigin()
    {
        await using var fixture = new Fixture { RequireTls = true };
        using var insecure = await fixture.Send(HttpMethod.Get, scheme: "http");
        await ExpectError(insecure, 403, "secure_transport_required");
        Assert.Equal(0, fixture.AuthenticationReads);
        foreach (var origin in new[] { null, "https://other.example.test" })
        {
            using var foreign = await fixture.Send(HttpMethod.Put, "{", origin);
            await ExpectError(foreign, 403, "cross_origin_request_rejected");
        }
        Assert.Equal(0, fixture.FactReads);
        Assert.Equal(0, fixture.Connections);
    }

    [Theory]
    [InlineData("""{"enabled":true,"path":"/mounted/backup","revision":"r1","action":"get"}""")]
    [InlineData("""{"enabled":true,"enabled":false,"path":"/mounted/backup","revision":"r1"}""")]
    [InlineData("""{"enabled":true,"revision":"r1"}""")]
    [InlineData("""{"enabled":"true","path":"/mounted/backup","revision":"r1"}""")]
    [InlineData("""{"enabled":true,"path":"/mnt\ncopy","revision":"r1"}""")]
    [InlineData("""{"enabled":true,"path":"relative","revision":"r1"}""")]
    [InlineData("""{"enabled":true,"path":null,"revision":"r1"}""")]
    [InlineData("""{"enabled":false,"path":null,"revision":null}""")]
    [InlineData("""{"enabled":false,"path":null,"revision":""}""")]
    [InlineData("""{"enabled":false,"path":null,"revision":"r1",}""")]
    public async Task RejectsInvalidMutationShapeBeforeTheSocket(string payload)
    {
        await using var fixture = new Fixture();
        using var response = await fixture.Send(HttpMethod.Put, payload);
        await ExpectError(response, 400, "backup_settings_invalid");
        Assert.Equal(0, fixture.Connections);
    }

    [Fact]
    public async Task BoundsTheBodyAndRequiresJsonMediaType()
    {
        await using var fixture = new Fixture();
        using var large = await fixture.Send(HttpMethod.Put, new string(' ', 20_000));
        await ExpectError(large, 413, "backup_settings_invalid");
        using var media = await fixture.Send(HttpMethod.Put, Update, mediaType: "text/plain");
        await ExpectError(media, 415, "backup_settings_invalid");
        Assert.Equal(0, fixture.Connections);
    }

    [Fact]
    public async Task BoundsTheNativeLineAndPreservesUtf8Paths()
    {
        await using var fixture = new Fixture { Reply = Configured + new string(' ', 8192) + "\n" };
        await ExpectError(await fixture.Send(HttpMethod.Put, Update), 503, "backup_settings_unavailable", exact: true);

        string path = "/mounted/" + new string('я', 1800);
        fixture.Reply = Configured + "\n";
        using var response = await fixture.Send(HttpMethod.Put, Update.Replace("/mounted/backup", path));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(path, JsonNode.Parse(fixture.Wire)!["path"]!.GetValue<string>());
        Assert.InRange(Encoding.UTF8.GetByteCount(fixture.Wire), path.Length, 8192);
    }

    [Theory]
    [InlineData("""{"enabled":false,"path":null,"revision":"r2"}""")]
    [InlineData("""{"enabled":false,"path":"/mounted/backup","revision":"r2"}""")]
    public async Task AllowsDisablingWithAnUnavailableOrUnselectedPath(string payload)
    {
        var selected = JsonNode.Parse(payload)!["path"]?.ToJsonString() ?? "null";
        await using var fixture = new Fixture
        {
            Reply = """{"ok":true,"enabled":false,"path":""" + selected + ""","revision":"r3","storage_status":"unavailable"}""" + "\n",
        };
        using var response = await fixture.Send(HttpMethod.Put, payload);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var wire = JsonNode.Parse(fixture.Wire)!.AsObject();
        Assert.True(wire.ContainsKey("path"));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(payload)!["path"], wire["path"]));
        Assert.Equal("r3", (await Json(response))["revision"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("backup_settings_revision_conflict", 409)]
    [InlineData("backup_settings_unavailable", 503)]
    [InlineData("backup_settings_invalid", 400)]
    [InlineData("native_backup_root_invalid", 400)]
    [InlineData("native_backup_root_untrusted", 400)]
    [InlineData("native_backup_root_same_device", 400)]
    [InlineData("native_backup_root_insufficient_space", 400)]
    [InlineData("native_backup_root_mount_mismatch", 400)]
    public async Task MapsOnlyTheKnownNativeErrors(string error, int status)
    {
        await using var fixture = new Fixture { Reply = "{\"ok\":false,\"error\":\"" + error + "\"}\n" };
        await ExpectError(await fixture.Send(HttpMethod.Put, Update), status, error, exact: true);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(Configured)]
    [InlineData("""{"ok":false,"error":"/private/files"}""")]
    [InlineData("""{"ok":false,"error":"backup_settings_revision_conflict","path":"/private/files"}""")]
    [InlineData("""{"ok":true,"ok":false,"path":null,"revision":"r1","storage_status":"ready"}""")]
    [InlineData("""{"ok":true,"enabled":false,"path":null,"revision":"r1","storage_status":"unknown"}""")]
    [InlineData("""{"ok":true,"enabled":false,"path":null,"revision":null,"storage_status":"unavailable"}""")]
    public async Task UnavailableOrMalformedCoordinatorFailsClosedWithoutLeaking(string? reply)
    {
        await using var fixture = new Fixture { Reply = reply is null || reply == Configured ? reply : reply + "\n" };
        using var get = await fixture.Send(HttpMethod.Get);
        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"enabled":false,"path":null,"revision":null,"storage_status":"unavailable"}"""),
            await Json(get)));
        await ExpectError(await fixture.Send(HttpMethod.Put, Update), 503, "backup_settings_unavailable", exact: true);
    }

    private static async Task<JsonObject> Json(HttpResponseMessage response) =>
        JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();

    private static async Task ExpectError(HttpResponseMessage response, int status, string error, bool exact = false)
    {
        using (response)
        {
            Assert.Equal(status, (int)response.StatusCode);
            var json = await Json(response);
            Assert.Equal(error, json["error"]!.GetValue<string>());
            if (exact) Assert.Single(json);
        }
    }

    private sealed class Fixture : IAsyncDisposable, IPrincipalAuthenticator, IAccessFactsRepository
    {
        private IHost? host;
        private HttpClient? client;
        private SocketExchange? transfer;
        public string? Reply { get; set; } = Configured + "\n";
        public bool Authenticated { get; init; } = true;
        public bool Owner { get; init; } = true;
        public bool RequireTls { get; init; }
        public string PrincipalType { get; init; } = "session";
        public int AuthenticationReads { get; private set; }
        public int FactReads { get; private set; }
        public int Connections { get; private set; }
        public string Wire => Encoding.UTF8.GetString(transfer!.Outgoing.ToArray());

        ValueTask<AuthenticationResult> IPrincipalAuthenticator.AuthenticateAsync(HttpContext context, CancellationToken ct)
        {
            AuthenticationReads++;
            return ValueTask.FromResult(Authenticated ? AuthenticationResult.Success(new(PrincipalType, 2, "admin", "fixture"))
                : AuthenticationResult.Denied(401, "authentication_required"));
        }

        public Task<AccessFacts> LoadAsync(Principal principal, CancellationToken ct)
        {
            FactReads++;
            return Task.FromResult(new AccessFacts(Owner, principal.Role, [], [], [], [], [], [], []));
        }

        public async Task<HttpResponseMessage> Send(HttpMethod method, string? body = null,
            string? origin = Origin, string scheme = "https", string mediaType = "application/json")
        {
            var ct = TestContext.Current.CancellationToken;
            if (host is null)
            {
                var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Sli:AuthRequired"] = "true", ["Sli:TrustedProxies"] = RequireTls ? "127.0.0.1" : "",
                }).Build();
                host = await new HostBuilder().ConfigureWebHost(web => web.UseTestServer().ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddSingleton(new AuthRequestPolicy(configuration));
                    services.AddSingleton(new TransportGate(configuration));
                    services.AddSingleton<IPrincipalAuthenticator>(this);
                    services.AddSingleton<IAccessFactsRepository>(this);
                    services.AddSingleton(new BackupSettingsClient(_ =>
                    {
                        Connections++;
                        if (Reply is null) throw new IOException("private file /secret/path");
                        transfer = new SocketExchange(Reply);
                        return ValueTask.FromResult<Stream>(transfer);
                    }));
                }).Configure(app => { app.UseRouting(); app.UseEndpoints(endpoints => endpoints.MapBackupSettings()); })).StartAsync(ct);
                client = host.GetTestClient();
            }
            using var request = new HttpRequestMessage(method, scheme + "://sli.example.test" + Endpoint);
            if (origin is not null) request.Headers.Add("Origin", origin);
            if (body is not null)
            {
                request.Content = new StringContent(body, Encoding.UTF8);
                request.Content.Headers.ContentType = new MediaTypeHeaderValue(mediaType);
            }
            return await client!.SendAsync(request, ct);
        }

        public async ValueTask DisposeAsync()
        {
            client?.Dispose();
            if (host is not null) { await host.StopAsync(); host.Dispose(); }
        }
    }

    internal sealed class SocketExchange(string reply) : Stream
    {
        private readonly MemoryStream incoming = new(Encoding.UTF8.GetBytes(reply));
        public MemoryStream Outgoing { get; } = new();
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => incoming.Read(buffer, offset, count);
        public override void Write(byte[] buffer, int offset, int count) => Outgoing.Write(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing) { incoming.Dispose(); Outgoing.Dispose(); }
            base.Dispose(disposing);
        }
    }
}
