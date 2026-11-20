using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Auth;

public sealed class ReportKeyProgramTests
{
    [Fact]
    public async Task ProgramIssuesProtectedReportKeyAndGateDeniesBlockedAndMissingRoutes()
    {
        var ct = TestContext.Current.CancellationToken;
        var binding = OwnedDatabaseBinding.FromEnvironment();
        Assert.Equal("7f76e02a-754d-435b-84d5-f16b96203c38", binding.RunId.ToString("D"));
        await using var database = await SyntheticDatabase.BorrowAsync(binding, ct);
        string configPath = Environment.GetEnvironmentVariable("SLI_PROGRAM_TEST_CONFIG")
            ?? throw new InvalidOperationException("Dedicated integration config is required");
        byte[] config = await File.ReadAllBytesAsync(configPath, ct);
        Assert.Equal(Environment.GetEnvironmentVariable("SLI_AUTH_CONFIG_SHA256"), Convert.ToHexStringLower(SHA256.HashData(config)));
        using var parsed = JsonDocument.Parse(config);
        string connectionString = parsed.RootElement.GetProperty("ConnectionStrings").GetProperty("Sli").GetString()!;
        string label = "netprogram_" + Guid.NewGuid().ToString("N");
        await using var connection = await database.OpenConnectionAsync(ct);
        var previous = new HashSet<long>();
        await using (var before = new NpgsqlCommand("select id from auth_users where username like 'report-key-%'", connection))
        await using (var reader = await before.ExecuteReaderAsync(ct))
            while (await reader.ReadAsync(ct)) previous.Add(reader.GetInt64(0));
        try
        {
            var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH")!)
            { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
            start.ArgumentList.Add(typeof(Program).Assembly.Location);
            foreach (string value in new[] { "issue-report-key", "--label", label, "--domain-id", "101" }) start.ArgumentList.Add(value);
            start.Environment["ConnectionStrings__Sli"] = connectionString;
            using var child = Process.Start(start)!;
            Task<string> output = child.StandardOutput.ReadToEndAsync(ct);
            Task<string> metadata = child.StandardError.ReadToEndAsync(ct);
            await child.WaitForExitAsync(ct);
            string token = await output;
            string metadataText = await metadata;
            Assert.Equal(0, child.ExitCode);
            Assert.StartsWith("adl_", token);
            Assert.DoesNotContain("\n", token);
            Assert.DoesNotContain(token, metadataText);
            using var metadataJson = JsonDocument.Parse(metadataText);
            Assert.True(metadataJson.RootElement.GetProperty("id").GetInt64() > 0);
            using var host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
                builder.ConfigureAppConfiguration((_, settings) =>
                {
                    settings.AddJsonStream(new MemoryStream(config));
                    settings.AddInMemoryCollection(new Dictionary<string, string?> {
                        ["Sli:TrustedProxies"] = "", ["Sli:AuthRequired"] = "1",
                        ["Sli:AllowUnauthenticated"] = "1", ["Sli:OwnerSetup"] = "0",
                        ["Sli:AuthAllowInsecureHttp"] = "1" });
                }));
            host.UseKestrel(options => options.Listen(IPAddress.Loopback, 0));
            host.StartServer();
            string address = Assert.Single(host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
            Assert.True(new Uri(address).IsLoopback);
            using var client = new HttpClient { BaseAddress = new Uri(address) };
            using var blocked = new HttpRequestMessage(HttpMethod.Post, "/api/auth/login");
            blocked.Headers.Add("X-ADLog-API-Key", token);
            using var blockedResponse = await client.SendAsync(blocked, ct);
            Assert.Equal(HttpStatusCode.Forbidden, blockedResponse.StatusCode);
            using var missing = new HttpRequestMessage(HttpMethod.Get, "/api/v1/events/9223372036854775807");
            missing.Headers.Add("X-ADLog-API-Key", token);
            using var missingResponse = await client.SendAsync(missing, ct);
            Assert.Equal(HttpStatusCode.NotFound, missingResponse.StatusCode);
            using var body = JsonDocument.Parse(await missingResponse.Content.ReadAsByteArrayAsync(ct));
            Assert.Equal("event_not_found", body.RootElement.GetProperty("error").GetString());
        }
        finally
        {
            // The dedicated fixture is exclusively leased; delete only subjects
            // created during this invocation and verify that any key has our label.
            var created = new List<long>();
            await using (var query = new NpgsqlCommand("select id from auth_users where username like 'report-key-%'", connection))
            await using (var reader = await query.ExecuteReaderAsync(CancellationToken.None))
                while (await reader.ReadAsync(CancellationToken.None)) if (!previous.Contains(reader.GetInt64(0))) created.Add(reader.GetInt64(0));
            foreach (long id in created)
            {
                await using var cleanup = new NpgsqlCommand("""
                    delete from auth_sessions where user_id=@id;
                    delete from access_report_assignments where subject_type='user' and subject_id=@id;
                    delete from access_capability_assignments where subject_type='user' and subject_id=@id;
                    delete from auth_api_keys where report_subject_id=@id and label=@label;
                    delete from auth_users where id=@id and username like 'report-key-%'
                    """, connection);
                cleanup.Parameters.AddWithValue("id", id);
                cleanup.Parameters.AddWithValue("label", label);
                await cleanup.ExecuteNonQueryAsync(CancellationToken.None);
            }
        }
    }
}
