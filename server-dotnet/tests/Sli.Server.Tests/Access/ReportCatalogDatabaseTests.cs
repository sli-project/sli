using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Access;

public sealed class ReportCatalogDatabaseTests
{
    [Fact]
    public async Task ExistingProgramHttpAndSoleWriterUseRealGenerationFilesAndRollbackStaleGenericGrant()
    {
        var ct = TestContext.Current.CancellationToken;
        var binding = OwnedDatabaseBinding.FromEnvironment();
        Assert.Equal(binding.RunId.ToString("D"), Environment.GetEnvironmentVariable("SLI_CATALOG_EXCLUSIVE_RUN"));
        string evidence = Environment.GetEnvironmentVariable("SLI_CATALOG_EVIDENCE_DIR") ?? throw new InvalidOperationException("Owned evidence required");
        string marker = "catalog_" + Guid.NewGuid().ToString("N");
        await File.WriteAllTextAsync(Path.Combine(evidence, "intent.json"), JsonSerializer.Serialize(new
        { marker, run_id = binding.RunId, side = binding.Side, scope = "two own users/sessions/capabilities/report assignments; no base mutation" }), ct);
        await using var database = await SyntheticDatabase.BorrowAsync(binding, ct);
        Assert.Equal(300, (await database.ReadBaselineAsync(ct)).SchemaVersion);
        byte[] config = await File.ReadAllBytesAsync(Path.Combine(binding.Root, binding.RunId.ToString("D"), "dotnet", "dotnet-test-config.json"), ct);
        Assert.Equal(Environment.GetEnvironmentVariable("SLI_AUTH_CONFIG_SHA256"), Convert.ToHexStringLower(SHA256.HashData(config)));
        var factory = new PostgresConnectionFactory(new ConfigurationBuilder().AddJsonStream(new MemoryStream(config)).Build());
        using var files = new ReportCatalogLifecycleTests.CatalogFiles();
        long admin = 0, target = 0;
        var ownUsers = new List<long>();
        string adminSession = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        string targetSession = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        var observations = new List<object>();
        string? baseOwnerState = null;
        try
        {
            await using (var connection = await database.OpenConnectionAsync(ct))
            {
                await using var identity = new NpgsqlCommand("select current_user", connection);
                Assert.Equal("adlog_user", await identity.ExecuteScalarAsync(ct));
                await using var before = new NpgsqlCommand("select jsonb_build_object('owners',(select jsonb_agg(user_id order by user_id) from access_platform_owners),'active_admins',(select count(*) from auth_users where role='admin' and is_active))::text", connection);
                baseOwnerState = (string)(await before.ExecuteScalarAsync(ct))!;
                async Task<long> User(string suffix, string role, string token)
                {
                    long proposed = 8_000_000_000L + RandomNumberGenerator.GetInt32(int.MaxValue);
                    await using var insert = new NpgsqlCommand("insert into auth_users(id,username,password_hash,role) values(@id,@name,'synthetic-no-password',@role) returning id", connection);
                    insert.Parameters.AddWithValue("id", proposed);
                    insert.Parameters.AddWithValue("name", marker + suffix); insert.Parameters.AddWithValue("role", role);
                    long id = Convert.ToInt64(await insert.ExecuteScalarAsync(ct));
                    ownUsers.Add(id);
                    await File.WriteAllTextAsync(Path.Combine(evidence, "own-users.json"), JsonSerializer.Serialize(new { marker, ids = ownUsers }), ct);
                    await using var session = new NpgsqlCommand("insert into auth_sessions(id,user_id,token_hash,expires_at) values(@id,@id,@hash,now()+interval '1 hour')", connection);
                    session.Parameters.AddWithValue("id", id); session.Parameters.AddWithValue("hash", Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token))));
                    await session.ExecuteNonQueryAsync(ct); return id;
                }
                admin = await User("_admin", "admin", adminSession);
                target = await User("_target", "viewer", targetSession);
                await using var setup = new NpgsqlCommand("""
                    insert into access_capability_assignments(id,subject_type,subject_id,capability_id,effect,scope_json,business_reason)
                    select @target+row_number() over(),'user',@target,id,'allow','{"kind":"all"}'::jsonb,@marker from access_capabilities where capability_key=any(array['workspace.view','field.identity_basic','field.security','field.technical']);
                    insert into access_capability_assignments(id,subject_type,subject_id,capability_id,effect,scope_json,business_reason)
                    select @admin,'user',@admin,id,'allow','{"kind":"all"}',@marker from access_capabilities where capability_key='reports.assign';
                    insert into access_report_assignments(id,subject_type,subject_id,report_key,effect,scope_json,business_reason)
                    select @target+row_number() over(),'user',@target,report_key,'deny','{"kind":"all"}',@marker from (select distinct report_key from report_registry_v4 where report_key<>'ad.state') r
                    """, connection);
                setup.Parameters.AddWithValue("admin", admin); setup.Parameters.AddWithValue("target", target); setup.Parameters.AddWithValue("marker", marker);
                await setup.ExecuteNonQueryAsync(ct);
            }
            using var host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                builder.ConfigureAppConfiguration((_, settings) =>
                {
                    settings.AddJsonStream(new MemoryStream(config));
                    settings.AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:TrustedProxies"] = "", ["Sli:AuthRequired"] = "1",
                        ["Sli:AllowUnauthenticated"] = "1", ["Sli:OwnerSetup"] = "0", ["Sli:AuthAllowInsecureHttp"] = "1" });
                });
                // Proposed typed DI hook only; actual Program bytes remain unchanged.
                builder.ConfigureServices(services =>
                {
                    services.AddSingleton<IReportCatalogProvider>(files.Catalog);
                });
            });
            host.UseKestrel(options => options.Listen(IPAddress.Loopback, 0));
            host.StartServer();
            string address = Assert.Single(host.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses);
            Assert.True(new Uri(address).IsLoopback);
            using var client = new HttpClient(new HttpClientHandler { UseCookies = false }) { BaseAddress = new Uri(address) };
            async Task<(HttpStatusCode Status, JsonElement Body)> Send(string path, string session, object? payload = null)
            {
                using var request = new HttpRequestMessage(payload is null ? HttpMethod.Get : HttpMethod.Post, path);
                request.Headers.Add("Cookie", "adlog_session=" + session);
                if (payload is not null) request.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                using var response = await client.SendAsync(request, ct);
                using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
                return (response.StatusCode, body.RootElement.Clone());
            }
            object Payload(string report, object scope, string[] fields) => new { subject_type = "user", subject_id = target,
                report_key = report, scope, field_categories = fields, allowed_actions = new[] { "view" }, business_reason = marker };
            var domainPayload = Payload("ad.state", new { kind = "domain", ids = new[] { 101 } }, ["identity_basic", "security", "technical"]);
            Assert.Equal(HttpStatusCode.Created, (await Send("/api/v1/access/assignments", adminSession, domainPayload)).Status);
            async Task Domains(string stage, bool granted)
            {
                var response = await Send("/api/v1/domains", targetSession);
                Assert.Equal(HttpStatusCode.OK, response.Status);
                var domains = response.Body.GetProperty("items").EnumerateArray().ToArray();
                Assert.Equal(granted ? 1 : 0, domains.Length);
                if (granted) Assert.Equal(101, domains[0].GetProperty("id").GetInt64());
                observations.Add(new { stage, domains = domains.Length, current_user = "adlog_user" });
            }
            await Domains("baseline", true);
            files.Fence("sli.ad"); await Domains("drain", false);
            files.Activate("sli.ad", new string('c', 64)); files.Unfence("sli.ad"); await Domains("unknown", false);
            files.Rollback("sli.ad"); await Domains("rollback", true);

            var generic = Payload("file-audit.overview", new { mode = "all", clauses = Array.Empty<object>() }, []);
            Assert.Equal(HttpStatusCode.Created, (await Send("/api/v1/access/assignments", adminSession, generic)).Status);
            long assignments = await Count("access_report_assignments", "business_reason");
            long audits = await Count("access_audit_v4", "reason");
            files.Fence("sli.file-audit");
            var rejected = await Send("/api/v1/access/assignments", adminSession, generic);
            Assert.Equal(HttpStatusCode.BadRequest, rejected.Status);
            Assert.Equal("scope_not_supported_by_dataset", rejected.Body.GetProperty("error").GetString());
            Assert.Single(rejected.Body.EnumerateObject());
            files.Unfence("sli.file-audit");
            var publishing = new PublishDuringValidation(files.Catalog, () => files.Fence("sli.file-audit"));
            var writer = new ReportAssignmentWriter(factory, publishing);
            var error = await Assert.ThrowsAsync<AssignmentValidationException>(() => writer.CreateAsync(new(JsonSerializer.SerializeToElement(generic)), new("session", admin), "127.0.0.1", ct));
            Assert.Equal("scope_not_supported_by_dataset", error.Message);
            Assert.Equal(assignments, await Count("access_report_assignments", "business_reason"));
            Assert.Equal(audits, await Count("access_audit_v4", "reason"));
            observations.Add(new { stage = "injected-fence-before-commit", assignments, audits, rollback = true });

            async Task<long> Count(string table, string column)
            {
                await using var connection = await database.OpenConnectionAsync(ct);
                await using var command = new NpgsqlCommand("select count(*) from " + table + " where " + column + "=@marker", connection);
                command.Parameters.AddWithValue("marker", marker); return Convert.ToInt64(await command.ExecuteScalarAsync(ct));
            }
        }
        finally
        {
            await using var connection = await database.OpenConnectionAsync(CancellationToken.None);
            await using var cleanup = new NpgsqlCommand("""
                delete from access_audit_v4 where reason=@marker;
                delete from access_report_assignments where subject_type='user' and subject_id=any(@users) and business_reason=@marker;
                delete from access_capability_assignments where subject_type='user' and subject_id=any(@users) and business_reason=@marker;
                delete from auth_sessions where user_id=any(@users);
                delete from auth_users where id=any(@users) and username in (@admin_name,@target_name)
                """, connection);
            cleanup.Parameters.AddWithValue("marker", marker); cleanup.Parameters.AddWithValue("users", ownUsers.ToArray());
            cleanup.Parameters.AddWithValue("admin_name", marker + "_admin"); cleanup.Parameters.AddWithValue("target_name", marker + "_target");
            await cleanup.ExecuteNonQueryAsync(CancellationToken.None);
            await using var verify = new NpgsqlCommand("""
                select jsonb_build_object(
                  'users',(select count(*) from auth_users where username in (@admin_name,@target_name)),
                  'sessions',(select count(*) from auth_sessions where user_id=any(@users)),
                  'assignments',(select count(*) from access_report_assignments where business_reason=@marker),
                  'capabilities',(select count(*) from access_capability_assignments where business_reason=@marker),
                  'legacy_audits',(select count(*) from access_audit_v4 where reason=@marker),
                  'owners',(select jsonb_agg(user_id order by user_id) from access_platform_owners),
                  'active_admins',(select count(*) from auth_users where role='admin' and is_active))::text
                """, connection);
            verify.Parameters.AddWithValue("marker", marker); verify.Parameters.AddWithValue("users", ownUsers.ToArray());
            verify.Parameters.AddWithValue("admin_name", marker + "_admin"); verify.Parameters.AddWithValue("target_name", marker + "_target");
            var remaining = JsonSerializer.Deserialize<JsonElement>((string)(await verify.ExecuteScalarAsync(CancellationToken.None))!);
            foreach (string key in new[] { "users", "sessions", "assignments", "capabilities", "legacy_audits" }) Assert.Equal(0, remaining.GetProperty(key).GetInt64());
            if (baseOwnerState is not null)
            {
                var before = JsonSerializer.Deserialize<JsonElement>(baseOwnerState);
                Assert.True(JsonElement.DeepEquals(before.GetProperty("owners"), remaining.GetProperty("owners")));
                Assert.Equal(before.GetProperty("active_admins").GetInt64(), remaining.GetProperty("active_admins").GetInt64());
            }
            observations.Add(new { stage = "selective-cleanup", marker, sql = remaining, append_only_audit = "not deleted or rewritten; own mutable access_audit_v4 rows removed" });
            await File.WriteAllTextAsync(Path.Combine(evidence, "outcomes.json"), JsonSerializer.Serialize(observations), CancellationToken.None);
        }
        Assert.True(await database.SeedRestoredAsync(ct));
    }

    // Explicit injected host publication between validation and commit; all state
    // reads, report writes and audits still use the real filesystem/SQL producers.
    private sealed class PublishDuringValidation(IReportCatalogProvider inner, Action publish) : IReportCatalogProvider
    {
        private int checks;
        public ReportCatalogSnapshot Capture() => inner.Capture();
        public ReportCatalogSnapshot Recheck(ReportCatalogSnapshot captured)
        { if (++checks == 2) publish(); return inner.Recheck(captured); }
    }
}
