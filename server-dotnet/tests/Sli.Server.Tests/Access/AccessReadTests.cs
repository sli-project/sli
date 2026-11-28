using System.Globalization;
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
using Sli.Server.Auth;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Integration;
using Xunit;

namespace Sli.Server.Tests.Access;

public sealed class AccessReadTests
{
    [Fact]
    public void TimestampContractPreservesRawReadStringsAndPydanticPrecisionWithoutTouchingAuditDetails()
    {
        var audit = JsonSerializer.SerializeToElement(AccessReadPresentation.Apply(new { items = new[] {
            new { created_at = "2026-01-02T03:04:05.123+00:00", details_json = new { created_at = "opaque-source-value" } } } }, "audit", "en"));
        Assert.Equal("2026-01-02 03:04:05.123000+00:00", audit.GetProperty("items")[0].GetProperty("created_at").GetString());
        Assert.Equal("opaque-source-value", audit.GetProperty("items")[0].GetProperty("details_json").GetProperty("created_at").GetString());
        var effective = JsonSerializer.SerializeToElement(AccessReadPresentation.Apply(new { evaluated_at_utc = "2026-01-02T03:04:05.123+00:00" }, "effective", "ru"));
        Assert.Equal("2026-01-02T03:04:05.123000Z", effective.GetProperty("evaluated_at_utc").GetString());
    }

    [Fact]
    public async Task GroupedAuditPreservesOriginalTimesAndKeepsChannelsAndAuthorsSeparate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(owner, """
            insert into access_audit_v4(actor_type,actor_id,action,target_type,target_key,reason,details_json,created_at)
            values ('session',1,'notification_channel_update','notification_channel','telegram','fixture','{"phase":"completed"}',now()),
                   ('session',1,'notification_channel_update','notification_channel','telegram','fixture','{"phase":"requested"}',now()-interval '2 minutes'),
                   ('session',1,'notification_channel_update','notification_channel','smtp','fixture','{}',now()),
                   ('system',null,'notification_channel_update','notification_channel','telegram','fixture','{}',now())
            """, ct);
        var reader = new AccessReadService(new AuditConnection(fixture));

        var raw = JsonSerializer.SerializeToElement(await reader.GetAuditAsync(100, ct));
        Assert.Equal(4, raw.GetProperty("items").EnumerateArray().Count(item => item.GetProperty("reason").GetString() == "fixture"));
        var result = await reader.GetAuditAsync(100, ct, collapse: true);
        var grouped = JsonSerializer.SerializeToElement(AccessReadPresentation.Apply(result, "audit", "en"));
        var rows = grouped.GetProperty("items").EnumerateArray()
            .Where(item => item.GetProperty("reason").GetString() == "fixture").ToArray();
        Assert.Equal(3, rows.Length);
        var telegram = Assert.Single(rows, row => row.GetProperty("actor_type").GetString() == "session"
            && row.GetProperty("target_key").GetString() == "telegram");
        var occurrences = telegram.GetProperty("occurrences").EnumerateArray().ToArray();
        Assert.Equal(2, occurrences.Length);
        Assert.NotEqual(occurrences[0].GetProperty("created_at").GetString(), occurrences[1].GetProperty("created_at").GetString());
        Assert.EndsWith("+00:00", occurrences[1].GetProperty("created_at").GetString());
    }

    private sealed class AuditConnection(SqlPostgresFixture fixture) : IPostgresConnectionFactory
    {
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => fixture.Pg.OpenAsync(ct, "adlog_user");
    }

    [Fact]
    public void FullReadProjectionMatchesIndependentFrozenPythonExports()
    {
        string directory = Environment.GetEnvironmentVariable("SLI_ACCESS_EXPORTS") ?? throw new InvalidOperationException("Explicit frozen facts required");
        foreach (string name in new[] { "owner-final", "scoped-final", "empty-final", "disjoint-final", "mixed-final" })
        {
            using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(directory, name + ".json")));
            var source = document.RootElement;
            var rows = source.GetProperty("facts");
            JsonElement[] Read(string key) => rows.TryGetProperty(key, out var values) ? values.EnumerateArray().Select(i => i.Clone()).ToArray() : [];
            var expected = source.GetProperty("composed_access"); var subject = expected.GetProperty("subject");
            var principal = new Principal(subject.GetProperty("type").GetString()!, subject.GetProperty("id").GetInt64(),
                subject.GetProperty("coarse_role").GetString()!, Username: subject.GetProperty("username").GetString());
            var facts = new AccessFacts(expected.GetProperty("platform_owner").GetBoolean(), principal.Role,
                Read("role_packages").Concat(Read("subject_packages")).Concat(Read("owner_packages")).ToArray(),
                Read("package_capabilities"), Read("direct_capabilities"), Read("all_capabilities"), Read("package_reports"), Read("report_assignments"), Read("definitions"))
                { Groups = Read("groups"), Requests = Read("requests"), Preferences = Read("preferences"),
                    EvaluatedAt = DateTimeOffset.Parse(expected.GetProperty("evaluated_at_utc").GetString()!, CultureInfo.InvariantCulture).UtcDateTime };
            var capabilities = new CapabilityComposer().Compose(facts);
            var actual = JsonSerializer.SerializeToElement(AccessReadProjection.Compose(principal, facts, capabilities,
                new ReportEligibility().Compose(facts, capabilities), false));
            EqualJson(expected, actual, name);
            string? messages = Environment.GetEnvironmentVariable("SLI_ACCESS_MESSAGE_EXPORTS");
            Assert.NotNull(messages);
            foreach (string locale in new[] { "ru", "en" })
            {
                using var localized = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(messages, name + "." + locale + ".json")));
                var rendered = JsonSerializer.SerializeToElement(AccessReadPresentation.Apply(actual, "effective", locale == "en" ? "ru;q=0.1,en-US;q=0.9" : "en;q=0.1,ru;q=1"));
                EqualJson(localized.RootElement, rendered, name + "." + locale);
            }
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RealHttpReadRoutesUseSqlIdentityPermissionsPreviewAndBoundedMetadata(bool kestrel)
    {
        var ct = TestContext.Current.CancellationToken;
        var binding = OwnedDatabaseBinding.FromEnvironment();
        await using var admitted = await SyntheticDatabase.BorrowAsync(binding, ct);
        byte[] config = await File.ReadAllBytesAsync(Path.Combine(binding.Root, binding.RunId.ToString("D"), binding.Side, "dotnet-test-config.json"), ct);
        Assert.Equal(Environment.GetEnvironmentVariable("SLI_AUTH_CONFIG_SHA256"), Convert.ToHexStringLower(SHA256.HashData(config)));
        string marker = "netread_" + Guid.NewGuid().ToString("N")[..16];
        string session = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        string key = "adl_" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        string viewerSession = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        long userId = 0, viewerId = 0, keyId = 0;
        string selectedReport = "";
        string Digest(string raw) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
        async Task<long> InsertUser(NpgsqlConnection connection, string suffix, string role)
        {
            await using var command = new NpgsqlCommand("insert into auth_users(username,password_hash,role,is_active,is_service) values(@name,'synthetic-unusable',@role,true,false) returning id", connection);
            command.Parameters.AddWithValue("name", marker + suffix); command.Parameters.AddWithValue("role", role);
            return Convert.ToInt64(await command.ExecuteScalarAsync(ct));
        }
        try
        {
            await using (var connection = await admitted.OpenConnectionAsync(ct))
            {
                userId = await InsertUser(connection, "_admin", "admin"); viewerId = await InsertUser(connection, "_viewer", "viewer");
                await using var command = new NpgsqlCommand("""
                    insert into auth_sessions(user_id,token_hash,expires_at) values(@user,@session,now()+interval '1 hour'),(@viewer,@viewer_session,now()+interval '1 hour');
                    insert into auth_api_keys(label,key_hash,key_prefix,role) values(@label,@key,@prefix,'viewer') returning id
                    """, connection);
                command.Parameters.AddWithValue("user", userId); command.Parameters.AddWithValue("viewer", viewerId);
                command.Parameters.AddWithValue("session", Digest(session)); command.Parameters.AddWithValue("viewer_session", Digest(viewerSession));
                command.Parameters.AddWithValue("label", marker); command.Parameters.AddWithValue("key", Digest(key)); command.Parameters.AddWithValue("prefix", key[..12]);
                keyId = Convert.ToInt64(await command.ExecuteScalarAsync(ct));
                // Explicit per-user grants must never leak into an ordinary key's
                // independent viewer identity (the source key table has no creator FK).
                await using var grants = new NpgsqlCommand("""
                    insert into access_capability_assignments(subject_type,subject_id,capability_id,effect,scope_json,source_type,business_reason)
                    select 'user',@id,id,'allow','{"kind":"all"}'::jsonb,'direct','Owned access read API test' from access_capabilities
                    where capability_key in ('workspace.view','access.manage','access.preview','reports.assign')
                    """, connection);
                grants.Parameters.AddWithValue("id", userId); await grants.ExecuteNonQueryAsync(ct);
                await using var metadata = new NpgsqlCommand("""
                    with selected as (
                      select r.report_key,r.version,d.version as dataset_version from report_registry_v4 r
                      join report_datasets_v4 d on d.id=r.dataset_id where r.status='published' and r.discoverable
                      order by r.report_key,r.version desc limit 1
                    ), preference as (
                      insert into user_report_preferences(user_id,report_key,pinned,view_json)
                      select @id,report_key,true,'{"focus_metric_keys":["owned.metric"]}'::jsonb from selected
                    )
                    insert into report_access_requests_v4(requester_user_id,report_key,report_version,dataset_version,
                      requested_scope_json,requested_valid_until,business_reason,requested_field_categories,requested_actions,status)
                    select @id,report_key,version,dataset_version,'{"kind":"all"}'::jsonb,now()+interval '1 day',
                      'Owned read projection fixture','{}'::text[],array['view'],'reviewing' from selected returning report_key
                    """, connection);
                metadata.Parameters.AddWithValue("id", userId); selectedReport = (string)(await metadata.ExecuteScalarAsync(ct))!;
            }
            using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, settings) =>
            {
                settings.AddJsonStream(new MemoryStream(config));
                settings.AddInMemoryCollection(new Dictionary<string, string?> { ["Sli:TrustedProxies"] = "", ["Sli:AuthRequired"] = "1", ["Logging:LogLevel:Default"] = "Warning" });
            }));
            if (kestrel) factory.UseKestrel(options => options.Listen(IPAddress.Loopback, 0));
            using var client = kestrel ? factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false, AllowAutoRedirect = false })
                : factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), HandleCookies = false, AllowAutoRedirect = false });
            if (kestrel)
            {
                var server = factory.Services.GetRequiredService<IServer>();
                client.BaseAddress = new Uri(Assert.Single(server.Features.Get<IServerAddressesFeature>()!.Addresses));
            }
            async Task<(HttpStatusCode Status, JsonElement Body)> Get(string path, string? cookie = null, string? apiKey = null)
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, path);
                if (cookie is not null) request.Headers.Add("Cookie", "adlog_session=" + cookie);
                if (apiKey is not null) request.Headers.Add("X-ADLog-API-Key", apiKey);
                using var response = await client.SendAsync(request, ct);
                Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
                using var body = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(ct));
                return (response.StatusCode, body.RootElement.Clone());
            }
            Assert.Equal(HttpStatusCode.Unauthorized, (await Get("/api/v1/access/effective")).Status);
            Assert.Equal(HttpStatusCode.Forbidden, (await Get("/api/v1/access/EFFECTIVE", session)).Status);
            Assert.Equal(HttpStatusCode.NotFound, (await Get("/api/v1/access/effective/", session)).Status);
            var effective = await Get("/api/v1/access/effective", session);
            Assert.Equal(HttpStatusCode.OK, effective.Status); Assert.Equal(userId, effective.Body.GetProperty("subject").GetProperty("id").GetInt64());
            Assert.Matches(@"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{6})?Z$", effective.Body.GetProperty("evaluated_at_utc").GetString()!);
            foreach (var field in new[] { "capability_explain", "capability_policies", "owner_policy", "package_explain", "reports", "navigation", "explicit_denies", "ignored_denies" }) Assert.True(effective.Body.TryGetProperty(field, out _));
            var personalized = Assert.Single(effective.Body.GetProperty("reports").EnumerateArray(), r => r.GetProperty("report_key").GetString() == selectedReport);
            Assert.True(personalized.GetProperty("pinned").GetBoolean()); Assert.True(personalized.GetProperty("focus_preference_configured").GetBoolean());
            Assert.Equal("owned.metric", Assert.Single(personalized.GetProperty("selected_optional_metric_keys").EnumerateArray()).GetString());
            Assert.Equal("reviewing", personalized.GetProperty("request").GetProperty("status").GetString());
            foreach (var report in effective.Body.GetProperty("reports").EnumerateArray())
                foreach (var grant in report.GetProperty("grants").EnumerateArray())
                { Assert.True(grant.TryGetProperty("validated_dataset_version", out _)); Assert.True(grant.TryGetProperty("scope", out _)); }
            var preview = await Get("/api/v1/access/effective?user_id=" + viewerId, session);
            Assert.Equal(HttpStatusCode.OK, preview.Status); Assert.True(preview.Body.GetProperty("preview").GetBoolean());
            Assert.Equal(viewerId, preview.Body.GetProperty("subject").GetProperty("id").GetInt64());
            Assert.Equal(HttpStatusCode.NotFound, (await Get("/api/v1/access/effective?user_id=-1", session)).Status);
            Assert.Equal(HttpStatusCode.BadRequest, (await Get("/api/v1/access/effective?user_id=bogus", session)).Status);
            Assert.False((await Get("/api/v1/access/effective?USER_ID=" + viewerId, session)).Body.GetProperty("preview").GetBoolean());
            Assert.False((await Get("/api/v1/access/effective?user_id=", session)).Body.GetProperty("preview").GetBoolean());
            Assert.Equal(HttpStatusCode.Forbidden, (await Get("/api/v1/access/effective?user_id=" + viewerId, viewerSession)).Status);
            Assert.Equal(HttpStatusCode.BadRequest, (await Get("/api/v1/access/subjects?account_type=people&account_type=service", session)).Status);
            foreach (string account in new[] { "all", "people", "service" })
            {
                var subjects = await Get("/api/v1/access/subjects?account_type=" + account, session);
                Assert.Equal(HttpStatusCode.OK, subjects.Status); Assert.Equal(500, subjects.Body.GetProperty("limits").GetProperty("subjects").GetInt32());
                if (account == "people") Assert.All(subjects.Body.GetProperty("users").EnumerateArray(), u => Assert.False(u.GetProperty("is_service").GetBoolean()));
                if (account == "service") Assert.All(subjects.Body.GetProperty("users").EnumerateArray(), u => Assert.True(u.GetProperty("is_service").GetBoolean()));
            }
            var options = await Get("/api/v1/access/grant-options", session);
            Assert.Equal(HttpStatusCode.OK, options.Status); Assert.NotEmpty(options.Body.GetProperty("items").EnumerateArray());
            var audit = await Get("/api/v1/access/audit?limit=99999999999999999999999999", session);
            Assert.Equal(HttpStatusCode.OK, audit.Status); Assert.Equal(500, audit.Body.GetProperty("limit").GetInt32());
            Assert.Equal("not_calculated", audit.Body.GetProperty("total_count").GetString());
            Assert.Equal(1, (await Get("/api/v1/access/audit?limit=-3", session)).Body.GetProperty("limit").GetInt32());
            Assert.Equal(10, (await Get("/api/v1/access/audit?limit=1_0", session)).Body.GetProperty("limit").GetInt32());
            Assert.Equal(10, (await Get("/api/v1/access/audit?limit=" + Uri.EscapeDataString("١٠"), session)).Body.GetProperty("limit").GetInt32());
            Assert.Equal(100, (await Get("/api/v1/access/audit?LIMIT=1", session)).Body.GetProperty("limit").GetInt32());
            Assert.Equal(100, (await Get("/api/v1/access/audit?limit=", session)).Body.GetProperty("limit").GetInt32());
            Assert.Equal("invalid literal for int() with base 10: '\\x00'", (await Get("/api/v1/access/audit?limit=%00", session)).Body.GetProperty("error").GetString());
            foreach (var item in audit.Body.GetProperty("items").EnumerateArray())
                Assert.Matches(@"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d{6})?\+00:00$", item.GetProperty("created_at").GetString()!);
            Assert.Equal(HttpStatusCode.BadRequest, (await Get("/api/v1/access/audit?limit=bad", session)).Status);
            foreach (string path in new[] { "subjects", "grant-options", "audit" })
            {
                Assert.Equal(HttpStatusCode.Forbidden, (await Get("/api/v1/access/" + path, viewerSession)).Status);
                Assert.Equal(HttpStatusCode.Forbidden, (await Get("/api/v1/access/" + path, apiKey: key)).Status);
            }
            var apiEffective = await Get("/api/v1/access/effective", apiKey: key);
            Assert.Equal(HttpStatusCode.OK, apiEffective.Status);
            Assert.Equal("api_key", apiEffective.Body.GetProperty("subject").GetProperty("type").GetString());
            Assert.False(apiEffective.Body.GetProperty("platform_owner").GetBoolean());
            Assert.DoesNotContain(apiEffective.Body.GetProperty("capabilities").EnumerateArray(), c => c.GetString() == "access.manage");
        }
        finally
        {
            await using var connection = await admitted.OpenConnectionAsync(ct);
            await using var cleanup = new NpgsqlCommand("""
                delete from access_capability_assignments where subject_type='user' and subject_id in (@user,@viewer);
                delete from auth_api_keys where id=@key and label=@marker;
                delete from auth_sessions where user_id in (@user,@viewer);
                delete from auth_users where id in (@user,@viewer) and username like @prefix
                """, connection);
            cleanup.Parameters.AddWithValue("user", userId); cleanup.Parameters.AddWithValue("viewer", viewerId); cleanup.Parameters.AddWithValue("key", keyId);
            cleanup.Parameters.AddWithValue("marker", marker); cleanup.Parameters.AddWithValue("prefix", marker + "%");
            await cleanup.ExecuteNonQueryAsync(ct);
        }
    }

    private static void EqualJson(JsonElement expected, JsonElement actual, string path)
    {
        Assert.True(expected.ValueKind == actual.ValueKind, path + ": value type");
        if (expected.ValueKind == JsonValueKind.Object)
        {
            Assert.Equal(expected.EnumerateObject().Select(p => p.Name).Order(), actual.EnumerateObject().Select(p => p.Name).Order());
            foreach (var property in expected.EnumerateObject()) EqualJson(property.Value, actual.GetProperty(property.Name), path + "." + property.Name);
        }
        else if (expected.ValueKind == JsonValueKind.Array)
        {
            Assert.True(expected.GetArrayLength() == actual.GetArrayLength(), path + ": array length");
            for (int i = 0; i < expected.GetArrayLength(); i++) EqualJson(expected[i], actual[i], path + "[" + i + "]");
        }
        else if (expected.ValueKind == JsonValueKind.String)
        {
            // Source fixture exporter uses +00:00; STJ emits Z. Compare the same
            // UTC instant only for declared timestamp fields, never other strings.
            if (path.EndsWith("evaluated_at_utc", StringComparison.Ordinal) || path.EndsWith("valid_from", StringComparison.Ordinal)
                || path.EndsWith("valid_until", StringComparison.Ordinal) || path.EndsWith("created_at", StringComparison.Ordinal)
                || path.EndsWith("updated_at", StringComparison.Ordinal))
                Assert.Equal(DateTimeOffset.Parse(expected.GetString()!, CultureInfo.InvariantCulture), DateTimeOffset.Parse(actual.GetString()!, CultureInfo.InvariantCulture));
            else Assert.True(expected.GetString() == actual.GetString(), path + ": string");
        }
        else Assert.True(expected.GetRawText() == actual.GetRawText(), path + ": scalar");
    }
}
