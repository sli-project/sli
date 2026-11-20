using System.Text.Json;
using Sli.Server.Auth.ReportKeys;
using Xunit;
using Microsoft.AspNetCore.Http;
using Npgsql;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Access.Administration;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Integration;

namespace Sli.Server.Tests.Auth;

public sealed class ExactEventLegacyScopeTests
{
    private sealed class Connections(SyntheticDatabase db) : IPostgresConnectionFactory
    { public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => db.OpenConnectionAsync(ct); }
    [Theory]
    [InlineData("{\"kind\":\"domain\",\"ids\":[\"7\"]}", true)]
    [InlineData("{\"kind\":\"domain\",\"ids\":[\" +7 \" ]}", true)]
    [InlineData("{\"kind\":\"domain\",\"ids\":[\"٧\"],\"note\":\"ignored\"}", true)]
    [InlineData("{\"kind\":\"domain\",\"ids\":[\"0_7\"]}", true)]
    [InlineData("{\"kind\":\"all\",\"note\":\"ignored\"}", true)]
    [InlineData("{\"kind\":\"domain\",\"ids\":[\"0\"]}", false)]
    [InlineData("{\"kind\":\"domain\",\"ids\":[\"9223372036854775808\"]}", false)]
    [InlineData("{\"kind\":\"domain\",\"ids\":[\"bad\"]}", false)]
    [InlineData("{\"kind\":\"domain\",\"ids\":[\"7\",\"bad\"]}", false)]
    [InlineData("{\"kind\":\"other\"}", false)]
    [InlineData("{\"note\":\"all\"}", false)]
    [InlineData("{\"kind\":\"domain\",\"ids\":[true]}", false)]
    [InlineData("{\"kind\":\"domain\",\"ids\":[7.0]}", false)]
    public void LegacyDomainAndAllRespectSpecifiedBoundaries(string json, bool allowed)
    {
        using var scope = JsonDocument.Parse(json);
        Assert.Equal(allowed, ExactEventScope.AllowsDomain(scope.RootElement, 7));
    }

    [Fact]
    public async Task ActualAssignmentAndAuthenticatedReportKeyAllowLegacyStringDomain()
    {
        var ct = TestContext.Current.CancellationToken;
        var binding = OwnedDatabaseBinding.FromEnvironment();
        Assert.Equal("7f76e02a-754d-435b-84d5-f16b96203c38", binding.RunId.ToString("D"));
        await using var database = await SyntheticDatabase.BorrowAsync(binding, ct);
        var connections = new Connections(database);
        await using var db = await database.OpenConnectionAsync(ct);
        using var fixture = JsonDocument.Parse(await File.ReadAllBytesAsync(Environment.GetEnvironmentVariable("SLI_REPORT_EVENT_FIXTURE")!, ct));
        long eventId = fixture.RootElement.GetProperty("first").GetInt64();
        string marker = "netlegacy_" + Guid.NewGuid().ToString("N");
        var tokens = new CredentialTokens(); string token = "adl_" + tokens.NewSessionToken();
        long user = 0, key = 0; Exception? primaryFailure = null;
        try
        {
            await using (var q = new NpgsqlCommand("insert into auth_users(username,password_hash,role,is_service) values(@name,'synthetic-no-password','viewer',true) returning id", db))
            { q.Parameters.AddWithValue("name", marker); user = Convert.ToInt64(await q.ExecuteScalarAsync(ct)); }
            await using (var q = new NpgsqlCommand("insert into auth_api_keys(key_prefix,key_hash,label,role,report_subject_id) values(@prefix,@hash,@label,'viewer',@user) returning id", db))
            { q.Parameters.AddWithValue("prefix", token[..12]); q.Parameters.AddWithValue("hash", tokens.Digest(token)); q.Parameters.AddWithValue("label", marker); q.Parameters.AddWithValue("user", user); key = Convert.ToInt64(await q.ExecuteScalarAsync(ct)); }
            await using (var q = new NpgsqlCommand("insert into access_capability_assignments(subject_type,subject_id,capability_id,effect,scope_json,business_reason) select 'user',@user,id,'allow','{\"kind\":\"all\"}'::jsonb,@reason from access_capabilities where capability_key=any(@caps)", db))
            { q.Parameters.AddWithValue("user", user); q.Parameters.AddWithValue("reason", marker); q.Parameters.AddWithValue("caps", new[] { "events.view", "field.raw_evidence", "field.technical", "field.security", "evidence.exact" }); Assert.Equal(5, await q.ExecuteNonQueryAsync(ct)); }
            var payload = JsonSerializer.SerializeToElement(new { subject_type = "user", subject_id = user, report_key = "events.explorer", scope = new { kind = "domain", ids = new[] { "1" } }, field_categories = new[] { "raw_evidence", "technical", "security" }, allowed_actions = new[] { "view" }, business_reason = marker });
            var result = await new ReportAssignmentWriter(connections).CreateAsync(new(payload), new("local_operator", null), null, ct);
            Assert.Equal(JsonValueKind.String, result.Item.GetProperty("scope_json").GetProperty("ids")[0].ValueKind);
            var context = new DefaultHttpContext(); context.Request.Method = "GET"; context.Request.Path = "/api/v1/events/" + eventId; context.Request.Headers.Authorization = "Bearer " + token;
            var auth = await new PrincipalAuthenticator(connections).AuthenticateAsync(context, ct);
            Assert.NotNull(auth.Principal); Assert.True(auth.Principal.RestrictedReportKey);
            Assert.Null(await new ExactEventAuthorization(connections).CheckAsync(auth.Principal, context.Request.Path.Value!, ct));
        }
        catch (Exception error) { primaryFailure = error; throw; }
        finally
        {
            var failures = new List<string>();
            foreach (var step in new[] {
                ("grants", "delete from access_report_assignments where subject_type='user' and subject_id=@user and business_reason=@name"),
                ("capabilities", "delete from access_capability_assignments where subject_type='user' and subject_id=@user and business_reason=@name"),
                ("key", "delete from auth_api_keys where id=@key and label=@name"),
                ("subject", "delete from auth_users where id=@user and username=@name") })
            {
                try { await using var q = new NpgsqlCommand(step.Item2, db); q.Parameters.AddWithValue("name", marker); q.Parameters.AddWithValue("user", user); q.Parameters.AddWithValue("key", key); await q.ExecuteNonQueryAsync(CancellationToken.None); }
                catch (Exception) { failures.Add(step.Item1); }
            }
            if (failures.Count > 0)
            {
                string message = "owned_fixture_cleanup_failed:" + string.Join(',', failures);
                if (primaryFailure is null) throw new InvalidOperationException(message);
                primaryFailure.Data["cleanup"] = message;
            }
        }
    }
}
