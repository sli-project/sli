using Sli.Server.Auth.ReportKeys;
using Sli.Server.Auth.Commands;
using Sli.Server.Auth;
using Sli.Server.Auth.Administration;
using Sli.Server.Auth.Administration.ApiKeys;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Access.Administration;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Integration;
using Npgsql;
using System.Numerics;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Sli.Server.Tests.Auth;

public sealed class ReportKeyLifecycleTests
{
    private sealed class Connections(SyntheticDatabase db) : IPostgresConnectionFactory
    { public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => db.OpenConnectionAsync(ct); }
    private sealed class FailCapabilityConnection(IPostgresConnectionFactory inner) : IPostgresConnectionFactory
    {
        private int count;
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => ++count == 2
            ? throw new InvalidOperationException("synthetic_capability_failure") : inner.OpenAsync(ct);
    }
    private sealed class FailKey(IApiKeyAdministration inner) : IApiKeyAdministration
    {
        public Task<ApiKeyIssueResult> IssueAsync(IssueApiKeyCommand command, UserAdministrationActor actor, CancellationToken ct) => throw new InvalidOperationException("synthetic_key_failure");
        public Task<IReadOnlyList<JsonElement>> ListAsync(CancellationToken ct) => inner.ListAsync(ct);
        public Task<bool> RevokeAsync(BigInteger id, UserAdministrationActor actor, CancellationToken ct) => inner.RevokeAsync(id, actor, ct);
    }
    private sealed class FailKeyAudit(IAuthAudit inner) : IAuthAudit
    {
        public Task WriteAsync(AuthAuditEvent item, CancellationToken ct) => inner.WriteAsync(item, ct);
        public Task AppendAsync(NpgsqlTransaction transaction, AuthAuditEvent item, CancellationToken ct) =>
            item.Action.StartsWith("api_key_issued:", StringComparison.Ordinal)
                ? throw new InvalidOperationException("synthetic_key_audit_failure") : inner.AppendAsync(transaction, item, ct);
    }
    private sealed class FailUserAudit(IAuthAudit inner) : IAuthAudit
    {
        public Task WriteAsync(AuthAuditEvent item, CancellationToken ct) => inner.WriteAsync(item, ct);
        public Task AppendAsync(NpgsqlTransaction transaction, AuthAuditEvent item, CancellationToken ct) =>
            item.Action.StartsWith("user_created:", StringComparison.Ordinal)
                ? throw new InvalidOperationException("synthetic_subject_audit_failure") : inner.AppendAsync(transaction, item, ct);
    }
    private sealed class CapturingUsers(IUserAdministration inner) : IUserAdministration
    {
        public long Id;
        public async Task<JsonElement> CreateAsync(CreateUserCommand command, UserAdministrationActor actor, CancellationToken ct)
        { var user = await inner.CreateAsync(command, actor, ct); Id = user.GetProperty("id").GetInt64(); return user; }
        public Task<JsonElement> UpdateAsync(UpdateUserCommand command, UserAdministrationActor actor, CancellationToken ct) => inner.UpdateAsync(command, actor, ct);
        public Task<IReadOnlyList<JsonElement>> ListAsync(CancellationToken ct) => inner.ListAsync(ct);
        public Task<JsonElement> ResetPasswordAsync(BigInteger userId, string password, UserAdministrationActor actor, CancellationToken ct) => inner.ResetPasswordAsync(userId, password, actor, ct);
    }
    private sealed class FailSecondAssignment(IReportAssignmentWriter inner) : IReportAssignmentWriter
    {
        private int count;
        public Task<ReportAssignmentResult> CreateAsync(ReportAssignmentCommand command, AssignmentActor? actor, string? remoteAddress, CancellationToken ct) =>
            ++count == 2 ? throw new InvalidOperationException("synthetic_assignment_failure") : inner.CreateAsync(command, actor, remoteAddress, ct);
    }
    private sealed class TerminalOutput(bool redirected = false) : IAuthConsoleIO
    {
        public TextWriter Output { get; } = new StringWriter();
        public TextWriter Error { get; } = new StringWriter();
        public bool CanPromptPassword => false;
        public bool IsOutputRedirected => redirected;
        public Task<string> ReadPasswordAsync(string prompt, CancellationToken ct) => throw new NotSupportedException();
    }

    private sealed class Issuer : IReportKeyAdministration
    {
        public IssueReportKeyCommand? Received;
        public Task<ReportKeyIssueResult> IssueAsync(IssueReportKeyCommand command, CancellationToken ct)
        {
            Received = command;
            return Task.FromResult(new ReportKeyIssueResult(17, new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), command.DomainId, "synthetic-secret"));
        }
    }
    private sealed class BrokenOutput : IAuthConsoleIO
    {
        private sealed class BrokenWriter : StringWriter { public override void Write(string? value) => throw new IOException("synthetic output failure"); }
        public TextWriter Output { get; } = new BrokenWriter();
        public TextWriter Error { get; } = new StringWriter();
        public bool CanPromptPassword => false;
        public bool IsOutputRedirected => true;
        public Task<string> ReadPasswordAsync(string prompt, CancellationToken ct) => throw new NotSupportedException();
    }

    [Fact]
    public async Task TerminalOutputIsRejectedBeforeResolvingIssuer()
    {
        var io = new TerminalOutput();
        var console = new AuthConsole(() => throw new InvalidOperationException(), () => throw new InvalidOperationException(), io,
            () => throw new InvalidOperationException());
        Assert.Equal(1, await console.RunAsync(["issue-report-key", "--label", "owned", "--domain-id", "1"], TestContext.Current.CancellationToken));
        Assert.Equal("report_key_requires_protected_output_pipe", io.Error.ToString()!.Trim());
    }

    [Fact]
    public async Task ProtectedPipeReceivesOnlySecretAndMetadataGoesToError()
    {
        var io = new TerminalOutput(true); var issuer = new Issuer();
        var console = new AuthConsole(() => throw new InvalidOperationException(), () => throw new InvalidOperationException(), io, () => issuer);
        Assert.Equal(0, await console.RunAsync(["issue-report-key", "--label", "owned", "--domain-id", "7", "--hours", "48", "--workstation-agent-id", "a", "--workstation-agent-id", "b"], TestContext.Current.CancellationToken));
        Assert.NotNull(issuer.Received); Assert.Equal(2, issuer.Received.WorkstationAgentIds.Length);
        Assert.True(io.Output.ToString() == "synthetic-secret");
        Assert.False(io.Error.ToString()!.Contains("synthetic-secret", StringComparison.Ordinal));
        using var metadata = System.Text.Json.JsonDocument.Parse(io.Error.ToString()!);
        Assert.Equal(17, metadata.RootElement.GetProperty("id").GetInt64());
        Assert.Equal(7, metadata.RootElement.GetProperty("domain_id").GetInt64());
    }

    [Fact]
    public async Task PublicationFailureOccursAfterIssuerReturns()
    {
        var issuer = new Issuer(); var io = new BrokenOutput();
        var console = new AuthConsole(() => throw new InvalidOperationException(), () => throw new InvalidOperationException(), io, () => issuer);
        await Assert.ThrowsAsync<ReportKeyPublicationException>(() => console.RunAsync(["issue-report-key", "--label", "owned", "--domain-id", "7"], TestContext.Current.CancellationToken));
        Assert.NotNull(issuer.Received);
    }
    [Theory]
    [InlineData(0)]
    [InlineData(169)]
    public async Task InvalidExpiryIsRejectedBeforeAnyProducer(int hours)
    {
        var service = new ReportKeyAdministration(null!, null!, null!, null!);
        await Assert.ThrowsAsync<ReportKeyException>(() => service.IssueAsync(new("synthetic", 1, hours, [], [], false), TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    public async Task RealIssuancePreservesStagesAndDisablesSubjectOnFailure(int failure)
    {
        var ct = TestContext.Current.CancellationToken;
        var binding = OwnedDatabaseBinding.FromEnvironment();
        Assert.Equal("7f76e02a-754d-435b-84d5-f16b96203c38", binding.RunId.ToString("D"));
        await using var db = await SyntheticDatabase.BorrowAsync(binding, ct);
        var connections = new Connections(db); var audit = new AuthAudit(connections);
        var users = new CapturingUsers(new UserAdministrationService(connections, new PasswordCodec(), failure == 8 ? new FailUserAudit(audit) : audit));
        IApiKeyAdministration keyService = new ApiKeyAdministrationService(connections, new CredentialTokens(), failure == 4 ? new FailKeyAudit(audit) : audit);
        if (failure == 2) keyService = new FailKey(keyService);
        IReportAssignmentWriter writer = new ReportAssignmentWriter(connections);
        if (failure == 1) writer = new FailSecondAssignment(writer);
        IPostgresConnectionFactory issuerConnections = failure == 3 ? new FailCapabilityConnection(connections) : connections;
        var service = new ReportKeyAdministration(issuerConnections, users, keyService, writer);
        await using var connection = await db.OpenConnectionAsync(ct);
        long domain;
        await using (var q = new NpgsqlCommand("select id from domains order by id limit 1", connection)) domain = Convert.ToInt64(await q.ExecuteScalarAsync(ct));
        string[] fileAgents = [];
        string[] stations = [];
        string? fileHost = null;
        if (failure is 5 or 6)
        {
            using var fixture = JsonDocument.Parse(await File.ReadAllBytesAsync(Environment.GetEnvironmentVariable("SLI_REPORT_AGENT_FIXTURE")!, ct));
            domain = fixture.RootElement.GetProperty("domain").GetInt64(); fileAgents = [fixture.RootElement.GetProperty("agent").GetString()!];
            fileHost = fixture.RootElement.GetProperty("host").GetString();
            if (failure == 6)
            {
                await using var other = new NpgsqlCommand("select id from domains where id<>@id order by id limit 1", connection);
                other.Parameters.AddWithValue("id", domain); domain = Convert.ToInt64(await other.ExecuteScalarAsync(ct));
                Assert.True(domain > 0);
            }
        }
        if (failure == 7)
        {
            using var fixture = JsonDocument.Parse(await File.ReadAllBytesAsync(Environment.GetEnvironmentVariable("SLI_REPORT_STATION_FIXTURE")!, ct));
            domain = fixture.RootElement.GetProperty("domain").GetInt64(); stations = [fixture.RootElement.GetProperty("agent").GetString()!];
            fileHost = fixture.RootElement.GetProperty("host").GetString();
        }
        string label = "netreport_" + Guid.NewGuid().ToString("N");
        Exception? primaryFailure = null;
        try
        {
            if (failure == 8)
            {
                async Task<long> CountSubjects()
                {
                    await using var count = new NpgsqlCommand("select count(*) from auth_users where username like 'report-key-%'", connection);
                    return Convert.ToInt64(await count.ExecuteScalarAsync(ct));
                }
                long before = await CountSubjects();
                await Assert.ThrowsAsync<InvalidOperationException>(() => service.IssueAsync(new(label, domain, 24, [], [], false), ct));
                Assert.Equal(0, users.Id); Assert.Equal(before, await CountSubjects());
                return;
            }
            if (failure == 6)
            {
                await Assert.ThrowsAsync<ReportKeyException>(() => service.IssueAsync(new(label, domain, 24, fileAgents, [], false), ct));
                Assert.Equal(0, users.Id);
                return;
            }
            ReportKeyIssueResult? result = null;
            if (failure is >= 1 and <= 4) await Assert.ThrowsAsync<InvalidOperationException>(() => service.IssueAsync(new(label, domain, 24, fileAgents, [], false), ct));
            else result = await service.IssueAsync(new(label, domain, 24, fileAgents, stations, failure == 7), ct);
            Assert.True(users.Id > 0);
            await using var q = new NpgsqlCommand("select is_active,(select count(*) from auth_api_keys where report_subject_id=@id),(select count(*) from access_report_assignments where subject_type='user' and subject_id=@id),(select count(*) from access_capability_assignments where subject_type='user' and subject_id=@id) from auth_users where id=@id", connection);
            q.Parameters.AddWithValue("id", users.Id); await using var reader = await q.ExecuteReaderAsync(ct); Assert.True(await reader.ReadAsync(ct));
            bool success = failure is 0 or 5 or 7;
            Assert.Equal(success, reader.GetBoolean(0)); Assert.Equal(success ? 1 : 0, reader.GetInt64(1));
            Assert.Equal(failure switch { 1 => 1, 3 => 0, 5 => 16, 7 => 4, _ => 8 }, reader.GetInt64(2));
            Assert.Equal(failure != 3, reader.GetInt64(3) > 0);
            await reader.DisposeAsync();
            if (success)
            {
                Assert.True(result!.Token.Length > 4 && StringComparer.Ordinal.Equals(result.Token[..4], "adl_"));
                var context = new DefaultHttpContext(); context.Request.Method = "GET"; context.Request.Path = "/api/v1/events/1";
                context.Request.Headers.Authorization = "Bearer " + result.Token;
                var authenticated = await new PrincipalAuthenticator(connections).AuthenticateAsync(context, ct);
                Assert.NotNull(authenticated.Principal); Assert.True(authenticated.Principal.RestrictedReportKey);
                Assert.Equal(users.Id, authenticated.Principal.ReportSubjectId);
                if (failure == 0)
                {
                    string session = await new SessionLifecycle(connections, new CredentialTokens(), TimeProvider.System)
                        .IssueAsync(new("session", users.Id, "viewer"), false, ct);
                    async Task<AuthenticationResult> Authenticate(string bearer, string? x, bool cookie)
                    {
                        var request = new DefaultHttpContext(); request.Request.Method = "GET"; request.Request.Path = "/api/v1/events/1";
                        request.Request.Headers.Authorization = "Bearer " + bearer;
                        if (x is not null) request.Request.Headers["X-ADLog-API-Key"] = x;
                        if (cookie) request.Request.Headers.Cookie = "adlog_session=" + session;
                        return await new PrincipalAuthenticator(connections).AuthenticateAsync(request, ct);
                    }
                    Assert.True((await Authenticate(result.Token, null, true)).Principal?.RestrictedReportKey == true);
                    Assert.True((await Authenticate("adl_invalid", result.Token, true)).Principal?.RestrictedReportKey == true);
                    Assert.Equal("session", (await Authenticate("adl_invalid", "adl_invalid", true)).Principal?.Type);
                    async Task SetState(string sql)
                    {
                        await using var change = new NpgsqlCommand(sql, connection);
                        change.Parameters.AddWithValue("id", result.Id); change.Parameters.AddWithValue("user", users.Id);
                        await change.ExecuteNonQueryAsync(ct);
                    }
                    await SetState("update auth_api_keys set expires_at=now()-interval '1 second' where id=@id");
                    Assert.False((await Authenticate(result.Token, null, false)).Succeeded);
                    await SetState("update auth_api_keys set expires_at=now()+interval '1 day',revoked_at=now() where id=@id");
                    Assert.False((await Authenticate(result.Token, null, false)).Succeeded);
                    await SetState("update auth_api_keys set revoked_at=null where id=@id; update auth_users set is_active=false where id=@user");
                    Assert.False((await Authenticate(result.Token, null, false)).Succeeded);
                }
            }
            if (failure == 5)
            {
                await using var scope = new NpgsqlCommand("select count(*) from access_report_assignments where subject_type='user' and subject_id=@id and report_key like 'file-audit.%' and scope_json->>'mode'='restricted' and scope_json->'clauses'->0->'plugin_ids' = '[\"sli.file-audit\"]'::jsonb and scope_json->'clauses'->0->'source_instance_ids' = jsonb_build_array(@host::text)", connection);
                scope.Parameters.AddWithValue("id", users.Id); scope.Parameters.AddWithValue("host", fileHost!);
                Assert.Equal(8, Convert.ToInt64(await scope.ExecuteScalarAsync(ct)));
            }
            if (failure == 7)
            {
                await using var scope = new NpgsqlCommand("select count(*) from access_report_assignments where subject_type='user' and subject_id=@id and report_key like 'workstations.%' and scope_json->>'mode'='restricted' and scope_json->'clauses'->0->'plugin_ids' = '[\"sli.workstations\"]'::jsonb and scope_json->'clauses'->0->'source_instance_ids' = jsonb_build_array(@host::text)", connection);
                scope.Parameters.AddWithValue("id", users.Id); scope.Parameters.AddWithValue("host", fileHost!);
                Assert.Equal(4, Convert.ToInt64(await scope.ExecuteScalarAsync(ct)));
            }
        }
        catch (Exception error) { primaryFailure = error; throw; }
        finally
        {
            if (users.Id > 0)
            {
                var failures = new List<string>();
                foreach (var step in new[] {
                    ("sessions", "delete from auth_sessions where user_id=@id"),
                    ("grants", "delete from access_report_assignments where subject_type='user' and subject_id=@id"),
                    ("capabilities", "delete from access_capability_assignments where subject_type='user' and subject_id=@id"),
                    ("keys", "delete from auth_api_keys where report_subject_id=@id and label=@label"),
                    ("subject", "delete from auth_users where id=@id and username like 'report-key-%'") })
                {
                    try
                    {
                        await using var cleanup = new NpgsqlCommand(step.Item2, connection);
                        cleanup.Parameters.AddWithValue("id", users.Id); cleanup.Parameters.AddWithValue("label", label);
                        await cleanup.ExecuteNonQueryAsync(CancellationToken.None);
                    }
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

    [Fact]
    public Task IssuedReportKeyAuthenticationAndFallback() => RealIssuancePreservesStagesAndDisablesSubjectOnFailure(0);

    [Fact]
    public Task SubjectCreationAuditFailureRollsBack() => RealIssuancePreservesStagesAndDisablesSubjectOnFailure(8);
}
