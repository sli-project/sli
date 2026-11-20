using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Administration;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Access;

// Vectors from tests/access/test_session_access_cache.py; each fixture owns its PG cluster.
public sealed class SessionAccessCacheTests
{
    static readonly Principal Viewer = new("session", 1, "viewer");
    static CancellationToken Ct => TestContext.Current.CancellationToken;

    sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
        public override long GetTimestamp() => Now.UtcTicks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    }

    sealed class Connections(PostCollectionPostgres pg) : IPostgresConnectionFactory
    {
        public int Opens;
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) { Opens++; return pg.OpenAsync(ct); }
    }

    sealed class Fixture : IAsyncDisposable
    {
        readonly PostCollectionPostgres pg = new(canonicalSchema: true);
        public readonly Clock Clock = new();
        public readonly Connections Connections;
        public readonly SessionAccessFactsCache Cache;
        public readonly CredentialTokens Tokens = new();
        public int Loads;
        public Fixture() { Connections = new(pg); Cache = new(Connections, Clock); }
        public async Task StartAsync()
        {
            await pg.StartAsync(Ct);
            await Sql("""
                create table access_audit_v4(id bigint primary key);
                insert into access_audit_v4 values(7);
                create table access_group_members(user_id bigint,group_id bigint,source text,valid_from timestamptz,valid_until timestamptz);
                create table access_subject_packages(subject_type text,subject_id bigint,package_id bigint,source_type text,effect text,valid_from timestamptz,valid_until timestamptz);
                create table access_capability_assignments(subject_type text,subject_id bigint,capability_id bigint,source_type text,effect text,scope_json jsonb,valid_from timestamptz,valid_until timestamptz);
                create table access_report_assignments(id bigint,subject_type text,subject_id bigint,report_key text,effect text,field_categories jsonb,allowed_actions jsonb,scope_json jsonb,source_type text,business_reason text,valid_from timestamptz,valid_until timestamptz);
                create table auth_users(id bigint primary key,username text,role text,is_active boolean default true,
                    password_hash text,created_at timestamptz default now(),updated_at timestamptz,last_login_at timestamptz);
                insert into auth_users(id,username,role) values(1,'synthetic-a','viewer'),(2,'synthetic-b','viewer');
                create table auth_sessions(id bigserial primary key,user_id bigint,token_hash text,expires_at timestamptz,revoked_at timestamptz,last_used_at timestamptz);
                create table auth_audit(id bigserial primary key,actor_type text,actor_id bigint,action text,outcome text,remote_address text,created_at timestamptz default now());
                """);
        }
        public async Task Sql(string sql)
        {
            await using var db = await pg.OpenAsync(Ct);
            await PostCollectionPostgres.Sql(db, sql, Ct);
        }
        public Task<AccessFacts> Load(string? token, Principal? principal = null) => Cache.LoadAsync(principal ?? Viewer, token,
            () => { Loads++; return Task.FromResult(new AccessFacts(false, "viewer", [], [], [], [], [], [], [])); }, Ct);
        public SessionLifecycle Sessions => new(Connections, Tokens, Clock, Cache);
        public ValueTask DisposeAsync() => pg.DisposeAsync();
    }

    [Fact]
    public async Task CachedFactsAreIndependentFromLoaderAndEveryReturnedCopy()
    {
        await using var f = new Fixture(); await f.StartAsync();
        var rows = new[] { JsonSerializer.SerializeToElement(new { allowed = true, nested = new[] { 1 } }) };
        var original = new AccessFacts(false, "viewer", rows, rows, rows, rows, rows, rows, rows)
            { Groups = rows, Requests = rows, Preferences = rows };
        int loads = 0;
        Task<AccessFacts> Loader() { loads++; return Task.FromResult(original); }
        Assert.Same(original, await f.Cache.LoadAsync(Viewer, "synthetic-a", Loader, Ct));
        rows[0] = JsonSerializer.SerializeToElement(new { allowed = false });
        var copy = await f.Cache.LoadAsync(Viewer, "synthetic-a", Loader, Ct);
        foreach (var list in new[] { copy.Packages, copy.PackageCapabilities, copy.DirectCapabilities, copy.AllCapabilities,
            copy.PackageReports, copy.ReportAssignments, copy.Definitions, copy.Groups, copy.Requests, copy.Preferences })
        {
            Assert.True(list[0].GetProperty("allowed").GetBoolean());
            Assert.Equal(1, list[0].GetProperty("nested")[0].GetInt32());
            Assert.IsType<JsonElement[]>(list)[0] = default;
        }
        var next = await f.Cache.LoadAsync(Viewer, "synthetic-a", Loader, Ct);
        Assert.All(new[] { next.Packages, next.PackageCapabilities, next.DirectCapabilities, next.AllCapabilities,
            next.PackageReports, next.ReportAssignments, next.Definitions, next.Groups, next.Requests, next.Preferences },
            list => Assert.True(list[0].GetProperty("allowed").GetBoolean()));
        Assert.Equal(1, loads);
    }

    [Fact]
    public async Task LeastRecentlyUsedEntryIsEvictedAndNonSessionsOrMissingTokensBypassCache()
    {
        await using var f = new Fixture(); await f.StartAsync();
        for (int i = 0; i < 256; i++) await f.Load($"synthetic-{i}");
        await f.Load("synthetic-0"); Assert.Equal(256, f.Loads);
        await f.Load("synthetic-256");
        await f.Load("synthetic-0"); Assert.Equal(257, f.Loads);
        await f.Load("synthetic-1"); Assert.Equal(258, f.Loads);
        int opens = f.Connections.Opens;
        foreach (var (principal, token) in new[] { (Viewer, (string?)null), (Viewer, ""),
            (Viewer with { Type = "api_key" }, "synthetic-api"), (Viewer with { Type = "local" }, "synthetic-local") })
        {
            await f.Load(token, principal); await f.Load(token, principal);
        }
        Assert.Equal(266, f.Loads); Assert.Equal(opens, f.Connections.Opens);
    }

    [Fact]
    public async Task BothFutureBoundariesOfEveryAssignmentTableAreObserved()
    {
        await using var f = new Fixture(); await f.StartAsync();
        foreach (string table in new[] { "access_group_members", "access_subject_packages", "access_capability_assignments", "access_report_assignments" })
        foreach (string column in new[] { "valid_from", "valid_until" })
        {
            // A distant DB-future value keeps this deterministic even on a slow CI host.
            f.Clock.Now = DateTimeOffset.UtcNow;
            await using (var db = await f.Connections.OpenAsync(Ct))
            await using (var insert = new NpgsqlCommand($"insert into {table}({column}) values(@at)", db))
            {
                insert.Parameters.AddWithValue("at", f.Clock.Now.AddDays(1)); await insert.ExecuteNonQueryAsync(Ct);
            }
            string token = $"synthetic-{table}-{column}";
            int before = f.Loads;
            await f.Load(token); await f.Load(token); Assert.Equal(before + 1, f.Loads);
            // First reload for the ordinary cache age, then capture immediately before the boundary.
            f.Clock.Now = f.Clock.Now.AddDays(1).AddSeconds(-1);
            await f.Load(token); Assert.Equal(before + 2, f.Loads);
            await f.Load(token); Assert.Equal(before + 2, f.Loads);
            f.Clock.Now = f.Clock.Now.AddSeconds(1);
            await f.Load(token); Assert.Equal(before + 3, f.Loads);
            await f.Sql($"delete from {table}");
        }
    }

    [Fact]
    public async Task UserEvictionLogoutRoleUpdateAndGlobalLogoutInvalidateOnlyTheirTargets()
    {
        await using var f = new Fixture(); await f.StartAsync();
        await f.Load("synthetic-a"); await f.Load("synthetic-a2"); await f.Load("synthetic-b", Viewer with { Id = 2 });
        f.Cache.Invalidate(userId: 1);
        await f.Load("synthetic-a"); await f.Load("synthetic-a2"); await f.Load("synthetic-b", Viewer with { Id = 2 }); Assert.Equal(5, f.Loads);
        var sessions = f.Sessions;
        string a = await sessions.IssueAsync(Viewer, false, Ct), b = await sessions.IssueAsync(Viewer with { Id = 2 }, false, Ct);
        await f.Load(a); await f.Load(b, Viewer with { Id = 2 });
        await sessions.RevokeAsync(a, Ct);
        await f.Load(a); await f.Load(b, Viewer with { Id = 2 }); Assert.Equal(8, f.Loads);
        var users = new UserAdministrationService(f.Connections, new PasswordCodec(), new AuthAudit(f.Connections), f.Cache);
        var updated = await users.UpdateAsync(new(1, "operator", null), new("local_operator", null, "192.0.2.1"), Ct);
        Assert.Equal("operator", updated.GetProperty("role").GetString());
        // Even a caller retaining the old role must miss after explicit user eviction.
        await f.Load("synthetic-a"); await f.Load("synthetic-a2"); await f.Load(b, Viewer with { Id = 2 }); Assert.Equal(10, f.Loads);
        Assert.Equal(1, await sessions.RevokeAllAsync(Ct));
        Assert.Equal(0, await sessions.RevokeAllAsync(Ct));
        await f.Load("synthetic-a"); await f.Load(b, Viewer with { Id = 2 }); Assert.Equal(12, f.Loads);
        await using var db = await f.Connections.OpenAsync(Ct);
        await using var active = new NpgsqlCommand("select count(*) from auth_sessions where revoked_at is null", db);
        Assert.Equal(0L, await active.ExecuteScalarAsync(Ct));
    }

    [Fact]
    public async Task SeparateAuthenticatedRequestsShareRepositoryFactsButRevokedSessionsAreDenied()
    {
        await using var f = new Fixture(); await f.StartAsync();
        await f.Sql("""
            create table access_platform_owners(user_id bigint);
            create table access_groups(id bigint,group_key text,name text,is_active boolean);
            create table access_packages(id bigint,package_key text,name text);
            insert into access_packages values(1,'synthetic-package','Synthetic package');
            create table access_role_packages(coarse_role text,package_id bigint);
            insert into access_role_packages values('viewer',1);
            create table access_capabilities(id bigint,capability_key text);
            create table access_package_capabilities(package_id bigint,capability_id bigint);
            create table access_package_reports(package_id bigint,report_key text,field_categories jsonb,allowed_actions jsonb,scope_json jsonb);
            create table report_registry_v4(report_key text,version bigint,definition_json jsonb,discoverable boolean,name text,owner_name text,purpose text,sensitivity text,status text,requestable boolean,request_profile_json jsonb,dataset_id bigint);
            create table report_datasets_v4(id bigint,dataset_key text,version bigint,fields_json jsonb,actions_json jsonb,status text);
            create table report_access_requests_v4(id bigint,requester_user_id bigint,report_key text,status text,created_at timestamptz,updated_at timestamptz,decision_reason text);
            create table user_report_preferences(user_id bigint,report_key text,pinned boolean,view_json jsonb,updated_at timestamptz);
            """);
        string token = await f.Sessions.IssueAsync(Viewer, false, Ct);
        var auth = new PrincipalAuthenticator(f.Connections);
        async Task<(AuthenticationResult Authentication, AccessFacts? Facts, int Opens)> Request(string path)
        {
            var context = new DefaultHttpContext(); context.Request.Method = "GET"; context.Request.Path = path;
            context.Request.Headers.Cookie = "adlog_session=" + token;
            var authenticated = await auth.AuthenticateAsync(context, Ct);
            if (!authenticated.Succeeded) return (authenticated, null, 0);
            int before = f.Connections.Opens;
            var repository = new AccessFactsRepository(f.Connections, f.Cache, new HttpContextAccessor { HttpContext = context });
            var facts = await repository.LoadAsync(authenticated.Principal!, Ct);
            await repository.LoadAsync(authenticated.Principal!, Ct);
            return (authenticated, facts, f.Connections.Opens - before);
        }
        var first = await Request("/api/v1/home/summary"); Assert.True(first.Authentication.Succeeded); Assert.Equal(2, first.Opens);
        Assert.Equal("synthetic-package", Assert.Single(first.Facts!.Packages).GetProperty("package_key").GetString());
        var second = await Request("/api/v1/domains"); Assert.True(second.Authentication.Succeeded); Assert.Equal(1, second.Opens);
        Assert.NotSame(first.Facts, second.Facts);
        // Leave the cache warm: live authentication must reject a DB-side revocation as well.
        await f.Sql("update auth_sessions set revoked_at=now()");
        var revoked = await Request("/api/v1/home/summary"); Assert.Null(revoked.Facts);
        Assert.Equal(401, revoked.Authentication.Failure!.StatusCode);
        Assert.Equal("authentication_required", revoked.Authentication.Failure.Code);
    }
}
