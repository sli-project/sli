using Microsoft.Extensions.Configuration;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Domains;

public sealed class HomeAccessCacheTests
{
    sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
        public override long GetTimestamp() => Now.UtcTicks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    }
    [Fact]
    public async Task SessionFactsAreReusedButRevisionCountExpiryStartsAndIdentityAlwaysInvalidate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true); await pg.StartAsync(ct);
        await using var db = await pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, """
            create table access_audit_v4(id bigint primary key);
            create table access_group_members(valid_from timestamptz,valid_until timestamptz);
            create table access_subject_packages(valid_from timestamptz,valid_until timestamptz);
            create table access_capability_assignments(valid_from timestamptz,valid_until timestamptz);
            create table access_report_assignments(valid_from timestamptz,valid_until timestamptz);
            insert into access_audit_v4 values(10);
            """, ct);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["ConnectionStrings:Sli"] = pg.ConnectionString }).Build();
        var clock = new Clock(); var cache = new SessionAccessFactsCache(new PostgresConnectionFactory(config), clock); int loads = 0;
        Task<AccessFacts> Load() { loads++; return Task.FromResult(new AccessFacts(false, "viewer", [], [], [], [], [], [], [])); }
        var principal = new Principal("session", 1, "viewer");
        await cache.LoadAsync(principal, "synthetic-session", Load, ct); await cache.LoadAsync(principal, "synthetic-session", Load, ct); Assert.Equal(1, loads);
        await PostCollectionPostgres.Sql(db, "insert into access_audit_v4 values(20)", ct);
        await cache.LoadAsync(principal, "synthetic-session", Load, ct); Assert.Equal(2, loads);
        // A transaction with a lower sequence id can commit after max(id).
        await PostCollectionPostgres.Sql(db, "insert into access_audit_v4 values(15)", ct);
        await cache.LoadAsync(principal, "synthetic-session", Load, ct); Assert.Equal(3, loads);
        await cache.LoadAsync(principal with { Role = "operator" }, "synthetic-session", Load, ct); Assert.Equal(4, loads);
        await cache.LoadAsync(principal with { Id = 2 }, "synthetic-session", Load, ct); Assert.Equal(5, loads);
        await cache.LoadAsync(principal, "another-synthetic-session", Load, ct); Assert.Equal(6, loads);
        clock.Now = clock.Now.AddSeconds(61); await cache.LoadAsync(principal, "another-synthetic-session", Load, ct); Assert.Equal(7, loads);
        // Reset the test clock to DB time, then pin both future grant boundaries.
        clock.Now = DateTimeOffset.UtcNow;
        await PostCollectionPostgres.Sql(db, "insert into access_report_assignments values(now()+interval '5 seconds',now()+interval '10 seconds')", ct);
        await cache.LoadAsync(principal, "future-boundary", Load, ct); Assert.Equal(8, loads);
        clock.Now = clock.Now.AddSeconds(6); await cache.LoadAsync(principal, "future-boundary", Load, ct); Assert.Equal(9, loads);
        clock.Now = DateTimeOffset.UtcNow;
        await PostCollectionPostgres.Sql(db, "delete from access_report_assignments; insert into access_report_assignments values(null,now()+interval '5 seconds')", ct);
        await cache.LoadAsync(principal, "expiry-boundary", Load, ct); Assert.Equal(10, loads);
        clock.Now = clock.Now.AddSeconds(6); await cache.LoadAsync(principal, "expiry-boundary", Load, ct); Assert.Equal(11, loads);
        await cache.LoadAsync(principal with { Type = "api_key" }, "uncached", Load, ct); await cache.LoadAsync(principal with { Type = "api_key" }, "uncached", Load, ct); Assert.Equal(13, loads);
    }
}
