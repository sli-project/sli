using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Problems;
using Sli.Server.Reporting.V2;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed partial class PasswordCoverageReportTests
{
    sealed class Connections(string dsn) : IPostgresConnectionFactory
    {
        internal readonly List<NpgsqlConnection> Opened = [];
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        {
            var db = new NpgsqlConnection(dsn); await db.OpenAsync(ct); Opened.Add(db); return db;
        }
    }
    [Fact]
    public async Task EmptyFindingsStillReadSanitizedCoverageAndSqlFailureClosesBeforeFollowUp()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(true); await pg.StartAsync(ct);
        await using var db = await pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, """
            create table findings_active(id bigint,rule_code text,status text,severity text,repeat_count integer,last_seen_utc text,updated_at timestamptz);
            create table auth_users(id bigint,username text);
            create table semantic_suppressions(id bigint,finding_id bigint,kind text,responsible_user_id bigint,state text,expires_at timestamptz,semantic_type text);
            create table runtime_worker_heartbeats(worker_name text,status text,phase text,heartbeat_at timestamptz,expected_interval_seconds integer,details_json jsonb);
            create function is_semantic_finding_published_v1(bigint) returns boolean language sql as $$select true$$;
            create function semantic_finding_in_domains_v265(bigint,bigint[]) returns boolean language sql as $$select true$$;
            create function semantic_finding_suppressed_v160(bigint,text) returns boolean language sql as $$select false$$;
            create function semantic_finding_review_v160(bigint) returns jsonb language sql as $$select null::jsonb$$;
            create function finding_decoy_context(bigint) returns jsonb language sql as $$select null::jsonb$$;
            create table semantic_control_audit(id bigint,action text,actor text,occurred_at timestamptz,details jsonb);
            create table domains(id bigint); insert into domains values(7),(8);
            create table coverage_fixture(page jsonb,seen bigint[],reads integer not null default 0);
            create function read_password_detection_coverage(ids bigint[]) returns jsonb language plpgsql as $$
            begin update coverage_fixture set seen=ids,reads=reads+1; return (select page from coverage_fixture); end $$;
            """, ct);
        var row = Row(); row["domain_id"] = 7; row["frozen_episode_count"] = 0; row["status"] = "healthy"; row["reason"] = null;
        var page = new JsonObject { ["as_of"] = Stamp, ["rows"] = new JsonArray(row), ["has_more"] = false };
        await using (var seed = new NpgsqlCommand("insert into coverage_fixture(page) values(@page::jsonb)", db)) {
            seed.Parameters.AddWithValue("page", page.ToJsonString()); await seed.ExecuteNonQueryAsync(ct);
        }
        var connections = new Connections(pg.ConnectionString);
        var repository = new ProblemRepository(connections, TimeProvider.System);
        var c = Context([7]); var query = SecurityProblemsReader.Input(c) with { GroupQueue = false };
        var result = await repository.FindingsAsync(query, new(c.Access), ct);
        Assert.Empty(result["items"]!.AsArray());
        Assert.Equal("observed", result["password_detection_coverage"]?["availability"]?.ToString());
        Assert.Equal("7", result["password_detection_coverage"]!["rows"]![0]!["domain_id"]!.GetValue<string>());
        await using (var seen = new NpgsqlCommand("select seen from coverage_fixture", db))
            Assert.Equal(new long[] { 7 }, (long[])(await seen.ExecuteScalarAsync(ct))!);
        await using (var reads = new NpgsqlCommand("select reads from coverage_fixture", db))
            Assert.Equal(1, await reads.ExecuteScalarAsync(ct));
        result = await repository.FindingsAsync(query with { Domains = null }, new(c.Access), ct);
        Assert.Equal("observed", result["password_detection_coverage"]?["availability"]?.ToString());
        await using (var seen = new NpgsqlCommand("select seen from coverage_fixture", db))
            Assert.Equal(new long[] { 7, 8 }, (long[])(await seen.ExecuteScalarAsync(ct))!);
        // A restricted read must not depend on the unrestricted catalog.
        await PostCollectionPostgres.Sql(db, "drop table domains", ct);
        result = await repository.FindingsAsync(query with { Domains = [7, 999] }, new(Context([7], true).Access), ct);
        Assert.Equal("observed", result["password_detection_coverage"]?["availability"]?.ToString());
        await using (var seen = new NpgsqlCommand("select seen from coverage_fixture", db))
            Assert.Equal(new long[] { 7 }, (long[])(await seen.ExecuteScalarAsync(ct))!);
        result = await repository.FindingsAsync(query with { Domains = [] }, new(c.Access), ct);
        Assert.Null(result["password_detection_coverage"]);
        await using (var reads = new NpgsqlCommand("select reads from coverage_fixture", db))
            Assert.Equal(3, await reads.ExecuteScalarAsync(ct));
        await PostCollectionPostgres.Sql(db, """
            create or replace function read_password_detection_coverage(ids bigint[]) returns jsonb language plpgsql as $$
            begin raise exception 'private SQL error'; end $$;
            """, ct);
        result = await repository.FindingsAsync(query, new(c.Access), ct);
        Assert.Equal("unavailable", result["password_detection_coverage"]?["availability"]?.ToString());
        Assert.DoesNotContain("private", result.ToJsonString());
        Assert.All(connections.Opened, connection => Assert.Equal(System.Data.ConnectionState.Closed, connection.State));
        await using var followUp = await connections.OpenAsync(ct);
        await using var command = new NpgsqlCommand("select 1", followUp);
        Assert.Equal(1, await command.ExecuteScalarAsync(ct));
    }
}
