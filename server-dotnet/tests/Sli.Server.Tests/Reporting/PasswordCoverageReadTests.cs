using System.Net;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Problems;
using Sli.Server.Reporting.V2;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Problems;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed partial class PasswordCoverageReportTests
{
    sealed class Connections(string dsn) : IPostgresConnectionFactory
    {
        internal readonly List<NpgsqlConnection> Opened = [];
        internal int CoverageCalls { get; private set; }
        public async Task<NpgsqlConnection> OpenAsync(CancellationToken ct)
        {
            var db = new NpgsqlConnection(dsn);
            db.Notice += (_, notice) => { if (notice.Notice.MessageText == "coverage fixture called") CoverageCalls++; };
            await db.OpenAsync(ct); Opened.Add(db); return db;
        }
    }
    [Fact]
    public async Task QueueReturnsBeforeCoverageAndSeparateEndpointKeepsDomainAndFailureBoundaries()
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
            create table coverage_fixture(page jsonb);
            create function read_password_detection_coverage(ids bigint[]) returns jsonb language plpgsql as $$
            begin
                raise notice 'coverage fixture called';
                return (select jsonb_set(page,'{rows}',(select jsonb_agg(
                    jsonb_set(page->'rows'->0,'{domain_id}',to_jsonb(id)) order by id) from unnest(ids) id))
                    from coverage_fixture);
            end $$;
            """, ct);
        var row = Row(); row["domain_id"] = 7; row["frozen_episode_count"] = 0; row["status"] = "healthy"; row["reason"] = null;
        var page = new JsonObject { ["as_of"] = Stamp, ["rows"] = new JsonArray(row), ["has_more"] = false };
        await using (var seed = new NpgsqlCommand("insert into coverage_fixture(page) values(@page::jsonb)", db)) {
            seed.Parameters.AddWithValue("page", page.ToJsonString()); await seed.ExecuteNonQueryAsync(ct);
        }
        var connections = new Connections(pg.ConnectionString);
        var repository = new ProblemRepository(connections, TimeProvider.System);
        var reader = new SecurityProblemsReader(repository, new NoEvidence());
        await using var host = await ReportFixture.Start(ProblemEndpointTests.Facts(), Context().Definition, nativeReader: reader);
        host.Client.DefaultRequestHeaders.AcceptLanguage.ParseAdd("en");
        const string endpoint = "/api/v2/reports/security.problems/";
        using (var queue = await host.Client.GetAsync(endpoint + "data?id=7&domain=7", ct)) {
            Assert.Equal(HttpStatusCode.OK, queue.StatusCode);
            var result = await ReportFixture.Body(queue);
            Assert.Empty(result["items"]!.AsArray());
            Assert.Null(result["coverage"]!["password_detection"]);
            Assert.Single(connections.Opened);
            Assert.Equal(0, connections.CoverageCalls);
        }
        using (var scoped = await host.Client.GetAsync(endpoint + "password-coverage?domain=7", ct)) {
            Assert.Equal(HttpStatusCode.OK, scoped.StatusCode);
            var coverage = (await ReportFixture.Body(scoped))["coverage"]!["password_detection"]!;
            Assert.Equal("observed", coverage["availability"]!.ToString());
            Assert.Equal("7", Assert.Single(coverage["rows"]!.AsArray())!["domain_id"]!.ToString());
            Assert.Equal(1, connections.CoverageCalls);
        }
        using (var all = await host.Client.GetAsync(endpoint + "password-coverage", ct)) {
            Assert.Equal(HttpStatusCode.OK, all.StatusCode);
            var coverage = (await ReportFixture.Body(all))["coverage"]!["password_detection"]!;
            Assert.Equal(new[] { "7", "8" }, coverage["rows"]!.AsArray().Select(r => r!["domain_id"]!.ToString()));
        }
        await PostCollectionPostgres.Sql(db, "truncate table domains", ct);
        using (var noDomains = await host.Client.GetAsync(endpoint + "password-coverage", ct)) {
            Assert.Equal(HttpStatusCode.OK, noDomains.StatusCode);
            var coverage = (await ReportFixture.Body(noDomains))["coverage"]!["password_detection"]!;
            Assert.Equal("unavailable", coverage["availability"]!.ToString());
        }
        // A restricted read must not depend on the unrestricted catalog.
        await PostCollectionPostgres.Sql(db, "drop table domains", ct);
        var restricted = await reader.PasswordCoverageAsync(Context([7, 999], true), ct);
        Assert.Equal("7", Assert.Single(restricted["coverage"]!["password_detection"]!["rows"]!.AsArray())!["domain_id"]!.ToString());
        int opened = connections.Opened.Count;
        Assert.Null((await reader.PasswordCoverageAsync(Context([999], true), ct))["coverage"]!["password_detection"]);
        Assert.Equal(opened, connections.Opened.Count);
        await PostCollectionPostgres.Sql(db, """
            create or replace function read_password_detection_coverage(ids bigint[]) returns jsonb language plpgsql as $$
            begin raise exception 'private SQL error'; end $$;
            """, ct);
        using (var failed = await host.Client.GetAsync(endpoint + "password-coverage?domain=7", ct)) {
            Assert.Equal(HttpStatusCode.OK, failed.StatusCode);
            var result = await ReportFixture.Body(failed);
            Assert.Equal("unavailable", result["coverage"]!["password_detection"]!["availability"]!.ToString());
            Assert.Contains("does not prove", Assert.Single(result["limitations"]!.AsArray())!["text"]!.ToString());
            Assert.DoesNotContain("private", result.ToJsonString());
        }
        opened = connections.Opened.Count;
        host.Facts.Value = ProblemEndpointTests.Facts(allowed: false);
        using (var denied = await host.Client.GetAsync(endpoint + "password-coverage?domain=7", ct))
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        Assert.Equal(opened, connections.Opened.Count);
        Assert.All(connections.Opened, connection => Assert.Equal(System.Data.ConnectionState.Closed, connection.State));
        await using var followUp = await connections.OpenAsync(ct);
        await using var command = new NpgsqlCommand("select 1", followUp);
        Assert.Equal(1, await command.ExecuteScalarAsync(ct));
    }
}
