using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Semantic;
using Sli.Server.Storage.Direct;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Storage;
using Xunit;

namespace Sli.Server.Tests.Semantic;

[Collection("Semantic producer environment")]
public sealed class SemanticRetainedShortPostgresTests
{
    [Fact]
    public async Task Retained_selection_and_source_proof_survive_hot_expiry_and_problem_copies()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        var admitted = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct);
        await PostCollectionPostgres.Sql(owner, "insert into storage_v2_provider(value) values('Microsoft-Windows-Security-Auditing'),('Microsoft-Windows-Eventlog') on conflict do nothing", ct);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture, admitted, ct);
        var now = DateTime.UtcNow.Date.AddHours(1);
        // An expired routine logon contributes a daily count, never an exact event.
        await using (var db = await fixture.Pg.OpenAsync(ct))
        await using (var tx = await db.BeginTransactionAsync(ct)) {
            await PostCollectionPostgres.Sql(db, "set local role adlog_storage_worker", ct);
            await ShortEventWriter.WriteAsync(db, tx, [admitted[1] with { EventId = 900009, Time = now.AddDays(-30), PacketId = null }], ct);
            await tx.CommitAsync(ct);
        }
        string hash;
        await using (var command = new NpgsqlCommand("select encode(source_sha256,'hex') from event_cold_facts where event_id=900001", owner))
            hash = (string)(await command.ExecuteScalarAsync(ct))!;
        var config = SemanticShortHistoryPostgresTests.Config(fixture.Dsn("adlog_user"));
        var database = new SemanticDatabase(new PostgresConnectionFactory(config));

        async Task AssertRetained(long high = 900001)
        {
            await using var session = await database.OpenAsync(false, ct);
            var rows = await session.QueryAsync("select id,encode(normalized_hash,'hex') as hash from semantic_event_rows where event_id=1102 order by id", ct);
            Assert.Empty(await session.QueryAsync("select id from semantic_event_rows where id=900009", ct));
            var row = Assert.Single(rows); Assert.Equal(900001, row.Number("id")); Assert.Equal(hash, row.Text("hash"));
            var plan = await new RetainedFactsControl(database, Path.Combine(fixture.Pg.Root, "plan-only.json"), "synthetic", () => { }).PlanAsync(ct);
            Assert.Equal(high, plan.Number("observed_high_watermark_event_id"));
            var exact = await new RetainedFactsControl(database, Path.Combine(fixture.Pg.Root, "plan-only.json"), "synthetic", () => { })
                .CheckPlanAsync([900001], Path.Combine(fixture.Pg.Root, "exact.json"), ct);
            Assert.Equal(new long[] { 900001 }, exact["event_ids"]!.AsArray().Select(x => x!.GetValue<long>()));
            var counts = Assert.Single(await session.QueryAsync(SemanticRetainedSql.Reconcile, ct, 1, SemanticEvent.Normalizer, SemanticEvent.Version,
                1, "semantic-shadow", SemanticEvent.Version, "Microsoft-Windows-Eventlog", 1102, 900010L));
            Assert.Equal(1, counts.Number("retained_count"));

        }
        await AssertRetained(900003);
        await PostCollectionPostgres.Sql(owner, "delete from event_hot", ct);
        await AssertRetained();
        await PostCollectionPostgres.Sql(owner, """
            insert into findings(id,fingerprint,rule_code,title,severity,status,evidence_count)
                values(123,'synthetic-retained','synthetic','synthetic','high','new',1),(124,'synthetic-retained-2','synthetic','synthetic','high','new',1);
            insert into finding_event_copies337 select 123,event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields,source_sha256,'semantic_scenario',null,event_record_id from event_cold_facts;
            insert into finding_event_copies337 select 124,event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields,source_sha256,evidence_role,note,event_record_id from finding_event_copies337 where finding_id=123;
            delete from event_cold_facts;
            """, ct);
        await AssertRetained();
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
