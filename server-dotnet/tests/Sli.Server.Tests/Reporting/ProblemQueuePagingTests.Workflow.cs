using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Problems;
using Sli.Server.Reporting.V2;
using Sli.Server.Tests.Agents;
using Sli.Server.Tests.Problems;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed partial class ProblemQueuePagingTests
{
    [Fact]
    public async Task ComputerOpenPopulationKeepsWorkingStatusesAndExcludesOtherFindings()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 396);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await SeedPopulation(owner, ct);
        string migration = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/397_problem_queue_workflow.sql");
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await PostCollectionPostgres.Sql(owner, """
            insert into storage_v2_entity_type(value) values('ad_computer') on conflict do nothing;
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
            select computer.id,type.id,computer.name,computer.name,d.id,sha256(computer.name::bytea)
            from domains d cross join storage_v2_entity_type type
                cross join (values(500,'synthetic-computer'),(501,'other-computer')) computer(id,name)
            where d.fqdn='example.test' and type.value='ad_computer';
            insert into finding_entities(finding_id,entity_id,entity_type,display_name,entity_role)
            select id,case when id=204 then 501 else 500 end,'ad_computer','Synthetic computer','target'
            from findings where id in (201,204,205,206,207,208,209,211,212,214);
            update findings set status='confirmed' where id=205;
            update findings set status='repeated' where id=206;
            insert into finding_queue_deferrals(finding_id,until_at) values (207,now()+interval '1 day');
            """, ct);

        long domain = Assert.Single(await Rows(owner, "select id from domains where fqdn='example.test'"))["id"]!.GetValue<long>();
        var context = Context(new JsonObject { ["entity_id"] = 500, ["queue_view"] = "all", ["population"] = "open", ["fold"] = "false" })
            with { DomainIds = [domain] };
        var repository = new ProblemRepository(new ReaderConnections(fixture), TimeProvider.System);
        var query = SecurityProblemsReader.Input(context) with { QueueList = true, Compact = true };
        var result = await repository.FindingsAsync(query, new(context.Access), ct);
        Assert.Equal([201L, 205L, 206L, 208L, 209L], result["items"]!.AsArray().Select(item => item!["id"]!.GetValue<long>()).Order());
        Assert.Equal(5L, result["summary"]!.AsArray().Sum(bucket => bucket!["count"]!.GetValue<long>()));
    }

    [Fact]
    public async Task WorkflowUpgradePreservesAssignmentsAndWritesAtomicDecisionHistory()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 396);
        await using var owner = await fixture.Pg.OpenAsync(ct);
        await SeedPopulation(owner, ct);
        await PostCollectionPostgres.Sql(owner, "update findings set assigned_to='platform-owner' where id=207", ct);
        const string queuePolicy = """
            select r.definition_json->>'export_policy' as policy,
                   (r.definition_json->'actions')::text as registry_actions, d.actions_json::text as dataset_actions
            from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id
            where r.report_key='security.queue' and r.status='published'
            """;
        var previousPolicy = Assert.Single(await Rows(owner, queuePolicy));
        Assert.Equal("disabled", previousPolicy["policy"]!.ToString());
        foreach (string key in new[] { "registry_actions", "dataset_actions" })
            Assert.DoesNotContain(JsonNode.Parse(previousPolicy[key]!.GetValue<string>())!.AsArray(), action => action!.ToString() == "export");
        string migration = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/397_problem_queue_workflow.sql");
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        Assert.True(JsonNode.DeepEquals(previousPolicy, Assert.Single(await Rows(owner, queuePolicy))));
        long domain = Assert.Single(await Rows(owner, "select id from domains where fqdn='example.test'"))["id"]!.GetValue<long>();
        long user = Assert.Single(await Rows(owner, "select id from auth_users where username='platform-owner'"))["id"]!.GetValue<long>();
        var repository = new ProblemRepository(new ReaderConnections(fixture), TimeProvider.System);
        var context = Context(new JsonObject { ["queue_view"] = "open" }) with { DomainIds = [domain] };
        var access = ProblemLifecycleTests.Access("security.queue",
            scope: $$"""{"kind":"domain","ids":[{{domain}}]}""", fields: ["security", "identity_basic"]);
        var principal = new Principal("session", user, "admin", "platform-owner");
        var before = DateTimeOffset.UtcNow;
        QueueDecision Input(string body) => QueueDecision.Parse(JsonNode.Parse(body)!.AsObject(), before);

        await repository.QueueDecisionAsync(Input($$"""{"ids":[207,206],"assignee_id":{{user}}}"""), access, principal, ct);
        Assert.Single(await Rows(owner, "select id from finding_status_history where finding_id=206 and old_status='new' and new_status='new'"));
        Assert.Empty(await Rows(owner, "select id from finding_status_history where finding_id=207"));
        await Assert.ThrowsAsync<ProblemException>(() => repository.QueueDecisionAsync(Input("""{"ids":[206,210],"state":"active"}"""), access, principal, ct));
        var outsideDomain = await Assert.ThrowsAsync<ProblemException>(() =>
            repository.QueueDecisionAsync(Input("""{"ids":[206,211],"state":"active"}"""), access, principal, ct));
        Assert.Equal(404, outsideDomain.Status);
        Assert.Equal("new", Assert.Single(await Rows(owner, "select status from findings where id=206"))["status"]!.GetValue<string>());

        await repository.QueueDecisionAsync(Input("""{"ids":[206],"state":"closed","classification":"fixed","comment":"Reset password"}"""), access, principal, ct);
        var entry = Assert.Single(await Rows(owner, """
            select changed_by, changed_at, old_status, new_status, note from finding_status_history where finding_id=206 and new_status='closed'
            """));
        Assert.Equal("platform-owner", entry["changed_by"]!.GetValue<string>());
        Assert.Equal("new", entry["old_status"]!.GetValue<string>());
        Assert.NotNull(entry["changed_at"]);
        Assert.Contains("Reset password", entry["note"]!.GetValue<string>());
        Assert.Contains("fixed", entry["note"]!.GetValue<string>());
        Assert.Equal(2, (await Rows(owner, "select id from access_audit_v4 where target_key='206' and action='finding_queue_decision'")).Length);

        var accessFacts = new AccessFactsRepository(new ReaderConnections(fixture));
        var facts = await accessFacts.LoadAsync(principal, ct);
        var ordinary = new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts));
        await fixture.SeedOwnerAsync(ct);
        var ownerFacts = await accessFacts.LoadAsync(principal, ct);
        var allowed = new ReportEligibility().Compose(ownerFacts, new CapabilityComposer().Compose(ownerFacts));
        Assert.DoesNotContain(ordinary.Reports.Single(r => r.ReportKey == "security.queue").Grants, grant => grant.AllowedActions.Contains("export"));
        var ownerQueue = allowed.Reports.Single(r => r.ReportKey == "security.queue");
        Assert.True(ownerQueue.Allowed);
        Assert.DoesNotContain(ownerQueue.Grants, grant => grant.AllowedActions.Contains("export"));

        await repository.QueueDecisionAsync(Input($$"""{"ids":[207],"state":"deferred","until":"{{before.AddDays(1):O}}"}"""), access, principal, ct);
        var query = SecurityProblemsReader.Input(context) with { QueueList = true, Compact = true };
        var deferred = await repository.FindingsAsync(query with { QueueView = "deferred" }, access, ct);
        Assert.Equal(207, Assert.Single(deferred["items"]!.AsArray())!["id"]!.GetValue<long>());
        Assert.Equal("platform-owner", deferred["items"]![0]!["assigned_to"]!.GetValue<string>());
        var report = SecurityProblemsReader.Render(context, await repository.FindingsAsync(query, access, ct));
        Assert.Equal(1, report["series"]!["queue_counts"]!["deferred"]!.GetValue<long>());
        Assert.DoesNotContain(report["items"]!.AsArray(), row => row!["id"]!.GetValue<long>() == 207);
        await PostCollectionPostgres.Sql(owner, "update finding_queue_deferrals set until_at=now()-interval '1 minute' where finding_id=207", ct);
        var expired = await repository.FindingsAsync(query, access, ct);
        Assert.Contains(expired["items"]!.AsArray(), row => row!["id"]!.GetValue<long>() == 207 && row["status"]!.GetValue<string>() == "new");

        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
        Assert.True(JsonNode.DeepEquals(previousPolicy, Assert.Single(await Rows(owner, queuePolicy))));
        Assert.Null(Assert.Single(await Rows(owner, "select to_regclass('public.finding_queue_deferrals')::text as deferrals"))["deferrals"]);
        Assert.Equal(396, Assert.Single(await Rows(owner, "select max(version) as version from schema_migrations"))["version"]!.GetValue<int>());
        Assert.Single(await Rows(owner, "select id from finding_status_history where finding_id=206 and new_status='closed'"));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
