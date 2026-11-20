using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Infrastructure;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Access;

// Behavioral vectors from tests/access/test_generic_report_assignments.py.
public sealed class GenericReportAssignmentTests
{
    [Theory]
    [InlineData("sli.fixture", "source-1", true)]
    [InlineData("sli.fixture", "source-2", false)]
    [InlineData(null, null, false)]
    public void GenericGrantRequiresTheCompleteResourceScope(string? plugin, string? source, bool allowed)
    {
        var resource = plugin is null ? new AccessResource("domain", 1)
            : new AccessResource("") { PluginId = plugin, SourceInstanceId = source };
        var result = Decide("""{"mode":"restricted","clauses":[{"plugin_ids":["sli.fixture"],"source_instance_ids":["source-1"]}]}""", [[resource]]);
        Assert.Equal(allowed, result.Allowed);
        Assert.Equal(allowed ? "report_scope_match" : "report_scope_denied", result.Reason);
    }

    [Fact]
    public void EmptyGenericClauseCannotAuthorizeAnEmptyResource()
    {
        var result = Decide("""{"mode":"restricted","clauses":[{}]}""", [[new("")]]);
        Assert.False(result.Allowed);
        Assert.Equal("report_scope_denied", result.Reason);
    }

    [Fact]
    public void LegacyDomainAdapterRejectsAnotherDomain()
    {
        // Matching domain 1 is already covered by InvestigationAccessTests.
        var result = Decide("""{"mode":"restricted","clauses":[{"collection_scope_ids":["ad-domain:1"]}]}""", [[new("domain", 2)]]);
        Assert.False(result.Allowed);
        Assert.Equal("report_scope_denied", result.Reason);
    }

    [Theory]
    [InlineData("""{"mode":"none","clauses":[]}""")]
    [InlineData("""{"mode":"all","clauses":[{}]}""")]
    [InlineData("""{"mode":[],"clauses":[]}""")]
    [InlineData("{}")]
    public void NonGlobalOrMalformedGenericScopeRequiresResourceContext(string scope)
    {
        // Valid generic all is already covered by InvestigationAccessTests.
        var result = Decide(scope, null);
        Assert.False(result.Allowed);
        Assert.Equal("resource_context_required", result.Reason);
    }

    [Fact]
    public async Task SourceTargetsMustExistInObservedProvenance()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var db = await fixture.Pg.OpenAsync(ct);
        using var files = new ReportCatalogLifecycleTests.CatalogFiles();
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        { ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user") }).Build();
        var writer = new ReportAssignmentWriter(new PostgresConnectionFactory(config), files.Catalog);
        await using var user = new NpgsqlCommand("select id from auth_users where username='platform-owner'", db);
        long userId = Convert.ToInt64(await user.ExecuteScalarAsync(ct));
        Task<ReportAssignmentResult> Assign(params string[] sources) => writer.CreateAsync(new(JsonSerializer.SerializeToElement(new
        {
            subject_type = "user", subject_id = userId, report_key = "workstations.logons",
            business_reason = "Synthetic generic source assignment", allowed_actions = new[] { "view" },
            scope = new { mode = "restricted", clauses = new[] { new { source_instance_ids = sources } } }
        })), new("session", userId), "192.0.2.47", ct);

        await PostCollectionPostgres.Sql(db, """
            insert into storage_v2_entity_type(value) values('workstation') on conflict(value) do nothing;
            insert into entities_v2(entity_type_id,natural_key,display_name,source_core_sha256)
            select id,'generic-assignment-device','Synthetic device',sha256('generic-assignment-device'::bytea)
            from storage_v2_entity_type where value='workstation';
            insert into core_entity_observations(observation_sha256,plugin_id,source_instance_id,entity_kind,
                entity_id,observed_at_utc,identifiers_json,evidence_refs,resolution)
            select sha256('generic-assignment-observation'::bytea),'sli.fixture','source-1','device',id,now(),
                '[{"namespace":"synthetic","value":"device"}]','{synthetic-observation}','resolved'
            from entities_v2 where natural_key='generic-assignment-device';
            """, ct);
        await using (var provenance = new NpgsqlCommand("select source_instance_id from core_entity_scope_resources where source_instance_id='source-1'", db))
            Assert.Equal("source-1", await provenance.ExecuteScalarAsync(ct));

        var accepted = await Assign("source-1");
        Assert.Equal("source-1", accepted.Item.GetProperty("scope_json").GetProperty("clauses")[0].GetProperty("source_instance_ids")[0].GetString());
        foreach (var sources in new[] { new[] { "source-2" }, new[] { "source-1", "source-2" } })
            Assert.Equal("report_scope_target_not_found", (await Assert.ThrowsAsync<AssignmentValidationException>(() => Assign(sources))).Message);
        await using var persisted = new NpgsqlCommand("select count(*) from access_report_assignments where report_key='workstations.logons' and subject_id=@id", db);
        persisted.Parameters.AddWithValue("id", userId);
        Assert.Equal(1L, await persisted.ExecuteScalarAsync(ct));
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    private static CapabilityResult Decide(string scope, IReadOnlyList<IReadOnlyList<AccessResource>>? groups)
    {
        var capabilities = new CapabilityDecisionSet(false, new HashSet<string>(), new HashSet<string>(), [], new Dictionary<string, JsonElement>());
        var grant = new AtomicReportGrant(JsonSerializer.Deserialize<JsonElement>(scope), new HashSet<string>(), new HashSet<string> { "view" }, 1, 1);
        var access = new AccessDecision("viewer", capabilities, [new("fixture.generic", true, [grant])]);
        return ResourceAccessDecisions.ReportAction(access, "fixture.generic", "view", groups);
    }
}
