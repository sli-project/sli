using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Ad;
using Sli.Server.Infrastructure;
using Sli.Server.Reporting.V2;
using Sli.Server.Semantic;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Reporting;

public sealed class SecurityEventDomainOptionsPostgresTests
{
    // Parity: tests/reporting/test_security_event_domain_options_postgres_integration.py.
    [Fact]
    public async Task Declaration_reads_only_authorized_metadata_without_an_event_store()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var pg = new PostCollectionPostgres(canonicalSchema: true);
        await pg.StartAsync(ct);
        await using var db = await pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, """
            create table domains (id bigint primary key, fqdn text not null);
            insert into domains values (7, 'active.example.test'),
                (8, 'archive.example.test'), (9, 'hidden.example.test');
            """, ct);
        await using (var probe = new NpgsqlCommand("select to_regclass('events_v2_core') is null", db))
            Assert.Equal(true, await probe.ExecuteScalarAsync(ct));

        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["ConnectionStrings:Sli"] = pg.ConnectionString }).Build();
        var connections = new PostgresConnectionFactory(config);
        var store = new AdReportStore(connections, null!);
        var reader = new SecurityEventsReader(store, new SemanticDatabase(connections), null!);
        var definition = new ReportDefinitionRegistry().Get("security.events.chains")!;
        var facts = Facts();
        await using var host = await ReportFixture.Start(facts, definition, nativeReader: reader);

        using var response = await host.Client.GetAsync("/api/v2/reports/security.events.chains", ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var payload = await ReportFixture.Body(response);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""
            [{"value":"7","label":"active.example.test"},
             {"value":"8","label":"archive.example.test"}]
            """), payload["filter_options"]!["domain"]));

        // Metadata discovery must finish even with more than 10,000 domains.
        await PostCollectionPostgres.Sql(db, """
            insert into domains select id, 'hidden-' || id || '.example.test'
            from generate_series(10, 10010) id;
            """, ct);
        var permitted = new ReportEligibility().Compose(facts, new CapabilityComposer().Compose(facts));
        Assert.True(JsonNode.DeepEquals(payload["filter_options"], await reader.OptionsAsync(definition, permitted, ct)));

        // Keep the report assignment; revoke the event capability only.
        var revoked = facts with { DirectCapabilities = facts.DirectCapabilities
            .Where(c => c.GetProperty("capability_key").GetString() != "events.view").ToArray() };
        var access = new ReportEligibility().Compose(revoked, new CapabilityComposer().Compose(revoked));
        Assert.True(Assert.Single(access.Reports).Allowed);
        Assert.Empty((await reader.OptionsAsync(definition, access, ct))["domain"]!.AsArray());
        host.Facts.Value = revoked;
        using var denied = await host.Client.GetAsync("/api/v2/reports/security.events.chains", ct);
        Assert.Equal(HttpStatusCode.OK, denied.StatusCode);
        Assert.Empty((await ReportFixture.Body(denied))["filter_options"]!["domain"]!.AsArray());
    }

    private static AccessFacts Facts()
    {
        string[] fields = ["identity_basic", "security", "technical", "raw_evidence"];
        return new(false, "viewer", [], [],
            new[] { "events.view", "evidence.exact" }.Concat(fields.Select(f => "field." + f))
                .Select(c => JsonSerializer.SerializeToElement(new
                    { capability_key = c, effect = "allow", scope_json = new { kind = "all" } })).ToArray(),
            [], [],
            [JsonSerializer.SerializeToElement(new { report_key = "security.events.chains", effect = "allow",
                allowed_actions = new[] { "view" }, field_categories = fields,
                scope_json = new { kind = "domain", ids = new[] { 7, 8 } } })],
            [JsonSerializer.SerializeToElement(new { report_key = "security.events.chains", version = 1, dataset_version = 1,
                definition_json = new { actions = new[] { "view" }, field_categories = fields },
                actions_json = new[] { "view" }, fields_json = fields.Select(f => new { category = f }).ToArray() })]);
    }
}
