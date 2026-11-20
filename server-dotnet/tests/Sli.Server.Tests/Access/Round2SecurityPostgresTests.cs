using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;
using Sli.Server.Reporting;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Access;

// Behavioral vectors from tests/access/test_round2_security_postgres_integration.py.
// Both readers use the installed schema and real PostgreSQL, with no inherited DSN.
public sealed class Round2SecurityPostgresTests
{
    private static PostgresConnectionFactory Connections(SqlPostgresFixture fixture) => new(
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["ConnectionStrings:Sli"] = fixture.Dsn("adlog_user") }).Build());

    [Fact]
    public async Task ViewerExplicitUserAndGroupGrantsPreserveScopedDeniesAndQuarantineMalformedAllow()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var db = await fixture.Pg.OpenAsync(ct);
        long userId, groupId;
        await using (var seed = new NpgsqlCommand("""
            with u as (
                insert into auth_users(username,password_hash,role)
                values ('round2-viewer','synthetic-unusable-hash','viewer') returning id
            ), g as (
                insert into access_groups(group_key,name) values ('round2-group','round2-group') returning id
            ), m as (
                insert into access_group_members(group_id,user_id,source) select g.id,u.id,'test' from g,u
            ) select u.id,g.id from u,g
            """, db))
        await using (var reader = await seed.ExecuteReaderAsync(ct))
        {
            Assert.True(await reader.ReadAsync(ct));
            userId = reader.GetInt64(0); groupId = reader.GetInt64(1);
        }
        await using (var seed = new NpgsqlCommand("""
            insert into access_capability_assignments(
                subject_type,subject_id,capability_id,effect,scope_json,business_reason,source_type)
            select v.subject_type,v.subject_id,c.id,v.effect,v.scope::jsonb,'round2 disposable test',v.source_type
            from (values
                ('user',@user,'evidence.exact','allow','{}','direct'),
                ('group',@group,'reports.export','allow','{}','group'),
                ('user',@user,'events.view','deny','{"kind":"server","ids":[7]}','direct'),
                ('user',@user,'tasks.create','allow','{"ids":[7]}','direct')
            ) v(subject_type,subject_id,capability_key,effect,scope,source_type)
            join access_capabilities c on c.capability_key=v.capability_key
            """, db))
        {
            seed.Parameters.AddWithValue("user", userId); seed.Parameters.AddWithValue("group", groupId);
            Assert.Equal(4, await seed.ExecuteNonQueryAsync(ct));
        }

        var principal = new Principal("session", userId, "viewer", Username: "round2-viewer");
        var evaluation = await new AccessReadService(Connections(fixture)).LoadAsync(principal, ct);
        var access = JsonSerializer.SerializeToElement(AccessReadProjection.Compose(principal,
            evaluation.Facts, evaluation.Capabilities, evaluation.Reports, false));

        var capabilities = access.GetProperty("capabilities").EnumerateArray().Select(v => v.GetString()).ToArray();
        Assert.Contains("evidence.exact", capabilities);
        Assert.Contains("reports.export", capabilities);
        Assert.DoesNotContain("tasks.create", capabilities);
        var quarantined = access.GetProperty("quarantined_capability_assignments").EnumerateArray().ToArray();
        var malformed = Assert.Single(quarantined);
        Assert.Equal("tasks.create", malformed.GetProperty("capability_key").GetString());
        Assert.Equal("invalid_scope", malformed.GetProperty("reason").GetString());
        var scoped = Assert.Single(access.GetProperty("resource_bound_capability_assignments").EnumerateArray());
        Assert.Equal("events.view", scoped.GetProperty("capability_key").GetString());
        Assert.Equal("deny", scoped.GetProperty("effect").GetString());
        Assert.DoesNotContain(quarantined, p => p.GetProperty("capability_key").GetString() == "events.view");
        var denied = evaluation.Capabilities.DecideForResourceGroups("events.view", [[new("server", 7)]]);
        Assert.False(denied.Allowed); Assert.Equal("explicit_deny", denied.Reason);
        Assert.True(evaluation.Capabilities.DecideForResourceGroups("events.view", [[new("server", 8)]]).Allowed);
        var noResource = evaluation.Capabilities.Decide("events.view");
        Assert.False(noResource.Allowed); Assert.Equal("resource_context_required", noResource.Reason);
        var explain = access.GetProperty("capability_explain");
        Assert.Equal($"user:{userId}", explain.GetProperty("evidence.exact")[0].GetProperty("source").GetString());
        Assert.Equal($"group:{groupId}", explain.GetProperty("reports.export")[0].GetProperty("source").GetString());
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task DisjointReportGrantsExecuteSeparateServerAndFieldProjectionsOnPostgres()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct);
        await using var db = await fixture.Pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db, """
            insert into forests(name) values ('round2-report');
            insert into domains(forest_id,fqdn) select id,'round2.example.test' from forests where name='round2-report';
            insert into servers(domain_id,hostname)
                select d.id,s.name from domains d cross join (values ('round2-basic'),('round2-technical')) s(name)
                where d.fqdn='round2.example.test';
            insert into storage_v2_entity_type(value) values ('round2-entity');
            insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,server_id,source_core_sha256)
                select v.id,t.id,v.natural_key,v.display_name,s.domain_id,s.id,decode(repeat(v.digest,32),'hex')
                from (values
                    (1000001,'basic-secret','basic-visible','round2-basic','11'),
                    (1000002,'technical-visible','technical-secret','round2-technical','22')
                ) v(id,natural_key,display_name,hostname,digest)
                join servers s on s.hostname=v.hostname
                cross join storage_v2_entity_type t where t.value='round2-entity';
            with dataset as (
                insert into report_datasets_v4(dataset_key,version,name,fields_json,filters_json,actions_json,status)
                select 'entities.v2',coalesce(max(version),0)+1,'Round2',
                    '[{"key":"display_name","label":"Name","category":"identity_basic"},
                      {"key":"natural_key","label":"Key","category":"technical"}]'::jsonb,
                    '[]'::jsonb,'["view"]'::jsonb,'published'
                from report_datasets_v4 where dataset_key='entities.v2' returning id
            ) insert into report_registry_v4(report_key,version,name,owner_name,purpose,dataset_id,definition_json,sensitivity,status)
                select 'round2.tuple',1,'Round2','round2','test',id,
                    '{"columns":["display_name","natural_key"],"actions":["view"]}'::jsonb,'internal','published' from dataset;
            """, ct);
        long basicServer, technicalServer;
        await using (var ids = new NpgsqlCommand("""
            select (select id from servers where hostname='round2-basic'),
                   (select id from servers where hostname='round2-technical')
            """, db))
        await using (var reader = await ids.ExecuteReaderAsync(ct))
        {
            Assert.True(await reader.ReadAsync(ct));
            basicServer = reader.GetInt64(0); technicalServer = reader.GetInt64(1);
        }
        var access = JsonSerializer.SerializeToNode(new { reports = new[] { new {
            report_key = "round2.tuple", version = 1, allowed = true,
            grants = new[] {
                new { source = "A", scope = new { kind = "server", ids = new[] { basicServer } }, field_categories = new[] { "identity_basic" }, allowed_actions = new[] { "view" } },
                new { source = "B", scope = new { kind = "server", ids = new[] { technicalServer } }, field_categories = new[] { "technical" }, allowed_actions = new[] { "view" } }
            } } } })!.AsObject();
        var capabilities = new CapabilityDecisionSet(false,
            new HashSet<string> { "reports.catalog", "field.identity_basic", "field.technical" },
            new HashSet<string>(), [], new Dictionary<string, JsonElement>());
        var caller = new ReportCaller(new Principal("session", 1, "viewer"),
            new AccessFacts(false, "viewer", [], [], [], [], [], [], []), capabilities, access);
        var result = await new ReportRunner(new ReportDatabase(Connections(fixture)))
            .ExecuteAsync(caller, "round2.tuple", 100, null, "view", new Dictionary<string, string>(), ct);

        var rows = result["items"]!.AsArray().Select(r => r!.AsObject()).ToArray();
        Assert.Equal(2, rows.Length);
        Assert.All(rows, row => Assert.Single(row));
        Assert.Contains(rows, row => row["display_name"]?.GetValue<string>() == "basic-visible");
        Assert.Contains(rows, row => row["natural_key"]?.GetValue<string>() == "technical-visible");
        Assert.Equal("per_grant", result["field_visibility"]!.GetValue<string>());
        Assert.Equal(2, result["limits"]!["grant_branches"]!.GetValue<int>());
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
