using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic.Detections;
using Sli.Server.Semantic.Password;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// A release that rewords a default detection policy used to fail every cycle with
// default_detection_policy_conflict: the stored version is immutable and its id
// depends only on the execution pin. Real PostgreSQL, real migrations, real roles.
[Collection("Semantic producer environment")]
public sealed class DefaultPolicyReconcileTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static readonly PasswordScope Scope = new("22222222-2222-2222-2222-222222222222", "sli.windows.ad-dc", "synthetic-dc", "generation-1", "");
    const string Rule = "qw.kerberoasting";

    static JsonObject Definition(string title)
    {
        var definition = IdentityAttacks.PolicyDefinition(Scope, Rule);
        definition["title"] = title;
        return definition;
    }
    static async Task<object?> Scalar(NpgsqlConnection db, string sql)
    {
        await using var command = new NpgsqlCommand(sql, db);
        return await command.ExecuteScalarAsync(Ct);
    }
    static async Task Sql(NpgsqlConnection db, string sql)
    {
        await using var command = new NpgsqlCommand(sql, db);
        await command.ExecuteNonQueryAsync(Ct);
    }
    static async Task<bool> Admit(NpgsqlConnection worker, JsonObject definition)
    {
        await using var tx = await worker.BeginTransactionAsync(Ct);
        bool enabled = await DetectionProducer.Admit(new DetectionSql(worker, tx), definition, Ct);
        await tx.CommitAsync(Ct);
        return enabled;
    }
    static string EnabledPolicies => $$"""
        select count(*) from semantic_risk_policies p join semantic_policy_admission a using(policy_id,policy_version)
        where p.source_kind='qw_signal' and a.enabled and p.lifecycle_status in ('shadow','enabled')
          and p.definition_json#>>'{source_selector,rule_id}'='{{Rule}}'
        """;

    [Fact]
    public async Task Reworded_untouched_default_is_replaced_by_one_current_policy_on_every_upgrade()
    {
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(Ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString);
        await admin.OpenAsync(Ct);
        await Sql(admin, $"""
            insert into finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,source_instance_id,
                source_generation,collection_scope_id,storage_kind,log_source_id,agent_id)
            select 'sli_semantic_login'::regrole,'sli_semantic_login','{Scope.InstallationId}','sli.windows.ad-dc','synthetic-dc',
                'generation-1','','core_event',(select id from log_sources where name='Security'),md5('agent:1')::uuid
            """);
        await using var worker = new NpgsqlConnection(fixture.Dsn("sli_semantic_login"));
        await worker.OpenAsync(Ct);
        await Sql(worker, "set role adlog_semantic_worker");

        Assert.True(await Admit(worker, Definition("Release 1 wording")));
        string original = (string)(await Scalar(admin, $"select policy_id from semantic_risk_policies where definition_json->>'title'='Release 1 wording'"))!;

        // Release 2 words the same policy differently: the stored version cannot change.
        Assert.True(await Admit(worker, Definition("Release 2 wording")));
        Assert.Equal(1L, await Scalar(admin, EnabledPolicies));
        Assert.Equal("system:defaults-superseded", await Scalar(admin, $"select updated_by from semantic_policy_admission where policy_id='{original}'"));
        Assert.False((bool)(await Scalar(admin, $"select enabled from semantic_policy_admission where policy_id='{original}'"))!);
        string current = (string)(await Scalar(admin, "select p.policy_id from semantic_risk_policies p join semantic_policy_admission a using(policy_id,policy_version) where a.enabled and p.definition_json->>'title'='Release 2 wording'"))!;
        Assert.StartsWith(original + ":r", current);

        // The same document again changes nothing; the next wording replaces the previous one.
        long policies = (long)(await Scalar(admin, "select count(*) from semantic_risk_policies"))!;
        Assert.True(await Admit(worker, Definition("Release 2 wording")));
        Assert.Equal(policies, await Scalar(admin, "select count(*) from semantic_risk_policies"));
        Assert.True(await Admit(worker, Definition("Release 3 wording")));
        Assert.Equal(1L, await Scalar(admin, EnabledPolicies));
        Assert.Equal("Release 3 wording", await Scalar(admin, "select p.definition_json->>'title' from semantic_risk_policies p join semantic_policy_admission a using(policy_id,policy_version) where a.enabled and p.definition_json#>>'{source_selector,rule_id}'='qw.kerberoasting'"));
        await fixture.AssertNoSqlErrorsAsync(Ct);
    }

    [Fact]
    public async Task Admin_modified_default_is_kept_and_reported_once()
    {
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(Ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString);
        await admin.OpenAsync(Ct);
        await Sql(admin, $"""
            insert into finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,source_instance_id,
                source_generation,collection_scope_id,storage_kind,log_source_id,agent_id)
            select 'sli_semantic_login'::regrole,'sli_semantic_login','{Scope.InstallationId}','sli.windows.ad-dc','synthetic-dc',
                'generation-1','','core_event',(select id from log_sources where name='Security'),md5('agent:1')::uuid
            """);
        await using var worker = new NpgsqlConnection(fixture.Dsn("sli_semantic_login"));
        await worker.OpenAsync(Ct);
        await Sql(worker, "set role adlog_semantic_worker");

        Assert.True(await Admit(worker, Definition("Release 1 wording")));
        string original = (string)(await Scalar(admin, "select policy_id from semantic_risk_policies where definition_json->>'title'='Release 1 wording'"))!;
        // The administrator confirms the policy under their own name (governance writes updated_by).
        await Sql(admin, $"update semantic_policy_admission set enabled=true,updated_by='alice' where policy_id='{original}'");

        Assert.True(await Admit(worker, Definition("Release 2 wording")));
        Assert.True(await Admit(worker, Definition("Release 2 wording")));
        Assert.Equal(1L, await Scalar(admin, "select count(*) from semantic_risk_policies where source_kind='qw_signal' and definition_json#>>'{source_selector,rule_id}'='qw.kerberoasting'"));
        Assert.Equal("alice", await Scalar(admin, $"select updated_by from semantic_policy_admission where policy_id='{original}'"));
        Assert.Equal("Release 1 wording", await Scalar(admin, $"select definition_json->>'title' from semantic_risk_policies where policy_id='{original}'"));
        Assert.Equal(1L, await Scalar(admin, $"select count(*) from semantic_control_audit where action='default_policy_customized_kept' and target='{original}:1'"));
        await fixture.AssertNoSqlErrorsAsync(Ct);
    }

    [Fact]
    public async Task Migration_340_applies_on_previous_maximum_and_rolls_back_to_the_old_admission()
    {
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(Ct, throughVersion: 337);
        string migration = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/340_default_policy_reconcile");
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString);
        await admin.OpenAsync(Ct);
        string before = (string)(await Scalar(admin, "select prosrc from pg_proc where oid='public.ensure_default_qw_policy_v262(text,integer,text)'::regprocedure"))!;
        await fixture.Pg.ApplyFileAsync(migration + ".sql", null, Ct);
        Assert.Equal(340, await Scalar(admin, "select max(version) from schema_migrations"));
        Assert.NotEqual(before, await Scalar(admin, "select prosrc from pg_proc where oid='public.ensure_default_qw_policy_v262(text,integer,text)'::regprocedure"));
        await fixture.Pg.ApplyFileAsync(migration + ".rollback.sql", null, Ct);
        Assert.Equal(337, await Scalar(admin, "select max(version) from schema_migrations"));
        Assert.Equal(before, await Scalar(admin, "select prosrc from pg_proc where oid='public.ensure_default_qw_policy_v262(text,integer,text)'::regprocedure"));
        await fixture.Pg.ApplyFileAsync(migration + ".sql", null, Ct);
        Assert.Equal(340, await Scalar(admin, "select max(version) from schema_migrations"));
    }
}
