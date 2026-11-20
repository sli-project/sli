using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Tests.Agents;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Vpn;

public sealed class RadiusSessionReconciliationPostgresTests
{
    const string Observation = "11111111-1111-1111-1111-111111111111";
    const string Evidence = "22222222-2222-2222-2222-222222222222";
    static readonly string Corpus = new('b', 64), Resolution = new('c', 64), Session = "radius-session:" + new string('a', 64);
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static string Id(int n) => Guid.Parse(n.ToString("D32")).ToString("D");
    static ReconciliationAttempt Attempt(string observation = Observation, string evidence = Evidence, bool projected = true, string resolver = "resolver-v1") =>
        new(Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(observation + "\0" + Corpus + "\0" + resolver))),
            observation, evidence, projected ? "projected" : "still_unresolved", Corpus, resolver, projected ? Resolution : null);
    static Dictionary<string, ExactResolutionProposal> Proposals(string observation = Observation) =>
        new() { [observation] = new(observation, Session, "entity:101", Resolution) };

    [Fact]
    public void Writer_contract_is_disabled_source_free_and_preserves_frozen_metadata()
    {
        var contract = RadiusSessionReconciliationWriter.LoadContract();
        Assert.Equal("sli.radius-session-reconciliation-writer.v1", contract["contract_id"]!.GetValue<string>());
        Assert.Equal(65, contract["required_migration"]!.GetValue<int>());
        Assert.Equal(50, contract["maximum_attempts_per_transaction"]!.GetValue<int>());
        foreach (string field in new[] { "source_contact_allowed", "production_migration_applied", "runtime_enabled", "autostart_enabled" })
            Assert.False(contract[field]!.GetValue<bool>());
        Assert.Equal(RadiusSessionReconciliationWriter.WriterRole, contract["writer_role"]!.GetValue<string>());
        Assert.Equal(3, contract["immutable_inputs"]!.AsArray().Count);
        Assert.Equal(2, contract["append_only_outputs"]!.AsArray().Count);
    }

    [Theory]
    [InlineData("runtime_enabled", "writer_contract_runtime_enabled_invalid")]
    [InlineData("source_contact_allowed", "writer_contract_source_contact_allowed_invalid")]
    [InlineData("writer_role", "writer_contract_writer_role_invalid")]
    [InlineData("immutable_inputs", "writer_contract_immutable_inputs_invalid")]
    [InlineData("append_only_outputs", "writer_contract_append_only_outputs_invalid")]
    public void Contract_rejects_activation_privilege_or_immutability_changes(string field, string code)
    {
        var contract = RadiusSessionReconciliationWriter.LoadContract(); contract[field] = true;
        Assert.Equal(code, Assert.Throws<VpnInputException>(() => RadiusSessionReconciliationWriter.LoadContract(contract.ToJsonString())).Message);
    }

    [Fact]
    public void Existing_migration_is_append_only_and_least_privilege()
    {
        string root = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations");
        string forward = File.ReadAllText(Path.Combine(root, "065_radius_session_reconciliation_overlay.sql")).ToLowerInvariant();
        string rollback = File.ReadAllText(Path.Combine(root, "065_radius_session_reconciliation_overlay.rollback.sql")).ToLowerInvariant();
        foreach (string sql in new[] { "values (65,'radius_session_reconciliation_overlay')", "create role adlog_radius_session_reconciliation_writer",
            "nologin nosuperuser", "create table radius_session_reconciliation_attempts", "create table radius_session_identity_overlays", "grant insert(" })
            Assert.Contains(sql, forward, StringComparison.Ordinal);
        Assert.DoesNotContain("grant update", forward, StringComparison.Ordinal);
        Assert.DoesNotContain("grant delete", forward, StringComparison.Ordinal);
        Assert.Contains("rollback 065 forbidden after reconciliation evidence", rollback, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Invalid_attempt_key_is_rejected_before_database_contact()
    {
        await using var db = new NpgsqlConnection();
        var attempt = Attempt() with { AttemptKey = new string('0', 64) };
        var error = await Assert.ThrowsAsync<VpnInputException>(() => RadiusSessionReconciliationWriter.WriteAsync(db, [attempt], Proposals(), Ct));
        Assert.Equal("writer_attempt_key_invalid", error.Message);
        Assert.Equal(ConnectionState.Closed, db.State);
    }

    [Fact]
    public async Task Empty_batch_is_rejected_before_database_contact()
    {
        await using var db = new NpgsqlConnection();
        var error = await Assert.ThrowsAsync<VpnInputException>(() => RadiusSessionReconciliationWriter.WriteAsync(db, [], new Dictionary<string, ExactResolutionProposal>(), Ct));
        Assert.Equal("writer_attempt_count_invalid", error.Message);
        Assert.Equal(ConnectionState.Closed, db.State);
    }

    [Theory]
    [InlineData("uuid", "writer_uuid_invalid")]
    [InlineData("corpus", "writer_corpus_hash_invalid")]
    [InlineData("resolver", "writer_resolver_contract_invalid")]
    [InlineData("outcome", "writer_outcome_invalid")]
    [InlineData("proposal", "writer_projected_proposal_required")]
    [InlineData("session", "writer_session_key_invalid")]
    [InlineData("principal", "writer_principal_key_invalid")]
    [InlineData("resolution", "writer_resolution_hash_invalid")]
    [InlineData("mismatch", "writer_resolution_hash_mismatch")]
    [InlineData("unresolved", "writer_unresolved_proposal_forbidden")]
    [InlineData("duplicate", "writer_duplicate_observation_in_batch")]
    [InlineData("extra", "writer_proposal_set_mismatch")]
    public async Task Invalid_batches_fail_closed_before_transaction(string vector, string code)
    {
        var a = Attempt(); var proposals = Proposals(); var proposal = proposals[Observation];
        a = vector switch {
            "uuid" => a with { ObservationId = "invalid" }, "corpus" => a with { EvidenceCorpusSha256 = "invalid" },
            "resolver" => a with { ResolverContractId = "" }, "outcome" => a with { Outcome = "invalid" },
            "resolution" => a with { ResolutionInputSha256 = "invalid" },
            "unresolved" => a with { Outcome = "still_unresolved" }, _ => a
        };
        if (vector == "proposal") proposals.Clear();
        if (vector == "session") proposals[Observation] = proposal with { SessionIdentityKey = Session + "\n" };
        if (vector == "principal") proposals[Observation] = proposal with { ExactPrincipalKey = "entity:0" };
        if (vector == "mismatch") proposals[Observation] = proposal with { ResolutionInputSha256 = new string('d', 64) };
        if (vector == "extra") proposals[Evidence] = proposal;
        await using var db = new NpgsqlConnection();
        var error = await Assert.ThrowsAsync<VpnInputException>(() => RadiusSessionReconciliationWriter.WriteAsync(db, vector == "duplicate" ? [a, a] : [a], proposals, Ct));
        Assert.Equal(code, error.Message); Assert.Equal(ConnectionState.Closed, db.State);
    }

    [Fact]
    public async Task Real_postgres_writer_is_atomic_idempotent_append_only_and_uses_dedicated_role()
    {
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(Ct);
        await using var admin = new NpgsqlConnection(fixture.Pg.ConnectionString); await admin.OpenAsync(Ct);
        await Seed(admin);
        await using var writer = new NpgsqlConnection(fixture.Dsn("synthetic_radius_writer")); await writer.OpenAsync(Ct);
        string before = (string)(await Scalar(admin, Inputs))!;
        var projected = Attempt(Id(1), Id(1001)); var proposals = Proposals(Id(1));
        var receipt = Assert.Single(await RadiusSessionReconciliationWriter.WriteAsync(writer, [projected], proposals, Ct));
        Assert.Equal(new(projected.AttemptKey, Id(1), "projected", "created", true), receipt);
        receipt = Assert.Single(await RadiusSessionReconciliationWriter.WriteAsync(writer, [projected], proposals, Ct));
        Assert.Equal(new(projected.AttemptKey, Id(1), "projected", "already_persisted", false), receipt);
        Assert.Equal("synthetic_radius_writer", await Scalar(writer, "select current_user::text"));
        var unresolved = Attempt(Id(2), Id(1002), false);
        receipt = Assert.Single(await RadiusSessionReconciliationWriter.WriteAsync(writer, [unresolved], new Dictionary<string, ExactResolutionProposal>(), Ct));
        Assert.Equal(new(unresolved.AttemptKey, Id(2), "still_unresolved", "created", false), receipt);
        Assert.Equal("already_persisted", Assert.Single(await RadiusSessionReconciliationWriter.WriteAsync(writer, [unresolved], new Dictionary<string, ExactResolutionProposal>(), Ct)).PersistenceState);

        async Task Reject(ReconciliationAttempt[] attempts, Dictionary<string, ExactResolutionProposal> p, string code) =>
            Assert.Equal(code, (await Assert.ThrowsAsync<VpnInputException>(() => RadiusSessionReconciliationWriter.WriteAsync(writer, attempts, p, Ct))).Message);
        await Reject([projected with { EvidenceUid = Id(1002) }], proposals, "writer_evidence_uid_mismatch");
        await Reject([Attempt(Id(999), Id(1001), false)], new(), "writer_observation_not_found");
        await Reject([Attempt(Id(1), Id(1001), true, "resolver-v2")], proposals, "writer_observation_already_resolved");
        var conflicting = Proposals(Id(1)); conflicting[Id(1)] = conflicting[Id(1)] with { SessionIdentityKey = "radius-session:" + new string('d', 64) };
        await Reject([projected], conflicting, "writer_overlay_replay_conflict");
        await Reject([projected with { Outcome = "still_unresolved", ResolutionInputSha256 = null }], new(), "writer_attempt_replay_conflict");

        // The first insert must roll back when a later observation cannot resolve to an existing entity.
        var absentEntity = Proposals(Id(4)); absentEntity[Id(4)] = absentEntity[Id(4)] with { ExactPrincipalKey = "entity:999" };
        await Reject([Attempt(Id(3), Id(1003), false), Attempt(Id(4), Id(1004))], absentEntity, "writer_exact_entity_not_found");
        Assert.Equal(2L, await Scalar(admin, "select count(*) from radius_session_reconciliation_attempts"));
        await PostCollectionPostgres.Sql(admin, "update radius_session_projection_receipts set outcome='timestamp_unresolved' where observation_id='" + Id(4) + "'", Ct);
        await Reject([Attempt(Id(4), Id(1004), false)], new(), "writer_terminal_unresolved_receipt_required");
        await PostCollectionPostgres.Sql(admin, "update radius_session_projection_receipts set outcome='identity_unresolved' where observation_id='" + Id(4) + "'", Ct);

        // Q500 supersedes the old process cap: 51 valid attempts are persisted in one atomic transaction.
        var large = Enumerable.Range(3, 51).Select(n => Attempt(Id(n), Id(1000 + n), false)).ToArray();
        Assert.Equal(51, (await RadiusSessionReconciliationWriter.WriteAsync(writer, large, new Dictionary<string, ExactResolutionProposal>(), Ct)).Count);
        Assert.Equal(before, await Scalar(admin, Inputs));
        foreach (string table in new[] { "radius_session_reconciliation_attempts", "radius_session_identity_overlays" }) {
            Assert.True(await Scalar(admin, $"select has_column_privilege('{RadiusSessionReconciliationWriter.WriterRole}','{table}','observation_id','INSERT')") is true);
            foreach (string privilege in new[] { "UPDATE", "DELETE", "TRUNCATE" })
                Assert.False((bool)(await Scalar(admin, $"select has_table_privilege('{RadiusSessionReconciliationWriter.WriterRole}','{table}','{privilege}')"))!);
        }
        Assert.False((bool)(await Scalar(admin, $"select rolcanlogin or rolsuper or rolbypassrls from pg_roles where rolname='{RadiusSessionReconciliationWriter.WriterRole}'"))!);
        await fixture.AssertNoSqlErrorsAsync(Ct);
    }

    const string Inputs = """
        select jsonb_build_array(
          (select jsonb_agg(to_jsonb(t) order by observation_id) from radius_accounting_session_observations t),
          (select jsonb_agg(to_jsonb(t) order by delivery_id) from radius_session_projection_receipts t),
          (select jsonb_agg(to_jsonb(t) order by evidence_uid) from core_evidence_manifests t))::text
        """;
    static async Task<object?> Scalar(NpgsqlConnection db, string sql)
    { await using var command = new NpgsqlCommand(sql, db); return await command.ExecuteScalarAsync(Ct); }
    static Task Seed(NpgsqlConnection db) => PostCollectionPostgres.Sql(db, """
        create role synthetic_radius_writer login noinherit nosuperuser nocreatedb nocreaterole nobypassrls;
        grant adlog_radius_session_reconciliation_writer to synthetic_radius_writer;
        insert into storage_v2_entity_type(value) values('synthetic_radius') on conflict do nothing;
        insert into entities_v2(id,entity_type_id,natural_key,display_name,source_core_sha256)
        select 101,id,'synthetic-radius','Synthetic radius',sha256('synthetic'::bytea) from storage_v2_entity_type where value='synthetic_radius';
        insert into acquisition_source_instances(source_instance_id,organization_scope,source_kind,endpoint_identity,adapter_binding,display_name,configuration_sha256)
        values('synthetic-radius','synthetic','radius','nps.example.test','synthetic','Synthetic radius',repeat('a',64));
        insert into acquisition_stream_cursors(source_instance_id,stream_id,transport_binding,cursor_epoch,file_generation,byte_offset)
        values('synthetic-radius','accounting','synthetic','00000000-0000-0000-0000-000000000001','synthetic',0);
        insert into acquisition_consumer_subscriptions(subscription_id,source_instance_id,stream_id,transport_binding,consumer_id,
            consumer_component_id,consumer_component_version,routing_contract_id,consumer_contract_version,replay_policy,resource_profile_id,
            selector_json,selector_sha256,authority_mode,partition_key)
        values('synthetic-subscription','synthetic-radius','accounting','synthetic','synthetic','synthetic','1','synthetic','1',
            'no_replay','synthetic','{}',repeat('a',64),'shadow','synthetic');
        insert into core_evidence_manifests(evidence_uid,source_instance_id,stream_id,transport_binding,cursor_epoch,file_generation,
            cursor_start_byte_offset,batch_record_ordinal,canonical_record_sha256,object_reference,object_sha256,object_size_bytes,verified_at_utc)
        select lpad((1000+n)::text,32,'0')::uuid,'synthetic-radius','accounting','synthetic','00000000-0000-0000-0000-000000000001',
            'synthetic',0,n,repeat('a',64),'evidence:synthetic-'||n,repeat('a',64),1,now() from generate_series(1,55) n;
        insert into radius_accounting_session_observations(observation_id,evidence_uid,lifecycle_event,identity_state,timestamp_state,
            session_confirmed_by_accounting,producer_contract_id,resource_groups,row_sensitivity,field_categories,
            evidence_access_requirement,label_policy_version,provenance_json)
        select lpad(n::text,32,'0')::uuid,lpad((1000+n)::text,32,'0')::uuid,'start','unresolved','unresolved',true,'synthetic',
            array['synthetic'],'internal',array['synthetic'],'synthetic','1','{}' from generate_series(1,55) n;
        insert into acquisition_delivery_outbox(subscription_id,evidence_uid,observation_id,idempotency_key)
        select 'synthetic-subscription',evidence_uid,observation_id,encode(sha256(observation_id::text::bytea),'hex') from radius_accounting_session_observations;
        insert into radius_session_projection_receipts(delivery_id,observation_id,outcome,projected_row_count,consumer_contract_id)
        select delivery_id,observation_id,'identity_unresolved',0,'synthetic' from acquisition_delivery_outbox;
        """, Ct);
}
