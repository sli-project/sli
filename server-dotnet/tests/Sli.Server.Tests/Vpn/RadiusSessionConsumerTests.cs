using System.Data;
using Npgsql;
using Sli.Server.Tests.Agents;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Vpn;

public sealed class RadiusSessionConsumerTests
{
    const string Subscription = "synthetic-subscription";
    const string SessionKey = "radius-session:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("Bad Error", 30, "error_code_invalid")]
    [InlineData("", 30, "error_code_invalid")]
    [InlineData("bounded_error", 3601, "retry_delay_invalid")]
    [InlineData("bounded_error", -1, "retry_delay_invalid")]
    public async Task Failure_inputs_are_rejected_before_database_use(string code, int delay, string expected)
    {
        await using var db = new NpgsqlConnection();
        var error = await Assert.ThrowsAsync<VpnInputException>(() => RadiusJobs.FailAsync(db, 1, Guid.NewGuid(), code, delay, Ct));
        Assert.Equal(expected, error.Message);
        Assert.Equal(ConnectionState.Closed, db.State);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Consumer_rebuilds_from_typed_manifest_evidence_with_optional_overlays(bool overlay)
    {
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(Ct);
        await using var db = await fixture.Pg.OpenAsync(Ct);
        await Seed(db, overlay);
        if (!overlay) await PostCollectionPostgres.Sql(db, "drop table radius_session_identity_overlays", Ct);
        await using (var transaction = await db.BeginTransactionAsync(Ct))
        {
            await RadiusJobs.Execute(db, "set local role sli_job_publisher_light", Ct);
            string role = (string)(await RadiusJobs.Scalar(db, "select current_user", Ct))!;
            if (overlay)
            {
                Assert.Equal(false, await RadiusJobs.Scalar(db, "select has_table_privilege(current_user,'public.radius_session_identity_overlays','SELECT')", Ct));
                Assert.Equal(true, await RadiusJobs.Scalar(db, RadiusConsumerSql.OverlayReadable, Ct));
            }
            await RadiusJobs.ConsumeAsync(db, Subscription, [1, 2], "synthetic-consumer", 10, Ct);
            Assert.Equal(role, await RadiusJobs.Scalar(db, "select current_user", Ct));
            await transaction.CommitAsync(Ct);
        }
        var row = Assert.Single(await RadiusJobs.Rows(db, "select * from radius_vpn_session_projection", Ct));
        Assert.Equal(SessionKey, row["session_identity_key"]!.ToString());
        Assert.Equal("entity:1", row["exact_principal_key"]!.ToString());
        Assert.Equal("closed", row["lifecycle_state"]!.ToString());
        Assert.Equal("complete", row["completeness"]!.ToString());
        Assert.Equal(60, row["duration_seconds"]!.GetValue<long>());
        Assert.Equal(2, row["observation_count"]!.GetValue<int>());
        Assert.Equal(overlay ? 1L : 2L, await RadiusJobs.Scalar(db, "select count(*) from radius_session_projection_receipts where outcome='projected' and projected_row_count=1 and consumer_contract_id='sli.radius-session-consumer.v1'", Ct));
        Assert.Equal(overlay ? 1L : 0L, await RadiusJobs.Scalar(db, "select count(*) from radius_session_projection_receipts where outcome='identity_unresolved' and projected_row_count=0", Ct));
        Assert.Equal(2L, await RadiusJobs.Scalar(db, "select count(*) from acquisition_delivery_outbox where delivery_state='delivered' and lease_token is null and heartbeat_at is not null", Ct));
        Assert.Equal("queued", await RadiusJobs.Scalar(db, "select delivery_state from acquisition_delivery_outbox where delivery_id=3", Ct));
        // No raw evidence objects exist. A forged provenance hash must never be used.
        if (overlay) Assert.Equal("unresolved", await RadiusJobs.Scalar(db, "select identity_state from radius_accounting_session_observations where observation_id='00000000-0000-4000-8000-000000000001'", Ct));
        await fixture.AssertNoSqlErrorsAsync(Ct);
    }

    [Fact]
    public async Task Shared_record_budget_rejects_before_projection_changes_and_publisher_rolls_back_receipts()
    {
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(Ct);
        await using var db = await fixture.Pg.OpenAsync(Ct);
        await Seed(db, false);
        await using (var locked = await db.BeginTransactionAsync(Ct))
        {
            await RadiusJobs.Rows(db, "select delivery_id from acquisition_delivery_outbox where delivery_id=1 for update", Ct);
            await using var peer = await fixture.Pg.OpenAsync(Ct);
            await using var peerTransaction = await peer.BeginTransactionAsync(Ct);
            var error = await Assert.ThrowsAsync<VpnInputException>(() => RadiusJobs.ConsumeAsync(peer, Subscription, [1], "synthetic-locked", 10, Ct));
            Assert.Equal("radius_input_changed", error.Message);
            await peerTransaction.RollbackAsync(Ct);
            await using var pinnedTransaction = await peer.BeginTransactionAsync(Ct);
            // A later pinned ID must win over the earlier unlocked ID 2.
            await RadiusJobs.ConsumeAsync(peer, Subscription, [3], "synthetic-pinned", 10, Ct);
            Assert.Equal("delivered", await RadiusJobs.Scalar(peer, "select delivery_state from acquisition_delivery_outbox where delivery_id=3", Ct));
            Assert.Equal("queued", await RadiusJobs.Scalar(peer, "select delivery_state from acquisition_delivery_outbox where delivery_id=2", Ct));
            await pinnedTransaction.RollbackAsync(Ct);
            await locked.RollbackAsync(Ct);
        }
        await using (var transaction = await db.BeginTransactionAsync(Ct))
        {
            // First rebuild reads one row; second reads two, exceeding the remaining one.
            var error = await Assert.ThrowsAsync<VpnInputException>(() => RadiusJobs.ConsumeAsync(db, Subscription, [1, 2], "synthetic-budget", 2, Ct));
            Assert.Equal("session_observation_limit_exceeded", error.Message);
            Assert.Equal(1L, await RadiusJobs.Scalar(db, "select observation_count::bigint from radius_vpn_session_projection", Ct));
            await transaction.RollbackAsync(Ct);
        }
        Assert.Equal(0L, await RadiusJobs.Scalar(db, "select count(*) from radius_vpn_session_projection", Ct));
        Assert.Equal(0L, await RadiusJobs.Scalar(db, "select count(*) from radius_session_projection_receipts", Ct));
        Assert.Equal(3L, await RadiusJobs.Scalar(db, "select count(*) from acquisition_delivery_outbox where delivery_state='queued' and attempt_count=0", Ct));
        await fixture.AssertNoSqlErrorsAsync(Ct);
    }

    [Fact]
    public async Task Failure_releases_only_matching_lease_and_schedules_retry()
    {
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(Ct);
        await using var db = await fixture.Pg.OpenAsync(Ct);
        await Seed(db, false);
        Guid token = Guid.NewGuid();
        await RadiusJobs.Execute(db, "update acquisition_delivery_outbox set delivery_state='leased',lease_token=$1,lease_until=now()+interval '120 seconds',attempt_count=1 where delivery_id=1", Ct, token);
        var wrongToken = await Assert.ThrowsAsync<VpnInputException>(() => RadiusJobs.FailAsync(db, 1, Guid.NewGuid(), "bounded_error", 0, Ct));
        Assert.Equal("delivery_lease_lost", wrongToken.Message);
        Assert.Equal("leased", await RadiusJobs.Scalar(db, "select delivery_state from acquisition_delivery_outbox where delivery_id=1", Ct));
        Assert.Equal("failed", await RadiusJobs.FailAsync(db, 1, token, " bounded_error ", 30, Ct));
        var row = Assert.Single(await RadiusJobs.Rows(db, "select last_error_code,lease_token,lease_until,heartbeat_at,available_at>now() as delayed from acquisition_delivery_outbox where delivery_id=1", Ct));
        Assert.Equal("bounded_error", row["last_error_code"]!.ToString());
        Assert.Null(row["lease_token"]); Assert.Null(row["lease_until"]); Assert.NotNull(row["heartbeat_at"]);
        Assert.True(row["delayed"]!.GetValue<bool>());
        var error = await Assert.ThrowsAsync<VpnInputException>(() => RadiusJobs.FailAsync(db, 1, token, "bounded_error", 0, Ct));
        Assert.Equal("delivery_lease_lost", error.Message);
        await RadiusJobs.Execute(db, "update acquisition_delivery_outbox set delivery_state='leased',lease_token=$1,lease_until=now()+interval '120 seconds' where delivery_id=1", Ct, token);
        Assert.Equal("failed", await RadiusJobs.FailAsync(db, 1, token, new string('a', 120), 3600, Ct));
        await fixture.AssertNoSqlErrorsAsync(Ct);
    }

    static async Task Seed(NpgsqlConnection db, bool overlay)
    {
        await PostCollectionPostgres.Sql(db, """
            insert into acquisition_source_instances(source_instance_id,organization_scope,source_kind,endpoint_identity,adapter_binding,display_name,configuration_sha256)
            values('synthetic-radius','synthetic','radius','radius.example.test','synthetic','synthetic',repeat('a',64));
            insert into acquisition_stream_cursors(source_instance_id,stream_id,transport_binding,cursor_epoch,file_generation,byte_offset)
            values('synthetic-radius','synthetic','synthetic','00000000-0000-4000-8000-000000000010','synthetic',0);
            insert into acquisition_consumer_subscriptions(subscription_id,source_instance_id,stream_id,transport_binding,consumer_id,consumer_component_id,consumer_component_version,routing_contract_id,consumer_contract_version,replay_policy,resource_profile_id,selector_json,selector_sha256,authority_mode,partition_key)
            values('synthetic-subscription','synthetic-radius','synthetic','synthetic','synthetic','synthetic','1','synthetic','1','no_replay','synthetic','{}',repeat('a',64),'authoritative','synthetic');
            insert into core_evidence_manifests(evidence_uid,source_instance_id,stream_id,transport_binding,cursor_epoch,file_generation,cursor_start_byte_offset,batch_record_ordinal,canonical_record_sha256,object_reference,object_sha256,object_size_bytes,verified_at_utc)
            select ('00000000-0000-4000-8000-'||lpad(i::text,12,'0'))::uuid,'synthetic-radius','synthetic','synthetic','00000000-0000-4000-8000-000000000010','synthetic',0,i,repeat('f',64),'evidence:synthetic-missing-'||i,repeat('a',64),1,now() from generate_series(1,3) i;
            insert into radius_accounting_session_observations(observation_id,evidence_uid,lifecycle_event,session_identity_key,exact_principal_key,identity_state,observed_at_utc,timestamp_basis,timestamp_state,session_confirmed_by_accounting,producer_contract_id,resource_groups,row_sensitivity,field_categories,evidence_access_requirement,label_policy_version,provenance_json)
            select evidence_uid,evidence_uid,case when batch_record_ordinal=2 then 'stop' else 'start' end,'radius-session:'||repeat('a',64),'entity:1','exact','2026-08-15 00:00:00+00'::timestamptz+(batch_record_ordinal-1)*interval '1 minute','synthetic','ready',true,'synthetic',array['vpn.sessions'],'internal',array['synthetic'],'synthetic','1','{"canonical_record_sha256":"forged"}' from core_evidence_manifests;
            insert into acquisition_delivery_outbox(delivery_id,subscription_id,evidence_uid,observation_id,idempotency_key)
            select batch_record_ordinal,'synthetic-subscription',evidence_uid,evidence_uid,lpad(batch_record_ordinal::text,64,'0') from core_evidence_manifests order by batch_record_ordinal;
            update plugin_installations_v1 set package_lifecycle='registered',desired_activation='disabled',component_runtime='draining' where plugin_id='sli.remote-access';
            update plugin_component_admission_v1 set admission_mode='drain_only' where plugin_id='sli.remote-access' and component_id='radius-session-observation';
            """, Ct);
        if (overlay) await PostCollectionPostgres.Sql(db, """
            update radius_accounting_session_observations set identity_state='unresolved',session_identity_key=null,exact_principal_key=null where observation_id='00000000-0000-4000-8000-000000000001';
            insert into radius_session_reconciliation_attempts(attempt_key,observation_id,evidence_uid,outcome,evidence_corpus_sha256,resolver_contract_id,resolution_input_sha256,writer_contract_id)
            values(repeat('b',64),'00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000001','projected',repeat('c',64),'synthetic',repeat('d',64),'synthetic');
            insert into radius_session_identity_overlays(observation_id,attempt_key,evidence_uid,session_identity_key,exact_principal_key,resolution_input_sha256,resolver_contract_id)
            values('00000000-0000-4000-8000-000000000001',repeat('b',64),'00000000-0000-4000-8000-000000000001','radius-session:'||repeat('a',64),'entity:1',repeat('d',64),'synthetic');
            """, Ct);
    }
}
