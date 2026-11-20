using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Server.Agents.Radius;
using Xunit;

namespace Sli.Server.Tests.Agents;

// Vectors from tests/sources/test_radius_accounting_postgres.py. These tests
// use synthetic records and configuration only; no PostgreSQL or NPS contact.
public sealed class RadiusAccountingPostgresTests
{
    private static readonly DateTimeOffset Observed=new(2026,7,30,8,0,0,TimeSpan.Zero);
    private static readonly RadiusCursor Current=new("radius-fixture-1","radius-accounting","fixture-log","in-20260730",0,null);
    private static string Read(string relative)=>File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(),relative));
    private static JsonObject Config(string name)=>JsonNode.Parse(Read("config/"+name))!.AsObject();
    private static string Line(string packet,string status="")
    {
        var fields=Enumerable.Repeat("",66).ToArray();
        fields[0]="NPS01";fields[1]="IAS";fields[2]="07/30/2026";fields[3]="15:00:00";fields[4]=packet;
        fields[6]="example.test/Users/sample.user";fields[11]="VPN-GW-01";fields[26]="opaque-class";fields[31]=status;fields[35]="opaque-session";
        return string.Join(',',fields);
    }
    private static async Task<(RadiusPlan Plan,RadiusEvidence[] Evidence,RadiusCursor Next)> Batch()
    {
        var plan=await RadiusPlanner.ProjectAsync([Line("2"),Line("4","1")],Current.SourceId,"N. Central Asia Standard Time",420,Observed,[],
            _=>Task.FromResult<string?>("sid:S-1-5-21-100000001-200000002-300000003-1101"));
        var evidence=plan.EvidenceHashes.Select((hash,i)=>new RadiusEvidence(Guid.Parse($"00000000-0000-0000-0000-{i+1:000000000000}"),hash,$"evidence:radius.fixture.{i+1}",128,Observed.AddMinutes(1))).ToArray();
        return (plan,evidence,Current with { ByteOffset=200,LastRecordSha256=plan.EvidenceHashes[^1] });
    }
    private static void Reject(string code,Action action)=>Assert.Equal(code,Assert.Throws<RadiusImportPending>(action).Code);

    [Fact]
    public void HistoricalPostgresContractRemainsDisabledAndDisposable()
    {
        var contract=Config("stage9_radius_postgres_contract_v1.json");
        Assert.Equal("accepted_for_disposable_only",contract["status"]!.GetValue<string>());
        foreach(string key in new[]{"runtime_enabled","production_migration_applied","source_contact_allowed"}) Assert.False(contract[key]!.GetValue<bool>());
        // Historical pilot contract value, not a new runtime processing limit.
        Assert.Equal(1000,contract["maximum_records_per_commit"]!.GetValue<int>());
    }

    [Fact]
    public void RegistrationTemplateFollowsRouteAndStaysDisabledUntilBootstrap()
    {
        var routes=Config("stage10_radius_collection_routes_v1.json");
        var contract=RadiusRegistrationContract.FromTemplate(Config("stage9_radius_registration_v1.json"),routes);
        Assert.Equal("prepared_disabled_only",contract["status"]!.GetValue<string>());
        Assert.Equal("disabled",contract["desired_activation"]!.GetValue<string>());
        Assert.Equal(routes["source_instance_id"]!.GetValue<string>(),contract["source"]!["source_instance_id"]!.GetValue<string>());
        Assert.Equal($"fqdn:{routes["source_name"]!.GetValue<string>()}|ipv4:{routes["owner_confirmed_ip"]!.GetValue<string>()}",contract["source"]!["endpoint_identity"]!.GetValue<string>());
        Assert.Equal("vpn-radius-session-observations-radius01-v1",contract["subscription"]!["subscription_id"]!.GetValue<string>());
        Assert.Null(contract["source"]!["credential_handle"]);
        Assert.Equal("requires_bounded_live_bootstrap",contract["stream"]!["initial_cursor_policy"]!.GetValue<string>());
        Assert.Contains("worker_activation",contract["prohibited_actions"]!.AsArray().Select(n=>n!.GetValue<string>()));
    }

    [Fact]
    public void RegistrationRejectsEndpointDrift()
    {
        var routes=Config("stage10_radius_collection_routes_v1.json");
        var contract=RadiusRegistrationContract.FromTemplate(Config("stage9_radius_registration_v1.json"),routes);
        contract["source"]!["endpoint_identity"]="fqdn:other.example.test|ipv4:192.0.2.7";
        Assert.Equal("registration_source_identity_mismatch",Assert.Throws<ArgumentException>(()=>RadiusRegistrationContract.Validate(contract,routes)).Message);
    }

    [Fact]
    public async Task EvidenceManifestMustMatchProjectedPlanExactly()
    {
        var (plan,evidence,next)=await Batch();
        RadiusAccountingImporter.ValidateBatch(Current,next,false,plan,evidence);
        Assert.Equal(2,plan.EvidenceHashes.Count);
        Assert.Equal("start",Assert.Single(plan.Observations).Lifecycle);
        Assert.Equal(Observed,plan.Observations[0].ObservedAt);
        evidence[0]=evidence[0] with { Hash=new string('0',64) };
        Reject("evidence_hash_mismatch",()=>RadiusAccountingImporter.ValidateBatch(Current,next,false,plan,evidence));
    }

    [Fact]
    public async Task EvidenceOrderCountAndIdentityCannotBeSubstituted()
    {
        var (plan,evidence,next)=await Batch();
        Reject("evidence_count_mismatch",()=>RadiusAccountingImporter.ValidateBatch(Current,next,false,plan,evidence[..1]));
        Reject("evidence_hash_mismatch",()=>RadiusAccountingImporter.ValidateBatch(Current,next,false,plan,evidence.Reverse().ToArray()));
        evidence[1]=evidence[1] with { Id=evidence[0].Id };
        Reject("evidence_uid_duplicate",()=>RadiusAccountingImporter.ValidateBatch(Current,next,false,plan,evidence));
    }

    [Fact]
    public async Task BatchCannotForgeRotationOrRegressOffset()
    {
        var (plan,evidence,next)=await Batch();
        Reject("rotation_claim_mismatch",()=>RadiusAccountingImporter.ValidateBatch(Current,next,true,plan,evidence));
        var rotated=next with { FileGeneration="in-20260731",ByteOffset=0 };
        Reject("rotation_claim_mismatch",()=>RadiusAccountingImporter.ValidateBatch(Current,rotated,false,plan,evidence));
        RadiusAccountingImporter.ValidateBatch(Current,rotated,true,plan,evidence);
        Reject("cursor_offset_regressed",()=>RadiusAccountingImporter.ValidateBatch(Current with { ByteOffset=201 },next,false,plan,evidence));
    }

    [Theory]
    [InlineData("source_instance_id")]
    [InlineData("stream_id")]
    [InlineData("transport_binding")]
    public async Task BatchCannotChangeCursorOwner(string field)
    {
        var (plan,evidence,next)=await Batch();
        next=field switch {
            "source_instance_id"=>next with { SourceId="other-source" },
            "stream_id"=>next with { StreamId="other-stream" },
            _=>next with { TransportBinding="other-binding" }
        };
        Reject("cursor_owner_changed_in_batch",()=>RadiusAccountingImporter.ValidateBatch(Current,next,false,plan,evidence));
    }

    [Fact]
    public void SharedMigration058PreservesAtomicLeastPrivilegeFoundation()
    {
        string sql=Read("config/postgres_migrations/058_radius_accounting_transaction_foundation.sql").ToLowerInvariant();
        foreach(string expected in new[]{"requires schema migration 055","create role adlog_radius_accounting_worker","nologin nosuperuser nocreatedb nocreaterole",
            "acquisition_source_instances","acquisition_consumer_subscriptions","core_evidence_manifests","radius_accounting_session_observations",
            "acquisition_delivery_outbox","radius_accounting_class_cache","cursor_start_byte_offset","batch_record_ordinal","values (58,'radius_accounting_transaction_foundation')"}) Assert.Contains(expected,sql);
        foreach(string forbidden in new[]{"raw_record","account_session_id","nas_identity"}) Assert.DoesNotContain(forbidden,sql);
    }

    [Fact]
    public void SharedMigration058RollbackRefusesPersistedStateBeforeDroppingAnything()
    {
        string sql=Read("config/postgres_migrations/058_radius_accounting_transaction_foundation.rollback.sql").ToLowerInvariant();
        int guard=sql.IndexOf("migration 058 rollback refuses persisted acquisition evidence/state",StringComparison.Ordinal);
        Assert.True(guard>=0 && guard<sql.IndexOf("drop table",StringComparison.Ordinal));
        Assert.Contains("drop role adlog_radius_accounting_worker",sql);
        Assert.Contains("delete from schema_migrations",sql);
    }

    [Theory]
    [InlineData("forward_sha256")]
    [InlineData("rollback_sha256")]
    public void PreflightRejectsMigrationHashDrift(string hash)
    {
        byte[] forward=File.ReadAllBytes(Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/058_radius_accounting_transaction_foundation.sql"));
        byte[] rollback=File.ReadAllBytes(Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/058_radius_accounting_transaction_foundation.rollback.sql"));
        var evidence=JsonNode.Parse("""
            {"status":"ready","blockers":[],"identity":{"database":"fixture"},"schema":{"maximum_marker":55},
             "privileges":{"storage_owner_member":true},"migration":{"version":58,"execution_contract":"single_file_058_only","excluded_from_automatic_sequence":[56,57]}}
            """)!.AsObject();
        evidence["migration"]!["forward_sha256"]=Convert.ToHexStringLower(SHA256.HashData(forward));
        evidence["migration"]!["rollback_sha256"]=Convert.ToHexStringLower(SHA256.HashData(rollback));
        var live=(JsonObject)evidence.DeepClone();live.Remove("migration");
        RadiusPostgresEvidence.ValidatePreflight(evidence,live,forward,rollback);
        evidence["migration"]![hash]=new string('0',64);
        Assert.Equal("migration files changed after preflight",Assert.Throws<InvalidOperationException>(()=>RadiusPostgresEvidence.ValidatePreflight(evidence,live,forward,rollback)).Message);
    }

    private static JsonObject ProducerResult()=>JsonNode.Parse("""
        {"status":"passed","generated_at_utc":"2026-08-11T00:00:00+00:00",
         "database":{"database":"sli_disposable_radius58_fixture","user":"fixture_user","server_version_num":160000,"encoding":"UTF8"},
         "evidence":{
           "migration":{"marker":true,"worker_role":true,"evidence_insert":true,"evidence_delete":false,"cursor_update":true},
           "registration":{"source_instance_id":"radius01.example.test","subscription_id":"vpn-radius-session-observations-radius01-v1",
             "stream_id":"radius-accounting","transport_binding":"windows-rpc-smb-readonly-tail-v1","registered_disabled_first":true,"disposable_manual_enable_only":true},
           "evidence_first":{"published_objects":2,"database_manifest_rows_before_commit":0,"orphan_retry_is_idempotent":true,"payload_in_result":false},
           "injected_failures":[{"phase":"evidence","rolled_back":true},{"phase":"outbox","rolled_back":true},{"phase":"cache","rolled_back":true}],
           "commit":{"evidence_rows":2,"observation_rows":1,"outbox_rows":1,"class_cache_rows":1,"cursor_revision":1,"cursor_byte_offset":200},
           "stale_replay_rejected":true,"persisted_state_rollback_guarded":true,
           "clean_rollback":{"marker":false,"foundation_table":false,"worker_role":false}},
         "production_database_changed":false,"radius_source_contacted":false,"runtime_enabled":false,"disposable_schema_cleaned":true}
        """)!.AsObject();

    [Fact]
    public void DisposableAcceptanceUsesActualNestedProducerShape()
    {
        var value=ProducerResult();
        Assert.Same(value,RadiusPostgresEvidence.AcceptedDisposable(value));
    }

    [Theory]
    [InlineData("source_instance_id")]
    [InlineData("subscription_id")]
    [InlineData("stream_id")]
    [InlineData("transport_binding")]
    public void DisposableAcceptanceRequiresEveryRegistrationIdentifier(string identifier)
    {
        var value=ProducerResult();value["evidence"]!["registration"]!.AsObject().Remove(identifier);
        Assert.Equal("disposable_058_evidence_invalid",Assert.Throws<InvalidOperationException>(()=>RadiusPostgresEvidence.AcceptedDisposable(value)).Message);
    }

    [Fact]
    public void DisposableAcceptanceRejectsMissingInjectedRollback()
    {
        var value=ProducerResult();value["evidence"]!["injected_failures"]![1]!["rolled_back"]=false;
        Assert.Equal("disposable_058_evidence_invalid",Assert.Throws<InvalidOperationException>(()=>RadiusPostgresEvidence.AcceptedDisposable(value)).Message);
    }
}
