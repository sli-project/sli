using Npgsql;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Sli.Server.Infrastructure;
using Sli.Server.Semantic;
using Sli.Server.Tests.Agents;
using Xunit;
using B = Sli.Server.Semantic.SemanticInvestigationBackfill;

namespace Sli.Server.Tests.Semantic;

public sealed partial class SemanticInvestigationBackfillTests
{
    [Fact] public async Task Selectors_execute_on_isolated_postgresql_with_frozen_provider_and_reset_proof()
    {
        await using var pg=new PostCollectionPostgres(canonicalSchema:true); await pg.StartAsync(Ct);
        await using var db=new NpgsqlConnection(pg.ConnectionString); await db.OpenAsync(Ct);
        await CreateSchema(db);
        await using var tx=await db.BeginTransactionAsync(Ct); await using var session=new SemanticSession(db,tx);
        foreach(var (id,eventId,provider,keywords,sid,stamp) in new (long,int,int,int,string,string)[] {
            (6,4724,1,1,Sid,"2026-09-11T00:00:00Z"),
            (7,4624,1,1,Sid+"1","2026-09-11T00:01:00Z"),
            (8,4624,1,1,Sid,"2026-09-11T00:01:00Z"),
            (9,4624,3,1,Sid,"2026-09-11T00:01:00Z"),
            (10,4624,1,1,Sid+" ","2026-09-11T00:01:00Z"),
            (11,1102,2,1,Sid,"2026-09-11T00:01:00Z"),
            (12,1102,1,1,Sid,"2026-09-11T00:01:00Z"),
            (13,4624,1,1,Sid,"2026-09-11T02:01:00Z"),
            (50,4724,1,1,Sid,"2026-09-11T02:00:00Z") }) {
            await session.ExecuteAsync("""
                insert into event_cold_facts(event_id,event_kind,source_sha256,domain_id,method,outcome,fields,time_created_utc)
                select $1,$2,$3,1,jsonb_build_object('$server_id',1,'$channel','Security','$provider',p.value),
                  jsonb_build_object('keywords',k.value),jsonb_build_object('TargetUserSid',$6::text),$7
                from storage_v2_provider p,storage_v2_keywords k where p.id=$4 and k.id=$5
                """,Ct,id,eventId,Convert.FromHexString(H('a')),provider,keywords,sid,DateTimeOffset.Parse(stamp));
        }
        await session.ExecuteAsync("insert into event_hot select * from event_cold_facts",Ct);
        await session.ExecuteAsync("insert into finding_event_copies337 select * from event_cold_facts",Ct);
        await session.ExecuteAsync("insert into finding_event_copies337 select * from event_cold_facts",Ct);
        var frozen=DateTimeOffset.Parse("2026-09-12T00:00:00Z");
        Assert.Equal(new long[]{11},await B.SelectHistoryTargets(session,1102,0,20,999,Ct));
        Assert.Equal(new long[]{8},await B.SelectContextTargets(session,0,20,6,5000,Ct));
        Assert.Equal(new long[]{8,13},await B.SelectContextTargets(session,0,20,50,5000,Ct));
        var cohorts=await B.HistoryCohorts(session,Ct,new Dictionary<int,long> { [4624]=20,[4724]=6 });
        Assert.Equal(1,cohorts["1102"].Number("count")); Assert.Equal(4,cohorts["4624"].Number("count")); Assert.Equal(6,cohorts["4724"].Number("high_watermark"));
        var before=await B.ContextCohort(session,20,6,Ct); Assert.Equal(1,before.Number("count"));
        foreach(var (id,type) in new[]{(6,"account.password.reset.succeeded"),(8,"authentication.session.created")}) {
            await session.ExecuteAsync("""
                insert into normalized_events
                select $1,event_id,1,$2,$3,'normalized',source_sha256,$4,$5,time_created_utc,
                  '{"relation_account_identity":{"state":"exact"}}'::jsonb,jsonb_build_object('domain_id',1,'relation_account_sid',fields->>'TargetUserSid')
                from event_cold_facts where event_id=$6
                """,Ct,Guid.NewGuid(),SemanticEvent.Normalizer,SemanticEvent.Version,type,frozen,id);
        }
        Assert.Empty(await B.SelectContextTargets(session,0,20,6,5000,Ct));
        var after=await B.ContextCohort(session,20,6,Ct); Assert.True(System.Text.Json.Nodes.JsonNode.DeepEquals(before,after));
        var relationTargets=await B.SelectRelationTargets(session,0,20,999,frozen,Ct);
        Assert.Equal(new long[]{6,8},relationTargets.Select(x=>x.Number("source_event_id")));
        Assert.Empty(await B.SelectRelationTargets(session,0,20,999,frozen.AddSeconds(-1),Ct));
        Assert.Equal(new long[]{6},(await B.SelectFactTargets(session,0,20,999,"anchors",Ct)).Select(x=>x.Number("id")));
        Assert.Contains(await B.SelectFactTargets(session,0,20,999,"context",Ct),x=>x.Number("id")==8);
        var reconciliation=await B.ReconcileV2Context(session,20,6,H('c'),Ct); Assert.Equal(1,reconciliation.Current.Number("retained_count")); Assert.Equal(1,reconciliation.Current.Number("normalized_count")); Assert.Equal(1,reconciliation.RepairStates.Number("conflict"));
        var pending=await B.FactsCompletion(session,[6,8],Ct); Assert.Equal("no_admitted_events",pending.Text("state"));
        await session.ExecuteAsync("insert into semantic_processing_outbox(job_id,source_event_id,job_kind,semantic_contract_version,processor_id,processor_version,status) select gen_random_uuid(),source_event_id,'normalize_event',1,$1,$2,'completed' from normalized_events",Ct,B.Processor,SemanticEvent.Version);
        Assert.Equal("processed",(await B.FactsCompletion(session,[6,8],Ct)).Text("state"));
        Assert.Empty(await B.RecoveryCandidates(session,frozen,20,Ct,true));
        await session.ExecuteAsync("delete from event_cold_facts",Ct);
        Assert.Equal(new long[]{11},await B.SelectHistoryTargets(session,1102,0,20,999,Ct));
        Assert.Equal(new long[]{6,8},(await B.SelectRelationTargets(session,0,20,999,frozen,Ct)).Select(x=>x.Number("source_event_id")));
        await session.ExecuteAsync("delete from finding_event_copies337",Ct);
        // The only remaining hot rows are expired; they must not become exact events.
        Assert.Empty(await B.SelectHistoryTargets(session,1102,0,20,999,Ct));
        Assert.Empty(await B.SelectRelationTargets(session,0,20,999,frozen,Ct));
    }

    private static async Task CreateSchema(NpgsqlConnection db)
    {
        // Only the columns these selectors consume; this cluster is owned by this test.
        await PostCollectionPostgres.Sql(db,"""
            create table storage_v2_channel(id integer primary key,value text);
            create table storage_v2_provider(id integer primary key,value text);
            create table storage_v2_keywords(id integer primary key,value text);
            create table servers(id bigint primary key,domain_id bigint);
            create table storage_v2_computer(id integer primary key,value text);
            create table storage_v2_domain_name(id integer primary key,value text);
            create table event_hot(event_id bigint primary key,time_created_utc timestamptz,event_kind integer,domain_id bigint,
              actor text,target text,source text,computer text,method jsonb,outcome jsonb,fields jsonb,source_sha256 bytea,event_record_id bigint);
            create table event_cold_facts(like event_hot including all);
            create table finding_event_copies337(like event_hot);
            insert into servers values(1,1);
            create table normalized_events(normalized_event_id uuid primary key,source_event_id bigint,semantic_contract_version integer,
              normalizer_id text,normalizer_version text,processing_status text,source_event_sha256 bytea,semantic_type text,
              normalized_at timestamptz,occurred_at_utc timestamptz,quality_json jsonb,facts_json jsonb);
            create table semantic_processing_outbox(job_id uuid primary key,source_event_id bigint,job_kind text,semantic_contract_version integer,
              processor_id text,processor_version text,status text,attempt_count integer,max_attempts integer,last_error_code text,last_error_detail text,
              source_identity_json jsonb,payload_json jsonb,idempotency_key bytea unique,source_id bigint,domain_id bigint,
              partition_key text,occurred_at_utc timestamptz);
            create table schema_migrations(version integer,name text);
            insert into schema_migrations values(143,'semantic_v2_quarantine_repair');
            create table runtime_worker_heartbeats(worker_name text,status text,heartbeat_at timestamptz,expected_interval_seconds integer,details_json jsonb);
            create role adlog_storage_worker;
            grant usage on schema public to adlog_storage_worker;
            create table canonical_action_evidence(normalized_event_id uuid,canonical_action_id uuid);
            create table semantic_correlation_rules(rule_id text,rule_version integer,definition_sha256 bytea,lifecycle_status text);
            create table semantic_correlation_dispatch_jobs(job_id uuid,normalized_event_id uuid,rule_id text,rule_version integer,
              dispatch_status text,attempt_count integer,max_attempts integer,completed_at timestamptz,last_error_code text,last_error_detail text);
            insert into storage_v2_channel values(1,'Security');
            insert into storage_v2_provider values(1,'Microsoft-Windows-Security-Auditing'),(2,'Microsoft-Windows-Eventlog'),(3,'synthetic-wrong-provider');
            insert into storage_v2_keywords values(1,'Audit Success'),(2,'Audit Failure');
            grant select,insert on all tables in schema public to adlog_storage_worker;
            grant update on runtime_worker_heartbeats to adlog_storage_worker;
            """,Ct);
    }

    [Fact] public async Task Quarantine_plan_and_apply_use_short_sources_and_preserve_terminal_originals()
    {
        await using var pg=new PostCollectionPostgres(canonicalSchema:true); await pg.StartAsync(Ct);
        await using var db=new NpgsqlConnection(pg.ConnectionString); await db.OpenAsync(Ct);
        await CreateSchema(db);
        JsonObject manifest;
        await using(var tx=await db.BeginTransactionAsync(Ct))
        await using(var session=new SemanticSession(db,tx)) {
            await session.ExecuteAsync("""
                insert into event_cold_facts(event_id,event_kind,time_created_utc,domain_id,method,outcome,fields,source_sha256)
                select i,case when i=1 then 4724 else 4624 end,
                  '2026-09-11T00:00:00Z'::timestamptz + case when i=1 then interval '0' else interval '1 minute' end,
                  1,'{"$server_id":1,"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing"}'::jsonb,
                  '{"keywords":"Audit Success"}'::jsonb,jsonb_build_object('TargetUserSid',$1::text),decode(repeat('a',64),'hex')
                from generate_series(1,261) i
                """,Ct,Sid);
            await session.ExecuteAsync("insert into finding_event_copies337 select * from event_cold_facts",Ct);
            await session.ExecuteAsync("insert into finding_event_copies337 select * from event_cold_facts",Ct);
            await session.ExecuteAsync("delete from event_cold_facts",Ct);
            var cohorts=await B.HistoryCohorts(session,Ct);
            var context=await B.ContextCohort(session,261,1,Ct);
            var identity=(await session.QueryAsync("select coalesce(inet_server_addr()::text,'') as host,current_database() as database,session_user as role",Ct))[0]!.AsObject();
            manifest=B.NewManifestV2(identity,H('b'),cohorts,context,null);
            await session.ExecuteAsync("""
                insert into semantic_processing_outbox(job_id,source_event_id,job_kind,semantic_contract_version,processor_id,processor_version,
                  status,attempt_count,max_attempts,last_error_code,last_error_detail,source_identity_json)
                select gen_random_uuid(),i,'normalize_event',1,'semantic-shadow',$1,'quarantined',5,5,'UniqueViolation',
                  'duplicate key violates unique constraint "canonical_actions_pkey"',jsonb_build_object('normalized_hash',repeat('a',64))
                from generate_series(2,261) i
                """,Ct,SemanticEvent.Version);
            await tx.CommitAsync(Ct);
        }
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> { ["ConnectionStrings:Sli"]=pg.ConnectionString }).Build();
        var controller=new SemanticQuarantineRepairController(new SemanticDatabase(new PostgresConnectionFactory(config)),()=>manifest.DeepClone().AsObject(),
            key=>key=="ADLOG_SEMANTIC_RUNTIME_MODE"?"investigation-v1":key is "ADLOG_SEMANTIC_PRODUCTION_ENABLED" or "ADLOG_SEMANTIC_NORMALIZATION_ENABLED" or "ADLOG_SEMANTIC_ASSEMBLY_ENABLED" or "ADLOG_SEMANTIC_CORRELATION_ENABLED"?"1":null,()=>H('f'));
        var plan=await controller.PlanAsync(Ct);
        Assert.Equal(260,plan.Number("target_events"));
        var heartbeat=SemanticWorkerContract.Details("investigation-v1",false,plan.Text("repair_plan_digest"));
        heartbeat["processing_contract"]!["release_fingerprint"]=H('f');
        await using(var command=new NpgsqlCommand("insert into runtime_worker_heartbeats values('semantic','idle',now(),60,$1)",db)) {
            command.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Jsonb,heartbeat.ToJsonString()); await command.ExecuteNonQueryAsync(Ct);
        }
        var applied=await controller.ApplyAsync(plan.Text("repair_plan_digest")!,plan.Text("confirmation")!,Ct);
        Assert.Equal(260,applied.Number("newly_queued"));
        Assert.Equal(0,(await controller.ApplyAsync(plan.Text("repair_plan_digest")!,plan.Text("confirmation")!,Ct)).Number("newly_queued"));
        await using var verify=new NpgsqlCommand("""
            select count(*) from semantic_processing_outbox where job_kind='semantic_v2_quarantine_repair'
              and source_identity_json->>'normalized_hash'=repeat('a',64) and source_identity_json->>'domain_id'='1'
            """,db);
        Assert.Equal(260L,await verify.ExecuteScalarAsync(Ct));
        await using var original=new NpgsqlCommand("select count(*) from semantic_processing_outbox where job_kind='normalize_event' and status='quarantined' and attempt_count=5",db);
        Assert.Equal(260L,await original.ExecuteScalarAsync(Ct));
    }
}
