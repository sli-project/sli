using System.Data;
using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Server.Semantic.Password;

namespace Sli.Server.Semantic.Risk;

public sealed record PasswordRiskOptions(bool Once=false,int PollSeconds=10,int MaxJobs=16,int LeaseSeconds=300);
public sealed record PasswordRiskBatch(int Claimed,int Completed,int Failed,int Published,int Pending,int Frozen);
internal sealed record PasswordRiskLease(Guid Id,Guid Token,int Attempt,int MaxAttempts);
internal sealed record PasswordRiskWork(PasswordRiskLease Lease,string Mode,PasswordRiskProposal Proposal,JsonObject Completeness,bool LockedEpisodeProof);
internal sealed record PasswordRiskOutcome(string State,long? Finding=null);

// One committed lease, one separately owned publication transaction, and fenced failure recovery.
public sealed class PasswordRiskConsumer(PasswordProducerRuntime runtime,PasswordRiskOptions options)
{
    private (string Available,string Created,string Job,string Policy,int Version)? discoveryCursor;
    private int discoveryClaims;
    internal static int RetrySeconds(int attempt)=>Math.Min(3600,30*(1<<Math.Min(Math.Max(0,attempt-1),7)));

    public async Task<PasswordRiskBatch> RunOnceAsync(CancellationToken ct)
    {
        await using var db=await runtime.OpenAsync(ct);int claimed=0,completed=0,failed=0,published=0,pending=0,frozen=0;
        for(int i=0;i<Math.Clamp(options.MaxJobs,1,16);i++) {
            ct.ThrowIfCancellationRequested();var lease=await Claim(db,ct);if(lease==null)break;claimed++;
            try {
                await using var tx=await db.BeginTransactionAsync(IsolationLevel.ReadCommitted,ct);
                var sql=new RiskSql(db,tx);var timer=Stopwatch.StartNew();var work=await Load(sql,lease,ct);
                var outcome=await Execute(sql,work,(int)Math.Min(timer.ElapsedMilliseconds,int.MaxValue),ct);
                // Deferred SQL integrity/lease guards remain authoritative. Report only after COMMIT.
                await tx.CommitAsync(ct);completed++;
                if(outcome.Finding.HasValue)published++;if(outcome.State=="evidence_pending")pending++;if(outcome.State=="episode_frozen")frozen++;
            }
            catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}
            catch (Exception error) {
                // A cancelled cycle retains its committed lease for ordinary expiry/reclaim.
                ct.ThrowIfCancellationRequested();if(db.State!=ConnectionState.Open)throw;
                if(SemanticProduction.LockWait(error)) {
                    await SemanticProduction.Fail(db,"semantic_risk_evaluation_jobs","evaluation_status",new JsonObject {
                        ["job_id"]=lease.Id.ToString(),["lease_token"]=lease.Token.ToString(),["attempt_count"]=lease.Attempt,["max_attempts"]=lease.MaxAttempts
                    },ct,error,SemanticProcessingStep.Risk);failed++;continue;
                }
                await using var failure=await db.BeginTransactionAsync(IsolationLevel.ReadCommitted,ct);
                var rows=await new RiskSql(db,failure).Rows("""
                    update public.semantic_risk_evaluation_jobs set evaluation_status=@status,
                      available_at=now()+(@retry*interval '1 second'),lease_token=null,lease_until=null,
                      last_error_code='password_risk_evaluation_failed',last_error_detail='password_risk_evaluation_failed',updated_at=now()
                    where job_id=@job and evaluation_status='leased' and lease_token=@token returning evaluation_status
                    """,ct,("status",lease.Attempt>=lease.MaxAttempts?"quarantined":"failed"),("retry",RetrySeconds(lease.Attempt)),("job",lease.Id),("token",lease.Token));
                RiskJson.Require(rows.Count==1,"password_risk_lease_lost_failure");await failure.CommitAsync(ct);failed++;
            }
        }
        if (published > 0 || claimed == 0) await TryRefreshStaleQueuePresentation(db,ct);
        return new(claimed,completed,failed,published,pending,frozen);
    }

    private static async Task TryRefreshStaleQueuePresentation(NpgsqlConnection db,CancellationToken ct)
    {
        try
        {
            // Publication has already committed. Bound only the optional projection transaction.
            await using var tx = await db.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct);
            var sql = new RiskSql(db, tx);
            await sql.Execute("set local lock_timeout='250ms'; set local statement_timeout='1500ms'", ct);
            var capability = await sql.Rows("select to_regprocedure('public.refresh_stale_password_queue399()') is not null as supported", ct);
            if (capability[0]["supported"]?.GetValue<bool>() == true)
                await sql.Execute("select public.refresh_stale_password_queue399()", ct);
            await tx.CommitAsync(ct);
        }
        catch (NpgsqlException error) when (!ct.IsCancellationRequested)
        {
            Console.Error.WriteLine("password_queue_projection_deferred:" + (error is PostgresException pg ? pg.SqlState : "database_unavailable"));
        }
    }

    private async Task<PasswordRiskLease?> Claim(NpgsqlConnection db,CancellationToken ct)
    {
        await using var tx=await db.BeginTransactionAsync(IsolationLevel.ReadCommitted,ct);var sql=new RiskSql(db,tx);
        // Read only metadata first. Compile the exact supported identity/contract BEFORE mutating a queue row.
        // The locked claim repeats definition SHA/JSON/mode/admission checks; draft or unrelated jobs stay untouched.
        var template=PasswordSignal.PolicyDefinition(new PasswordRule(new("00000000-0000-0000-0000-000000000001","sli.windows.ad-dc","synthetic","generation","")));
        template["source_selector"]!.AsObject().Remove("execution");
        var sprayTemplate=PasswordSignal.PolicyDefinition(new PasswordRule(new("00000000-0000-0000-0000-000000000001","sli.windows.ad-dc","synthetic","generation",""),"spray"));
        sprayTemplate["source_selector"]!.AsObject().Remove("execution");
        var capabilities=await sql.Rows("select to_regprocedure('public.password_is_catchup388(jsonb)') is not null as live_first",ct);
        string query="""
            select p.policy_id,p.policy_version,p.definition_json,encode(p.definition_sha256,'hex') as sha256,
              oldest.available_at,oldest.created_at,oldest.job_id::text as oldest_job_id,
              public.password_is_catchup388(p.definition_json#>'{source_selector,execution}') as history_pass
            from public.semantic_risk_policies p join lateral(
              select j.available_at,j.created_at,j.job_id from public.semantic_risk_evaluation_jobs j
              where j.policy_id=p.policy_id and j.policy_version=p.policy_version and j.source_kind='qw_signal'
                and j.qw_signal_id=j.source_reference and j.attempt_count<j.max_attempts and j.available_at<=now()
                and (j.evaluation_status in ('queued','failed') or (j.evaluation_status='leased' and j.lease_until<now()))
                and j.evaluation_mode=public.semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)
                and j.evaluation_mode in ('test','shadow','enabled')
                and (j.evaluation_mode<>'enabled' or exists(select 1 from public.semantic_policy_admission a
                  where a.policy_id=p.policy_id and a.policy_version=p.policy_version and a.enabled is true))
              order by j.available_at,j.created_at,j.job_id limit 1) oldest on true
            where p.source_kind='qw_signal' and p.policy_version=1
              and p.policy_id ~ '^default:qw[.]password-(brute-force|spray):[a-f0-9]{32}$'
              and p.definition_json#>>'{source_selector,rule_id}' in ('qw.password-brute-force','qw.password-spray')
              and p.definition_json#>'{source_selector,execution,rule_version}'>='2'::jsonb
              and (p.definition_json#-'{source_selector,execution}'=@template::jsonb or p.definition_json#-'{source_selector,execution}'=@spray_template::jsonb)
              and (not @has_cursor or not public.password_is_catchup388(p.definition_json#>'{source_selector,execution}') or (oldest.available_at,oldest.created_at,oldest.job_id,p.policy_id,p.policy_version)
                > (@available::timestamptz,@created::timestamptz,@job::uuid,@cursor_policy,@version))
            order by history_pass,oldest.available_at,oldest.created_at,oldest.job_id,p.policy_id,p.policy_version limit 256
            """;
        if(capabilities[0]["live_first"]?.GetValue<bool>()!=true)
            query=query.Replace("public.password_is_catchup388(p.definition_json#>'{source_selector,execution}')","false",StringComparison.Ordinal);
        var policies=await sql.Rows(query,ct,("template",template),("spray_template",sprayTemplate),("has_cursor",discoveryCursor.HasValue),
            ("available",discoveryCursor?.Available??"1970-01-01T00:00:00Z"),("created",discoveryCursor?.Created??"1970-01-01T00:00:00Z"),
            ("job",discoveryCursor?.Job??"00000000-0000-0000-0000-000000000000"),("cursor_policy",discoveryCursor?.Policy??""),("version",discoveryCursor?.Version??0));
        static (string,string,string,string,int) Cursor(JsonObject row)=>
            (RiskJson.String(row,"available_at"),RiskJson.String(row,"created_at"),RiskJson.String(row,"oldest_job_id"),RiskJson.String(row,"policy_id"),RiskJson.Int(row,"policy_version"));
        foreach(var row in policies) {
            ct.ThrowIfCancellationRequested();PasswordRiskPolicy policy;
            try{policy=PasswordRiskPolicy.Compile(RiskJson.String(row,"policy_id"),RiskJson.Int(row,"policy_version"),RiskJson.Obj(row["definition_json"]));}
            catch(PasswordRiskFailure){continue;}
            if(policy.Sha256!=RiskJson.String(row,"sha256"))continue;
            Guid token=Guid.NewGuid();var rows=await sql.Rows("""
                with eligible_policy as materialized (
                  select p.policy_id,p.policy_version,public.semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status) as mode
                  from public.semantic_risk_policies p where p.policy_id=@policy and p.policy_version=1
                    and p.source_kind='qw_signal' and p.definition_sha256=@sha and p.definition_json=@definition::jsonb
                  for share of p skip locked
                ), candidate as (
                  select j.job_id from eligible_policy p join public.semantic_risk_evaluation_jobs j using(policy_id,policy_version)
                  where j.policy_id=@policy and j.policy_version=1 and j.source_kind='qw_signal'
                    and j.qw_signal_id=j.source_reference and j.attempt_count<j.max_attempts and j.available_at<=now()
                    and j.evaluation_mode in ('test','shadow','enabled')
                    and (j.evaluation_status in ('queued','failed') or (j.evaluation_status='leased' and j.lease_until<now()))
                    and p.mode=j.evaluation_mode
                    and (j.evaluation_mode<>'enabled' or exists(select 1 from public.semantic_policy_admission a
                      where a.policy_id=p.policy_id and a.policy_version=p.policy_version and a.enabled is true))
                  order by j.available_at,j.created_at,j.job_id for update of j skip locked limit 1)
                update public.semantic_risk_evaluation_jobs j set evaluation_status='leased',attempt_count=j.attempt_count+1,
                  lease_token=@token,lease_until=now()+(@seconds*interval '1 second'),heartbeat_at=now(),updated_at=now(),
                  last_error_code=null,last_error_detail=null from candidate where j.job_id=candidate.job_id
                returning j.job_id::text as job_id,j.lease_token::text as lease_token,j.attempt_count,j.max_attempts
                """,ct,("policy",policy.Id),("sha",Convert.FromHexString(policy.Sha256)),("definition",policy.Definition),("token",token),("seconds",Math.Clamp(options.LeaseSeconds,60,3600)));
            if(rows.Count==0)continue;RiskJson.Require(rows.Count==1,"password_risk_claim_invalid");
            var job=rows[0];var lease=new PasswordRiskLease(Guid.Parse(RiskJson.String(job,"job_id")),Guid.Parse(RiskJson.String(job,"lease_token")),RiskJson.Int(job,"attempt_count"),RiskJson.Int(job,"max_attempts"));
            await tx.CommitAsync(ct);
            // Periodically revisit jobs that became eligible behind the moving cursor.
            if(row["history_pass"]?.GetValue<bool>()==false||++discoveryClaims>=16){discoveryCursor=null;discoveryClaims=0;}
            else discoveryCursor=Cursor(row);
            return lease;
        }
        await tx.CommitAsync(ct);
        if(policies.Count==256)discoveryCursor=Cursor(policies[^1]);
        else{discoveryCursor=null;discoveryClaims=0;}
        return null;
    }

    private static async Task<PasswordRiskWork> Load(RiskSql sql,PasswordRiskLease lease,CancellationToken ct)
    {
        var schema=await sql.Rows("""
            select to_regprocedure('public.read_locked_password_episode402(jsonb,jsonb,text)') is not null as locked_episode_proof
            from public.schema_migrations where version=52 and name='semantic_conclusion_completeness'
            """,ct);
        RiskJson.Require(schema.Count==1,"password_risk_schema_required");
        var rows=await sql.Rows("""
            select j.job_id::text as job_id,j.evaluation_mode,j.source_kind,j.source_reference,j.qw_signal_id,
              p.policy_id,p.policy_version,p.source_kind as policy_source_kind,p.definition_json,encode(p.definition_sha256,'hex') as sha256,
              public.semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status) as lifecycle_status
            from public.semantic_risk_evaluation_jobs j join public.semantic_risk_policies p
              on p.policy_id=j.policy_id and p.policy_version=j.policy_version
            where j.job_id=@job and j.evaluation_status='leased' and j.lease_token=@token for share of p nowait
            """,ct,("job",lease.Id),("token",lease.Token));
        RiskJson.Require(rows.Count==1,"password_risk_lease_lost");var row=rows[0];string mode=RiskJson.String(row,"evaluation_mode");
        RiskJson.Require((mode is "test" or "shadow" or "enabled")&&RiskJson.String(row,"lifecycle_status")==mode,"password_risk_admission_changed");
        RiskJson.Require(RiskJson.String(row,"policy_source_kind")=="qw_signal"&&RiskJson.String(row,"source_kind")=="qw_signal"&&RiskJson.String(row,"source_reference")==RiskJson.String(row,"qw_signal_id"));
        if(mode=="enabled") {
            var admission=await sql.Rows("select enabled from public.semantic_policy_admission where policy_id=@policy and policy_version=@version",ct,("policy",RiskJson.String(row,"policy_id")),("version",RiskJson.Int(row,"policy_version")));
            RiskJson.Require(admission.Count==1&&admission[0]["enabled"]?.GetValue<bool>()==true,"password_risk_admission_required");
        }
        var policy=PasswordRiskPolicy.Compile(RiskJson.String(row,"policy_id"),RiskJson.Int(row,"policy_version"),RiskJson.Obj(row["definition_json"]));
        RiskJson.Require(policy.Sha256==RiskJson.String(row,"sha256"),"password_risk_policy_hash_conflict");
        var signal=await PasswordRiskProof.LoadSignal(sql,RiskJson.String(row,"source_reference"),ct);RiskJson.Require(signal.Mode==mode,"password_risk_mode_mismatch");
        var proposal=PasswordRiskProposal.Create(policy,signal);
        return new(lease,mode,proposal,PasswordRiskCompleteness.Capture(DateTimeOffset.UtcNow,proposal.At),schema[0].Flag("locked_episode_proof"));
    }

    private static async Task<PasswordRiskOutcome> Execute(RiskSql sql,PasswordRiskWork work,int evaluationMs,CancellationToken ct)
    {
        var assessment=work.Proposal.Assessment;JsonObject? scenario=null;string state="evaluated";
        if(work.Mode=="enabled") {
            await sql.Execute("select pg_advisory_xact_lock(hashtextextended(@identity,0))",ct,("identity",work.Proposal.Identity));
            scenario=await PasswordRiskScenario.Find(sql,work.Proposal,ct);
            if(scenario!=null)await PasswordRiskProof.ScenarioSignals(sql,Guid.Parse(RiskJson.String(scenario,"scenario_id")),work.Proposal.Signal,ct);
            PasswordRiskEpisode? episode=null;
            bool locked;
            if(work.LockedEpisodeProof) {
                episode=await PasswordRiskProof.LockEpisode(sql,work.Proposal.Signal,ct);
                locked=episode is not null;
            } else locked=await PasswordRiskProof.Lock(sql,work.Proposal.Signal,ct) is not null;
            if(!locked){await Ack(sql,work.Lease,ct);return new("episode_frozen");}
            scenario=await PasswordRiskScenario.Persist(sql,work.Proposal,scenario,ct);Guid scenarioId=Guid.Parse(RiskJson.String(scenario,"scenario_id"));
            episode??=await PasswordRiskProof.LoadEpisode(sql,work.Proposal.Signal,ct);
            var members=await PasswordRiskProof.ScenarioSignals(sql,scenarioId,work.Proposal.Signal,ct);
            if(!episode.ContainsExactly(members.Select(s=>s.Id))) {
                await sql.Execute("update public.semantic_security_scenarios set evidence_state='evidence_pending' where scenario_id=@scenario",ct,("scenario",scenarioId));scenario["evidence_state"]="evidence_pending";
            }
            state=RiskJson.String(scenario,"evidence_state");assessment=PasswordRiskScenario.Assessment(scenario);
            await PasswordRiskPublication.SupersedeScenario(sql,scenarioId,ct);
        }
        Guid? sid=scenario==null?null:Guid.Parse(RiskJson.String(scenario,"scenario_id"));
        await sql.Execute("""
            insert into public.semantic_risk_evaluation_results(job_id,scenario_id,evaluation_mode,risk_class,raw_score,display_score,
              hard_critical,confidence,confidence_score,coverage_status,evaluation_ms,conclusion_state,completeness_snapshot_json)
            values(@job,@scenario::uuid,@mode,@risk,@raw,@display,@hard,@confidence,@score,@coverage,@ms,'observed',@snapshot::jsonb)
            on conflict(job_id) do nothing
            """,ct,("job",work.Lease.Id),("scenario",sid),("mode",work.Mode),("risk",assessment.Risk),("raw",assessment.Raw),("display",assessment.Display),("hard",assessment.HardCritical),("confidence",assessment.Confidence),("score",assessment.Score),("coverage",assessment.Coverage),("ms",evaluationMs),("snapshot",work.Completeness));
        long? finding=null;
        if(work.Mode=="enabled"&&state=="ready")finding=await PasswordRiskPublication.Publish(sql,work,scenario!,ct);
        await Ack(sql,work.Lease,ct);return new(state,finding);
    }

    private static async Task Ack(RiskSql sql,PasswordRiskLease lease,CancellationToken ct)
    {
        var rows=await sql.Rows("""
            update public.semantic_risk_evaluation_jobs set evaluation_status='completed',completed_at=now(),heartbeat_at=now(),
              lease_token=null,lease_until=null,updated_at=now(),last_error_code=null,last_error_detail=null
            where job_id=@job and evaluation_status='leased' and lease_token=@token returning job_id::text as job_id
            """,ct,("job",lease.Id),("token",lease.Token));
        RiskJson.Require(rows.Count==1,"password_risk_lease_lost");
    }
}

internal sealed class RiskSql(NpgsqlConnection db,NpgsqlTransaction tx)
{
    private static NpgsqlCommand Command(string query,NpgsqlConnection db,NpgsqlTransaction tx,(string,object?)[] args)
    {
        SemanticWork.Query(db,query);var cmd=new NpgsqlCommand(query,db,tx){CommandTimeout=0};
        foreach(var (name,value) in args) {
            if(value is JsonNode node)cmd.Parameters.AddWithValue(name,NpgsqlDbType.Jsonb,CanonicalJson.Serialize(node,ensureAscii:false));
            else if(value==null)cmd.Parameters.AddWithValue(name,NpgsqlDbType.Text,DBNull.Value);
            else cmd.Parameters.AddWithValue(name,value);
        }return cmd;
    }
    internal async Task<List<JsonObject>> Rows(string query,CancellationToken ct,params (string,object?)[] args)
    {
        await using var cmd=Command(query,db,tx,args);await using var reader=await cmd.ExecuteReaderAsync(ct);var rows=new List<JsonObject>();
        while(await reader.ReadAsync(ct)) {
            RiskJson.Require(rows.Count<16384,"password_risk_reader_bound");var row=new JsonObject();
            for(int i=0;i<reader.FieldCount;i++) {
                JsonNode? value=null;
                if(!reader.IsDBNull(i))value=reader.GetDataTypeName(i) is "jsonb" or "json"?JsonNode.Parse(reader.GetString(i)):reader.GetValue(i) switch {
                    byte[] bytes=>JsonValue.Create(Convert.ToHexStringLower(bytes)),Guid id=>JsonValue.Create(id.ToString()),DateTime at=>JsonValue.Create(PasswordJson.Stamp(new DateTimeOffset(at))),
                    long number=>JsonValue.Create(number),int number=>JsonValue.Create(number),short number=>JsonValue.Create((int)number),decimal number=>JsonValue.Create(number),double number=>JsonValue.Create(number),bool flag=>JsonValue.Create(flag),string text=>JsonValue.Create(text),_=>throw new PasswordRiskFailure("password_risk_reader_invalid")};
                row[reader.GetName(i)]=value;
            }rows.Add(row);
        }return rows;
    }
    internal async Task Execute(string query,CancellationToken ct,params (string,object?)[] args){await using var cmd=Command(query,db,tx,args);await cmd.ExecuteNonQueryAsync(ct);}
}
