using System.Data;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Agent.Protocol;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Semantic.Password;

namespace Sli.Server.Semantic.Detections;

internal interface IDetectionSql
{
    Task<List<JsonObject>> Rows(string query,CancellationToken ct,params (string,object?)[] args);
    Task Execute(string query,CancellationToken ct,params (string,object?)[] args);
}
internal sealed class DetectionSql(NpgsqlConnection db,NpgsqlTransaction tx,DetectionDiagnostics? diagnostics=null):IDetectionSql
{
    private static NpgsqlCommand Command(string query,NpgsqlConnection db,NpgsqlTransaction tx,(string,object?)[] args)
    {
        SemanticWork.Query(db,query);var cmd=new NpgsqlCommand(query,db,tx){CommandTimeout=0};foreach(var (key,value) in args){if(value is null)cmd.Parameters.AddWithValue(key,NpgsqlDbType.Array|NpgsqlDbType.Bigint,DBNull.Value);else if(value is JsonNode n)cmd.Parameters.AddWithValue(key,NpgsqlDbType.Jsonb,CanonicalJson.Serialize(n));else cmd.Parameters.AddWithValue(key,value);}return cmd;
    }
    public async Task<List<JsonObject>> Rows(string query,CancellationToken ct,params (string,object?)[] args)
    {
        diagnostics?.Query(query);await using var cmd=Command(query,db,tx,args);await using var reader=await cmd.ExecuteReaderAsync(ct);var result=new List<JsonObject>();long bytes=0;
        while(await reader.ReadAsync(ct)){D.Require(result.Count<10001,"detection_reader_bound");var row=new JsonObject();for(int i=0;i<reader.FieldCount;i++){
            if(reader.IsDBNull(i)){row[reader.GetName(i)]=null;continue;}object v=reader.GetValue(i);row[reader.GetName(i)]=reader.GetDataTypeName(i) is "jsonb" or "json"?JsonNode.Parse((string)v):v switch{DateTime t=>JsonValue.Create(D.Stamp(new(t))),long l=>JsonValue.Create(l),int n=>JsonValue.Create(n),bool b=>JsonValue.Create(b),string s=>JsonValue.Create(s),_=>throw new DetectionFailure("detection_reader_type")};
        }bytes+=CanonicalJson.Length(row);D.Require(bytes<=33554432,"detection_reader_bound");result.Add(row);}return result;
    }
    public async Task Execute(string query,CancellationToken ct,params (string,object?)[] args){diagnostics?.Query(query);await using var cmd=Command(query,db,tx,args);await cmd.ExecuteNonQueryAsync(ct);}
}

public sealed record DetectionBatch(int Sources=0,int Jobs=0,int Failed=0)
{
    public int Completed {get;init;}
    [System.Text.Json.Serialization.JsonPropertyName("failure_reasons")]
    public JsonObject FailureReasons {get;init;} = new();
    public JsonObject ImportSummary {get;init;} = new();
}

// Runs with the same restricted, non-pooled semantic login as PasswordProducer.
public sealed class IdentityAttackProducer
{
    internal Task<int> RunAsync(IDetectionSql sql,JsonObject source,DateTimeOffset now,CancellationToken ct)=>DetectionProducer.RunIdentity(sql,source,now,ct);
}
public sealed class AttackPrecursorProducer
{
    internal Task<int> RunAsync(IDetectionSql sql,JsonObject source,DateTimeOffset now,CancellationToken ct)=>DetectionProducer.RunPrecursors(sql,source,now,ct);
}
public sealed class DetectionProducer(IdentityAttackProducer identities,AttackPrecursorProducer precursors)
{
    internal SemanticWork? Work { get; init; }
    internal PasswordProducerRuntime? Runtime { get; init; }
    public async Task<DetectionBatch> RunOnceAsync(NpgsqlConnection db,CancellationToken ct,JsonArray? discovered=null,bool refreshImport=true)
    {
        if(ct.IsCancellationRequested)return new();var diagnostics=new DetectionDiagnostics();D.Require(db.FullState==ConnectionState.Open,"detection_connection_not_idle");var sources=new List<(JsonObject Source,bool Identity)>();JsonObject importSummary=refreshImport?await RefreshImportSummary(db,ct):new();
        bool passwordThresholds;
        try { await using(var tx=await db.BeginTransactionAsync(ct)){
            var sql=new DetectionSql(db,tx,diagnostics);
            passwordThresholds=(await sql.Rows("select to_regprocedure('public.password_threshold_pass418(jsonb,text,timestamptz)') is not null as enabled",ct)).Single()["enabled"]!.GetValue<bool>();
            IEnumerable<JsonNode?> rows=discovered is null ? await sql.Rows("select source from public.default_detection_sources()",ct) : discovered;
            foreach(var row in rows){var source=row!["source"]!.AsObject();if(D.Text(source["scope"]?["plugin_id"]) is "sli.windows.ad-dc" or "sli.ad-snapshot")sources.Add((source,true));}
            foreach(var row in await sql.Rows("select source from public.t109_detection_sources()",ct))sources.Add((row["source"]!.AsObject(),false));importSummary=await ReadImportProgress(sql,ct);await tx.CommitAsync(ct);
        }}catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}
        catch(Exception error){diagnostics.Add(error);diagnostics.Write("detections");D.Require(db.FullState==ConnectionState.Open,"detection_session_lost");return new(0,0,1){FailureReasons=diagnostics.Counts,ImportSummary=importSummary};}
        async Task<int> Run(NpgsqlConnection connection,JsonObject source,bool identity,DetectionDiagnostics sourceDiagnostics) {
            int passwordJobs = 0;
            Exception? passwordFailure = null;
            var scope = PasswordScope.Read(source["scope"]);
            if (passwordThresholds && identity && scope.PluginId == "sli.windows.ad-dc")
                foreach (string rule in PasswordAttacks.Rules)
                {
                    try { passwordJobs += await RunPasswordThreshold(connection, scope, rule, DateTimeOffset.UtcNow, ct); }
                    catch (Exception error) when (error is not OperationCanceledException && connection.FullState == ConnectionState.Open && !SemanticWork.ConnectionWait(error)) { passwordFailure = error; }
                }
            int jobs;await using(var tx=await connection.BeginTransactionAsync(ct)){var sql=new DetectionSql(connection,tx,sourceDiagnostics);await sql.Execute("set local statement_timeout=0",ct);await sql.Execute("set local lock_timeout='1s'",ct);jobs=identity?await identities.RunAsync(sql,source,DateTimeOffset.UtcNow,ct):await precursors.RunAsync(sql,source,DateTimeOffset.UtcNow,ct);sourceDiagnostics.Step="source_commit";await tx.CommitAsync(ct);}
            if (passwordFailure is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw(passwordFailure);
            return jobs + passwordJobs;
        }
        if(Work is null || Runtime is null) {
            var result=await RunSources(sources,(source,identity)=>Run(db,source,identity,diagnostics),()=>db.FullState==ConnectionState.Open,ct,diagnostics);
            return result with {ImportSummary=importSummary};
        }
        int added=0,failed=0,completed=0;
        foreach(var (source,identity) in sources) {
            var batch=await Work.Run("attack_source:"+PasswordJson.Hash(source["scope"])+":"+identity,async()=>{
                var sourceDiagnostics=new DetectionDiagnostics();
                try { await using var sourceDb=await Runtime.OpenAsync(ct);int jobs=await Run(sourceDb,source,identity,sourceDiagnostics);return new DetectionBatch(1,jobs){Completed=1}; }
                catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}
                catch(Exception error)when(SemanticWork.ConnectionWait(error)){throw;}
                catch(Exception error){sourceDiagnostics.Add(error);sourceDiagnostics.Write("detections");return new DetectionBatch(1,0,1){FailureReasons=sourceDiagnostics.Counts};}
            },ct);
            if(batch is null)continue;added+=batch.Jobs;failed+=batch.Failed;completed+=batch.Completed;
            foreach(var (key,value) in batch.FailureReasons)for(int i=0;i<value!.GetValue<int>();i++)diagnostics.Add(new JsonObject{["reason"]=key});
        }
        return new(sources.Count,added,failed){Completed=completed,FailureReasons=diagnostics.Counts,ImportSummary=importSummary};
    }
    internal static async Task<JsonObject> RefreshImportSummary(NpgsqlConnection db,CancellationToken ct)
    {
        // Detections read only short events; the former import refresh was retired with migration 372.
        await Task.CompletedTask;
        return new();
    }
    internal static async Task<JsonObject> ReadImportProgress(IDetectionSql sql,CancellationToken ct)
    {
        // Older installed schemas remain executable during staged upgrades.
        var ready=await sql.Rows("select to_regprocedure('public.semantic_import_progress320()') is not null as ready",ct);
        return ready[0]["ready"]!.GetValue<bool>() ? (await sql.Rows("select public.semantic_import_progress320() as progress",ct))[0]["progress"]!.DeepClone().AsObject() : new();
    }
    internal static async Task<DetectionBatch> RunSources(IReadOnlyList<(JsonObject Source,bool Identity)> sources,Func<JsonObject,bool,Task<int>> run,Func<bool> idle,CancellationToken ct,DetectionDiagnostics? diagnostics=null)
    {
        if(ct.IsCancellationRequested)return new();diagnostics??=new();int jobs=0,failed=0,completed=0;
        try { foreach(var (source,identity) in sources){if(ct.IsCancellationRequested)break;diagnostics.Step="source";try{int committed=await run(source,identity);D.Require(idle(),"detection_session_lost");jobs+=committed;completed++;}catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}catch(Exception error){diagnostics.Add(error);D.Require(idle(),"detection_session_lost");failed++;}} }
        finally { diagnostics.Write("detections"); }
        return new(sources.Count,jobs,failed){Completed=completed,FailureReasons=diagnostics.Counts};
    }
    internal static async Task<bool> Admit(IDetectionSql sql,JsonObject definition,CancellationToken ct)
    {
        var execution=definition["source_selector"]!["execution"]!.AsObject();var rows=await sql.Rows("select public.ensure_default_qw_policy(@id,1,@definition) as enabled",ct,("id",DetectionSignal.PolicyId(execution)),("definition",CanonicalJson.Serialize(definition,ensureAscii:false)));
        D.Require(rows.Count==1&&rows[0]["enabled"] is JsonValue v&&v.TryGetValue<bool>(out _),"detection_admission_unconfirmed");return rows[0]["enabled"]!.GetValue<bool>();
    }
    internal static async Task<int> RunPasswordThreshold(NpgsqlConnection db, PasswordScope scope, string rule, DateTimeOffset now, CancellationToken ct)
    {
        try
        {
            await using var tx = await db.BeginTransactionAsync(ct);
            var sql = new DetectionSql(db, tx);
            await sql.Execute("set local lock_timeout='1s'", ct);
            var policy = new PasswordThresholdPolicy();
            var definition = PasswordAttacks.PolicyDefinition(scope, rule, policy);
            var policyId = DetectionSignal.PolicyId(definition["source_selector"]!["execution"]!.AsObject());
            var admission = (await sql.Rows("select public.admit_password_threshold418(@id,@definition) as enabled", ct,
                ("id", policyId), ("definition", CanonicalJson.Serialize(definition, ensureAscii: false)))).Single();
            if (admission["enabled"]?.GetValue<bool>() != true)
            {
                await RecordPasswordPass(sql, scope, rule, 0, "disabled", [], ct);
                await tx.CommitAsync(ct);
                return 0;
            }
            var pass = (await sql.Rows("select * from public.password_threshold_pass418(@scope,@rule,@now)", ct,
                ("scope", scope.Document), ("rule", rule), ("now", now))).Single();
            long cursor = pass["cursor_id"]!.GetValue<long>(), end = pass["end_id"]!.GetValue<long>();
            int jobs = 0;
            var states = new JsonArray();
            if (pass["first_at"] is { } first)
            {
                var from = (cursor == 0 ? now : D.Time(first)).AddSeconds(-policy.WindowSeconds);
                var active = (await sql.Rows("select * from public.read_password_threshold_episodes418(@scope,@rule,@from)", ct,
                    ("scope", scope.Document), ("rule", rule), ("from", from.AddSeconds(-PasswordAttacks.QuietSeconds))))
                    .ToDictionary(row => D.Text(row["entity_key"]), row => PasswordAttacks.Episode.Read(D.Text(row["episode_key"]), row["facts"]!.AsObject()) with
                    { ClosedAt = row["closed_at"] is { } closed ? D.Time(closed) : null });
                var rows = new List<DetectionRow>();
                var after = from;
                long id = 0;
                while (true)
                {
                    var page = await sql.Rows("select * from public.read_password_threshold_events418(@scope,@rule,@from,@after,@id,@now,@end)", ct,
                        ("scope", scope.Document), ("rule", rule), ("from", from), ("after", after), ("id", id), ("now", now), ("end", end));
                    foreach (var row in page)
                    {
                        id = row["native_id"]!.GetValue<long>();
                        after = D.Time(row["occurred_at_utc"]);
                        rows.Add(new(new(scope, "core_event", id.ToString(System.Globalization.CultureInfo.InvariantCulture), D.Text(row["sha256"])),
                            after, row["event_id"]!.GetValue<int>(), Fields: row["fields"]!.AsObject()));
                    }
                    if (page.Count < 4000) break;
                }
                foreach (var signal in PasswordAttacks.Evaluate(scope, rule, policy, rows, cursor, active, now))
                {
                    var facts = PasswordAttacks.Validate(signal);
                    jobs += await Enqueue(sql, signal, ct);
                    states.Add(new JsonObject { ["entity_key"] = signal["entity_key"]!.DeepClone(),
                        ["episode_key"] = signal["episode_key"]!.DeepClone(), ["facts"] = facts.DeepClone() });
                }
            }
            await RecordPasswordPass(sql, scope, rule, end, "current", states, ct);
            await tx.CommitAsync(ct);
            return jobs;
        }
        catch (Exception error) when (error is not OperationCanceledException && !ct.IsCancellationRequested && db.FullState == ConnectionState.Open && !SemanticWork.ConnectionWait(error))
        {
            try
            {
                await using var tx = await db.BeginTransactionAsync(ct);
                var sql = new DetectionSql(db, tx);
                await sql.Execute("set local lock_timeout='1s'", ct);
                await RecordPasswordPass(sql, scope, rule, 0, "failed", [], ct);
                await tx.CommitAsync(ct);
            }
            catch (PostgresException) when (!ct.IsCancellationRequested) { }
            throw;
        }
    }

    private static Task RecordPasswordPass(IDetectionSql sql, PasswordScope scope, string rule, long cursor, string state, JsonArray episodes, CancellationToken ct) =>
        sql.Execute("select public.write_password_threshold_pass418(@scope,@rule,@cursor,@state,@episodes)", ct,
            ("scope", scope.Document), ("rule", rule), ("cursor", cursor), ("state", state), ("episodes", episodes));
    internal static async Task<IReadOnlyList<DetectionRow>> ReadIdentity(IDetectionSql sql,PasswordScope scope,CancellationToken ct,long[]? refs=null)
    {
        bool snapshot=scope.PluginId=="sli.ad-snapshot";string query=snapshot?"select * from public.read_identity_attack_snapshot_v301(@scope::jsonb,@refs::bigint[])":"select * from public.read_identity_attack_events_v301(@scope::jsonb,@refs::bigint[])";
        var rows=await sql.Rows(query,ct,("scope",scope.Document),("refs",refs));return snapshot?DetectionNative.Snapshots(scope,rows):DetectionNative.ParseEvents(scope,rows,true);
    }
    internal static async Task<int> RunIdentity(IDetectionSql sql,JsonObject source,DateTimeOffset now,CancellationToken ct)
    {
        var scope=PasswordScope.Read(source["scope"]);bool snapshot=scope.PluginId=="sli.ad-snapshot";var policy=new IdentityAttackPolicy();var enabled=new HashSet<string>();
        foreach(var rule in IdentityAttacks.Rules.Keys.Where(r=>(r=="qw.ad-preauth-disabled")==snapshot))if(await Admit(sql,IdentityAttacks.PolicyDefinition(scope,rule,policy),ct))enabled.Add(rule);
        if(enabled.Count==0)return 0;var rows=await ReadIdentity(sql,scope,ct);var signals=snapshot?IdentityAttacks.EvaluateSnapshot(scope,rows,now,policy):IdentityAttacks.Evaluate(scope,rows,now,policy);int jobs=0;
        foreach(var signal in signals.Where(s=>enabled.Contains(D.Text(s["rule_id"])))){
            var episode=await sql.Rows("select public.identity_attack_episode_v301(@scope::jsonb,@rule,@entity,@at,@seed) as episode",ct,("scope",scope.Document),("rule",D.Text(signal["rule_id"])),("entity",D.Text(signal["entity_key"])),("at",D.Time(signal["occurred_at_utc"])),("seed",D.Text(signal["episode_key"])));
            D.Require(episode.Count==1&&PasswordJson.Hex(D.Text(episode[0]["episode"])),"identity_attack_episode_invalid");signal["episode_key"]=episode[0]["episode"]!.DeepClone();await VerifyIdentity(sql,signal,ct);jobs+=await Enqueue(sql,signal,ct);
        }return jobs;
    }
    internal static async Task VerifyIdentity(IDetectionSql sql,JsonObject signal,CancellationToken ct)
    {
        var policy=IdentityAttacks.Validate(signal);var refs=signal["evidence_refs"]!.AsArray().Select(DetectionRef.Read).ToArray();var scope=refs[0].Scope;var rows=await ReadIdentity(sql,scope,ct,refs.Select(r=>long.Parse(r.NativeId)).ToArray());
        var candidates=scope.PluginId=="sli.ad-snapshot"?IdentityAttacks.EvaluateSnapshot(scope,rows,D.Time(signal["occurred_at_utc"]),policy):IdentityAttacks.Evaluate(scope,rows,D.Time(signal["occurred_at_utc"]),policy);
        var matching=candidates.FirstOrDefault(s=>new[]{"rule_id","entity_key","evidence_refs","identity_context","occurred_at_utc","severity_reasons"}.All(key=>JsonNode.DeepEquals(s[key],signal[key])));D.Require(matching!=null,"identity_attack_native_proof_invalid");
        if(!JsonNode.DeepEquals(matching!["episode_key"],signal["episode_key"])){
            var known=await sql.Rows("select public.identity_attack_episode_known_v301(@scope::jsonb,@rule,@entity,@episode) as known",ct,("scope",scope.Document),("rule",D.Text(signal["rule_id"])),("entity",D.Text(signal["entity_key"])),("episode",D.Text(signal["episode_key"])));D.Require(known.Count==1&&known[0]["known"]?.GetValue<bool>()==true,"identity_attack_episode_invalid");
        }
    }
    internal static IReadOnlyList<DetectionRow> FileRows(PasswordScope scope,IEnumerable<JsonObject> rows,string host)=>rows.Select(row=>new DetectionRow(new(scope with{CollectionScopeId=D.Text(row["collection_scope_id"])},"file_audit_observation",D.Text(row["native_id"]),D.Text(row["sha256"])),D.Time(row["occurred_at_utc"]),Host:host,Record:row["document"]!.AsObject())).ToArray();
    internal static async Task<int> RunPrecursors(IDetectionSql sql,JsonObject source,DateTimeOffset now,CancellationToken ct)
    {
        var scope=PasswordScope.Read(source["scope"]);var policies=await sql.Rows("select public.read_t109_policy() as policy",ct);var policy=PrecursorPolicy.Read(policies.Single()["policy"]);var rows=await sql.Rows("select * from public.read_t109_native(@scope::jsonb)",ct,("scope",scope.Document));D.Require(rows.Count<=10000&&rows.Sum(r=>(long)CanonicalJson.Length(r))<=16777216,"t109_source_window_truncated");
        IReadOnlyList<JsonObject> signals;
        if(scope.PluginId=="sli.file-audit"){
            var exclusions=(source["config"]?["service_account_exclusions"]?.AsArray()??[]).Select(n=>n!.GetValue<string>());policy=policy with{BackupSids=(policy.BackupSids??[]).Concat(exclusions).Distinct().Order(StringComparer.Ordinal).ToArray()};policy.Validate();var context=new List<JsonObject>();
            if(rows.Count>0){var start=rows.Min(r=>D.Time(r["occurred_at_utc"]));var end=rows.Max(r=>D.Time(r["occurred_at_utc"]));int padding=Math.Max(policy.FastSeconds,policy.ReadSeconds);var ranges=end-start+TimeSpan.FromSeconds(2*padding)>TimeSpan.FromDays(2)?new[]{(start.AddSeconds(-padding),start.AddSeconds(padding)),(end.AddSeconds(-padding),end.AddSeconds(padding))}:new[]{(start.AddSeconds(-padding),end.AddSeconds(padding))};
                foreach(var (from,to) in ranges)context.AddRange(await sql.Rows("select * from public.read_t109_native(@scope::jsonb,@from,@to)",ct,("scope",scope.Document),("from",from),("to",to)));
            }
            signals=AttackPrecursors.DetectFiles(FileRows(scope,context.Take(10000).Concat(rows),D.Text(source["host_name"])),now,policy);if(context.Count>10000)foreach(var s in signals)s["quality"]="degraded";
        }else{
            string instance=D.Text(source["instance_name"]);var services=AttackPrecursors.AgentServices.Concat(new[]{instance==""?"sliagent":"sli-agent-"+instance.ToLowerInvariant(),instance==""?"sli agent":"sli agent ("+instance+")"});
            signals=AttackPrecursors.DetectEvents(DetectionNative.ParseEvents(scope,rows),now,policy,services);var healthRows=await sql.Rows("select public.read_t109_agent_health(@scope::jsonb) as context",ct,("scope",scope.Document));var context=healthRows.Single()["context"];
            if(context is JsonObject healthContext){var health=DetectionHealth.Project(healthContext,now);var recent=await sql.Rows("select signal_id from public.read_t109_recent_threats(@scope::jsonb)",ct,("scope",scope.Document));var threats=signals.ToList();foreach(var r in recent){var stored=await sql.Rows("select document_json from public.semantic_qw_signals where signal_id=@id",ct,("id",D.Text(r["signal_id"])));if(stored.Count==1){var s=stored[0]["document_json"]!.AsObject();D.Require(DetectionSignal.Id(s)==D.Text(r["signal_id"]),"t109_signal_conflict");AttackPrecursors.Validate(s);threats.Add(s);}}
                signals=signals.Concat(threats.Select(t=>AttackPrecursors.SilenceSignal(t,health,now)).OfType<JsonObject>()).ToArray();
            }
        }
        int jobs=0;foreach(var original in signals){var item=await BindEpisode(sql,original,ct);if(await Admit(sql,AttackPrecursors.PolicyDefinition(item),ct)){await VerifyPrecursors(sql,item,source,now,ct);jobs+=await Enqueue(sql,item,ct);}}
        string kind=scope.PluginId=="sli.file-audit"?"file_audit_observation":scope.PluginId=="sli.workstations"?"workstation_observation":"core_event";
        foreach(var id in rows.Select(r=>D.Text(r["native_id"])).Distinct().Order(StringComparer.Ordinal))await sql.Execute("insert into public.semantic_t109_seen(source_key,native_id,scope_json,storage_kind) values(@key,@native,@scope::jsonb,@kind) on conflict do nothing",ct,("key",D.Hash(scope.Document)),("native",id),("scope",scope.Document),("kind",kind));return jobs;
    }
    internal static async Task<JsonObject> BindEpisode(IDetectionSql sql,JsonObject original,CancellationToken ct)
    {
        string rule=D.Text(original["rule_id"]);if(rule is not ("qw.mass-file-read" or "qw.file-ransom-fast" or "qw.agent-silenced"))return original;
        var item=(JsonObject)original.DeepClone();var context=item["attack_context"]!;var policy=PrecursorPolicy.Read(context["policy"]);var execution=DetectionSignal.Execution(item);if(rule=="qw.mass-file-read")execution["scope"]!["collection_scope_id"]="";string key=D.Hash(new JsonArray(execution,JsonValue.Create(D.Text(item["entity_key"]))));var first=D.Time(context["first"]);var last=D.Time(context["last"]);int seconds=rule=="qw.file-ransom-fast"?policy.FastSeconds:policy.ReadSeconds;
        await sql.Execute("select pg_advisory_xact_lock(hashtextextended(@key,0))",ct,("key",key));var rows=await sql.Rows("select episode_key,anchor_ref from public.semantic_t109_episodes where execution_key=@key and first_seen<=@end and last_seen>=@start order by first_seen,episode_key for update",ct,("key",key),("end",last.AddSeconds(seconds)),("start",first.AddSeconds(-seconds)));D.Require(rows.Count<=1,"t109_late_episode_bridge");
        var anchor=rows.Count==0?item["evidence_refs"]![0]!.DeepClone():rows[0]["anchor_ref"]!.DeepClone();string episode=rows.Count==0?D.Text(item["episode_key"]):D.Text(rows[0]["episode_key"]);
        if(rule=="qw.mass-file-read"){
            var refs=item["evidence_refs"]!.AsArray().Select(DetectionRef.Read).Append(DetectionRef.Read(anchor)).Distinct().OrderBy(r=>!JsonNode.DeepEquals(r.Document,anchor)).ThenBy(r=>r.SortKey,StringComparer.Ordinal).ToArray();D.Require(refs.Length<=256,"t109_evidence_window_too_large");item["evidence_refs"]=D.Array(refs,r=>r.Document);item["attack_context"]!["anchor_ref"]=anchor.DeepClone();
        }
        var reference=DetectionRef.Read(item["evidence_refs"]![0]);await sql.Execute("insert into public.semantic_t109_episodes(execution_key,episode_key,scope_json,storage_kind,first_seen,last_seen,anchor_ref) values(@key,@episode,@scope::jsonb,@kind,@first,@last,@anchor::jsonb) on conflict(execution_key,episode_key) do update set first_seen=least(semantic_t109_episodes.first_seen,excluded.first_seen),last_seen=greatest(semantic_t109_episodes.last_seen,excluded.last_seen)",ct,("key",key),("episode",episode),("scope",reference.Scope.Document),("kind",reference.Kind),("first",first),("last",last),("anchor",anchor));item["episode_key"]=episode;return item;
    }
    internal static async Task VerifyPrecursors(IDetectionSql sql,JsonObject signal,JsonObject source,DateTimeOffset now,CancellationToken ct)
    {
        var policy=AttackPrecursors.Validate(signal);var scope=PasswordScope.Read(source["scope"]);var context=signal["attack_context"]!;string rule=D.Text(signal["rule_id"]);
        // Resolve every individually authorized root, including a retained cross-window anchor.
        await Resolve(sql,signal,ct);
        var first=D.Time(context["first"]);var last=D.Time(context["last"]);D.Require(last-first<=TimeSpan.FromDays(2),"t109_native_proof_invalid");
        var rows=await sql.Rows("select * from public.read_t109_native(@scope::jsonb,@from,@to)",ct,("scope",scope.Document),("from",first),("to",last));
        var refs=signal["evidence_refs"]!.AsArray().Select(DetectionRef.Read).ToArray();var selected=rows.Where(r=>refs.Any(w=>w.NativeId==D.Text(r["native_id"])&&w.Sha256==D.Text(r["sha256"]))).ToList();
        var native=scope.PluginId=="sli.file-audit"?FileRows(scope,selected,D.Text(source["host_name"])):DetectionNative.ParseEvents(scope,selected);
        if(rule=="qw.agent-silenced"){
            var threats=AttackPrecursors.DetectEvents(native,now,policy);var health=(await sql.Rows("select public.read_t109_agent_health(@scope::jsonb) as context",ct,("scope",scope.Document))).Single()["context"]!.AsObject();
            D.Require(threats.Any(t=>AttackPrecursors.SilenceSignal(t,DetectionHealth.Project(health,now),now) is {} s&&JsonNode.DeepEquals(s["attack_context"],signal["attack_context"])),"t109_native_proof_invalid");
        }else{
            string instance=D.Text(source["instance_name"]);var services=AttackPrecursors.AgentServices.Concat(new[]{instance==""?"sliagent":"sli-agent-"+instance.ToLowerInvariant(),instance==""?"sli agent":"sli agent ("+instance+")"});
            var candidates=scope.PluginId=="sli.file-audit"?AttackPrecursors.DetectFiles(native,now,policy):AttackPrecursors.DetectEvents(native,now,policy,services);
            D.Require(candidates.Any(s=>D.Text(s["rule_id"])==rule&&JsonNode.DeepEquals(s["entity_key"],signal["entity_key"])&&D.Text(s["attack_context"]?["reason"])==D.Text(context["reason"])&&s["attack_context"]!["count"]!.GetValue<int>()==context["count"]!.GetValue<int>()&&s["evidence_refs"]!.AsArray().Select(DetectionRef.Read).All(refs.Contains)),"t109_native_proof_invalid");
        }
    }
    private static async Task Resolve(IDetectionSql sql,JsonObject signal,CancellationToken ct)
    {
        foreach(var r in signal["evidence_refs"]!.AsArray().Select(DetectionRef.Read)){
            var scope=r.Scope;var resolved=await sql.Rows("select public.resolve_finding_evidence_ref(@installation,@plugin,@source,@generation,@collection,@kind,@native,@sha) as resolved",ct,("installation",Guid.Parse(scope.InstallationId)),("plugin",scope.PluginId),("source",scope.SourceInstanceId),("generation",scope.SourceGeneration),("collection",scope.CollectionScopeId),("kind",r.Kind),("native",r.NativeId),("sha",r.Sha256));D.Require(resolved.Count==1&&resolved[0]["resolved"]?.GetValue<bool>()==true,"detection_evidence_unavailable");
        }
    }
    internal static async Task<int> Enqueue(IDetectionSql sql,JsonObject signal,CancellationToken ct)
    {
        DetectionSignal.ValidateEnvelope(signal);await Resolve(sql,signal,ct);string id=DetectionSignal.Id(signal);var execution=DetectionSignal.Execution(signal);
        await sql.Execute("insert into public.semantic_qw_signals(signal_id,evaluation_mode,document_json) values(@id,'enabled',@document::jsonb) on conflict(signal_id) do nothing",ct,("id",id),("document",signal));
        var persisted=await sql.Rows("select evaluation_mode,document_json from public.semantic_qw_signals where signal_id=@id",ct,("id",id));D.Require(persisted.Count==1&&D.Text(persisted[0]["evaluation_mode"])=="enabled"&&DetectionSignal.Id(persisted[0]["document_json"]!.AsObject())==id,"detection_signal_conflict");
        var policies=await sql.Rows("""
            select p.policy_id,p.policy_version,encode(p.definition_sha256,'hex') as policy_sha256
            from public.semantic_risk_policy_subscriptions s join public.semantic_risk_policies p
              on p.policy_id=s.policy_id and p.policy_version=s.policy_version and p.definition_sha256=s.definition_sha256
            where s.source_kind='qw_signal' and s.selector_value=@rule
              and public.semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)='enabled'
              and p.policy_version=1 and p.definition_json#>'{source_selector,execution}'=@execution::jsonb
              and exists(select 1 from public.semantic_policy_admission a where a.policy_id=p.policy_id and a.policy_version=p.policy_version and a.enabled is true)
            order by p.policy_id,p.policy_version
            """,ct,("rule",D.Text(signal["rule_id"])),("execution",execution));
        foreach(var p in policies){var identity=new JsonObject{["policy_id"]=p["policy_id"]!.DeepClone(),["policy_version"]=1,["policy_sha256"]=p["policy_sha256"]!.DeepClone(),["source_kind"]="qw_signal",["source_id"]=id,["evaluation_mode"]="enabled"};string hash=D.Hash(identity);Guid job=AuthAudit.Uuid5("adlog:risk-evaluation:"+hash);
            await sql.Execute("insert into public.semantic_risk_evaluation_jobs(job_id,policy_id,policy_version,source_kind,source_reference,evaluation_mode,idempotency_key,qw_signal_id) values(@job,@policy,1,'qw_signal',@source,'enabled',@identity,@source) on conflict(idempotency_key) do nothing",ct,("job",job),("policy",D.Text(p["policy_id"])),("source",id),("identity",Convert.FromHexString(hash)));
            var existing=await sql.Rows("select job_id::text as job_id from public.semantic_risk_evaluation_jobs where idempotency_key=@identity",ct,("identity",Convert.FromHexString(hash)));D.Require(existing.Count==1&&D.Text(existing[0]["job_id"])==job.ToString(),"detection_queue_identity_conflict");
        }return policies.Count;
    }
}
