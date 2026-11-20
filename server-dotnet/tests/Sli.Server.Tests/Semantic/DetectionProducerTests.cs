using System.Text.Json.Nodes;
using Sli.Server.Semantic.Detections;
using Sli.Server.Semantic.Password;
using Sli.Server.Semantic;
using Npgsql;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public class DetectionProducerTests
{
    [Fact] public async Task Import_progress_is_optional_on_old_schema_and_detached_for_cycle_result()
    {
        var sql=new Sql();var ct=TestContext.Current.CancellationToken;
        Assert.Empty(await DetectionProducer.ReadImportProgress(sql,ct));
        sql.ImportProgress=new JsonObject {["bootstrap_done"]=false,["bootstrap_packets"]=512,["revision"]=1};
        var summary=await DetectionProducer.ReadImportProgress(sql,ct);
        var cycle=new JsonObject {["import_summary"]=summary};
        Assert.Equal(512,cycle["import_summary"]!["bootstrap_packets"]!.GetValue<int>());
        Assert.False(cycle["import_summary"]!["bootstrap_done"]!.GetValue<bool>());
    }
    [Fact] public void Native_parser_matches_python_format_vectors()
    {
        using var stream=typeof(DetectionProducerTests).Assembly.GetManifestResourceStream("Sli.Server.Tests.Semantic.Fixtures.native-reference.json")!;
        var reference=JsonNode.Parse(stream)!;var scope=PasswordScope.Read(reference["scope"]);
        foreach(var vector in reference["vectors"]!.AsArray()) {
            var row=vector!["row"]!.AsObject();bool identity=vector["identity"]!.GetValue<bool>();
            // Explicitly approved correction to the Python identity timestamp defect.
            var expected=vector["corrected_expected"]??vector["expected"];
            if(expected is null) {Assert.Throws<DetectionFailure>(()=>DetectionNative.ParseEvents(scope,[row],identity));continue;}
            var parsed=Assert.Single(DetectionNative.ParseEvents(scope,[row],identity));
            Assert.True(JsonNode.DeepEquals(expected["fields"],parsed.Fields),vector["name"]!.ToString());
            Assert.Equal(D.Text(expected["host"]),parsed.Host);
        }
    }
    [Theory]
    [InlineData("1234567","123456",true)][InlineData("1234567","123457",true)]
    [InlineData("1234565","123456",true)][InlineData("1234565","123457",false)]
    [InlineData("1234575","123458",true)][InlineData("9999997","000000",true)]
    [InlineData("1234567","123458",false)][InlineData("1234567","123455",false)]
    [InlineData("1234567","1234571",false)][InlineData("1234567","1234569",false)]
    [InlineData("1234567","1234570",true)]
    [InlineData("1234564","123457",false)][InlineData("123456","123457",false)]
    public void Native_time_accepts_only_truncation_or_storage_rounding(string xmlFraction,string storedFraction,bool accepted)
    {
        var v=DetectionTests.Vector("kerberoasting");var row=DetectionTests.Native(DetectionTests.Row(v["rows"]![0]!));
        row["native_id"]=row["source_event_id"]!.ToString();
        var root=System.Xml.Linq.XElement.Parse(D.Text(row["source_xml"]));var ns=root.Name.Namespace;
        root.Element(ns+"System")!.Element(ns+"TimeCreated")!.SetAttributeValue("SystemTime","2026-11-01T00:00:00."+xmlFraction+"Z");
        row["source_xml"]=root.ToString();row["occurred_at_utc"]="2026-11-01T00:00:"+(xmlFraction=="9999997"?"01":"00")+"."+storedFraction+"Z";
        foreach(bool identity in new[]{false,true}) {
            if(accepted)Assert.Single(DetectionNative.ParseEvents(PasswordScope.Read(v["scope"]),[row],identity));
            else {var error=Assert.Throws<DetectionFailure>(()=>DetectionNative.ParseEvents(PasswordScope.Read(v["scope"]),[row],identity));Assert.Equal(DetectionFailure.NativeField.SystemTime,error.Field);}
        }
    }
    [Theory]
    [InlineData("EventID","missing")][InlineData("SystemTime","missing")]
    [InlineData("SystemTime","type")][InlineData("SystemTime","value")]
    [InlineData("Status","value")][InlineData("EventData","value")]
    public void Native_diagnostics_report_only_enumerated_field_and_difference(string field,string difference)
    {
        var v=DetectionTests.Vector("kerberoasting");var row=DetectionTests.Native(DetectionTests.Row(v["rows"]![0]!));
        var root=System.Xml.Linq.XElement.Parse(D.Text(row["source_xml"]));var ns=root.Name.Namespace;var system=root.Element(ns+"System")!;
        if(field=="EventID")system.Element(ns+field)!.Remove();
        else if(field=="SystemTime") {
            var attribute=system.Element(ns+"TimeCreated")!.Attribute(field)!;
            if(difference=="missing")attribute.Remove();else attribute.Value=difference=="type"?"private-token":"2026-01-01T00:00:00Z";
        } else {
            string name=field=="EventData"?"private-host-token":field;
            root.Element(ns+"EventData")!.Add(new System.Xml.Linq.XElement(ns+"Data",new System.Xml.Linq.XAttribute("Name",name)),new System.Xml.Linq.XElement(ns+"Data",new System.Xml.Linq.XAttribute("Name",name)));
        }
        row["source_xml"]=root.ToString();
        var error=Assert.Throws<DetectionFailure>(()=>DetectionNative.ParseEvents(PasswordScope.Read(v["scope"]),[row],true));
        var safe=DetectionDiagnostics.Describe(new InvalidOperationException("private",error),"read_identity_attack_events_v301");
        Assert.Equal(field,D.Text(safe["field"]));Assert.Equal(difference,D.Text(safe["difference"]));Assert.DoesNotContain("private",safe.ToJsonString());
    }
    [Fact] public void Client_timeout_and_transport_failures_keep_safe_distinct_reasons()
    {
        Assert.Equal("client_timeout", DetectionDiagnostics.Describe(new NpgsqlException("private", new TimeoutException("private")), "source")["reason"]!.GetValue<string>());
        Assert.Equal("connection_lost", DetectionDiagnostics.Describe(new NpgsqlException("private", new IOException("private")), "source")["reason"]!.GetValue<string>());
        Assert.Equal("operation_cancelled", DetectionDiagnostics.Describe(new OperationCanceledException("private"), "source")["reason"]!.GetValue<string>());
    }
    [Fact] public void Acl_failures_report_only_allowlisted_nonzero_counts()
    {
        var diagnostics = new DetectionDiagnostics();
        diagnostics.FileAcl(new JsonObject { ["owner_denied"] = 2, ["private-host"] = 1, ["verified_excluded"] = 0 });
        var lines = new List<string>(); diagnostics.Write("detections", lines.Add);
        string line = Assert.Single(lines);
        var safe = JsonNode.Parse(line[(line.IndexOf(':') + 1)..])!;
        Assert.Equal(2, safe["diagnostic_counts"]!["owner_denied"]!.GetValue<int>());
        Assert.Equal(1, safe["diagnostic_counts"]!["unrecognized_status"]!.GetValue<int>());
        Assert.DoesNotContain("private", line);
        Assert.Equal(1, diagnostics.Counts["file_acl_source_diagnostics"]!.GetValue<int>());
    }
    internal sealed class Sql:IDetectionSql
    {
        internal JsonObject? ImportProgress;
        internal List<JsonObject> Native=[];internal readonly List<string> Queries=[];internal readonly Dictionary<string,JsonObject> Signals=[];internal readonly Dictionary<string,Guid> Jobs=[];internal readonly Dictionary<string,JsonObject> Policies=[];internal readonly List<JsonObject> Episodes=[];internal readonly HashSet<string> Seen=[];internal bool Enabled=true,Resolve=true;internal JsonObject? SnapshotRun;internal List<JsonObject> Entities=[],Relations=[];
        public Task<List<JsonObject>> Rows(string query,CancellationToken ct,params (string,object?)[] args)
        {
            ct.ThrowIfCancellationRequested();Queries.Add(query);var p=args.ToDictionary(a=>a.Item1,a=>a.Item2);List<JsonObject> rows=[];
            if(query.Contains("to_regprocedure('public.semantic_import_progress320()')",StringComparison.Ordinal))rows=[new(){["ready"]=ImportProgress is not null}];
            else if(query.Contains("select public.semantic_import_progress320()",StringComparison.Ordinal))rows=[new(){["progress"]=ImportProgress?.DeepClone()}];
            else if(query.Contains("ensure_default_qw_policy",StringComparison.Ordinal)){var def=JsonNode.Parse((string)p["definition"]!)!.AsObject();Policies[(string)p["id"]!]=def;rows=[new(){["enabled"]=Enabled}];}
            else if(query.Contains("read_identity_attack_",StringComparison.Ordinal)){var ids=(long[]?)p["refs"];rows=Native.Where(r=>ids==null||ids.Contains(r["source_event_id"]!.GetValue<long>())).ToList();}
            else if(query.Contains("identity_attack_episode_known",StringComparison.Ordinal))rows=[new(){["known"]=true}];
            else if(query.Contains("identity_attack_episode_v301",StringComparison.Ordinal))rows=[new(){["episode"]=(string)p["seed"]!}];
            else if(query.Contains("resolve_finding_evidence_ref",StringComparison.Ordinal))rows=[new(){["resolved"]=Resolve}];
            else if(query.Contains("from public.semantic_qw_signals",StringComparison.Ordinal)){if(Signals.TryGetValue((string)p["id"]!,out var doc))rows=[new(){["evaluation_mode"]="enabled",["document_json"]=doc.DeepClone()}];}
            else if(query.Contains("from public.semantic_risk_policy_subscriptions",StringComparison.Ordinal)){rows=Policies.Where(k=>JsonNode.DeepEquals(k.Value["source_selector"]!["execution"],p["execution"] as JsonNode)).Select(k=>new JsonObject{["policy_id"]=k.Key,["policy_version"]=1,["policy_sha256"]=new string('b',64)}).ToList();}
            else if(query.Contains("select job_id",StringComparison.Ordinal)){if(Jobs.TryGetValue(Convert.ToHexString((byte[])p["identity"]!),out var job))rows=[new(){["job_id"]=job.ToString()}];}
            else if(query.Contains("read_t109_policy",StringComparison.Ordinal))rows=[new(){["policy"]=new JsonObject()}];
            else if(query.Contains("read_t109_native",StringComparison.Ordinal))rows=Native;
            else if(query.Contains("read_t109_agent_health",StringComparison.Ordinal))rows=[new(){["context"]=null}];
            else if(query.Contains("select episode_key,anchor_ref",StringComparison.Ordinal))rows=Episodes.Where(r=>D.Text(r["key"])==(string)p["key"]!&&D.Time(r["first"])<=(DateTimeOffset)p["end"]!&&D.Time(r["last"])>=(DateTimeOffset)p["start"]!).Select(r=>new JsonObject{["episode_key"]=r["episode"]!.DeepClone(),["anchor_ref"]=r["anchor"]!.DeepClone()}).ToList();
            else if(query.Contains("ad_hardening_published_runs",StringComparison.Ordinal))rows=SnapshotRun==null?[]:[SnapshotRun];
            else if(query.Contains("ad_hardening_snapshot_entities",StringComparison.Ordinal))rows=Entities;
            else if(query.Contains("ad_hardening_snapshot_memberships",StringComparison.Ordinal))rows=Relations;
            else throw new InvalidOperationException("Unexpected test query: "+query);
            return Task.FromResult(rows.Select(r=>(JsonObject)r.DeepClone()).ToList());
        }
        public Task Execute(string query,CancellationToken ct,params (string,object?)[] args)
        {
            ct.ThrowIfCancellationRequested();Queries.Add(query);var p=args.ToDictionary(a=>a.Item1,a=>a.Item2);
            if(query.Contains("insert into public.semantic_qw_signals",StringComparison.Ordinal))Signals.TryAdd((string)p["id"]!,(JsonObject)((JsonObject)p["document"]!).DeepClone());
            else if(query.Contains("insert into public.semantic_risk_evaluation_jobs",StringComparison.Ordinal))Jobs.TryAdd(Convert.ToHexString((byte[])p["identity"]!),(Guid)p["job"]!);
            else if(query.Contains("insert into public.semantic_t109_seen",StringComparison.Ordinal))Seen.Add((string)p["native"]!);
            else if(query.Contains("insert into public.semantic_t109_episodes",StringComparison.Ordinal)){
                var row=Episodes.SingleOrDefault(r=>D.Text(r["key"])==(string)p["key"]!&&D.Text(r["episode"])==(string)p["episode"]!);if(row==null)Episodes.Add(new(){["key"]=(string)p["key"]!,["episode"]=(string)p["episode"]!,["first"]=D.Stamp((DateTimeOffset)p["first"]!),["last"]=D.Stamp((DateTimeOffset)p["last"]!),["anchor"]=((JsonNode)p["anchor"]!).DeepClone()});else{row["first"]=D.Stamp(new[]{D.Time(row["first"]),(DateTimeOffset)p["first"]!}.Min());row["last"]=D.Stamp(new[]{D.Time(row["last"]),(DateTimeOffset)p["last"]!}.Max());}
            }return Task.CompletedTask;
        }
    }
    [Theory][InlineData("asrep_0")][InlineData("fanout")][InlineData("privileged_S-1-5-21-1-2-3-512")][InlineData("preauth_snapshot")]
    public async Task Identity_native_publication_is_exact_and_replay_queues_one_job(string vector)
    {
        var v=DetectionTests.Vector(vector);var sql=new Sql();var source=new JsonObject{["scope"]=v["scope"]!.DeepClone()};foreach(var row in v["rows"]!.AsArray().Select(n=>DetectionTests.Row(n!)))sql.Native.Add(row.Record==null?DetectionTests.Native(row):new(){["source_event_id"]=long.Parse(row.Ref.NativeId),["occurred_at_utc"]=D.Stamp(row.At),["sha256"]=row.Ref.Sha256,["attributes_json"]=row.Record.DeepClone()});
        Assert.Equal(1,await DetectionProducer.RunIdentity(sql,source,D.Time(v["now"]),TestContext.Current.CancellationToken));Assert.Equal(1,await DetectionProducer.RunIdentity(sql,source,D.Time(v["now"]).AddSeconds(1),TestContext.Current.CancellationToken));Assert.Single(sql.Signals);Assert.Single(sql.Jobs);
        Assert.True(JsonNode.DeepEquals(v["expected"]![0]!["evidence_refs"],sql.Signals.Values.Single()["evidence_refs"]));
    }
    [Fact]public async Task Disabled_policies_do_not_read_identity_native_and_denied_refs_never_publish()
    {
        var rows=KerberosDetectionTests.Events(false);var scope=rows[0].Ref.Scope;var now=rows[^1].At;var sql=new Sql{Enabled=false};Assert.Equal(0,await DetectionProducer.RunIdentity(sql,new(){["scope"]=scope.Document},now,TestContext.Current.CancellationToken));Assert.DoesNotContain(sql.Queries,q=>q.Contains("read_identity_attack",StringComparison.Ordinal));
        sql.Resolve=false;await Assert.ThrowsAsync<DetectionFailure>(()=>DetectionProducer.Enqueue(sql,Assert.Single(IdentityAttacks.Evaluate(scope,rows,now)),TestContext.Current.CancellationToken));Assert.Empty(sql.Signals);
    }
    internal static List<JsonObject> FileNative(IEnumerable<DetectionRow> rows)=>rows.Select(r=>new JsonObject{["native_id"]=r.Ref.NativeId,["sha256"]=r.Ref.Sha256,["occurred_at_utc"]=D.Stamp(r.At),["collection_scope_id"]=r.Ref.Scope.CollectionScopeId,["document"]=r.Record!.DeepClone()}).ToList();
    [Theory][InlineData("fast_write")][InlineData("fast_delete")][InlineData("mass_read_200")][InlineData("mass_read_10")]
    public async Task Precursor_file_publication_replays_and_keeps_durable_anchor_across_windows(string name)
    {
        var v=DetectionTests.Vector(name);var native=v["rows"]!.AsArray().Select(n=>DetectionTests.Row(n!)).ToArray();var sql=new Sql{Native=FileNative(native)};var source=new JsonObject{["scope"]=native[0].Ref.Scope.Document,["config"]=new JsonObject()};
        Assert.Equal(1,await DetectionProducer.RunPrecursors(sql,source,D.Time(v["now"]),TestContext.Current.CancellationToken));Assert.Equal(1,await DetectionProducer.RunPrecursors(sql,source,D.Time(v["now"]),TestContext.Current.CancellationToken));Assert.Single(sql.Jobs);Assert.Single(sql.Episodes);Assert.Equal(native.Length,sql.Seen.Count);
        if(name=="mass_read_200"){
            var original=sql.Signals.Values.Single();var next=native.Select((r,i)=>r with{Ref=r.Ref with{NativeId=(i+201).ToString("x64"),Scope=r.Ref.Scope with{CollectionScopeId="scope:a"}},At=r.At.AddSeconds(60)}).ToArray();sql.Native=FileNative(next);
            Assert.Equal(1,await DetectionProducer.RunPrecursors(sql,source,D.Time(v["now"]),TestContext.Current.CancellationToken));Assert.Single(sql.Episodes);Assert.Equal(400,sql.Seen.Count);var updated=sql.Signals.Values.Last();Assert.Equal(D.Text(original["episode_key"]),D.Text(updated["episode_key"]));Assert.True(JsonNode.DeepEquals(original["evidence_refs"]![0],updated["evidence_refs"]![0]));
        }
    }
    [Fact]public async Task Source_backup_exclusion_marks_seen_without_signals()
    {
        var v=DetectionTests.Vector("mass_read_200");var native=v["rows"]!.AsArray().Select(n=>DetectionTests.Row(n!)).ToArray();var sql=new Sql{Native=FileNative(native)};var source=new JsonObject{["scope"]=native[0].Ref.Scope.Document,["config"]=new JsonObject{["service_account_exclusions"]=new JsonArray(D.Text(native[0].Record!["subject_sid"]))}};
        Assert.Equal(0,await DetectionProducer.RunPrecursors(sql,source,D.Time(v["now"]),TestContext.Current.CancellationToken));Assert.Empty(sql.Signals);Assert.Equal(200,sql.Seen.Count);
    }
    [Fact]public async Task Recoverable_commit_failure_continues_and_only_committed_jobs_count()
    {
        int calls=0;var sources=new[]{(new JsonObject(),false),(new JsonObject(),false)};var batch=await DetectionProducer.RunSources(sources,(_,_)=>++calls==1?Task.FromException<int>(new InvalidOperationException("commit failure")):Task.FromResult(2),()=>true,TestContext.Current.CancellationToken);Assert.Equal((2,2,1),(batch.Sources,batch.Jobs,batch.Failed));Assert.Equal(1,batch.FailureReasons["operation_failed"]!.GetValue<int>());Assert.Equal(2,calls);
        await Assert.ThrowsAsync<DetectionFailure>(()=>DetectionProducer.RunSources(sources,(_,_)=>Task.FromException<int>(new InvalidOperationException()),()=>false,TestContext.Current.CancellationToken));
    }
    [Fact]public async Task Repeated_source_failures_are_counted_without_private_exception_fields()
    {
        var sources=Enumerable.Range(0,3).Select(_=>(new JsonObject(),false)).ToArray();
        var batch=await DetectionProducer.RunSources(sources,(_,_)=>Task.FromException<int>(new DetectionFailure("detection_reader_type")),()=>true,TestContext.Current.CancellationToken);
        var json=System.Text.Json.JsonSerializer.Serialize(batch);
        Assert.Contains("failure_reasons",json);
        Assert.Contains("detection_reader_type",json);
        Assert.Equal(3,batch.FailureReasons["detection_reader_type"]!.GetValue<int>());
        Assert.Equal(0,batch.Completed);
        var result=new JsonObject { ["failed"]=batch.Failed, ["password_producer"]=new JsonObject { ["sources"]=batch.Sources,["completed"]=batch.Completed,["failed"]=batch.Failed } };
        Assert.Equal("error",SemanticProduction.CycleStatus(result));
    }
    [Fact]public async Task Successful_source_without_jobs_keeps_partial_cycle_active()
    {
        int calls=0;var sources=new[]{(new JsonObject(),false),(new JsonObject(),false)};
        var batch=await DetectionProducer.RunSources(sources,(_,_)=>++calls==1?Task.FromException<int>(new InvalidOperationException()):Task.FromResult(0),()=>true,TestContext.Current.CancellationToken);
        Assert.Equal(1,batch.Completed);Assert.Equal(0,batch.Jobs);
        var result=new JsonObject { ["failed"]=batch.Failed,["password_producer"]=new JsonObject { ["completed"]=batch.Completed,["failed"]=batch.Failed } };
        Assert.Equal("partial",SemanticProduction.CycleStatus(result));
    }
    [Fact]public void Diagnostics_aggregate_wrapped_sql_failures_and_redact_all_untrusted_fields()
    {
        var diagnostics=new DetectionDiagnostics();diagnostics.Query("select * from public.read_t109_native(@scope::jsonb)");
        var error=new InvalidOperationException("password=private",new PostgresException("private event XML","ERROR","ERROR","42501",detail:"private AD",constraintName:"private-host"));
        diagnostics.Add(error);diagnostics.Add(error);
        var lines=new List<string>();diagnostics.Write("detections",lines.Add);string line=Assert.Single(lines);
        var safe=JsonNode.Parse(line[(line.IndexOf(':')+1)..])!;
        Assert.Equal("read_t109_native",safe["step"]!.GetValue<string>());
        Assert.Equal("InvalidOperationException",safe["exception_type"]!.GetValue<string>());
        Assert.Equal("42501",safe["sql_state"]!.GetValue<string>());
        Assert.Equal("operation_failed",safe["reason"]!.GetValue<string>());Assert.Equal(2,safe["count"]!.GetValue<int>());
        Assert.Equal(5,safe.AsObject().Count);Assert.DoesNotContain("private",line);
        Assert.Equal("file_ransom_source_policy_mismatch",DetectionDiagnostics.Describe(new PostgresException("file_ransom_source_policy_mismatch","ERROR","ERROR","P0001"),"source")["reason"]!.GetValue<string>());
        Assert.Equal("unknown",DetectionDiagnostics.Describe(new PostgresException("secret","ERROR","ERROR","bad state"),"source")["sql_state"]!.GetValue<string>());
        diagnostics.Query("select public.read_file_ransom_results(@scope)");
        Assert.Equal("read_file_ransom_results",diagnostics.Step);
        Assert.Equal("file_ransom_result_invalid",DetectionDiagnostics.Describe(new InvalidDataException("file_ransom_result_invalid"),diagnostics.Step)["reason"]!.GetValue<string>());
    }
    [Fact]public async Task Stop_before_discovery_and_between_sources_preserves_unstarted_work()
    {
        using var stop=new CancellationTokenSource();stop.Cancel();int calls=0;var sources=new[]{(new JsonObject(),false),(new JsonObject(),false)};Assert.Equal(0,(await DetectionProducer.RunSources(sources,(_,_)=>{calls++;return Task.FromResult(1);},()=>true,stop.Token)).Sources);Assert.Equal(0,calls);
        using var nextStop=new CancellationTokenSource();var result=await DetectionProducer.RunSources(sources,(_,_)=>{calls++;nextStop.Cancel();return Task.FromResult(1);},()=>true,nextStop.Token);Assert.Equal(1,calls);Assert.Equal(1,result.Jobs);
    }
}
