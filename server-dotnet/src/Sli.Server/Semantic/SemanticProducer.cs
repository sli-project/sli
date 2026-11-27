using System.Globalization;
using System.Numerics;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Semantic;

// semantic_producer.py and semantic_publisher_for_runtime. No database ownership here:
// the caller supplies the exact transaction that inserted the source events.
internal static class SemanticProducer
{
    internal const string ImportLock = "adlog_semantic_event_publication";
    internal static async Task LockImportAsync(NpgsqlConnection db,NpgsqlTransaction tx,CancellationToken ct)
    {
        await using var command=new NpgsqlCommand("select pg_advisory_xact_lock_shared(hashtextextended($1,0))",db,tx);
        command.Parameters.AddWithValue(ImportLock); await command.ExecuteNonQueryAsync(ct);
    }
    internal const int MaxBatch = 5000;
    internal sealed record Source(long Id, string EventKey, string Stream, string Provider);
    internal sealed record Candidate(long Id, string Reason, string Kind = "normalize_event");
    internal sealed record Selection(Candidate[] Jobs, JsonObject Counters);
    private static string Norm(string? s) => UnicodeLower.Lower((s ?? "").Trim());
    internal static string? AuditOutcome(string? keywords)
    {
        // The normalizer's common spellings plus Python's int(clean, 0) bit
        // interpretation, including additional native keyword flags.
        string? named=SemanticNormalization.AuditOutcome(keywords);
        if(named is not null) return named;
        string clean=UnicodeCaseFold.TrimAndFold(keywords ?? "");
        bool negative=clean.StartsWith('-');
        if(clean.StartsWith('+') || negative) clean=clean[1..];
        int radix=10;
        if(clean.StartsWith("0x")) { radix=16; clean=clean[2..]; }
        else if(clean.StartsWith("0o")) { radix=8; clean=clean[2..]; }
        else if(clean.StartsWith("0b")) { radix=2; clean=clean[2..]; }
        if(radix!=10 && clean.StartsWith('_')) clean=clean[1..];
        string digit=radix switch {16=>"[0-9a-f]",8=>"[0-7]",2=>"[01]",_=>"[0-9]"};
        if(!Regex.IsMatch(clean,"\\A"+digit+"(?:_?"+digit+")*\\z",RegexOptions.CultureInvariant)) return null;
        clean=clean.Replace("_","");
        if(radix==10 && clean.Length>1 && clean[0]=='0' && clean.Any(c=>c!='0')) return null;
        BigInteger numeric=0;
        foreach(char c in clean) numeric=numeric*radix+(c<='9'?c-'0':c-'a'+10);
        if(negative) numeric=-numeric;
        bool success=(numeric & 0x0020000000000000L)!=0, failure=(numeric & 0x0010000000000000L)!=0;
        return success==failure?null:success?"success":"failure";
    }
    private static readonly Dictionary<(string Stream,string Event,string Provider),string> Catalog = LoadCatalog();
    private static Dictionary<(string,string,string),string> LoadCatalog()
    {
        var result = new Dictionary<(string,string,string),string>();
        foreach(string name in new[]{"event_catalog","file_audit_event_catalog","radius_event_catalog","workstations_event_catalog"}) {
            using var stream=typeof(SemanticProducer).Assembly.GetManifestResourceStream("Sli.Server.Semantic.Risk."+name+".json")!;
            foreach(var entry in JsonNode.Parse(stream)!["entries"]!.AsArray().OfType<JsonObject>())
                result[(Norm(entry.Text("stream") ?? entry.Text("channel")),Norm(entry.Text("event_key") ?? entry["event_id"]?.ToString()),Norm(entry.Text("provider_name")))]=Norm(entry.Text("noise_class"));
        }
        return result;
    }
    internal static string? RuntimeMode(Func<string,string?>? get = null)
    {
        get ??= Environment.GetEnvironmentVariable;
        if(!SemanticRuntimeSettings.Enabled(get("ADLOG_SEMANTIC_PRODUCTION_ENABLED"))) {
            if(!string.IsNullOrWhiteSpace(get("ADLOG_SEMANTIC_RUNTIME_MODE"))) _=SemanticRuntimeSettings.Mode(get);
            return null;
        }
        string mode=SemanticRuntimeSettings.Mode(get);
        SemanticRuntimeSettings.Read(get).Validate(mode,get);
        return mode;
    }
    internal static Selection Select(IReadOnlyList<Source> rows, bool includeContext=false, IReadOnlySet<long>? contextIds=null, int maxBatch=MaxBatch)
    {
        if(rows.Count>maxBatch) throw new ArgumentOutOfRangeException(nameof(rows),"semantic producer batch exceeds 5000 events");
        var signals=new List<Candidate>(); var contexts=new List<Candidate>(); var unknown=new List<Candidate>();
        int contextSkipped=0,noiseSkipped=0;
        var descriptors=new Dictionary<(string,string,string),(bool Found,string? Noise)>();
        foreach(var row in rows) {
            if(row.Id<=0) throw new ArgumentOutOfRangeException(nameof(rows),"semantic producer requires positive source_event_id");
            bool admitted=contextIds?.Contains(row.Id)==true;
            // A missing provider cannot pass lookup_semantic_event_descriptor.
            var identity=(row.Stream,row.EventKey,row.Provider);
            if(!descriptors.TryGetValue(identity,out var descriptor)) {
                bool exists=Norm(row.Provider).Length>0 && Catalog.TryGetValue((Norm(row.Stream),Norm(row.EventKey),Norm(row.Provider)),out _);
                descriptor=(exists,exists?Catalog[(Norm(row.Stream),Norm(row.EventKey),Norm(row.Provider))]:null);
                descriptors.Add(identity,descriptor);
            }
            bool found=descriptor.Found; string? noise=descriptor.Noise;
            if(!found && admitted) contexts.Add(new(row.Id,"related_context"));
            else if(!found) unknown.Add(new(row.Id,"descriptor_missing"));
            else if(noise=="signal") signals.Add(new(row.Id,"signal"));
            else if(noise=="context") {
                if(includeContext || admitted) contexts.Add(new(row.Id,includeContext?"explicit_context":"related_context"));
                else contextSkipped++;
            } else if(noise=="noise") noiseSkipped++;
            else if(admitted) contexts.Add(new(row.Id,"related_context"));
            else unknown.Add(new(row.Id,"noise_class_not_classified"));
        }
        int sample=Math.Min(32,rows.Count==0?0:Math.Max(1,(int)Math.Ceiling(rows.Count*0.05)));
        var selected=unknown.Take(sample).ToArray();
        var jobs=signals.Concat(contexts).Concat(selected).OrderBy(x=>x.Id).ToArray();
        return new(jobs,new JsonObject { ["scanned"]=rows.Count,["queued"]=jobs.Length,["signal_queued"]=signals.Count,
            ["unknown_queued"]=selected.Length,["unknown_suppressed"]=unknown.Count-selected.Length,["context_skipped"]=contextSkipped,["noise_skipped"]=noiseSkipped });
    }
    internal static async Task<Selection> ReadSelection(ISemanticSession session,long[] ids,string mode,CancellationToken ct)
    {
        if(ids.Length>MaxBatch) throw new ArgumentOutOfRangeException(nameof(ids));
        if(ids.Length==0) return Select([]);
        var rows=await session.QueryAsync("""
            select e.id,e.event_id::text as event_key,e.channel as stream,coalesce(e.provider_name,'') as provider_name
            from public.semantic_event_source355 e where e.id=any($1) order by e.id
            """,ct,ids);
        if(rows.Count!=ids.Length) throw new InvalidDataException("semantic_producer_source_rows_missing");
        if(mode!=SemanticRuntimeSettings.InvestigationMode)
            return Select(rows.Select(r=>new Source(r.Number("id"),r.Text("event_key")!,r.Text("stream")!,r.Text("provider_name")!)).ToArray(),mode==SemanticRuntimeSettings.FactsMode);
        var jobs=rows.Where(r=>r.Text("stream")=="Security" && int.TryParse(r.Text("event_key"),out int key) && ReportIds.Contains(key) &&
            r.Text("provider_name")== (key==1102?"Microsoft-Windows-Eventlog":"Microsoft-Windows-Security-Auditing"))
            .Select(r=>new Candidate(r.Number("id"),"signal")).ToList();
        var context=await session.QueryAsync("""
            select distinct login.id,reset.keywords from public.semantic_event_source355 login
            join public.semantic_event_source355 reset on reset.domain_id=login.domain_id and reset.event_id=4724
              and lower(nullif(btrim(reset.target_user_sid),''))=lower(nullif(btrim(login.target_user_sid),''))
              and reset.target_user_sid=login.target_user_sid
              and login.time_created_utc>reset.time_created_utc and login.time_created_utc<=reset.time_created_utc+interval '1 hour'
            where login.id=any($1) and login.event_id=4624
              and login.channel='Security' and login.provider_name='Microsoft-Windows-Security-Auditing'
              and reset.channel='Security' and reset.provider_name='Microsoft-Windows-Security-Auditing'
              and length(login.target_user_sid)<=184 and login.target_user_sid ~ '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$'
            """,ct,ids);
        jobs.AddRange(context.Where(x=>AuditOutcome(x.Text("keywords"))=="success")
            .Select(x=>x.Number("id")).Distinct().Select(id=>new Candidate(id,"related_context")));
        var anchors=await session.QueryAsync("""
            select e.id,e.keywords from public.semantic_event_source355 e
            where e.channel='Security' and e.provider_name='Microsoft-Windows-Security-Auditing'
              and e.id=any($1) and e.event_id=4724 order by e.id
            """,ct,ids);
        jobs.AddRange(anchors.Where(x=>AuditOutcome(x.Text("keywords"))=="success").Select(x=>new Candidate(x.Number("id"),"late_context_expansion","investigation_context")));
        return new(jobs.ToArray(),new JsonObject { ["scanned"]=ids.Length,["queued"]=jobs.Count,["signal_queued"]=jobs.Count(x=>x.Reason=="signal"),["unknown_queued"]=0,["unknown_suppressed"]=0,["context_skipped"]=0,["noise_skipped"]=ids.Length-jobs.Where(x=>x.Kind=="normalize_event").Select(x=>x.Id).Distinct().Count() });
    }
    internal static readonly HashSet<int> ReportIds=[1102,4719,4720,4722,4723,4724,4725,4726,4727,4728,4729,4730,4731,4732,4733,4734,4735,4737,4738,4740,4754,4755,4756,4757,4758,4764,4767,4781,4625,4771,4776];
    internal static string JobIdentity(long id, string kind = "normalize_event", string version = SemanticEvent.Version, string identityVersion = "1.0") =>
        Password.PasswordJson.Hash(new JsonObject { ["event"]=id,["kind"]=kind,["contract"]=1,["processor"]="semantic-shadow",["version"]=version,["identity_resolution_version"]=identityVersion });
    internal static string? SecurityReportProvider(int id) => id == 4624 || ReportIds.Contains(id)
        ? id == 1102 ? "Microsoft-Windows-Eventlog" : "Microsoft-Windows-Security-Auditing" : null;
    internal static JsonArray JobRows(IEnumerable<Candidate> jobs) => new(jobs.Select(job=> {
        string hash=JobIdentity(job.Id, job.Kind);
        return (JsonNode)new JsonObject { ["id"]=job.Id,["job_id"]=AuthAudit.Uuid5("adlog:semantic:"+hash),["kind"]=job.Kind,["hash"]="\\x"+hash,["payload"]=new JsonObject { ["selection_reason"]=job.Reason } };
    }).ToArray());
    internal const int EnqueueBatchSize = 500;
    // A separate read keeps all event lookups outside the outbox write. The
    // lateral boundary makes each lookup use the source ID from this page.
    internal const string EnqueueSourcesSql="""
        select w.job_id,e.id,w.kind,w.hash,w.payload,e.log_source_id as source_id,e.domain_id,
          e.server_id::text||':'||e.channel_id::text as partition_key,e.time_created_utc as occurred_at_utc,
          jsonb_build_object('id',e.id,'server_id',e.server_id,'domain_id',e.domain_id,'log_source_id',e.log_source_id,'event_id',e.event_id,'time_created_utc',e.time_created_utc,'normalized_hash',encode(e.normalized_hash,'hex'),'correlation_id',e.correlation_id,'migrated_at',e.migrated_at,'provider_name',e.provider_name,'channel',e.channel,'computer',e.computer) as source_identity_json
        from jsonb_to_recordset($1) w(id bigint,job_id uuid,kind text,hash text,payload jsonb)
        cross join lateral (select * from public.semantic_event_source355 source where source.id=w.id offset 0) e
        """;
    internal const string EnqueueSql="""
        insert into semantic_processing_outbox(job_id,source_event_id,job_kind,semantic_contract_version,processor_id,processor_version,idempotency_key,payload_json,source_id,domain_id,partition_key,occurred_at_utc,source_identity_json)
        select w.job_id,w.id,w.kind,1,'semantic-shadow',$2,w.hash,w.payload,w.source_id,w.domain_id,w.partition_key,w.occurred_at_utc,w.source_identity_json
        from jsonb_to_recordset($1) w(job_id uuid,id bigint,kind text,hash bytea,payload jsonb,source_id bigint,
          domain_id bigint,partition_key text,occurred_at_utc timestamptz,source_identity_json jsonb)
        order by w.id,w.kind
        on conflict(idempotency_key) do nothing returning job_id
        """;
    internal static async Task<int> Enqueue(ISemanticSession session,IEnumerable<Candidate> jobs,CancellationToken ct)
    {
        var payload=JobRows(jobs); if(payload.Count==0) return 0;
        var sources=await session.QueryAsync(EnqueueSourcesSql,ct,payload);
        if(sources.Count!=payload.Count) throw new InvalidDataException("semantic_producer_source_rows_missing");
        int queued=0;
        foreach(var page in sources.Chunk(EnqueueBatchSize)) {
            var ready=new JsonArray(page.Select(row=>row.Copy()).ToArray());
            queued+=(await SemanticProduction.Change(session,EnqueueSql,ct,ready,SemanticEvent.Version)).Count;
        }
        return queued;
    }
    internal static async Task PublishAsync(NpgsqlConnection db,NpgsqlTransaction tx,IEnumerable<long> eventIds,CancellationToken ct)
    {
        string? mode=RuntimeMode(); if(mode is null) return;
        var session=new SemanticSession(db,tx);
        foreach(var ids in eventIds.Distinct().Order().Chunk(MaxBatch)) {
            Selection selection;
            if(mode==SemanticRuntimeSettings.InvestigationMode) selection=await ReadSelection(session,ids,mode,ct);
            else {
                // Import batches are already bounded. Avoid materializing thousands
                // of generic JSON objects merely to read four scalar columns.
                var sources=new List<Source>(ids.Length);
                await using var command=new NpgsqlCommand("""
                    select e.id,e.event_id::text,e.channel,coalesce(e.provider_name,'') from public.semantic_event_source355 e
                    where e.id=any($1) order by e.id
                    """,db,tx);
                command.Parameters.AddWithValue(ids);
                await using(var reader=await command.ExecuteReaderAsync(ct)) while(await reader.ReadAsync(ct))
                    sources.Add(new(reader.GetInt64(0),reader.GetString(1),reader.GetString(2),reader.GetString(3)));
                if(sources.Count!=ids.Length) throw new InvalidDataException("semantic_producer_source_rows_missing");
                selection=Select(sources,mode==SemanticRuntimeSettings.FactsMode);
            }
            await Enqueue(session,selection.Jobs,ct);
            await RecordDecisions(session,ids,mode,ct);
        }
    }
    internal static async Task RecordDecisions(ISemanticSession session,long[] ids,string mode,CancellationToken ct) =>
        _=await session.QueryAsync("""
            insert into semantic_producer_coverage(runtime_mode,processor_version,decided_ids)
            select $1,$2,range_agg(int8range(id,id,'[]')) from unnest($3::bigint[]) ids(id)
            on conflict(runtime_mode,processor_version) do update
              set decided_ids=semantic_producer_coverage.decided_ids+excluded.decided_ids
            returning runtime_mode
            """,ct,mode,SemanticEvent.Version,ids);
}
