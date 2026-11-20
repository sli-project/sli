using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests;

public sealed partial class SemanticLargeDatabaseTests
{
    [Fact]
    public async Task Schema325_accepts326_with_identical_nps_thresholds_and_packet_id_probes()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture();
        await fixture.StartAsync(ct, throughVersion: 325);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        async Task<string> Scalar(string sql) {
            await using var q = new NpgsqlCommand(sql, db) { CommandTimeout = 0 };
            return (string)(await q.ExecuteScalarAsync(ct))!;
        }
        const string watermark = "public.nps_threshold_watermark(uuid,text,text,text,timestamptz)";
        const string quality = "public.nps_threshold_window_quality(uuid,text,text,text,timestamptz,timestamptz,timestamptz)";
        string Definition(string signature) => $"select pg_get_functiondef('{signature}'::regprocedure)";
        string Catalog(string signature) => $"select (to_jsonb(p)-'prosrc')::text from pg_proc p where oid='{signature}'::regprocedure";
        string oldWatermark = await Scalar(Definition(watermark)), oldQuality = await Scalar(Definition(quality));
        string watermarkCatalog = await Scalar(Catalog(watermark)), qualityCatalog = await Scalar(Catalog(quality));
        await PostCollectionPostgres.Sql(db, """
            insert into sli_agents(id,host_id,key_fingerprint)
            select md5('326-agent:'||a)::uuid,md5('326-host:'||a)::uuid,repeat('a',64) from generate_series(1,40) a;
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            select md5('326-agent:'||a)::uuid,'sli.vpn-nps',n,md5('326-packet:'||a||':'||n)::uuid,repeat('a',64),
                jsonb_build_object('agent_id',md5('326-agent:'||a)::uuid,'source_instance_id','synthetic-nps',
                    'generation','current'),'{"status":"committed"}' from generate_series(1,40) a cross join generate_series(1,400) n;
            insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            select agent_id,'sli.windows.ad-dc',401,md5('326-other-module')::uuid,envelope_sha256,envelope,receipt
                from sli_agent_receipts where packet_id=md5('326-packet:1:400')::uuid;
            insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,received_at,imported_at)
            select packet_id,envelope,jsonb_build_object('contract','sli.collection-packet.v1',
                'header',jsonb_build_object('observed_at_utc','2026-11-07 11:53:20+00'::timestamptz+sequence*interval '1 second'),
                'continuity',jsonb_build_object('status','complete','from_utc','2026-11-07T11:00:00Z','to_utc','2026-11-07T12:00:00Z')),
                '[]','2026-11-07T12:00:00Z','2026-11-07T12:00:00Z' from sli_agent_receipts;
            insert into finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
                source_instance_id,source_generation,collection_scope_id,storage_kind,log_source_id,agent_id)
            select 'sli_semantic_login'::regrole,'sli_semantic_login',installation_id,'sli.vpn-nps',
                'synthetic-nps','current','','core_event',1,md5('326-agent:1')::uuid from semantic_default_installation;
            analyze sli_agent_receipts; analyze sli_agent_packet_inbox; analyze finding_evidence_source_bindings;
            """, ct);
        string installation = await Scalar("select installation_id::text from semantic_default_installation");
        string args = $"'{installation}'::uuid,'sli.vpn-nps','synthetic-nps','current'";
        const string now = "'2026-11-07T12:00:00Z'::timestamptz";
        const string window = "'2026-11-07T11:30:00Z'::timestamptz,'2026-11-07T12:00:00Z'::timestamptz";
        const string target = " where packet_id=md5('326-packet:1:400')::uuid";
        const string agent = " where envelope->>'agent_id'=md5('326-agent:1')::uuid::text";
        // A missing status is legal under the receipt CHECK (NULL); it must
        // still be excluded by both readers' explicit committed predicate.
        var cases = new (string Name, string Mutation, string Clock, string Mark, string Quality)[] {
            ("baseline", "", now, "12:00:00", "good"),
            ("uncommitted", "update sli_agent_receipts set receipt='{}'"+target, now, "11:59:59", "good"),
            ("foreign envelope", "update sli_agent_packet_inbox set envelope=envelope||'{\"foreign\":true}'"+target, now, "11:59:59", "good"),
            ("future packet", "update sli_agent_packet_inbox set packet=jsonb_set(packet,'{header,observed_at_utc}','\"2026-11-07T13:00:00Z\"')"+target, now, "11:59:59", "good"),
            ("continuity fallback", "update sli_agent_packet_inbox set packet=packet-'header'"+target, now, "12:00:00", "good"),
            ("no timestamp", "update sli_agent_packet_inbox set packet=packet-'header'-'continuity'"+target, now, "11:59:59", "good"),
            ("wrong generation", "update sli_agent_receipts set envelope=jsonb_set(envelope,'{generation}','\"old\"')"+target+";update sli_agent_packet_inbox set envelope=jsonb_set(envelope,'{generation}','\"old\"')"+target, now, "11:59:59", "good"),
            ("wrong source", "update sli_agent_receipts set envelope=jsonb_set(envelope,'{source_instance_id}','\"foreign\"')"+target+";update sli_agent_packet_inbox set envelope=jsonb_set(envelope,'{source_instance_id}','\"foreign\"')"+target, now, "11:59:59", "good"),
            ("wrong envelope agent", "update sli_agent_receipts set envelope=jsonb_set(envelope,'{agent_id}',to_jsonb(md5('326-agent:2')::uuid::text))"+target+";update sli_agent_packet_inbox set envelope=jsonb_set(envelope,'{agent_id}',to_jsonb(md5('326-agent:2')::uuid::text))"+target, now, "11:59:59", "good"),
            ("pending", "update sli_agent_packet_inbox set imported_at=null"+target, now, "11:59:59", "partial"),
            ("pending uncommitted", "update sli_agent_receipts set receipt='{}'"+target+";update sli_agent_packet_inbox set imported_at=null"+target, now, "11:59:59", "partial"),
            ("pending before window", "update sli_agent_packet_inbox set imported_at=null,received_at='2026-11-07T11:29:59Z'"+target, now, "11:59:59", "good"),
            ("pending at window start", "update sli_agent_packet_inbox set imported_at=null,received_at='2026-11-07T11:30:00Z'"+target, now, "11:59:59", "partial"),
            ("no imports", "update sli_agent_packet_inbox set imported_at=null"+agent, now, "null", "not_collected"),
            ("stale", "update sli_agent_packet_inbox set received_at='2026-11-07T11:54:59Z'"+agent, now, "12:00:00", "stale"),
            ("exact freshness", "update sli_agent_packet_inbox set received_at='2026-11-07T11:55:00Z'"+agent, now, "12:00:00", "good"),
            ("last 64 only", "update sli_agent_packet_inbox set packet=jsonb_set(packet,'{continuity,status}','\"not_proven\"') where packet_id in (select packet_id from sli_agent_receipts where agent_id=md5('326-agent:1')::uuid and sequence>336)", now, "12:00:00", "partial"),
            ("skip 200 rejected", "update sli_agent_packet_inbox set envelope=envelope||'{\"foreign\":true}' where packet_id in (select packet_id from sli_agent_receipts where agent_id=md5('326-agent:1')::uuid and sequence>200)", now, "11:56:40", "good"),
            ("empty binding", "delete from finding_evidence_source_bindings", now, "null", "42501"),
            ("principal name mismatch", "update finding_evidence_source_bindings set principal_name='foreign'", now, "null", "42501"),
            ("principal OID mismatch", "update finding_evidence_source_bindings set principal_oid='adlog_user'::regrole", now, "null", "42501"),
            ("null clock", "", "null::timestamptz", "null", "42501"),
            ("window after clock", "", "'2026-11-07T11:59:59Z'::timestamptz", "11:59:59", "42501"),
            // Preserve the original pending veto even for a receipt whose
            // envelope names this source but whose relational agent is foreign.
            ("foreign receipt pending", "update sli_agent_receipts set envelope=jsonb_set(envelope,'{agent_id}',to_jsonb(md5('326-agent:1')::uuid::text)) where packet_id=md5('326-packet:2:1')::uuid;update sli_agent_packet_inbox set imported_at=null,envelope=jsonb_set(envelope,'{agent_id}',to_jsonb(md5('326-agent:1')::uuid::text)) where packet_id=md5('326-packet:2:1')::uuid", now, "12:00:00", "partial"),
        };
        async Task<string[]> Snapshot() {
            var values = new List<string>();
            foreach (var c in cases) {
                await using var tx = await db.BeginTransactionAsync(ct);
                string mark, state;
                try {
                    if (c.Mutation.Length != 0) await PostCollectionPostgres.Sql(db, c.Mutation, ct);
                    await PostCollectionPostgres.Sql(db, "set session authorization sli_semantic_login;set role adlog_semantic_worker", ct);
                    mark = await Scalar($"select coalesce(to_char(public.nps_threshold_watermark({args},{c.Clock}) at time zone 'UTC','HH24:MI:SS'),'null')");
                    try { state = await Scalar($"select public.nps_threshold_window_quality({args},{window},{c.Clock})"); }
                    catch (PostgresException error) { state = error.SqlState; }
                } finally {
                    await tx.RollbackAsync(ct);
                    await PostCollectionPostgres.Sql(db, "reset role;reset session authorization", ct);
                }
                Assert.True(mark == c.Mark && state == c.Quality, $"{c.Name}: watermark={mark}, quality={state}");
                values.Add(mark+":"+state);
            }
            return values.ToArray();
        }
        string[] before = await Snapshot();
        string directory = Path.Combine(SqlPostgresFixture.Repository(), "config/postgres_migrations");
        string forward = Path.Combine(directory, "326_nps_threshold_paths.sql");
        await fixture.Pg.ApplyFileAsync(forward, null, ct);
        Assert.Equal(watermarkCatalog, await Scalar(Catalog(watermark)));
        Assert.Equal(qualityCatalog, await Scalar(Catalog(quality)));
        Assert.Equal(before, await Snapshot());
        Assert.Equal("false", await Scalar("select (has_table_privilege('adlog_semantic_worker','sli_agent_packet_inbox','SELECT') or has_table_privilege('adlog_semantic_worker','nps_threshold_definitions326','SELECT') or has_function_privilege('adlog_user','public.nps_threshold_watermark(uuid,text,text,text,timestamptz)','EXECUTE'))::text"));

        string newWatermark = await Scalar(Definition(watermark)), newQuality = await Scalar(Definition(quality));
        string Bind(string sql) => sql.Replace("p_installation", $"'{installation}'::uuid", StringComparison.Ordinal)
            .Replace("p_plugin", "'sli.vpn-nps'", StringComparison.Ordinal).Replace("p_source", "'synthetic-nps'", StringComparison.Ordinal)
            .Replace("p_generation", "'current'", StringComparison.Ordinal).Replace("p_now", now, StringComparison.Ordinal)
            .Replace("p_from", "'2026-11-07T11:30:00Z'::timestamptz", StringComparison.Ordinal)
            .Replace("session_user", "'sli_semantic_login'", StringComparison.Ordinal);
        string markSql = newWatermark.Split("$function$")[1];
        foreach (var (name, sql, maximum) in new[] { ("watermark", markSql, 1) }) {
            var plan = JsonNode.Parse(await Scalar("explain(analyze,buffers,format json) "+Bind(sql)))!;
            var nodes = PlanNodes(plan[0]!["Plan"]!).ToArray();
            var probes = nodes.Where(n => n["Relation Name"]?.ToString() == "sli_agent_packet_inbox").ToArray();
            Assert.NotEmpty(probes);
            Assert.All(probes, n => {
                Assert.Contains("Index", n["Node Type"]!.ToString());
                Assert.Contains("packet_id", n["Index Cond"]!.ToString());
                Assert.InRange(n["Actual Loops"]!.GetValue<double>(), 1, maximum);
            });
            Assert.Contains(nodes, n => n["Index Name"]?.ToString() == "sli_agent_receipts_pkey" && n["Scan Direction"]?.ToString() == "Backward");
            output.WriteLine($"326 {name}: 16001 packets, inbox probes <= {maximum}; "+plan.ToJsonString());
        }
        // Measure the real SECURITY DEFINER call, including its sparse pending
        // veto and cached PL/pgSQL statements, rather than just a copied query.
        await using (var tx = await db.BeginTransactionAsync(ct)) {
            const string reads = "select jsonb_build_object('seq',seq_tup_read,'index',idx_tup_fetch)::text from pg_stat_xact_user_tables where relid='sli_agent_packet_inbox'::regclass";
            var prior = JsonNode.Parse(await Scalar(reads))!;
            await PostCollectionPostgres.Sql(db, "set session authorization sli_semantic_login;set role adlog_semantic_worker", ct);
            Assert.Equal("good", await Scalar($"select public.nps_threshold_window_quality({args},{window},{now})"));
            await PostCollectionPostgres.Sql(db, "reset role;reset session authorization", ct);
            var current = JsonNode.Parse(await Scalar(reads))!;
            long sequential = current["seq"]!.GetValue<long>()-prior["seq"]!.GetValue<long>();
            long indexed = current["index"]!.GetValue<long>()-prior["index"]!.GetValue<long>();
            Assert.Equal(0, sequential); Assert.Equal(64, indexed);
            output.WriteLine($"326 real quality: 16001 packets; inbox sequential tuples={sequential}, indexed fetches={indexed}");
            await tx.RollbackAsync(ct);
        }
        string receiptSql = newQuality.Split("$receipts$")[1]
            .Replace("$1", "md5('326-agent:1')::uuid", StringComparison.Ordinal)
            .Replace("$2", "'sli.vpn-nps'", StringComparison.Ordinal).Replace("$3", "null::bigint", StringComparison.Ordinal);
        var receiptPlan = JsonNode.Parse(await Scalar("explain(analyze,buffers,format json) "+receiptSql))!;
        // With only 400 receipts per agent PostgreSQL can prefer a scoped
        // bitmap scan + sort over a backward scan. Both use the same PK and
        // bound the page before any inbox read; a table scan is a regression.
        var receiptNodes = PlanNodes(receiptPlan[0]!["Plan"]!).ToArray();
        Assert.Contains(receiptNodes, n => n["Index Name"]?.ToString() == "sli_agent_receipts_pkey"
            && n["Index Cond"]!.ToString().Contains("agent_id", StringComparison.Ordinal)
            && n["Index Cond"]!.ToString().Contains("module_id", StringComparison.Ordinal));
        Assert.DoesNotContain(receiptNodes, n => n["Relation Name"]?.ToString() == "sli_agent_receipts" && n["Node Type"]?.ToString() == "Seq Scan");
        Assert.Equal(256, receiptPlan[0]!["Plan"]!["Actual Rows"]!.GetValue<double>());
        output.WriteLine("326 receipt page: "+receiptPlan.ToJsonString());
        // The sparse pending check must also use its time-range index.
        int first = newQuality.IndexOf("if exists(select 1 from public.finding_evidence_source_bindings", StringComparison.Ordinal)+"if exists(".Length;
        int last = newQuality.IndexOf(") then", first, StringComparison.Ordinal);
        var pendingPlan = JsonNode.Parse(await Scalar("explain(analyze,buffers,format json) "+Bind(newQuality[first..last])))!;
        var pendingScans = PlanNodes(pendingPlan[0]!["Plan"]!).Where(n => n["Relation Name"]?.ToString() == "sli_agent_packet_inbox").ToArray();
        Assert.NotEmpty(pendingScans);
        Assert.All(pendingScans, n => Assert.Equal("sli_agent_packet_inbox_pending", n["Index Name"]?.ToString()));
        output.WriteLine("326 pending: "+pendingPlan.ToJsonString());
        await fixture.Pg.ApplyFileAsync(Path.Combine(directory, "326_nps_threshold_paths.rollback.sql"), null, ct);
        Assert.Equal(oldWatermark, await Scalar(Definition(watermark)));
        Assert.Equal(oldQuality, await Scalar(Definition(quality)));
        Assert.Equal(watermarkCatalog, await Scalar(Catalog(watermark)));
        Assert.Equal(qualityCatalog, await Scalar(Catalog(quality)));
        await fixture.Pg.ApplyFileAsync(forward, null, ct);
        output.WriteLine($"326: {cases.Length} old/new boundary cases; exact rollback and reapply passed");
    }
}
