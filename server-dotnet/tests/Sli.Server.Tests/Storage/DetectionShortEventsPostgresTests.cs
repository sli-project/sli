using Npgsql;
using System.Text.Json.Nodes;
using Sli.Server.Storage.Direct;
using Sli.Server.Semantic;
using Sli.Server.Semantic.Detections;
using Sli.Server.Semantic.Password;
using Sli.Server.Problems;
using Sli.Agent.Core;
using Sli.Server.Domains;
using NpgsqlTypes;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

[Collection("Semantic producer environment")]
public sealed class DetectionShortEventsPostgresTests
{
    [Fact]
    public async Task PowerShell_writer_event_reaches_t109_SQL_and_preserves_the_detection()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner = new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        var rows = await ShortEventAdmissionPostgresTests.SeedAsync(owner,ct,powershell:true);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,rows,ct);
        await using var worker = new NpgsqlConnection(fixture.Dsn("sli_semantic_login")); await worker.OpenAsync(ct);
        await PostCollectionPostgres.Sql(worker,"set role adlog_semantic_worker",ct);
        JsonObject source;
        await using (var read = new NpgsqlCommand("select source::text from public.t109_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'",worker))
            source = JsonNode.Parse((string)(await read.ExecuteScalarAsync(ct))!)!.AsObject();
        var scope = PasswordScope.Read(source["scope"]);
        async Task<IReadOnlyList<DetectionRow>> Read() {
            await using var tx = await worker.BeginTransactionAsync(ct);
            var rows = await new DetectionSql(worker,tx).Rows("select * from public.read_t109_native(@scope::jsonb)",ct,("scope",scope.Document));
            await tx.CommitAsync(ct); return DetectionNative.ParseEvents(scope,rows);
        }
        var shortRows = await Read();
        Assert.Equal(4104,Assert.Single(shortRows).EventId);
        var now = DateTimeOffset.UtcNow;
        var signal = Assert.Single(AttackPrecursors.DetectEvents(shortRows,now));
        Assert.DoesNotContain("<",signal.ToJsonString());
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Writer_events_preserve_detection_decisions_and_problem_details_survive_hot_retention()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var owner = new NpgsqlConnection(fixture.Pg.ConnectionString); await owner.OpenAsync(ct);
        var seededRows = await ShortEventAdmissionPostgresTests.SeedAsync(owner, ct);
        await ShortEventAdmissionPostgresTests.WriteAsync(fixture,seededRows,ct);
        await using var worker = new NpgsqlConnection(fixture.Dsn("sli_semantic_login")); await worker.OpenAsync(ct);
        await PostCollectionPostgres.Sql(worker, "set role adlog_semantic_worker", ct);
        JsonObject source;
        await using (var read = new NpgsqlCommand("select source::text from public.default_detection_sources() where source#>>'{scope,plugin_id}'='sli.windows.ad-dc'", worker))
            source = JsonNode.Parse((string)(await read.ExecuteScalarAsync(ct))!)!.AsObject();
        var scope = PasswordScope.Read(source["scope"]);
        async Task<List<JsonObject>> Read(string query) {
            await using var tx = await worker.BeginTransactionAsync(ct); var sql = new DetectionSql(worker, tx);
            var rows = await sql.Rows(query, ct, ("scope", scope.Document)); await tx.CommitAsync(ct); return rows;
        }
        const string identity = "select * from public.read_identity_attack_events_v301(@scope::jsonb,null)";
        const string precursor = "select * from public.read_t109_native(@scope::jsonb)";
        const string password = "select * from public.read_default_password_events(@scope::jsonb)";
        var shortIdentity = DetectionNative.ParseEvents(scope, await Read(identity), true);
        var shortPrecursors = DetectionNative.ParseEvents(scope, await Read(precursor));
        var shortPassword = await Read(password);
        // The beta reads native short events. Disabling the retired-core producer
        // must preserve exactly the same inputs to all three detection readers.
        var beforeBackfill=new[] { await Read(identity),await Read(precursor),await Read(password) };
        using(var environment=new Sli.Server.Tests.Semantic.SemanticProducerPostgresTests.Admission()) {
            environment.Set("Sli__Storage__ShortEventReads","true");
            var skipped=await SemanticProducerBackfill.RunAsync(worker,SemanticRuntimeSettings.FindingsMode,1024,ct);
            Assert.Equal("short_events",skipped["status"]!.GetValue<string>());
        }
        var afterBackfill=new[] { await Read(identity),await Read(precursor),await Read(password) };
        for(int i=0;i<beforeBackfill.Length;i++)
            Assert.True(JsonNode.DeepEquals(new JsonArray(beforeBackfill[i].Select(r=>(JsonNode)r).ToArray()),
                new JsonArray(afterBackfill[i].Select(r=>(JsonNode)r).ToArray())));
        var now = DateTimeOffset.UtcNow;
        Assert.NotEmpty(AttackPrecursors.DetectEvents(shortPrecursors,now));
        Assert.NotEmpty(shortPrecursors); Assert.NotEmpty(shortPassword);
        PasswordNative Parse(JsonObject r) => PasswordNative.Parse(scope, r["source_event_id"]!.GetValue<long>(), D.Text(r["sha256"]), r["event_id"]!.GetValue<int>(), D.Time(r["occurred_at_utc"]), D.Text(r["source_xml"]));
        // Exercise the complete bounded password reader and current-content proof,
        // including SQL's authoritative byte/hash check and both account readers.
        var window = await Read("select * from public.read_default_password_window_v2(@scope::jsonb)");
        Assert.NotEmpty(window.Skip(1));
        var witness = Parse(window[1]).Witness;
        await using (var tx = await worker.BeginTransactionAsync(ct)) {
            var sql = new DetectionSql(worker, tx);
            var proof = await sql.Rows("select * from public.read_password_retained_proof_v2(@scope::jsonb,@refs::jsonb)", ct,
                ("scope", scope.Document), ("refs", new JsonArray(witness.Document)));
            Assert.Equal(witness, Parse(Assert.Single(proof)).Witness);
            foreach (string family in new[] { "decoy", "watch" })
                await new SemanticSession(worker,tx).QueryAsync($"select * from public.read_account_{family}_events($1,$2,$3,$4,$5,null::uuid)", ct,
                    Guid.Parse(scope.InstallationId), scope.PluginId, scope.SourceInstanceId, scope.SourceGeneration, new string('a',64));
            await tx.CommitAsync(ct);
        }
        long finding;
        await using (var insert = new NpgsqlCommand("insert into findings(fingerprint,rule_code,title,severity,status,evidence_count) values('synthetic-short','semantic.qw.log-cleared','synthetic','high','new',1) returning id", owner))
            finding = (long)(await insert.ExecuteScalarAsync(ct))!;
        var reference = shortPrecursors[0].Ref;
        await using (var tx = await worker.BeginTransactionAsync(ct)) {
            var sql = new DetectionSql(worker, tx);
            async Task<bool> Resolves(string generation, string nativeId, string hash) {
                var rows = await sql.Rows("select public.resolve_finding_evidence_ref(@i,@p,@s,@g,'','core_event',@n,@h) as allowed", ct,
                    ("i", Guid.Parse(scope.InstallationId)), ("p", scope.PluginId), ("s", scope.SourceInstanceId), ("g", generation), ("n", nativeId), ("h", hash));
                return Assert.Single(rows)["allowed"]!.GetValue<bool>();
            }
            Assert.True(await Resolves(scope.SourceGeneration, reference.NativeId, reference.Sha256));
            Assert.False(await Resolves("synthetic-other-generation", reference.NativeId, reference.Sha256));
            Assert.False(await Resolves(scope.SourceGeneration, "0" + reference.NativeId, reference.Sha256));
            Assert.False(await Resolves(scope.SourceGeneration, "9223372036854775808", reference.Sha256));
            Assert.False(await Resolves(scope.SourceGeneration, reference.NativeId, new string('g', 64)));
            await sql.Rows("select public.link_finding_evidence_ref(@f,@i,@p,@s,@g,'','core_event',@n,@h) as added", ct,
                ("f",finding),("i",Guid.Parse(scope.InstallationId)),("p",scope.PluginId),("s",scope.SourceInstanceId),("g",scope.SourceGeneration),("n",reference.NativeId),("h",reference.Sha256));
            await tx.CommitAsync(ct);
        }
        async Task<JsonObject> Details() {
            await using var tx = await owner.BeginTransactionAsync(ct);
            var rows = new JsonArray(new JsonObject { ["id"] = finding, ["evidence_count"] = 1 });
            await ProblemRepository.AttachDetails(tx, rows, ct); await tx.CommitAsync(ct); return rows[0]!.AsObject();
        }
        var before = await Details(); Assert.Single(before["evidence"]!.AsArray());
        await PostCollectionPostgres.Sql(owner, "update sli_agent_packet_inbox set event_rows='[]'", ct);
        Assert.Equal(shortPrecursors.Count, (await Read(precursor)).Count);
        // Removing a day's hot partition cannot cascade into the problem.
        string day = witness.At.UtcDateTime.ToString("yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture);
        await PostCollectionPostgres.Sql(owner, $"alter table event_hot detach partition event_hot_d{day}; drop table event_hot_d{day}", ct);
        Assert.True(JsonNode.DeepEquals(before, await Details()));
        await using (var domain = new NpgsqlCommand("select semantic_finding_in_domains_v265(@id,array[1]::bigint[]),semantic_finding_in_domains_v265(@id,array[2]::bigint[])",owner)) {
            domain.Parameters.AddWithValue("id",finding); await using var read = await domain.ExecuteReaderAsync(ct); Assert.True(await read.ReadAsync(ct));
            Assert.True(read.GetBoolean(0)); Assert.False(read.GetBoolean(1));
        }
        await using (var identityRead = new NpgsqlCommand(HomeDecisionSummary.IdentitySql,owner)) {
            identityRead.Parameters.AddWithValue("requests",NpgsqlDbType.Jsonb,new JsonArray(new JsonObject {
                ["request_index"]=0,["finding"]=finding,["sid"]="s-1-5-21-100000001-200000002-300000003-1001",["hostname"]=null }).ToJsonString());
            await using var read = await identityRead.ExecuteReaderAsync(ct); Assert.True(await read.ReadAsync(ct));
            Assert.True(read.GetBoolean(read.GetOrdinal("witness_verified")));
        }
        await using (var queue = new NpgsqlCommand(ProblemCohorts.Queue("from findings_active findings"," where false","findings.status","false")+" select * from queue_groups",owner)) {
            queue.Parameters.AddWithValue("cohort_zone","UTC"); await using var read = await queue.ExecuteReaderAsync(ct); Assert.False(await read.ReadAsync(ct));
        }
        // The application role (not the superuser fixture owner) must read the
        // problem's own copies after the hot partition is gone, and the semantic
        // role must have no direct read of either event table.
        await using (var app = await fixture.Pg.OpenAsync(ct, "adlog_user")) {
            await using var tx = await app.BeginTransactionAsync(ct);
            var rows = new JsonArray(new JsonObject { ["id"] = finding, ["evidence_count"] = 1 });
            await ProblemRepository.AttachDetails(tx, rows, ct); await tx.CommitAsync(ct);
            Assert.True(JsonNode.DeepEquals(before, rows[0]));
            await using var identityRead = new NpgsqlCommand(HomeDecisionSummary.IdentitySql, app);
            identityRead.Parameters.AddWithValue("requests", NpgsqlDbType.Jsonb, new JsonArray(new JsonObject {
                ["request_index"]=0,["finding"]=finding,["sid"]="s-1-5-21-100000001-200000002-300000003-1001",["hostname"]=null }).ToJsonString());
            await using var read = await identityRead.ExecuteReaderAsync(ct); Assert.True(await read.ReadAsync(ct));
        }
        foreach (string table in new[] { "event_hot", "event_cold_daily" }) {
            await using var privilege = new NpgsqlCommand($"select has_table_privilege(current_user,'public.{table}','select')", worker);
            Assert.Equal(false, await privilege.ExecuteScalarAsync(ct));
        }
        await fixture.AssertNoSqlErrorsAsync(ct);
    }

    [Fact]
    public async Task Database_at_336_accepts_337_and_rolls_back_without_changing_old_events()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = new SqlPostgresFixture(); await fixture.StartAsync(ct, throughVersion: 336);
        await using var db = new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        string migration = Path.Combine(PostCollectionPostgres.Repository(), "config/postgres_migrations/337_detection_short_events.sql");
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await using (var mode = new NpgsqlCommand("select public.detections_use_short337()", db)) Assert.Equal(true, await mode.ExecuteScalarAsync(ct));
        await using (var worker = new NpgsqlConnection(fixture.Dsn("sli_semantic_login"))) {
            await worker.OpenAsync(ct);
            await PostCollectionPostgres.Sql(worker, "set role adlog_semantic_worker", ct);
            await using var sources = new NpgsqlCommand("select source from public.default_detection_sources(); select source from public.t109_detection_sources()", worker);
            await using var rows = await sources.ExecuteReaderAsync(ct); Assert.False(await rows.ReadAsync(ct));
            Assert.True(await rows.NextResultAsync(ct)); Assert.False(await rows.ReadAsync(ct));
        }
        await fixture.Pg.ApplyFileAsync(Path.ChangeExtension(migration, ".rollback.sql"), null, ct);
        await fixture.Pg.ApplyFileAsync(migration, null, ct);
        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
