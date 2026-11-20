using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Server.Infrastructure;
using CoreJobHandler=Sli.Server.Jobs.CoreJobHandler;
using CoreJobPluginCatalog=Sli.Server.Jobs.CoreJobPluginCatalog;
using Sli.Server.Tests.Agents;
using Sli.Server.Workstations;
using Xunit;

namespace Sli.Server.Tests.Workstations;

// S6 retires workstation ClickHouse I/O. These tests retain the live PostgreSQL
// hold, deletion and audit guarantees when publication cannot preserve a row.
public sealed class WorkstationHistoryParityTests
{
    static readonly DateTimeOffset Now=DateTimeOffset.Parse("2026-10-09T00:00:00Z");
    const string Agent="11111111-1111-4111-8111-111111111111";
    const string Other="22222222-2222-4222-8222-222222222222";
    static CancellationToken Ct=>TestContext.Current.CancellationToken;
    static string Id(int n)=>n.ToString("x64",CultureInfo.InvariantCulture);
    static JsonObject Observation(int n=1,int age=91,string family="processes",string agent=Agent)
    {
        const string xml="<Event><fixture/></Event>";
        var body=new JsonObject{["family"]=family,["semantic_type"]="fixture.observed",["facts"]=new JsonObject{["process_image"]="fixture.exe",["storage_evidence"]=family=="usb"},["quality"]=new JsonObject(),["source_sha256"]=Ws.Sha(xml)};
        return new(){["id"]=Id(n),["agent_key"]=agent,["entity_id"]=17,["ad_computer_id"]=null,["family"]=family,["event_id"]=4688,["observed_at"]=Ws.Stamp(Now.AddDays(-age)),["observation"]=body,["observation_sha256"]=Ws.Hash(body),["source_xml"]=xml};
    }
    sealed class UnexpectedHistoryTransport : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            throw new InvalidOperationException("Retired workstation history must never contact transport");
    }

    sealed class Stores:IPostgresConnectionFactory,IAsyncDisposable
    {
        internal readonly PostCollectionPostgres Pg=new(canonicalSchema:true);
        internal CoreJobHandler Handler=null!;
        internal string AuditRoot=>Path.Combine(Pg.Root,"receipts");
        internal JsonObject Job=new(){["plugin_id"]="sli.workstations",["handler_id"]="workstations.evidence-retention",["source_instance_id"]="workstations:history",["available_at_utc"]=Ws.Stamp(Now),["job_id"]=Guid.NewGuid().ToString(),["lease_token"]=Guid.NewGuid().ToString(),["lease_generation"]=1,["budget"]=new JsonObject{["max_records"]=50}};
        public Task<NpgsqlConnection> OpenAsync(CancellationToken ct)=>Pg.OpenAsync(ct);
        internal static async Task<Stores> CreateAsync(CancellationToken ct)
        {
            var f=new Stores();
            try
            {
                await f.Pg.StartAsync(ct);await using var db=await f.OpenAsync(ct);
                await PostCollectionPostgres.Sql(db,"create schema sli_plugin_workstations; create table platform_settings(key text primary key,value text)",Ct);
                // Reuse the canonical evidence/hold constraints, without unrelated migrations.
                foreach(var (file,table) in new[]{("159_workstation_security.sql","observations"),("176_workstation_history.sql","observation_holds")})
                {
                    string source=File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations",file));
                    string ddl=Regex.Match(source,@"create table sli_plugin_workstations\."+table+@" \([\s\S]*?\r?\n\);").Value;
                    Assert.NotEmpty(ddl);await PostCollectionPostgres.Sql(db,ddl,Ct);
                }
                await PostCollectionPostgres.Sql(db,"""
                    create sequence delete_attempts;
                    create function count_delete_attempt() returns trigger language plpgsql as $$
                    begin perform nextval('delete_attempts'); return old; end $$;
                    create trigger count_delete_attempt before delete on sli_plugin_workstations.observations
                        for each row execute function count_delete_attempt();
                    """,ct);
                var catalog = new CoreJobPluginCatalog();
                new WorkstationJobPlugin(
                    () => new WorkstationHistory(new HttpClient(new UnexpectedHistoryTransport()), new Uri("http://127.0.0.1:1/"), true),
                    () => new(f.AuditRoot)).Register(catalog);
                f.Handler = catalog.Resolve(f.Job);
                return f;
            }
            catch{await f.DisposeAsync();throw;}
        }
        internal async Task Seed(params JsonObject[] rows)
        {await using var db=await OpenAsync(Ct);foreach(var row in rows)await Ws.Insert(db,"observations",row," ",Ct);}
        internal async Task Days(int? days)
        {await using var db=await OpenAsync(Ct);await Ws.Exec(db,"delete from platform_settings",Ct);if(days is not null)await Ws.Exec(db,"insert into platform_settings values('workstations.evidence_retention_days',@p0)",Ct,days.Value.ToString(CultureInfo.InvariantCulture));}
        internal async Task Retain()
        {
            await using var db = await OpenAsync(Ct);
            await using var tx = await db.BeginTransactionAsync(Ct);
            var result = await Handler.Stage(db, Job, Ct);
            await Handler.Publish(db, Job, result, Ct);
            await tx.CommitAsync(Ct);
        }
        internal async Task<long> Count()
        {await using var db=await OpenAsync(Ct);return (long)(await Ws.Scalar(db,"select count(*) from sli_plugin_workstations.observations",Ct))!;}
        internal async Task<long> DeleteAttempts()
        {await using var db=await OpenAsync(Ct);return (long)(await Ws.Scalar(db,"select case when is_called then last_value else 0 end from delete_attempts",Ct))!;}
        internal JsonObject Receipt()=>JsonNode.Parse(File.ReadAllText(Directory.GetFiles(Path.Combine(AuditRoot,"runtime/purge-runs"),"*.json").OrderDescending(StringComparer.Ordinal).First()))!.AsObject();
        public ValueTask DisposeAsync() => Pg.DisposeAsync();
    }

    [Theory]
    [InlineData("processes")]
    [InlineData("usb")]
    public async Task Disabled_history_preserves_postgres_rows_and_records_a_safe_receipt(string family)
    {
        await using var store = await Stores.CreateAsync(Ct);
        await store.Days(90);
        await store.Seed(Observation(family: family));
        var error = await Assert.ThrowsAsync<WorkstationException>(store.Retain);
        Assert.Equal("module_disabled", error.Message);
        Assert.Equal(1, await store.Count());
        Assert.Equal(0, await store.DeleteAttempts());

        var receipt = store.Receipt();
        Assert.Equal("blocked", receipt.Text("status"));
        Assert.Equal(0, receipt["tables"]!["sli_plugin_workstations.observations"].Number("deleted_count"));
        Assert.DoesNotContain("fixture.exe", receipt.ToJsonString());
        Assert.DoesNotContain("<Event>", receipt.ToJsonString());
    }

    [Fact]public async Task Holds_and_other_families_remain_in_pg()
    {
        await using var f=await Stores.CreateAsync(Ct);await f.Seed(Observation(),Observation(2,family:"usb"),Observation(3,family:"logons"),Observation(4,family:"protection"));
        await using(var db=await f.OpenAsync(Ct))foreach(int n in new[]{1,2})await Ws.Exec(db,"insert into sli_plugin_workstations.observation_holds(observation_id,reason) values(@p0,'legal_hold')",Ct,Id(n));
        await f.Retain();Assert.Equal(4,await f.Count());Assert.Equal(0,await f.DeleteAttempts());
    }
    [Fact]public async Task Registered_publisher_without_explicit_adapter_rejects_before_pg_access()
    {
        var catalog=new CoreJobPluginCatalog();new WorkstationJobPlugin(()=>null,()=>throw new InvalidOperationException("must not open audit")).Register(catalog);
        var job=new JsonObject{["plugin_id"]="sli.workstations",["handler_id"]="workstations.evidence-retention",["source_instance_id"]="workstations:history",["available_at_utc"]=Ws.Stamp(Now),["budget"]=new JsonObject{["max_records"]=50}};
        var result=new JsonObject{["candidates"]=new JsonObject{[Id(1)]=new string('a',64)}};
        await using var closed=new NpgsqlConnection();
        Assert.Equal("workstation_history_unavailable",(await Assert.ThrowsAsync<IOException>(()=>catalog.Resolve(job).Publish(closed,job,result,Ct))).Message);
    }
    [Theory]
    [InlineData("entity_id")]
    [InlineData("payload_json")]
    public void Retained_history_record_checks_entity_and_payload_identity(string field)
    {
        var record = WorkstationHistory.Record(Observation());
        if (field == "entity_id")
            record[field] = 99;
        else
            record[field] = record.Text(field)!.Replace("fixture.exe", "changed.exe", StringComparison.Ordinal);

        Assert.Equal("workstation_history_receipt_mismatch",
            Assert.Throws<WorkstationException>(() => WorkstationHistory.Decode(record)).Message);
    }

    [Fact]public void Shared_history_schema_is_explicit_durable_and_contains_no_pg_deletion_or_ttl()
    {
        string ddl=File.ReadAllText(Path.Combine(PostCollectionPostgres.Repository(),"config/clickhouse/005_workstation_history.sql"));
        var statements=ddl.Split(';',StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries);
        Assert.Equal(2,statements.Length);Assert.All(statements,s=>Assert.StartsWith("CREATE",s));
        Assert.Contains("ReplacingMergeTree",statements[1]);Assert.Contains("ORDER BY id",statements[1]);
        Assert.Contains("fsync_after_insert = 1",statements[1]);Assert.Contains("fsync_part_directory = 1",statements[1]);
        Assert.DoesNotContain("TTL",ddl,StringComparison.OrdinalIgnoreCase);Assert.DoesNotContain("DELETE",ddl,StringComparison.OrdinalIgnoreCase);
    }
}
