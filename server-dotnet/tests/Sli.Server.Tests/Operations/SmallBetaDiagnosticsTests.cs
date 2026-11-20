using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Infrastructure;
using Sli.Server.Operations;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Operations;

public sealed class SmallBetaDiagnosticsTests
{
    sealed class Connections(PostCollectionPostgres pg):IPostgresConnectionFactory
    { public Task<NpgsqlConnection> OpenAsync(CancellationToken ct)=>pg.OpenAsync(ct); }
    sealed class Queries(OperationsQueries postgres):IOperationsQueries
    {
        public Task<JsonArray> ReadAsync(string sql,CancellationToken ct,params (string Name,object? Value)[] parameters) =>
            sql.Contains("pg_class c join pg_namespace",StringComparison.Ordinal)||sql.Contains("raw_batch_lifecycle",StringComparison.Ordinal)
                ? postgres.ReadAsync(sql,ct,parameters) : Task.FromResult(new JsonArray());
    }
    sealed class Files(IConfiguration configuration):OperationsFiles(configuration)
    {
        public override JsonObject RuntimeStorage(bool force,DateTimeOffset now)=>new() {
            ["snapshot"]=new JsonObject{["status"]="ready"},["sizes"]=new JsonObject(),["warnings"]=new JsonArray()
        };
    }
    [Fact]
    public async Task System_counts_hot_partitions_and_protects_uncommitted_raw_batches()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var pg=new PostCollectionPostgres(canonicalSchema:true);await pg.StartAsync(ct);
        await using var db=await pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db,"""
            create table event_hot(event_id bigint) partition by range(event_id);
            create table event_hot_a partition of event_hot for values from(0) to(10);
            create table event_hot_b partition of event_hot for values from(10) to(20);
            insert into event_hot values(1),(2),(11);
            create table servers(id bigint);insert into servers values(1);
            create table findings(id bigint);insert into findings values(1),(2);
            analyze event_hot;analyze servers;analyze findings;
            create table raw_batch_lifecycle(batch_identity text,raw_path text,import_outcome text,cursor_outcome text,
                expected_channels int,committed_channels int,cleanup_outcome text,updated_at timestamptz);
            """,ct);
        string root=Path.Combine(Path.GetTempPath(),"sli-small-beta-"+Guid.NewGuid().ToString("N"));
        try {
            string raw=Path.Combine(root,"data","raw");Directory.CreateDirectory(raw);
            foreach(string name in new[]{"complete","pending","waiting","unconfirmed"}) {
                string path=Path.Combine(raw,name+".jsonl");await File.WriteAllTextAsync(path,"synthetic",ct);File.SetLastWriteTimeUtc(path,DateTime.UtcNow.AddDays(-100));
                if(name=="unconfirmed")continue;
                await using var insert=new NpgsqlCommand("insert into raw_batch_lifecycle values(@name,@path,'succeeded',@cursor,2,@committed,'retained',now())",db);
                insert.Parameters.AddWithValue("name",name);insert.Parameters.AddWithValue("path",path);
                insert.Parameters.AddWithValue("cursor",name=="waiting"?"not_committed":"committed");
                insert.Parameters.AddWithValue("committed",name=="pending"?1:2);await insert.ExecuteNonQueryAsync(ct);
            }
            var configuration=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
                ["Sli:ProjectRoot"]=root,["Sli:DataDirectory"]=Path.Combine(root,"data")
            }).Build();
            var service=new OperationsService(new Queries(new OperationsQueries(new Connections(pg))),new Files(configuration),new OperationsCatalog(),new OperationsJobs(),TimeProvider.System);
            var health=await service.ReadAsync("/api/system/health",new(),ct);
            Assert.Equal(3,health["db"]!["events"]!.GetValue<long>());
            Assert.Equal(1,health["db"]!["servers"]!.GetValue<long>());
            Assert.Equal(2,health["db"]!["findings"]!.GetValue<long>());
            var cleanup=await service.CleanupPreviewAsync(ct);
            var action=Assert.Single(cleanup["actions"]!.AsArray())!;
            Assert.Equal(Path.Combine(raw,"complete.jsonl"),action["path"]!.ToString());
            Assert.All(Directory.GetFiles(raw),path=>Assert.True(File.Exists(path)));
        }
        finally { if(Directory.Exists(root))Directory.Delete(root,true); }
    }
}
