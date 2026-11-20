using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Npgsql;
using Sli.Server.Storage.Archive;
using Sli.Server.Storage.History;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed partial class EventArchiveHydrationTests
{
    static JsonObject BatchRow(long id) => new()
    {
        ["id"]=id,["server_id"]=3,["domain_id"]=2,["log_source_id"]=4,
        ["event_id"]=4625,["time_created_utc"]="2026-01-02T03:04:05Z"
    };

    static ArchiveBlock BatchBlock(string root,params JsonObject[] rows)
    {
        var raw=ArchiveCodec.Encode("event",rows); byte[] compressed=ArchiveCodec.Compress(raw.Raw);
        string path=Path.Combine(root,"published",Guid.NewGuid().ToString("N")+".jsonl.gz");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.WriteAllBytes(path,compressed);
        return new(Guid.NewGuid(),"event",1,0,raw.First,raw.Last,rows.Length,raw.Raw.Length,compressed.Length,
            ArchiveCodec.Hash(raw.Raw),ArchiveCodec.Hash(compressed),path,"published",DateTime.UtcNow,DateTime.UtcNow);
    }

    static async Task SeedBatchBlock(NpgsqlConnection db,ArchiveBlock block,CancellationToken ct)
    {
        await using var command=new NpgsqlCommand("""
            insert into storage_v2_archive_sets(archive_set_id,archive_kind,format_version,source_min_event_id,source_max_event_id,expected_rows,state)
            values(@set,@kind,1,@first,@last,@rows,@state);
            insert into storage_v2_archive_blocks(archive_set_id,archive_kind,format_version,block_index,first_event_id,last_event_id,
                row_count,raw_bytes,compressed_bytes,raw_sha256,archive_sha256,object_location,state,verified_at)
            values(@set,@kind,1,0,@first,@last,@rows,@raw,@compressed,@raw_hash,@hash,@path,@state,now())
            """,db);
        command.Parameters.AddWithValue("set",block.SetId); command.Parameters.AddWithValue("kind",block.Kind);
        command.Parameters.AddWithValue("first",block.FirstId); command.Parameters.AddWithValue("last",block.LastId);
        command.Parameters.AddWithValue("rows",block.Rows); command.Parameters.AddWithValue("state",block.State);
        command.Parameters.AddWithValue("raw",block.RawBytes); command.Parameters.AddWithValue("compressed",block.CompressedBytes);
        command.Parameters.AddWithValue("raw_hash",Convert.FromHexString(block.RawSha256)); command.Parameters.AddWithValue("hash",Convert.FromHexString(block.ArchiveSha256));
        command.Parameters.AddWithValue("path",block.ObjectLocation);
        await command.ExecuteNonQueryAsync(ct);
    }

    [Fact]
    public async Task Sparse_batch_uses_one_exact_id_manifest_query_and_deduplicates_blocks()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var pg=new PostCollectionPostgres(canonicalSchema:true); await pg.StartAsync(ct);
        await using var db=await pg.OpenAsync(ct);
        string migration=await File.ReadAllTextAsync(Path.Combine(PostCollectionPostgres.Repository(),"config/postgres_migrations/009_storage_v2_foundation.sql"),ct);
        foreach(string table in new[]{"storage_v2_archive_sets","storage_v2_archive_blocks"})
        {
            var definition=Regex.Match(migration,@"create table if not exists "+table+@"\s*\([\s\S]*?\r?\n\);");
            Assert.True(definition.Success);
            await PostCollectionPostgres.Sql(db,definition.Value,ct);
        }
        string root=Path.Combine(pg.Root,"archive");
        var first=BatchBlock(root,BatchRow(1),BatchRow(2),BatchRow(10));
        var last=BatchBlock(root,BatchRow(1_000_000));
        await SeedBatchBlock(db,first,ct); await SeedBatchBlock(db,last,ct);
        // A range scan would include more than sixteen unrelated published blocks.
        for(int id=20;id<38;id++) await SeedBatchBlock(db,BatchBlock(root,BatchRow(id)),ct);
        await SeedBatchBlock(db,BatchBlock(root,BatchRow(10)) with { State="staging" },ct);
        await SeedBatchBlock(db,BatchBlock(root,BatchRow(10)) with { Kind="link_detail" },ct);

        using var profile=new BatchCommandProfile();
        using var logging=LoggerFactory.Create(builder=>builder.SetMinimumLevel(LogLevel.Debug).AddProvider(profile));
        await using var source=new NpgsqlDataSourceBuilder(pg.ConnectionString).UseLoggerFactory(logging).Build();
        var store=new EventDetailStore(source);
        var blocks=await store.BlocksAsync([10,1_000_000],TimeSpan.FromSeconds(30),ct);
        Assert.Equal(new[]{first.SetId,last.SetId},blocks.Select(block=>block.SetId));
        Assert.Single(profile.Selects);
        using(var command=EventDetailStore.CreateBlocksCommand(db,null,[10,1_000_000],TimeSpan.FromSeconds(30)))
        {
            Assert.Contains("unnest(@ids::bigint[]) with ordinality",command.CommandText);
            Assert.Equal(new long[]{10,1_000_000},command.Parameters["ids"].Value);
        }
        var summaries=new Dictionary<long,JsonObject>{{10,BatchRow(10)},{1_000_000,BatchRow(1_000_000)}};
        summaries[10]["server"]="dc-a"; summaries[1_000_000]["server"]="dc-z";
        var result=new EventArchiveHydrator(new ArchiveReader(root,new UnusedManifest())).ReadCancellable(blocks,summaries,ct);
        Assert.Equal(new long[]{10,1_000_000},result.Keys.Order());
        Assert.Equal("dc-a",result[10]["server"]!.GetValue<string>());
        Assert.Equal("dc-z",result[1_000_000]["server"]!.GetValue<string>());
        foreach(long id in summaries.Keys)
        {
            var expected=(JsonObject)summaries[id].DeepClone(); expected.Remove("server");
            var actual=(JsonObject)result[id].DeepClone(); actual.Remove("server");
            Assert.True(JsonNode.DeepEquals(expected,actual));
        }

        profile.Selects.Clear();
        blocks=await store.BlocksAsync([1,2,1_000_000],TimeSpan.FromSeconds(30),ct);
        Assert.Single(profile.Selects);
        Assert.Equal(new[]{first.SetId,last.SetId},blocks.Select(block=>block.SetId));

        // The independent block boundary applies even when the request has 100 valid IDs.
        await PostCollectionPostgres.Sql(db,"delete from storage_v2_archive_blocks; delete from storage_v2_archive_sets",ct);
        for(int id=1;id<=17;id++) await SeedBatchBlock(db,BatchBlock(root,BatchRow(id)),ct);
        var error=await Assert.ThrowsAsync<InvalidDataException>(()=>store.BlocksAsync(Enumerable.Range(1,100).Select(id=>(long)id).ToArray(),TimeSpan.FromSeconds(30),ct));
        Assert.Equal("event_archive_block_limit",error.Message);
    }

    [Theory]
    [InlineData(16)]
    [InlineData(17)]
    public void Batch_archive_block_boundary_is_independent_of_100_event_boundary(int count)
    {
        string root=Path.Combine(Path.GetTempPath(),"event-batch-"+Guid.NewGuid().ToString("N"));
        try
        {
            var summaries=Enumerable.Range(1,100).ToDictionary(id=>(long)id,id=>BatchRow(id));
            var blocks=Enumerable.Range(0,count).Select(group=>BatchBlock(root,summaries.Where(pair=>(pair.Key-1)%count==group).Select(pair=>pair.Value).ToArray())).ToArray();
            var hydrator=new EventArchiveHydrator(new ArchiveReader(root,new UnusedManifest()));
            if(count==17)
            {
                // No payload can be read: exceeding the boundary must fail before hydration.
                foreach(var block in blocks) File.Delete(block.ObjectLocation);
                var error=Assert.Throws<InvalidDataException>(()=>hydrator.ReadCancellable(blocks,summaries,TestContext.Current.CancellationToken));
                Assert.Equal("event_archive_block_limit",error.Message);
            }
            else
            {
                var result=hydrator.ReadCancellable(blocks,summaries,TestContext.Current.CancellationToken);
                Assert.Equal(100,result.Count);
                Assert.Equal(summaries.Keys.Order(),result.Keys.Order());
            }
        }
        finally
        {
            string resolved=Path.GetFullPath(root),parent=Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);
            if(Directory.Exists(resolved) && Path.GetDirectoryName(resolved)==parent && Path.GetFileName(resolved).StartsWith("event-batch-",StringComparison.Ordinal)) Directory.Delete(resolved,true);
        }
    }

    // Observe real SQL executions without enabling parameter logging.
    sealed class BatchCommandProfile : ILoggerProvider,ILogger
    {
        internal readonly List<string> Selects=[];
        public ILogger CreateLogger(string categoryName) => this;
        public bool IsEnabled(LogLevel level) => true;
        public IDisposable? BeginScope<TState>(TState state) where TState:notnull => null;
        public void Dispose() { }
        public void Log<TState>(LogLevel level,EventId id,TState state,Exception? error,Func<TState,Exception?,string> format)
        {
            if(id.Name!="CommandExecutionCompleted") return;
            var fields=((IEnumerable<KeyValuePair<string,object?>>)(object)state!).ToDictionary(pair=>pair.Key,pair=>pair.Value);
            string sql=(string)fields["CommandText"]!;
            if(sql.Contains("storage_v2_archive_blocks",StringComparison.Ordinal)) Selects.Add(sql);
        }
    }
}
