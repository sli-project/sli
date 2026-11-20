using System.Text.Json.Nodes;
using Sli.Server.Storage.Archive;
using Sli.Server.Storage.History;
using Xunit;

namespace Sli.Server.Tests.Storage;
public sealed partial class EventArchiveHydrationTests
{
    [Fact] public void Reader_does_not_create_archive_directories()
    {
        string root=Path.Combine(Path.GetTempPath(),"event-read-only-"+Guid.NewGuid().ToString("N"));
        try { _=new ArchiveReader(root,new UnusedManifest()); Assert.False(Directory.Exists(root)); }
        finally { if(Directory.Exists(root)) Directory.Delete(root,true); }
    }
    [Fact] public void Missing_manifest_degrades_exact_card_but_fails_batch()
    {
        string root=Path.Combine(Path.GetTempPath(),"event-missing-"+Guid.NewGuid().ToString("N"));
        try
        {
            var hydrator=new EventArchiveHydrator(new ArchiveReader(root,new UnusedManifest()));
            var rows=new Dictionary<long,JsonObject> { [7]=new JsonObject { ["id"]=7,["event_id"]=4625,["server_id"]=3,["server"]="DC1",["time_created_utc"]="2026-10-09T10:00:00Z" } };
            Assert.Throws<InvalidDataException>(()=>hydrator.Read([],rows));
            var result=hydrator.ReadCancellable([],rows,TestContext.Current.CancellationToken,exact:true);
            Assert.Equal("archive_unavailable",result[7]["source_payload_state"]!.GetValue<string>());
            Assert.Equal(7,result[7]["id"]!.GetValue<int>());
            Assert.Equal("DC1",result[7]["server"]!.GetValue<string>());
            Assert.False(result[7].ContainsKey("event_data"));
            Assert.False(rows[7].ContainsKey("source_payload_state"));
        }
        finally { if(Directory.Exists(root)) Directory.Delete(root,true); }
    }
    sealed class UnusedManifest : IArchiveManifestStore
    {
        public Task EnsureSetAsync(ArchiveSet s,CancellationToken c) => throw new NotSupportedException();
        public Task<ArchiveBlock?> GetAsync(Guid i,string k,int n,CancellationToken c) => throw new NotSupportedException();
        public Task<ArchiveBlock> StageAsync(ArchiveBlock b,CancellationToken c) => throw new NotSupportedException();
        public Task<ArchiveBlock> MarkPublishedAsync(ArchiveBlock b,CancellationToken c) => throw new NotSupportedException();
        public Task<ArchiveBlock?> FindPublishedAsync(string k,long i,CancellationToken c) => throw new NotSupportedException();
        public Task<IReadOnlyList<ArchiveBlock>> FindPublishedRangeAsync(string k,long first,long last,CancellationToken c) => throw new NotSupportedException();
        public Task<IReadOnlyList<ArchiveBlock>> FindPublishedRangeAsync(string k,long first,long last,int limit,CancellationToken c) => throw new NotSupportedException();
    }
    // tests/events/test_event_detail_archive_unavailable.py: a published block
    // that omits the requested row is corrupt, rather than unavailable.
    [Fact] public void Missing_row_inside_published_block_fails_closed_for_exact_card()
    {
        string root=Path.Combine(Path.GetTempPath(),"event-missing-row-"+Guid.NewGuid().ToString("N"));
        try
        {
            var encoded=ArchiveCodec.Encode("event",[new JsonObject { ["id"]=6 },new JsonObject { ["id"]=8 }]);
            var compressed=ArchiveCodec.Compress(encoded.Raw);
            string path=Path.Combine(root,"published","fixture.jsonl.gz");
            Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.WriteAllBytes(path,compressed);
            var block=new ArchiveBlock(Guid.NewGuid(),"event",1,0,6,8,2,encoded.Raw.Length,compressed.Length,ArchiveCodec.Hash(encoded.Raw),ArchiveCodec.Hash(compressed),path,"published",DateTime.UtcNow);
            var reader=new ArchiveReader(root,new UnusedManifest());
            var summaries=new Dictionary<long,JsonObject> { [7]=new JsonObject { ["id"]=7,["server"]="DC1" } };

            var error=Assert.Throws<InvalidDataException>(()=>new EventArchiveHydrator(reader).ReadCancellable([block],summaries,TestContext.Current.CancellationToken,exact:true));

            Assert.Equal("event_archive_payload_missing",error.Message);
            Assert.False(summaries[7].ContainsKey("source_payload_state"));
        }
        finally { if(Directory.Exists(root)) Directory.Delete(root,true); }
    }
    [Fact] public void Verified_payload_and_identity_mismatch()
    {
        string root = Path.Combine(Path.GetTempPath(), "event-read-" + Guid.NewGuid().ToString("N"));
        try
        {
            var reader = new ArchiveReader(root,new UnusedManifest());
            var row = JsonNode.Parse("{\"id\":7,\"server_id\":3,\"domain_id\":2,\"log_source_id\":4,\"event_id\":4625,\"time_created_utc\":\"2026-01-02T03:04:05Z\",\"message_text\":\"event\"}")!.AsObject();
            var raw = ArchiveCodec.Encode("event",[row]); var compressed = ArchiveCodec.Compress(raw.Raw);
            string path = Path.Combine(root,"published","fixture.jsonl.gz"); Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.WriteAllBytes(path,compressed);
            var block = new ArchiveBlock(Guid.NewGuid(),"event",1,0,7,7,1,raw.Raw.Length,compressed.Length,ArchiveCodec.Hash(raw.Raw),ArchiveCodec.Hash(compressed),path,"published",DateTime.UtcNow);
            var summary = (JsonObject)row.DeepClone(); summary["server"] = "fixture";
            var hydrator = new EventArchiveHydrator(reader);
            var got = hydrator.Read([block],new Dictionary<long,JsonObject> { [7] = summary });
            Assert.Equal("event",got[7]["message_text"]!.GetValue<string>()); Assert.Equal("fixture",got[7]["server"]!.GetValue<string>());
            summary["domain_id"] = 9;
            Assert.Throws<InvalidDataException>(() => hydrator.Read([block],new Dictionary<long,JsonObject> { [7] = summary }));
            summary["domain_id"] = 2;
            File.WriteAllBytes(path, new byte[compressed.Length]);
            Assert.Throws<InvalidDataException>(() => hydrator.Read([block],new Dictionary<long,JsonObject> { [7] = summary }));
            File.Delete(path);
            var degraded = hydrator.Read([block],new Dictionary<long,JsonObject> { [7] = summary });
            Assert.Equal("archive_unavailable",degraded[7]["source_payload_state"]!.GetValue<string>());
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root,true); }
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public void Outside_root_degrades_without_reading_the_object(bool exact)
    {
        string directory=Path.Combine(Path.GetTempPath(),"event-root-"+Guid.NewGuid().ToString("N"));
        string root=Path.Combine(directory,"root");
        try
        {
            Directory.CreateDirectory(directory);
            string outside=Path.Combine(directory,"outside.gz");
            File.WriteAllBytes(outside,[0x78]);
            var reader=new ArchiveReader(root,new UnusedManifest());
            var block=new ArchiveBlock(Guid.NewGuid(),"event",1,0,7,7,1,1,1,"bad","bad",outside,"published",DateTime.UtcNow);
            // An existing foreign object must be refused before its invalid hash is checked.
            var error=Assert.Throws<InvalidDataException>(()=>reader.ReadBlockRows(block));
            Assert.Equal("archive_object_outside_root",error.Message);
            var row=new JsonObject { ["id"]=7,["server"]="fixture" };
            var got=new EventArchiveHydrator(reader).ReadCancellable([block],new Dictionary<long,JsonObject>{{7,row}},TestContext.Current.CancellationToken,exact);
            Assert.Single(got);
            Assert.Equal("archive_unavailable",got[7]["source_payload_state"]!.GetValue<string>());
            Assert.Equal("fixture",got[7]["server"]!.GetValue<string>());
            Assert.Null(row["source_payload_state"]);
            var invalid=block with { State="quarantined" };
            Assert.Throws<InvalidDataException>(()=>new EventArchiveHydrator(reader).ReadCancellable([invalid],new Dictionary<long,JsonObject>{{7,row}},TestContext.Current.CancellationToken,exact));
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory,true); }
    }    [Fact] public void Archive_verification_observes_pre_cancelled_token()
    {
        string root=Path.Combine(Path.GetTempPath(),"event-cancel-"+Guid.NewGuid().ToString("N"));
        try
        {
            var reader=new ArchiveReader(root,new UnusedManifest());
            using var cts=new CancellationTokenSource(); cts.Cancel();
            var block=new ArchiveBlock(Guid.NewGuid(),"event",1,0,7,7,1,1,1,"bad","bad",Path.Combine(root,"published","absent"),"published",DateTime.UtcNow);
            var summary=new Dictionary<long,JsonObject>{{7,new JsonObject { ["id"]=7 }}};
            Assert.ThrowsAny<OperationCanceledException>(()=>new EventArchiveHydrator(reader).ReadCancellable([block],summary,cts.Token));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root,true); }
    }}
