using System.Text.Json.Nodes;
using Sli.Server.Storage.Archive;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed class ArchivePublisherTests
{
    const string SourceGzip = "H4sIAAAAAAAA/6tWys7MS1GyUkotS80rUdJRKsovV7KqVspMUbIyrK3lqsYjb6SjVJSanF+UEl+Rm6NkpWTjClJjd7Hxwo4Ley82Xdh6senCjgu7Lmyw0YfIKNXWcgEAs3ajbHEAAAA=";
    const string SourceRawSha = "9CF11C30D7C2A0FB1BE257FE0D98D46871121172E28A111576D9B03A0F87469B";
    static CancellationToken Token => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("published")]
    [InlineData("staging")]
    public async Task Recovery_syncs_both_rename_directories_before_manifest_publication(string failDirectory)
    {
        using var scope = new Scope();
        var manifest = new MemoryManifest();
        var syncs = new List<string>();
        bool failSync = true;
        var publisher = new ArchivePublisher(scope.Root,manifest,path =>
        {
            string name = Path.GetFileName(path);
            if (name is not ("published" or "staging") || !Directory.EnumerateFiles(Path.Combine(scope.Root,"published")).Any()) return;
            syncs.Add(name);
            if (failSync && name == failDirectory) throw new IOException("injected post-rename directory sync failure");
        });
        JsonObject[] events = [new() { ["id"] = 1L }];
        await Assert.ThrowsAsync<IOException>(()=>publisher.PublishDirectAsync("rename-sync",events,[],Token));
        var staged = Assert.Single(manifest.Blocks.Values);
        Assert.Equal("staging",staged.State);
        byte[] bytes = File.ReadAllBytes(staged.ObjectLocation);
        Assert.Equal(0,manifest.PublishCalls);
        syncs.Clear();
        // A second failed sync during recovery must still leave the manifest staging.
        await Assert.ThrowsAsync<IOException>(()=>publisher.PublishDirectAsync("rename-sync",events,[],Token));
        Assert.Equal(0,manifest.PublishCalls);
        Assert.Equal(staged,Assert.Single(manifest.Blocks.Values));
        Assert.Equal(failDirectory == "published" ? new[] {"published"} : new[] {"published","staging"},syncs);
        syncs.Clear(); failSync = false;
        manifest.BeforePublish = () => Assert.Equal(new[] {"published","staging"},syncs);
        await publisher.PublishDirectAsync("rename-sync",events,[],Token);
        Assert.Equal(1,manifest.PublishCalls);
        Assert.Equal("published",Assert.Single(manifest.Blocks.Values).State);
        Assert.Equal(bytes,File.ReadAllBytes(staged.ObjectLocation));
    }

    [Theory]
    [InlineData("length",false)]
    [InlineData("hash",false)]
    [InlineData("gzip",false)]
    [InlineData("raw",false)]
    [InlineData("hash",true)]
    public async Task Staged_manifest_corrupt_partial_is_quarantined_without_replacing_identity_or_collision(string corruption, bool collision)
    {
        using var scope = new Scope();
        var manifest = new MemoryManifest();
        var syncs = new List<string>();
        var publisher = new ArchivePublisher(scope.Root,manifest,path =>
        { if (Path.GetFileName(path) is "quarantine" or "staging") syncs.Add(Path.GetFileName(path)); });
        JsonObject[] events = [new() { ["id"] = 1L }];
        var encoded = ArchiveCodec.Encode("event",events);
        byte[] expected = ArchiveCodec.Compress(encoded.Raw), corrupt = expected.ToArray();
        if (corruption == "length") corrupt = [1];
        else if (corruption == "hash") corrupt[^1] ^= 1;
        else if (corruption == "gzip") corrupt = new byte[expected.Length];
        else corrupt = ArchiveCodec.Compress(ArchiveCodec.Encode("event",[new() { ["id"] = 2L }]).Raw);
        // gzip/raw cases independently exercise verification failures AFTER the physical SHA passes.
        bool physicallyAttested = corruption is "gzip" or "raw";
        string physicalHash = ArchiveCodec.Hash(physicallyAttested ? corrupt : expected);
        Guid id = ArchiveCodec.SetId("staged-corrupt","event",1,1);
        string name = $"event-{id:D}-00000000-1-1-{physicalHash[..16]}.jsonl.gz";
        string partial = Path.Combine(scope.Root,"staging",name+".partial"), final = Path.Combine(scope.Root,"published",name);
        string quarantine = Path.Combine(scope.Root,"quarantine",name+".hash-mismatch");
        File.WriteAllBytes(partial,corrupt);
        byte[] collisionBytes = [4,5,6];
        if (collision) File.WriteAllBytes(quarantine,collisionBytes);
        var staged = new ArchiveBlock(id,"event",1,0,1,1,1,encoded.Raw.Length,physicallyAttested ? corrupt.Length : expected.Length,
            ArchiveCodec.Hash(encoded.Raw),physicalHash,final,"staging",DateTime.UtcNow);
        manifest.Blocks[(id,"event",0)] = staged;
        syncs.Clear();
        if (collision)
        {
            await Assert.ThrowsAsync<IOException>(()=>publisher.PublishDirectAsync("staged-corrupt",events,[],Token));
            Assert.Equal(corrupt,File.ReadAllBytes(partial));
            Assert.Equal(collisionBytes,File.ReadAllBytes(quarantine));
            Assert.Empty(syncs);
        }
        else
        {
            await Assert.ThrowsAsync<InvalidDataException>(()=>publisher.PublishDirectAsync("staged-corrupt",events,[],Token));
            Assert.False(File.Exists(partial));
            Assert.Equal(corrupt,File.ReadAllBytes(quarantine));
            Assert.Equal(new[] {"quarantine","staging"},syncs);
        }
        Assert.False(File.Exists(final));
        Assert.Equal(staged,Assert.Single(manifest.Blocks.Values));
        Assert.Equal(0,manifest.PublishCalls);
    }

    [Fact]
    public void Immutable_publication_never_replaces_a_conflicting_final_object()
    {
        using var scope=new Scope();
        var objects=new ArchiveObjectStore(scope.Root);
        var compressed=ArchiveCodec.Compress([1,2,3]);
        string prepared=objects.Prepare("synthetic.gz",compressed), final=objects.Final("synthetic.gz");
        File.WriteAllText(final,"existing-conflict");
        Assert.Throws<InvalidDataException>(()=>objects.Publish(prepared,final,compressed));
        Assert.Equal("existing-conflict",File.ReadAllText(final));
        Assert.Equal(compressed,File.ReadAllBytes(prepared));
        Assert.Throws<InvalidDataException>(()=>objects.Final("../outside.gz"));
        Assert.Throws<InvalidDataException>(()=>new ArchiveObjectStore("relative"));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Source_python_object_and_staged_old_encoding_are_preserved(bool alternateEncoding, bool stagedPartial)
    {
        using var scope = new Scope();
        var manifest = new MemoryManifest();
        var publisher = new ArchivePublisher(scope.Root, manifest);
        JsonObject[] events = [new() { ["id"] = 2L, ["record_xml"] = "<Event>синтетика</Event>" }, new() { ["id"] = 1L }];
        var encoded = ArchiveCodec.Encode("event", events);
        Assert.Equal(SourceRawSha, ArchiveCodec.Hash(encoded.Raw));
        var id = ArchiveCodec.SetId("3:hash:0:1-2", "event", 1, 2);
        Assert.Equal(Guid.Parse("fc6ab397-d5ec-5bc9-8766-4f10fe31248c"), id);
        byte[] compressed = Convert.FromBase64String(SourceGzip);
        Assert.Equal("B6F8650F39D4187DD1480F015A1E990E82F99E1BB6D0E15A4078B43EA65149BD", ArchiveCodec.Hash(compressed));
        if (alternateEncoding) compressed[9] = 3; // Valid legacy Linux gzip OS marker; raw/hash unchanged.
        string hash = ArchiveCodec.Hash(compressed);
        string name = $"event-{id:D}-00000000-1-2-{hash[..16]}.jsonl.gz";
        string final = Path.Combine(scope.Root,"published",name);
        string path = stagedPartial ? Path.Combine(scope.Root,"staging",name+".partial") : final;
        File.WriteAllBytes(path, compressed);
        var old = new ArchiveBlock(id,"event",1,0,1,2,2,113,104,SourceRawSha,hash,final,stagedPartial ? "staging" : "published",DateTime.UtcNow);
        manifest.Blocks[(id,"event",0)] = old;
        var result = await publisher.PublishDirectAsync("3:hash:0:1-2", events, [], Token);
        Assert.Equal(id,result.EventSetId);
        Assert.Equal(compressed, File.ReadAllBytes(final));
        Assert.Equal("published",manifest.Blocks[(id,"event",0)].State);
        Assert.Equal(new long[] {1,2},new ArchiveReader(scope.Root,manifest).ReadBlockRows(manifest.Blocks[(id,"event",0)]).Select(x=>x["id"]!.GetValue<long>()));
        if (stagedPartial) Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task Whole_batch_is_validated_before_publication_and_quarantine_cannot_republish()
    {
        using var scope = new Scope();
        var manifest = new MemoryManifest();
        var publisher = new ArchivePublisher(scope.Root,manifest);
        JsonObject[] events = [new() { ["id"] = 1L }];
        await Assert.ThrowsAsync<InvalidDataException>(()=>publisher.PublishDirectAsync("invalid",events,[new(){["event_id"]=2L}],Token));
        Assert.Empty(manifest.Blocks);
        Assert.Empty(Directory.GetFiles(Path.Combine(scope.Root,"published")));
        await Assert.ThrowsAsync<InvalidDataException>(()=>publisher.PublishDirectAsync("duplicate",[new(){["id"]=1L},new(){["id"]=1L}],[],Token));
        await publisher.PublishDirectAsync("quarantine",events,[],Token);
        var block=Assert.Single(manifest.Blocks.Values);
        manifest.Blocks[(block.SetId,block.Kind,0)]=block with {State="quarantined"};
        await Assert.ThrowsAsync<InvalidDataException>(()=>publisher.PublishDirectAsync("quarantine",events,[],Token));
    }

    [Fact]
    public async Task Partial_mismatch_is_quarantined_without_overwriting_and_stage_failure_retries()
    {
        using var scope = new Scope();
        var manifest = new MemoryManifest { FailStage = true };
        var publisher = new ArchivePublisher(scope.Root,manifest);
        JsonObject[] events=[new(){["id"]=1L}];
        await Assert.ThrowsAsync<IOException>(()=>publisher.PublishDirectAsync("partial",events,[],Token));
        string partial=Assert.Single(Directory.GetFiles(Path.Combine(scope.Root,"staging")));
        Assert.Empty(manifest.Blocks);
        Assert.Empty(Directory.GetFiles(Path.Combine(scope.Root,"published")));
        File.WriteAllText(partial,"corrupt");
        manifest.FailStage=false;
        await Assert.ThrowsAsync<InvalidDataException>(()=>publisher.PublishDirectAsync("partial",events,[],Token));
        Assert.False(File.Exists(partial));
        Assert.Equal("corrupt",File.ReadAllText(Assert.Single(Directory.GetFiles(Path.Combine(scope.Root,"quarantine")))));
        await publisher.PublishDirectAsync("partial",events,[],Token);
        Assert.Equal("published",Assert.Single(manifest.Blocks.Values).State);
    }

    [Fact]
    public async Task Reader_lookup_checks_full_block_and_missing_row_fails_closed()
    {
        using var scope = new Scope();
        var manifest=new MemoryManifest();
        await new ArchivePublisher(scope.Root,manifest).PublishDirectAsync("lookup",[new(){["id"]=1L},new(){["id"]=3L}],[],Token);
        var reader=new ArchiveReader(scope.Root,manifest);
        Assert.Equal(1L,(await reader.ReadRowsForEventAsync("event",1,Token))[0]["id"]!.GetValue<long>());
        await Assert.ThrowsAsync<InvalidDataException>(()=>reader.ReadRowsForEventAsync("event",2,Token));
        await Assert.ThrowsAsync<FileNotFoundException>(()=>reader.ReadRowsForEventAsync("event",4,Token));
        var block=Assert.Single(manifest.Blocks.Values);
        Assert.Throws<InvalidDataException>(()=>reader.ReadBlockRows(block with {Rows=3}));
        Assert.Throws<InvalidDataException>(()=>reader.ReadBlockRows(block with {RawSha256=new string('0',64)}));
        byte[] bomb=ArchiveCodec.Compress(new byte[1024]);
        Assert.Throws<InvalidDataException>(()=>ArchiveCodec.Decompress(bomb,1));
    }
    [Fact]
    public async Task Published_payload_is_read_back_and_replay_is_immutable()
    {
        using var scope = new Scope();
        var manifest = new MemoryManifest();
        var publisher = new ArchivePublisher(scope.Root, manifest);
        JsonObject[] events = [new() { ["id"] = 2L, ["record_xml"] = "<Event>синтетика</Event>" }, new() { ["id"] = 1L }];
        JsonObject[] links = [new() { ["event_id"] = 2L, ["entity_id"] = 7, ["confidence"] = 1.0, ["evidence_json"] = new JsonObject { ["value"] = "proof" } }];
        var result = await publisher.PublishDirectAsync("3:hash:0:1-2", events, links, Token);
        Assert.NotNull(result.LinkSetId);
        Assert.Equal("proof", result.VerifiedLinkRows[0]["evidence_json"]!["value"]!.GetValue<string>());
        var block = manifest.Blocks.Values.Single(x => x.Kind == "event");
        byte[] bytes = File.ReadAllBytes(block.ObjectLocation);
        await publisher.PublishDirectAsync("3:hash:0:1-2", events.Reverse().ToArray(), links, Token);
        Assert.Equal(bytes, File.ReadAllBytes(block.ObjectLocation));
        events[0]["record_xml"] = "changed";
        await Assert.ThrowsAsync<InvalidDataException>(() => publisher.PublishDirectAsync("3:hash:0:1-2", events, links, Token));
    }

    [Fact]
    public async Task Rename_before_manifest_failure_is_recoverable_and_corruption_is_closed()
    {
        using var scope = new Scope();
        var manifest = new MemoryManifest { FailPublish = true };
        var publisher = new ArchivePublisher(scope.Root, manifest);
        JsonObject[] events = [new() { ["id"] = 1L }];
        await Assert.ThrowsAsync<IOException>(() => publisher.PublishDirectAsync("recovery", events, [], Token));
        Assert.Single(Directory.GetFiles(Path.Combine(scope.Root, "published")));
        manifest.FailPublish = false;
        await publisher.PublishDirectAsync("recovery", events, [], Token);
        var block = Assert.Single(manifest.Blocks.Values);
        Assert.Equal("published", block.State);
        File.WriteAllText(block.ObjectLocation, "corrupt");
        await Assert.ThrowsAsync<InvalidDataException>(() => publisher.PublishDirectAsync("recovery", events, [], Token));
    }

    [Fact]
    public async Task Reader_refuses_unpublished_external_and_wrong_envelopes()
    {
        using var scope = new Scope();
        var manifest = new MemoryManifest();
        var publisher = new ArchivePublisher(scope.Root, manifest);
        await publisher.PublishDirectAsync("reader", [new() { ["id"] = 1L }], [], Token);
        var block = Assert.Single(manifest.Blocks.Values);
        var reader = new ArchiveReader(scope.Root, manifest);
        Assert.Throws<InvalidDataException>(() => reader.ReadBlockRows(block with { State = "staging" }));
        Assert.Throws<InvalidDataException>(() => reader.ReadBlockRows(block with { ObjectLocation = Path.Combine(Path.GetDirectoryName(scope.Root)!, "outside.gz") }));
        Assert.Throws<InvalidDataException>(() => reader.ReadBlockRows(block with { Kind = "link_detail" }));
        Assert.Throws<InvalidDataException>(() => reader.ReadBlockRows(block with { RawBytes = ArchiveCodec.MaxRawBytes + 1 }));
    }

    internal sealed class MemoryManifest : IArchiveManifestStore
    {
        internal readonly Dictionary<(Guid, string, int), ArchiveBlock> Blocks = [];
        readonly Dictionary<Guid, ArchiveSet> sets = [];
        internal bool FailPublish, FailStage;
        internal int PublishCalls;
        internal List<(string Kind, long First, long Last)> RangeCalls = [];
        internal Action? BeforePublish;
        public Task EnsureSetAsync(ArchiveSet set, CancellationToken ct) { if (sets.TryGetValue(set.Id, out var old) && old != set) throw new InvalidDataException(); sets[set.Id] = set; return Task.CompletedTask; }
        public Task<ArchiveBlock?> GetAsync(Guid id, string kind, int index, CancellationToken ct) => Task.FromResult(Blocks.GetValueOrDefault((id, kind, index)));
        public Task<ArchiveBlock> StageAsync(ArchiveBlock block, CancellationToken ct) { if(FailStage)throw new IOException("synthetic stage commit failure"); Blocks[(block.SetId, block.Kind, block.Index)] = block; return Task.FromResult(block); }
        public Task<ArchiveBlock> MarkPublishedAsync(ArchiveBlock block, CancellationToken ct) { BeforePublish?.Invoke(); PublishCalls++; if (FailPublish) throw new IOException("synthetic manifest commit failure"); block = block with { State = "published" }; Blocks[(block.SetId, block.Kind, block.Index)] = block; return Task.FromResult(block); }
        public Task<ArchiveBlock?> FindPublishedAsync(string kind, long id, CancellationToken ct) => Task.FromResult(Blocks.Values.FirstOrDefault(x => x.Kind == kind && x.State == "published" && x.FirstId <= id && x.LastId >= id));
        internal Action? BeforeRangeRead;
        public Task<IReadOnlyList<ArchiveBlock>> FindPublishedRangeAsync(string kind,long first,long last,int limit,CancellationToken ct)
        {
            BeforeRangeRead?.Invoke();
            return Task.FromResult<IReadOnlyList<ArchiveBlock>>(Blocks.Values.Where(b=>b.Kind==kind && b.State=="published" && b.LastId>=first && b.FirstId<=last)
                .OrderBy(b=>b.FirstId).ThenBy(b=>b.LastId).ThenBy(b=>b.SetId.ToString("D"),StringComparer.Ordinal).ThenBy(b=>b.Index).Take(limit).ToArray());
        }
        public Task<IReadOnlyList<ArchiveBlock>> FindPublishedRangeAsync(string kind, long firstId, long lastId, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            RangeCalls.Add((kind, firstId, lastId));
            return Task.FromResult<IReadOnlyList<ArchiveBlock>>(Blocks.Values.Where(x => x.Kind == kind && x.State == "published" && x.LastId >= firstId && x.FirstId <= lastId)
                .OrderBy(x => x.FirstId).ThenBy(x => x.LastId).ThenBy(x => x.SetId).ThenBy(x => x.Index).ToArray());
        }
    }
    sealed class Scope : IDisposable
    {
        internal string Root { get; } = Path.Combine(AppContext.BaseDirectory, "sli-archive-test-" + Guid.NewGuid().ToString("N"));
        public void Dispose() { if (Directory.Exists(Root)) Directory.Delete(Root, true); }
    }
}
