using System.Text.Json.Nodes;
using Sli.Server.Storage.Archive;
using Sli.Server.Storage.History;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Vectors from tests/storage/test_storage_v2_deep_candidates.py, using real
// publisher/reader objects and synthetic JSONL files, never a running store.
public sealed class EventDeepCandidateTests
{
    static CancellationToken Token => TestContext.Current.CancellationToken;
    static JsonObject Row(long id, int second) => new()
    {
        ["id"]=id,["server_id"]=1,["domain_id"]=1,["log_source_id"]=1,
        ["event_id"]=4624,["event_record_id"]=id,
        ["time_created_utc"]=$"2026-10-20T00:00:{second:00}Z",["message_text"]="needle"
    };
    static long[] Ids(IReadOnlyList<JsonObject> rows) => rows.Select(r=>r["id"]!.GetValue<long>()).ToArray();

    [Fact]
    public async Task Exact_candidates_are_filtered_before_limit_in_metadata_order()
    {
        using var scope = new Scope();
        var a=Row(100,50); var excluded=Row(101,30); var b=Row(102,10);
        await scope.Publish(a,excluded,b);
        Assert.Equal(new long[]{100},Ids(await scope.Search([a,b],1)));
        Assert.Equal(new long[]{102},Ids(await scope.Search([b,a],1)));
        Assert.Equal(new long[]{102,100},Ids(await scope.Search([b,a])));
    }

    [Fact]
    public async Task Missing_and_mixed_payloads_fail_instead_of_returning_partial_results()
    {
        using var scope = new Scope();
        var a=Row(100,50); var b=Row(102,10);
        await Assert.ThrowsAsync<KeyNotFoundException>(()=>scope.Search([a]));
        await scope.Publish(a);
        await Assert.ThrowsAsync<KeyNotFoundException>(()=>scope.Search([a,b]));
        Assert.Empty(await scope.Search([]));
        File.Delete(Assert.Single(scope.Manifest.Blocks.Values).ObjectLocation);
        await Assert.ThrowsAsync<FileNotFoundException>(()=>scope.Search([a]));
    }

    [Theory]
    [InlineData("id")]
    [InlineData("server_id")]
    [InlineData("domain_id")]
    [InlineData("log_source_id")]
    [InlineData("event_id")]
    [InlineData("time_created_utc")]
    public async Task Identity_and_timestamp_guards_survive(string field)
    {
        using var scope = new Scope();
        var a=Row(100,50);
        await scope.Publish(a);
        var corrupt=(JsonObject)a.DeepClone();
        if(field=="time_created_utc") corrupt[field]="2026-10-20T00:00:49Z";
        else corrupt[field]=field=="id" ? 101 : 2;
        // An absent ID rejects the exact selection; all other mismatches reject identity.
        if(field=="id") await Assert.ThrowsAsync<KeyNotFoundException>(()=>scope.Search([corrupt]));
        else await Assert.ThrowsAsync<InvalidDataException>(()=>scope.Search([corrupt]));
    }

    [Fact]
    public async Task Corrupt_archive_hash_is_rejected()
    {
        using var scope = new Scope();
        var a=Row(100,50);
        await scope.Publish(a);
        var block=Assert.Single(scope.Manifest.Blocks.Values);
        File.WriteAllBytes(block.ObjectLocation,new byte[block.CompressedBytes]);
        var error=await Assert.ThrowsAsync<InvalidDataException>(()=>scope.Search([a]));
        Assert.Equal("archive_compressed_hash_mismatch",error.Message);
    }

    [Theory]
    [InlineData("needle")]
    [InlineData("different")]
    public async Task Later_candidate_is_verified_even_after_limit_and_on_text_nonmatch(string text)
    {
        using var scope = new Scope();
        var a=Row(100,50); var b=Row(102,10); b["message_text"]=text;
        await scope.Publish(a,b);
        b["server_id"]=2;
        await Assert.ThrowsAsync<InvalidDataException>(()=>scope.Search([a,b],1));
    }

    [Fact]
    public async Task Account_filter_precedes_limit_and_matches_exact_case_in_either_role()
    {
        using var scope = new Scope();
        var a=Row(100,50); var b=Row(101,30); var c=Row(102,10);
        a["subject_user_name"]="Alice"; b["subject_user_name"]="alice-prefix"; c["target_user_name"]="alice";
        await scope.Publish(a,b,c);
        Assert.Equal(new long[]{102},Ids(await scope.Search([a,b,c],1,["alice"])));
        Assert.Equal(new long[]{100},Ids(await scope.Search([a,b,c],1,["Alice"])));
        Assert.Empty(await scope.Search([a,b,c],1,[]));
        Assert.Empty(await scope.Search([a,b,c],1,[""]));
    }

    [Fact]
    public async Task Candidate_count_boundary_and_canonical_record_keys()
    {
        using var scope = new Scope();
        var a=Row(100,50);
        var error=await Assert.ThrowsAsync<ArgumentException>(()=>scope.Search(Enumerable.Repeat(a,10001).ToArray()));
        Assert.Contains("candidate limit; narrow",error.Message);
        Assert.Equal(0,scope.RangeReads);
        await scope.Publish(a);
        Assert.Single(await scope.Search(Enumerable.Repeat(a,10000).ToArray(),1));
        a["event_record_id"]=0;
        Assert.Equal(0,(await scope.Search([a]))[0]["event_record_id"]!.GetValue<int>());
        a["event_record_id"]=null;
        Assert.Null((await scope.Search([a]))[0]["event_record_id"]);
        a.Remove("event_record_id"); a["time_created_utc"]="2026-10-20T01:00:50+01:00";
        var result=Assert.Single(await scope.Search([a]));
        Assert.Null(result["event_record_id"]);
        Assert.Equal("2026-10-20T01:00:50+01:00",result["time_created_utc"]!.GetValue<string>());
        var archived=Assert.Single(await new ArchiveReader(scope.Root,scope.Manifest).ReadRowsForEventAsync("event",100,Token));
        Assert.Equal(100,archived["event_record_id"]!.GetValue<int>());
    }

    [Fact]
    public async Task No_match_does_not_fill_page_and_candidates_share_one_block_selection()
    {
        using var scope = new Scope();
        var a=Row(100,50); var b=Row(102,10); a["message_text"]="other";
        await scope.Publish(a,b);
        Assert.Equal(new long[]{102},Ids(await scope.Search([a,b],1)));
        Assert.Equal(1,scope.RangeReads);
        Assert.Single(scope.Manifest.Blocks);
        Assert.Empty(await scope.Search([a]));
        Assert.Empty(await scope.Search([]));
        Assert.Equal(2,scope.RangeReads);
    }

    [Fact]
    public async Task Archive_block_budget_rejects_window_before_returning_matches()
    {
        using var scope = new Scope();
        var rows=Enumerable.Range(1,9).Select(i=>Row(i,i)).ToArray();
        foreach(var row in rows) await scope.Publish(row);
        Assert.Equal(8,(await scope.Search(rows[..8],8)).Count);
        // A small result page cannot conceal an incomplete search window.
        var error=await Assert.ThrowsAsync<InvalidDataException>(()=>scope.Search(rows,1));
        Assert.Equal("event_archive_block_limit",error.Message);
        Assert.Equal(2,scope.RangeReads);
    }

    [Fact]
    public async Task Text_search_uses_all_payload_fields_and_source_unicode_json_format()
    {
        using var scope = new Scope();
        var a=Row(100,50); a["message_text"]="Straße";
        a["event_data_json"]=new JsonObject { ["z"]=1,["a"]="Игла" };
        a["record_xml"]="<Event>NEEDLE</Event>";
        await scope.Publish(a);
        foreach(string term in new[]{" STRASSE ","\u001cИГЛА\u001c","\"a\": \"игла\", \"z\": 1","<event>needle</event>"})
            Assert.Single(await scope.Reader.SearchAsync(term,[a],ct:Token));
    }

    [Theory]
    [InlineData("x",1,8)]
    [InlineData("needle",0,8)]
    [InlineData("needle",1001,8)]
    [InlineData("needle",1,0)]
    [InlineData("needle",1,65)]
    public async Task Invalid_search_arguments_fail_before_manifest_reads(string term,int results,int blocks)
    {
        using var scope = new Scope();
        await Assert.ThrowsAnyAsync<ArgumentException>(()=>scope.Reader.SearchAsync(term,[Row(100,50)],results,blocks,ct:Token));
        Assert.Equal(0,scope.RangeReads);
    }

    sealed class Scope : IDisposable
    {
        internal string Root { get; }=Path.Combine(Path.GetTempPath(),"deep-candidates-"+Guid.NewGuid().ToString("N"));
        internal ArchivePublisherTests.MemoryManifest Manifest { get; }=new();
        internal EventDeepCandidateReader Reader { get; }
        internal int RangeReads;
        readonly ArchivePublisher publisher;
        internal Scope()
        {
            publisher=new(Root,Manifest);
            Reader=new(new ArchiveReader(Root,Manifest));
            Manifest.BeforeRangeRead=()=>RangeReads++;
        }
        internal Task Publish(params JsonObject[] rows) => publisher.PublishDirectAsync(Guid.NewGuid().ToString("N"),rows,[],Token);
        internal Task<IReadOnlyList<JsonObject>> Search(IReadOnlyList<JsonObject> rows,int limit=2,IReadOnlyList<string>? accounts=null) =>
            Reader.SearchAsync("needle",rows,limit,accountValues:accounts,ct:Token);
        public void Dispose() { if(Directory.Exists(Root)) Directory.Delete(Root,true); }
    }
}
