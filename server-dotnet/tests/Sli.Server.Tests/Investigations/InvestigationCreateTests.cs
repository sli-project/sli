using System.Numerics;
using System.Text.Json;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Server.Investigations;
using Xunit;
namespace Sli.Server.Tests.Investigations;
public sealed class InvestigationCreateTests
{
    private sealed class Tx:IInvestigationCreateTransaction
    {
        public List<string> Calls=[];public bool Exists=true,FailAudit,FailLink,FailRead;public Guid PublicId;
        public Task LockAsync(CancellationToken ct){Calls.Add("lock");return Task.CompletedTask;}
        public Task<bool> EventExistsAsync(BigInteger id,CancellationToken ct){Calls.Add("exists");return Task.FromResult(Exists);}
        public Task<long> InsertAsync(Guid publicId,string title,string? owner,string actor,CancellationToken ct){Calls.Add("insert");PublicId=publicId;return Task.FromResult(4L);}
        public Task CreatedAuditAsync(long id,string actor,CancellationToken ct){Calls.Add("created");if(FailAudit)throw new InvalidOperationException();return Task.CompletedTask;}
        public Task LinkEventAsync(long id,BigInteger eventId,string actor,CancellationToken ct){Calls.Add("link");if(FailLink)throw new InvalidOperationException();return Task.CompletedTask;}
        public Task<JsonObject> ReadAsync(long id,CancellationToken ct){Calls.Add("read");if(FailRead)throw new InvalidOperationException();return Task.FromResult(JsonNode.Parse("{\"id\":4,\"events\":[],\"notes\":[],\"evidence_refs\":[]}")!.AsObject());}
        public Task CommitAsync(CancellationToken ct){Calls.Add("commit");return Task.CompletedTask;}
    }
    static JsonElement J(string s)=>JsonDocument.Parse(s).RootElement.Clone();
    [Theory] [InlineData("{\"title\":\"  example  \"}","example",null)] [InlineData("{\"title\":true,\"owner\":[1,true]}","True","[1, True]")]
    public void SourceStringDefaults(string json,string title,string? owner){var input=InvestigationCreateInput.Parse(J(json));input.Validate();Assert.Equal(title,input.Title);Assert.Equal(owner,input.Owner);}
    [Fact] public void TitleAndOwnerLimitsCountUnicodeScalars()
    {
        var input=InvestigationCreateInput.Parse(J(JsonSerializer.Serialize(new {title=string.Concat(Enumerable.Repeat("😀",301)),owner=new string('x',201)})));
        Assert.Equal(300,input.Title.EnumerateRunes().Count());Assert.Equal(200,input.Owner!.Length);
    }
    [Fact] public void EmptyTitleIsInvalid(){var input=InvestigationCreateInput.Parse(J("{}"));var e=Assert.Throws<InvestigationException>(()=>input.Validate());Assert.Equal("invalid_title",e.Code);}
    [Fact] public async Task NoAnchorDoesNotLockAndCreatesDistinctUuids()
    {var one=new Tx();var two=new Tx();var input=InvestigationCreateInput.Parse(J("{\"title\":\"A\"}"));await InvestigationCreate.ExecuteAsync(one,input,"alice",CancellationToken.None);await InvestigationCreate.ExecuteAsync(two,input,"alice",CancellationToken.None);Assert.NotEqual(one.PublicId,two.PublicId);Assert.NotEqual(Guid.Empty,one.PublicId);Assert.Equal(new[]{"insert","created","read","commit"},one.Calls);}
    [Fact] public async Task AnchorIsFencedBeforeExistenceAndAudit()
    {var tx=new Tx();var input=InvestigationCreateInput.Parse(J("{\"title\":\"A\",\"event_db_id\":7}"));await InvestigationCreate.ExecuteAsync(tx,input,"a",CancellationToken.None);Assert.Equal(new[]{"lock","exists","insert","created","link","read","commit"},tx.Calls);}
    [Fact] public async Task FailurePreventsCommitAndMissingEventPreventsInsert()
    {var missing=new Tx{Exists=false};var input=InvestigationCreateInput.Parse(J("{\"title\":\"A\",\"event_db_id\":7}"));var e=await Assert.ThrowsAsync<InvestigationException>(()=>InvestigationCreate.ExecuteAsync(missing,input,"a",CancellationToken.None));Assert.Equal("event_not_found",e.Code);Assert.DoesNotContain("insert",missing.Calls);var failed=new Tx{FailAudit=true};await Assert.ThrowsAsync<InvalidOperationException>(()=>InvestigationCreate.ExecuteAsync(failed,input,"a",CancellationToken.None));Assert.DoesNotContain("commit",failed.Calls);}
    [Theory] [InlineData(true,false)] [InlineData(false,true)]
    public async Task LinkOrReadFailureDoesNotCommit(bool failLink,bool failRead)
    {var tx=new Tx{FailLink=failLink,FailRead=failRead};var input=InvestigationCreateInput.Parse(J("{\"title\":\"A\",\"event_db_id\":7}"));await Assert.ThrowsAsync<InvalidOperationException>(()=>InvestigationCreate.ExecuteAsync(tx,input,"a",CancellationToken.None));Assert.DoesNotContain("commit",tx.Calls);}
    [Fact] public void NullAnchorIsAbsentButMalformedAnchorRejected()
    {Assert.Null(InvestigationCreateInput.Parse(J("{\"title\":\"a\",\"event_db_id\":null}")).EventId);var e=Assert.Throws<InvestigationException>(()=>InvestigationCreateInput.Parse(J("{\"event_db_id\":\"1e2\"}")));Assert.Equal("invalid_event_db_id",e.Code);}
}
