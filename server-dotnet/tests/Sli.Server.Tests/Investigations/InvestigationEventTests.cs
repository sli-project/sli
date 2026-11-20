using System.Numerics;
using System.Text.Json;
using Sli.Server.Investigations;
using Xunit;
namespace Sli.Server.Tests.Investigations;
public sealed class InvestigationEventTests
{
    sealed class Tx:IInvestigationEventTransaction
    {
        public List<string> Calls=[];public InvestigationEventRow? Inserted,Existing;public bool Exists=true,Removed=true,FailAudit;
        public Task LockAsync(CancellationToken ct){Calls.Add("lock");return Task.CompletedTask;}
        public Task<long> ReadCaseAsync(InvestigationIdentity id,CancellationToken ct){Calls.Add("case");return Task.FromResult(4L);}
        public Task<bool> EventExistsAsync(BigInteger id,CancellationToken ct){Calls.Add("exists");return Task.FromResult(Exists);}
        public Task<InvestigationEventRow?> InsertAsync(long id,BigInteger ev,string relation,string actor,CancellationToken ct){Calls.Add("insert");return Task.FromResult(Inserted);}
        public Task<InvestigationEventRow?> ReadExistingAsync(long id,BigInteger ev,CancellationToken ct){Calls.Add("existing");return Task.FromResult(Existing);}
        public Task<bool> DeleteAsync(long id,BigInteger ev,CancellationToken ct){Calls.Add("delete");return Task.FromResult(Removed);}
        public Task UpdateAndAuditAsync(long id,BigInteger ev,string? relation,string actor,CancellationToken ct){Calls.Add("audit");if(FailAudit)throw new InvalidOperationException();return Task.CompletedTask;}
        public Task CommitAsync(CancellationToken ct){Calls.Add("commit");return Task.CompletedTask;}
    }
    static JsonElement J(string s)=>JsonDocument.Parse(s).RootElement.Clone();
    [Theory] [InlineData("{\"event_db_id\":\"１２\"}",12,"confirmed")] [InlineData("{\"event_db_id\":true,\"relation_status\":\"EXCLUDED\"}",1,"excluded")] [InlineData("{\"event_db_id\":4.9}",4,"confirmed")]
    public void SourceBodyCoercion(string body,long expected,string relation){var input=InvestigationEventInput.Parse(J(body),true);Assert.Equal(new BigInteger(expected),input.EventId);Assert.Equal(relation,input.Relation);}
    [Theory] [InlineData("{}")] [InlineData("{\"event_db_id\":null}")] [InlineData("{\"event_db_id\":\"1e2\"}")] [InlineData("{\"event_db_id\":[]}")]
    public void InvalidEventInputUsesSourceError(string body){var e=Assert.Throws<InvestigationException>(()=>InvestigationEventInput.Parse(J(body),true));Assert.Equal("invalid_event_db_id",e.Code);}
    [Fact] public void NonFiniteFloatOverflowIsNotMisclassifiedAsInvalidEventId()
    {Assert.Throws<OverflowException>(()=>InvestigationEventInput.Parse(J("{\"event_db_id\":1e400}"),true));}
    [Fact] public void RelationDoesNotTrimSourceWhitespace(){var input=InvestigationEventInput.Parse(J("{\"event_db_id\":1,\"relation_status\":\" confirmed \"}"),true);var e=Assert.Throws<InvestigationException>(()=>input.Validate());Assert.Equal("invalid_relation_status",e.Code);}
    [Fact] public async Task AddFencesThenCommitsNewLinkAndAudit()
    {var row=new InvestigationEventRow(7,"confirmed","alice","2026-01-01 00:00:00+00:00");var tx=new Tx{Inserted=row};var result=await InvestigationEventMutation.AddAsync(tx,new(4,null),new(7,"confirmed"),"alice",CancellationToken.None);Assert.Equal(row,result.Row);Assert.False(result.Replay);Assert.Equal(new[]{"lock","case","exists","insert","audit","commit"},tx.Calls);}
    [Fact] public async Task ReplayNeverUpdatesOrAudits()
    {var row=new InvestigationEventRow(7,"confirmed","alice","2026-01-01 00:00:00+00:00");var tx=new Tx{Existing=row};var result=await InvestigationEventMutation.AddAsync(tx,new(4,null),new(7,"confirmed"),"alice",CancellationToken.None);Assert.True(result.Replay);Assert.DoesNotContain("audit",tx.Calls);Assert.Contains("commit",tx.Calls);}
    [Fact] public async Task DifferentRelationConflictsWithoutCommit()
    {var tx=new Tx{Existing=new(7,"excluded","alice","2026-01-01 00:00:00+00:00")};var e=await Assert.ThrowsAsync<InvestigationException>(()=>InvestigationEventMutation.AddAsync(tx,new(4,null),new(7,"confirmed"),"alice",CancellationToken.None));Assert.Equal("conflict",e.Code);Assert.DoesNotContain("commit",tx.Calls);}
    [Fact] public async Task MissingEventOrAuditFailureNeverCommit()
    {var missing=new Tx{Exists=false};await Assert.ThrowsAsync<InvestigationException>(()=>InvestigationEventMutation.AddAsync(missing,new(4,null),new(7,"confirmed"),"alice",CancellationToken.None));Assert.DoesNotContain("insert",missing.Calls);var failed=new Tx{Inserted=new(7,"confirmed","a","x"),FailAudit=true};await Assert.ThrowsAsync<InvalidOperationException>(()=>InvestigationEventMutation.AddAsync(failed,new(4,null),new(7,"confirmed"),"a",CancellationToken.None));Assert.DoesNotContain("commit",failed.Calls);}
    [Fact] public async Task RemovalAuditsOrReturnsNotFound()
    {var tx=new Tx();await InvestigationEventMutation.RemoveAsync(tx,new(4,null),7,"a",CancellationToken.None);Assert.Equal(new[]{"case","delete","audit","commit"},tx.Calls);var missing=new Tx{Removed=false};var e=await Assert.ThrowsAsync<InvestigationException>(()=>InvestigationEventMutation.RemoveAsync(missing,new(4,null),7,"a",CancellationToken.None));Assert.Equal("not_found",e.Code);Assert.DoesNotContain("commit",missing.Calls);}
}
