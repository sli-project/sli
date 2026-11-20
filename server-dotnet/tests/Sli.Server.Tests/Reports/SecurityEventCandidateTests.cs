using System.Text.Json;
using Sli.Server.Access;
using Sli.Server.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Sli.Server.Reports.SecurityCandidates;
using Sli.Server.Investigations;
using Xunit;
namespace Sli.Server.Tests.Reports;
public sealed class SecurityEventCandidateTests
{
    static JsonElement J(string s)=>JsonDocument.Parse(s).RootElement.Clone();
    static AtomicReportGrant Grant(string scope,string[] fields)=>new(J(scope),fields.ToHashSet(),new HashSet<string>{"view"},1,1);
    static AccessDecision Access(bool objects=true,bool investigations=true,bool events=true,params AtomicReportGrant[] security)
    {
        var caps=new HashSet<string>();if(objects)caps.Add("objects.view");if(investigations)caps.Add("investigations.view");if(events)caps.Add("events.view");
        return new("viewer",new(false,caps,new HashSet<string>(),[],new Dictionary<string,JsonElement>()),[new("investigations.workspace",true,[Grant("{\"kind\":\"domain\",\"ids\":[1]}",[])]),new("security.events.chains",true,security)]);
    }
    sealed class Store:ISecurityCandidateStore
    {
        public EntityResource? Entity=new(22,1,3);public int Preflights,Queries;public List<long> Rows=[];public long Original;public bool Fail;public DateTimeOffset SeenStart,SeenEnd;
        public Task<EntityResource?> EntityAsync(long id,CancellationToken ct){Preflights++;return Task.FromResult(Entity);}
        public Task<IReadOnlyList<long>> CandidatesAsync(long id,long domain,DateTimeOffset start,DateTimeOffset end,int count,CancellationToken ct){Queries++;Original=id;SeenStart=start;SeenEnd=end;if(Fail)throw new InvalidOperationException("synthetic");return Task.FromResult<IReadOnlyList<long>>(Rows.Take(count).ToArray());}
    }
    static readonly DateTimeOffset Start=DateTimeOffset.Parse("2026-01-01T00:00:00Z"),End=DateTimeOffset.Parse("2026-01-02T00:00:00Z");
    static AtomicReportGrant Full()=>Grant("{\"kind\":\"domain\",\"ids\":[1]}",["security","technical","raw_evidence"]);
    [Fact] public async Task MissingEntityIsNotCollectedAndNeverQueries()
    {var store=new Store{Entity=null};var result=await new SecurityCandidateOwner(store).ReadAsync(55,Start,End,2,Access(true,true,true,Full()),CancellationToken.None);Assert.Equal("not_collected",result.State);Assert.Empty(result.Ids);Assert.Equal(0,store.Queries);}
    [Fact] public async Task MissingCapabilityOrFragmentedFieldGrantsDenyBeforeQuery()
    {
        var store=new Store();var split=new[]{Grant("{\"kind\":\"domain\",\"ids\":[1]}",["security","technical"]),Grant("{\"kind\":\"domain\",\"ids\":[1]}",["raw_evidence"])};
        foreach(var access in new[]{Access(false,true,true,Full()),Access(true,false,true,Full()),Access(true,true,false,Full()),Access(true,true,true,split)}) {var result=await new SecurityCandidateOwner(store).ReadAsync(55,Start,End,2,access,CancellationToken.None);Assert.Equal("not_authorized",result.State);}
        Assert.Equal(0,store.Queries);
    }
    [Fact] public async Task BoundedResultPreservesOriginalEntityAndHasMore()
    {var store=new Store{Rows=[8,7,6]};var result=await new SecurityCandidateOwner(store).ReadAsync(55,Start,End,2,Access(true,true,true,Full()),CancellationToken.None);Assert.Equal("available",result.State);Assert.Equal(new long[]{8,7},result.Ids);Assert.True(result.HasMore);Assert.Equal(55,store.Original);}
    [Fact] public async Task FailureIsNotAnEmptySuccess()
    {var store=new Store{Fail=true};await Assert.ThrowsAsync<InvalidOperationException>(()=>new SecurityCandidateOwner(store).ReadAsync(55,Start,End,2,Access(true,true,true,Full()),CancellationToken.None));}
    [Fact] public async Task QueryScopeMustMatchDomain()
    {var store=new Store{Entity=new(22,2,3)};var result=await new SecurityCandidateOwner(store).ReadAsync(55,Start,End,2,Access(true,true,true,Full()),CancellationToken.None);Assert.Equal("not_authorized",result.State);Assert.Equal(0,store.Queries);}
    [Fact] public async Task BoundsFailClosedWithoutCandidateRead()
    {var store=new Store();await Assert.ThrowsAsync<SecurityCandidateException>(()=>new SecurityCandidateOwner(store).ReadAsync(55,Start,Start,2,Access(true,true,true,Full()),CancellationToken.None));await Assert.ThrowsAsync<SecurityCandidateException>(()=>new SecurityCandidateOwner(store).ReadAsync(55,Start,Start.AddDays(32),2,Access(true,true,true,Full()),CancellationToken.None));Assert.Equal(0,store.Queries);}
    [Fact] public void EventVocabularyMatchesFrozenSourcePack()
    {Assert.Equal(new[]{1102,4624,4625,4719,4720,4722,4723,4724,4725,4726,4727,4728,4729,4730,4731,4732,4733,4734,4735,4737,4738,4740,4754,4755,4756,4757,4758,4764,4767,4771,4776,4781},SecurityCandidateStore.EventIds);}
    [Fact] public async Task EmptyDomainPreflightReturnsNotCollected()
    {var store=new Store{Entity=new(22,null,3)};var result=await new SecurityCandidateOwner(store).ReadAsync(55,Start,End,2,Access(true,true,true,Full()),CancellationToken.None);Assert.Equal("not_collected",result.State);Assert.Equal(0,store.Queries);}
    [Fact] public async Task ExactThirtyOneDayWindowAndLimitAreAccepted()
    {var store=new Store();var result=await new SecurityCandidateOwner(store).ReadAsync(55,Start,Start.AddDays(31),500,Access(true,true,true,Full()),CancellationToken.None);Assert.Equal("available",result.State);Assert.Equal(1,store.Queries);}
    [Theory] [InlineData(0)] [InlineData(501)] public async Task InvalidLimitDoesNotReadCandidates(int limit)
    {var store=new Store();var e=await Assert.ThrowsAsync<SecurityCandidateException>(()=>new SecurityCandidateOwner(store).ReadAsync(55,Start,End,limit,Access(true,true,true,Full()),CancellationToken.None));Assert.Equal("security_events_limit_invalid",e.Code);Assert.Equal(0,store.Queries);}
    [Fact] public async Task SuccessfulEmptyIsDistinctFromStorageFailure()
    {var store=new Store();var result=await new SecurityCandidateOwner(store).ReadAsync(55,Start,End,2,Access(true,true,true,Full()),CancellationToken.None);Assert.Equal("available",result.State);Assert.Empty(result.Ids);Assert.False(result.HasMore);Assert.Equal(1,store.Queries);}
    [Fact] public async Task FractionalInstantsAreUtcTruncatedToSourceMicroseconds()
    {var store=new Store();var a=Start.AddTicks(19);var b=End.AddTicks(29);await new SecurityCandidateOwner(store).ReadAsync(55,a,b,2,Access(true,true,true,Full()),CancellationToken.None);Assert.Equal(Start.AddTicks(10),store.SeenStart);Assert.Equal(End.AddTicks(20),store.SeenEnd);}
    [Theory] [InlineData(0L)] [InlineData(9_007_199_254_740_992L)]
    public async Task InvalidWorkspaceEntityIdDoesNotRead(long id)
    {var store=new Store();var e=await Assert.ThrowsAsync<SecurityCandidateException>(()=>new SecurityCandidateOwner(store).ReadAsync(id,Start,End,2,Access(true,true,true,Full()),CancellationToken.None));Assert.Equal("security_events_filter_invalid",e.Code);Assert.Equal(0,store.Preflights);}
    private sealed class NeverConnect:IPostgresConnectionFactory
    {public Task<Npgsql.NpgsqlConnection> OpenAsync(CancellationToken ct)=>throw new InvalidOperationException("not invoked");}
    [Fact] public async Task EntityOutsidePostgresIntegerRangeDoesNotOpenDatabase()
    {var store=new SecurityCandidateStore(new NeverConnect());Assert.Null(await store.EntityAsync((long)int.MaxValue+1,CancellationToken.None));await Assert.ThrowsAsync<ArgumentOutOfRangeException>(()=>store.CandidatesAsync((long)int.MaxValue+1,1,Start,End,2,CancellationToken.None));}
    [Fact] public void RegistrationUsesRealStoreWithoutOpeningDatabase()
    {using var services=new ServiceCollection().AddSingleton<IPostgresConnectionFactory>(new NeverConnect()).AddInvestigationWorkspace().BuildServiceProvider();using var scope=services.CreateScope();Assert.IsType<SecurityCandidateStore>(scope.ServiceProvider.GetRequiredService<ISecurityCandidateStore>());Assert.NotNull(scope.ServiceProvider.GetRequiredService<SecurityCandidateOwner>());Assert.IsType<InvestigationEntityHistory>(scope.ServiceProvider.GetRequiredService<IInvestigationEntityHistory>());}
}
