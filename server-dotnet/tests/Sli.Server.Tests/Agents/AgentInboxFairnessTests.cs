using Sli.Server.Agents.Consumer;
using Xunit;

namespace Sli.Server.Tests.Agents;

public sealed class AgentInboxFairnessTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task Short_polls_finish_rounds_and_retry_a_failed_stream_while_another_is_busy(int limit)
    {
        var fairness=new AgentWorkstationInboxConsumer.StreamFairness();
        var queue=new QueueDouble(fairness,limit,continuallyArriving:true);
        for(int poll=0;poll<9;poll++) {
            queue.BeginPoll();
            await fairness.PollAsync(limit,queue.ProcessAsync,[]);
        }
        Assert.InRange(queue.FailedAttempts,3,9*limit);
        Assert.True(queue.Imported>0);
        Assert.Equal(queue.Attempts.Count,queue.Attempts.Distinct().Count());
    }

    [Fact]
    public async Task Permanent_failure_is_tried_once_per_round_and_does_not_block_another_stream()
    {
        const int limit=16;
        var fairness=new AgentWorkstationInboxConsumer.StreamFairness();
        var queue=new QueueDouble(fairness,limit,continuallyArriving:true);
        await fairness.PollAsync(limit,queue.ProcessAsync,[]);
        Assert.Equal(limit,queue.Scanned);
        Assert.InRange(queue.FailedAttempts,2,limit-1);
        Assert.Equal(limit-queue.FailedAttempts,queue.Imported);
        Assert.Equal(queue.Attempts.Count,queue.Attempts.Distinct().Count());
        Assert.InRange(queue.Steps,limit,2*limit+1);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Empty_or_only_failed_queue_finishes_without_restarting_an_empty_round(bool failedPacket)
    {
        const int limit=16;
        var fairness=new AgentWorkstationInboxConsumer.StreamFairness();
        var queue=new QueueDouble(fairness,limit,empty:!failedPacket);
        Assert.True(await fairness.PollAsync(limit,queue.ProcessAsync,[]));
        Assert.Equal(failedPacket?1:0,queue.Scanned);
        Assert.Equal(0,queue.Imported);
        Assert.InRange(queue.Steps,1,3);
    }

    // Only the claim/import boundary is doubled. The poll loop and stream state are production code.
    // An extra empty round fails by step count even if the poll would otherwise run forever.
    private sealed class QueueDouble(AgentWorkstationInboxConsumer.StreamFairness fairness,int limit,bool continuallyArriving=false,bool empty=false)
    {
        private readonly DateTime received=new(2026,10,7,0,0,0,DateTimeKind.Utc);
        private int round,nextB=1,stepsInPoll;
        public int Steps { get; private set; }
        public int Scanned { get; private set; }
        public int Imported { get; private set; }
        public int FailedAttempts { get; private set; }
        public List<(int Round,string Stream)> Attempts { get; }=[];
        public void BeginPoll() => stepsInPoll=0;

        public Task<AgentInboxStep> ProcessAsync()
        {
            Steps++;
            Assert.True(++stepsInPoll<=2*limit+1,"Poll exceeded the claim-step budget");
            if(!empty && CanClaim("A",received)) {
                Scanned++; FailedAttempts++; Attempts.Add((round,"A"));
                return Task.FromResult(new AgentInboxStep(true,false,"agent_projection_failed",received,Guid.Empty) { StreamKey="A" });
            }
            if(continuallyArriving && CanClaim("B",received.AddSeconds(nextB))) {
                Scanned++; Imported++; Attempts.Add((round,"B"));
                return Task.FromResult(new AgentInboxStep(true,true,null,received.AddSeconds(nextB++),Guid.Empty) { StreamKey="B" });
            }
            round++;
            return Task.FromResult(new AgentInboxStep(false,false,null,default,default));
        }

        private bool CanClaim(string stream,DateTime time) => !fairness.Served.Contains(stream)
            && (!fairness.Passed.TryGetValue(stream,out var cursor) || time>cursor.Received);
    }
}
