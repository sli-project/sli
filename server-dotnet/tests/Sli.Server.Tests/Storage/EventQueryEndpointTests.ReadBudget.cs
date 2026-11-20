using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Sli.Server.Storage.EventReports;
using Xunit;

namespace Sli.Server.Tests.Storage;

public sealed partial class EventQueryEndpointTests
{
    // Cancellation/cleanup vectors from tests/reporting/test_evsearch_read_budget.py.
    // Numeric deadline caps are superseded by Q500's no elapsed-time limits rule.
    static DefaultHttpContext SearchContext(Fixture fixture,CancellationToken ct)
    {
        var context=new DefaultHttpContext { RequestServices=fixture.Services,RequestAborted=ct };
        context.Request.Method="POST";
        context.Request.Path="/api/v1/event-search/query";
        context.Request.ContentType="application/json";
        byte[] body=Encoding.UTF8.GetBytes(Query());
        context.Request.Body=new MemoryStream(body);
        context.Request.ContentLength=body.Length;
        context.Response.Body=new MemoryStream();
        return context;
    }

    [Fact]
    public async Task Search_read_uses_the_callers_cancellation_without_a_new_deadline()
    {
        await using var fixture=await new Fixture().Start();
        using var caller=new CancellationTokenSource();
        fixture.Store.Capture=ct=>
        {
            // A linked token plus an independent timer would change ownership
            // and could terminate live work before the caller cancels it.
            Assert.Equal(caller.Token,ct);
            Assert.False(ct.IsCancellationRequested);
            return Task.FromResult<IReadOnlyList<SearchEvent>>([]);
        };
        var context=SearchContext(fixture,caller.Token);
        await EventQueryEndpoints.HandleAsync(context);
        Assert.Equal(StatusCodes.Status200OK,context.Response.StatusCode);
        Assert.True(context.Response.Body.Length>0);
        Assert.Equal(1,fixture.Store.Captures);
    }

    [Fact]
    public async Task Cancelling_an_active_reader_cleans_up_and_does_not_cancel_the_next_request()
    {
        await using var fixture=await new Fixture().Start();
        using var caller=new CancellationTokenSource();
        var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var observed=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Store.Capture=async ct=>
        {
            var stopped=new TaskCompletionSource<IReadOnlyList<SearchEvent>>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var registration=ct.Register(()=> { observed.TrySetResult(); stopped.TrySetCanceled(ct); });
            entered.SetResult();
            return await stopped.Task;
        };
        var context=SearchContext(fixture,caller.Token);
        Task request=EventQueryEndpoints.HandleAsync(context);
        await entered.Task.WaitAsync(TestContext.Current.CancellationToken);
        Assert.False(request.IsCompleted);
        caller.Cancel();
        await observed.Task.WaitAsync(TestContext.Current.CancellationToken);
        await request.WaitAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0,context.Response.Body.Length); // No frozen success after cancellation.

        fixture.Store.Capture=null;
        var next=await Start(fixture);
        Assert.NotNull(next["execution_id"]);
        Assert.Equal(2,fixture.Store.Captures); // The operation semaphore was released.
    }

    [Fact]
    public async Task Cancellation_after_read_before_snapshot_publication_is_observed()
    {
        await using var fixture=await new Fixture().Start();
        using var caller=new CancellationTokenSource();
        fixture.Store.Capture=_=>
        {
            caller.Cancel();
            return Task.FromResult<IReadOnlyList<SearchEvent>>([]);
        };
        var context=SearchContext(fixture,caller.Token);
        await EventQueryEndpoints.HandleAsync(context);
        Assert.Equal(0,context.Response.Body.Length);
        fixture.Store.Capture=null;
        Assert.NotNull((await Start(fixture))["execution_id"]);
    }

    [Theory]
    [InlineData("timeout","evsearch.snapshot_timeout")]
    [InlineData("cancelled","evsearch.snapshot_timeout")]
    [InlineData("read_failed","evsearch.history_unavailable")]
    public async Task Reader_failure_releases_context_and_preserves_later_requests(string failure,string code)
    {
        await using var fixture=await new Fixture().Start();
        using var caller=new CancellationTokenSource();
        fixture.Store.Error=failure switch
        {
            "timeout"=>new TimeoutException(),
            "cancelled"=>new OperationCanceledException(),
            _=>new IOException()
        };
        var context=SearchContext(fixture,caller.Token);
        await EventQueryEndpoints.HandleAsync(context);
        Assert.Equal(StatusCodes.Status503ServiceUnavailable,context.Response.StatusCode);
        context.Response.Body.Position=0;
        var body=await JsonNode.ParseAsync(context.Response.Body,cancellationToken:TestContext.Current.CancellationToken);
        Assert.Equal(code,body!["error"]!.ToString());
        caller.Cancel();

        fixture.Store.Error=null;
        using var next=await Post(fixture,"query",Query());
        Assert.Equal(HttpStatusCode.OK,next.StatusCode);
        Assert.NotNull((await Body(next))["execution_id"]);
        Assert.Equal(2,fixture.Store.Captures);
    }
}
