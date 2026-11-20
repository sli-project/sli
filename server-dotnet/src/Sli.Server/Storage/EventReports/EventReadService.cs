using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Infrastructure;

namespace Sli.Server.Storage.EventReports;

internal sealed class EventReadConfigurationException(string code) : InvalidOperationException(code);

// Read adapters use the application connection, never the storage worker identity.
internal sealed partial class EventReadService(IPostgresConnectionFactory connections,IConfiguration config,IHostEnvironment host,ILogger<EventReadService>? logger=null) : IEventReadService,IEventQueryStore,IAsyncDisposable
{
    public Task<IReadOnlyList<AccessResource>> ResourcesAsync(long id,CancellationToken ct) =>
        ShortResourcesAsync(id,ct);

    public Task<Dictionary<long,JsonObject>> DetailsAsync(long[] ids,bool exact,Func<long,CancellationToken,Task<bool>> admitted,CancellationToken ct) =>
        ShortDetailsAsync(ids,admitted,ct);

    public Task<JsonObject> RelationsAsync(long id,Func<long,CancellationToken,Task<bool>> admitted,CancellationToken ct) =>
        new EventRelationsReader(new EventRelationStore(QueryPgAsync,config),admitted).ReadAsync(id,100,null,TimeSpan.FromSeconds(30),ct);
    public Task<JsonObject> RelationsPageAsync(long id,int limit,string? cursor,Func<long,CancellationToken,Task<bool>> admitted,CancellationToken ct) =>
        new EventRelationsReader(new EventRelationStore(QueryPgAsync,config),admitted).ReadAsync(id,limit,cursor,TimeSpan.FromSeconds(30),ct);

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
