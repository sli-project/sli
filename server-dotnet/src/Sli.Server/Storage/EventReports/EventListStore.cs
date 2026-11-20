using System.Text.Json.Nodes;
using Sli.Server.Access;

namespace Sli.Server.Storage.EventReports;

internal sealed partial class EventReadService
{
    public Task<JsonObject> ListAsync(EventListInput input,CapabilityDecisionSet capabilities,CancellationToken ct) =>
        ListShortAsync(input,capabilities,ct);
}
