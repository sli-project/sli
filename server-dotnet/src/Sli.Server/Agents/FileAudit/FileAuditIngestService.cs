using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.Control;

namespace Sli.Server.Agents.FileAudit;

internal sealed class FileAuditIngestService
{
    public FileAuditIngestService(FileAuditAdEnrichment enrichment) { }

    // Called only after the endpoint authenticates the agent's mTLS identity.
    public Task<JsonObject> Ingest(NpgsqlConnection db,NpgsqlTransaction tx,AgentIdentity identity,JsonNode? input,CancellationToken ct)
        => throw new AgentControlException("module_disabled",503);
}
