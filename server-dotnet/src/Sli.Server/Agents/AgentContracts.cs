using System.Security.Cryptography.X509Certificates;
using Npgsql;

namespace Sli.Server.Agents;

public sealed record AgentIdentity(Guid Id, Guid HostId, string KeyFingerprint, string Status);

public interface IAgentIdentityService
{
    Task<AgentIdentity> AuthenticateAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        X509Certificate2 certificate, bool lifecycle, CancellationToken cancellationToken);
}
