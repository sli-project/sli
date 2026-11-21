using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Npgsql;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Certificates;
using Sli.Server.Hosting;

namespace Sli.Server.Agents.Registry;

public sealed class AgentIdentityService(AgentIssuingCa ca, AgentLinkHistory? links = null,
    AgentCertificateRejections? rejections = null) : IAgentIdentityService
{
    public Task<AgentIdentity> AuthenticateAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        X509Certificate2 certificate, bool lifecycle, CancellationToken cancellationToken) => AuthenticateCoreAsync(connection,transaction,certificate,lifecycle,false,cancellationToken);
    public Task<AgentIdentity> AuthenticateRemovalAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        X509Certificate2 certificate, CancellationToken cancellationToken) => AuthenticateCoreAsync(connection,transaction,certificate,false,true,cancellationToken);
    private async Task<AgentIdentity> AuthenticateCoreAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        X509Certificate2 certificate, bool lifecycle, bool removalOnly, CancellationToken cancellationToken)
    {
        ca.VerifyClient(certificate);
        Guid agentId;
        try
        {
            var name = new AsnReader(certificate.SubjectName.RawData, AsnEncodingRules.DER).ReadSequence();
            var rdn = name.ReadSetOf();
            var attribute = rdn.ReadSequence();
            if (attribute.ReadObjectIdentifier() != "2.5.4.3") throw new CryptographicException();
            var tag = attribute.PeekTag();
            var value = attribute.ReadCharacterString((UniversalTagNumber)tag.TagValue);
            if (attribute.HasData || rdn.HasData || name.HasData || !Guid.TryParse(value, out agentId)) throw new CryptographicException();
        }
        catch (Exception ex) when (ex is CryptographicException or AsnContentException or ArgumentException)
        { throw new AgentCertificateException("agent_certificate_rejected", 401); }

        await using var agentCommand = new NpgsqlCommand("select id, host_id, key_fingerprint, status, last_seen, collection_policy from sli_agents where id=@id " +
            (lifecycle ? "for update" : "for no key update"), connection, transaction);
        agentCommand.Parameters.AddWithValue("id", agentId);
        AgentIdentity identity;
        DateTimeOffset? previous;
        JsonObject policy;
        await using (var reader = await agentCommand.ExecuteReaderAsync(cancellationToken))
        {
            if (!await reader.ReadAsync(cancellationToken)) throw Reject();
            identity = new(reader.GetGuid(0), reader.GetGuid(1), reader.GetString(2), reader.GetString(3));
            previous = reader.IsDBNull(4) ? null : new DateTimeOffset(reader.GetDateTime(4));
            policy = JsonNode.Parse(reader.GetString(5))!.AsObject();
        }
        if (identity.Status != "active" && !removalOnly) throw Reject();
        try
        {
            var extension = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single();
            var san = new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadSequence();
            var uri = new Asn1Tag(TagClass.ContextSpecific, 6);
            if (san.ReadCharacterString(UniversalTagNumber.IA5String, uri) != $"urn:sli:agent:{identity.Id}" ||
                san.ReadCharacterString(UniversalTagNumber.IA5String, uri) != $"urn:sli:host:{identity.HostId}" || san.HasData) throw Reject();
        }
        catch (Exception ex) when (ex is AsnContentException or InvalidOperationException or ArgumentException)
        { throw Reject(); }
        var serialBytes = certificate.GetSerialNumber();
        Array.Reverse(serialBytes);
        var serial = Convert.ToHexString(serialBytes).TrimStart('0').ToLowerInvariant();
        if (serial.Length == 0) serial = "0";
        var fingerprint = SHA256.HashData(certificate.RawData);
        await using var certCommand = new NpgsqlCommand("select fingerprint, not_after, revoked_at from sli_agent_certificates where agent_id=@id and serial=@serial for update", connection, transaction);
        certCommand.Parameters.AddWithValue("id", agentId);
        certCommand.Parameters.AddWithValue("serial", serial);
        DateTime? revokedAt=null;
        await using (var reader = await certCommand.ExecuteReaderAsync(cancellationToken))
        {
            if (!await reader.ReadAsync(cancellationToken) || reader.GetFieldValue<DateTime>(1) <= DateTime.UtcNow) throw Reject();
            revokedAt=reader.IsDBNull(2)?null:reader.GetDateTime(2);
            var stored = reader.GetString(0);
            byte[] bytes;
            try { bytes = Convert.FromHexString(stored); } catch (FormatException) { throw Reject(); }
            if (!CryptographicOperations.FixedTimeEquals(bytes, fingerprint)) throw Reject();
            // Registry revocation is checked here because the listener's TLS chain policy is offline.
            if (revokedAt is not null && !removalOnly)
            {
                rejections?.Record(certificate, "revoked");
                throw Reject();
            }
        }
        if(removalOnly) {
            await using var removal=new NpgsqlCommand("select state,requested_at from sli_agent_removals where agent_id=@id for update",connection,transaction);
            removal.Parameters.AddWithValue("id",agentId);await using var reader=await removal.ExecuteReaderAsync(cancellationToken);
            if(!await reader.ReadAsync(cancellationToken) || identity.Status!="disabled" || revokedAt is null ||
                reader.GetString(0)=="state_cleaned" || revokedAt<reader.GetDateTime(1))throw Reject();
        }
        await using var update = new NpgsqlCommand("update sli_agents set last_seen=clock_timestamp() where id=@id returning last_seen", connection, transaction);
        update.Parameters.AddWithValue("id", agentId);
        var observed = new DateTimeOffset((DateTime)(await update.ExecuteScalarAsync(cancellationToken))!);
        links?.Contact(agentId, previous, observed, policy["interval_seconds"]?.GetValue<long>() ?? 60,
            identity.Status == "active" && (policy["state"]?.GetValue<string>() ?? "active") == "active");
        return identity;
    }
    private static AgentCertificateException Reject() => new("agent_certificate_rejected", 401);
}
