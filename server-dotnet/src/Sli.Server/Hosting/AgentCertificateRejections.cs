using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Sli.Server.Hosting;

public sealed class AgentCertificateRejections(ILogger<AgentCertificateRejections> logger)
{
    private const int Capacity = 2048;
    private const int WarningsPerMinute = 30;
    private readonly Dictionary<string, LinkedListNode<Entry>> entries = new(StringComparer.Ordinal);
    private readonly LinkedList<Entry> recent = new();
    private DateTimeOffset windowStart;
    private int warnings;

    private sealed record Entry(string Thumbprint, Rejection Rejection, DateTimeOffset WarnedAt);
    internal sealed record Rejection(string Reason, DateTimeOffset ObservedAt);

    internal void Record(X509Certificate2 certificate, string reason)
    {
        string thumbprint = certificate.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant();
        bool warn;
        lock (entries)
        {
            var now = DateTimeOffset.UtcNow;
            if (now - windowStart >= TimeSpan.FromMinutes(1))
            {
                windowStart = now;
                warnings = 0;
            }
            entries.TryGetValue(thumbprint, out var node);
            var previous = node?.Value;
            warn = warnings < WarningsPerMinute && (previous is null || previous.Rejection.Reason != reason
                || now - previous.WarnedAt >= TimeSpan.FromMinutes(1));
            if (warn) warnings++;
            if (node is not null) recent.Remove(node);
            else if (entries.Count == Capacity)
            {
                entries.Remove(recent.First!.Value.Thumbprint);
                recent.RemoveFirst();
            }
            entries[thumbprint] = recent.AddLast(new Entry(thumbprint, new Rejection(reason, now),
                warn ? now : previous?.WarnedAt ?? DateTimeOffset.MinValue));
        }
        if (warn)
        {
            var subject = certificate.Subject;
            // The peer controls its public subject. Keep it bounded and on one log line.
            var safeSubject = JsonEncodedText.Encode(subject.AsSpan(0, Math.Min(256, subject.Length))).ToString();
            var description = reason switch
            {
                "untrusted_root" => "untrusted root",
                "unexpected_chain_length" => "unexpected chain length",
                "wrong_eku" => "wrong extended key usage",
                "expired" => "expired",
                "not_yet_valid" => "not yet valid",
                "revoked" => "revoked",
                _ => "invalid chain"
            };
            logger.LogWarning("Agent client certificate rejected ({Reason}). Subject \"{Subject}\", SHA-256 thumbprint {Thumbprint}",
                description, safeSubject, thumbprint);
        }
    }

    internal Dictionary<string, Rejection> Snapshot()
    {
        lock (entries) return entries.ToDictionary(item => item.Key, item => item.Value.Value.Rejection, StringComparer.Ordinal);
    }
}
