using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Agent.Tests.Support;

public static class Helpers
{
    public const string AgentId = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";
    public const string HostId = "6f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f";
    public static readonly DateTimeOffset Now = new(2026, 10, 7, 12, 0, 0, TimeSpan.Zero);

    public static ECDsa NewKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public static IPacketSigner Signer(ECDsa key) => new EcdsaPacketSigner(key);

    /// <summary>A minimal sample of a test-only module with record-id cursors (positions <c>before</c> to <c>after</c>).</summary>
    public static Sample Sample(string before, string after, string module = "sli.test", string generation = "gen-1", string channel = "test")
        => new(module, HostId, channel, generation, new Cursor("record_id", before), new Cursor("record_id", after),
            new JsonObject { ["contract"] = "sli.test.v1", ["records"] = new JsonArray() });

    public static JsonObject Receipt(SignedPacket packet, string status = "committed") => new()
    {
        ["contract_id"] = "sli.agent-receipt.v1",
        ["packet_id"] = packet.Envelope.PacketId,
        ["payload_sha256"] = packet.Envelope.PayloadSha256,
        ["status"] = status,
        ["committed_cursor"] = packet.Envelope.CursorAfter.ToJson(),
        ["evidence_ref"] = "agent-packet:" + packet.Envelope.PacketId,
        ["committed_at_utc"] = Iso8601.Format(Now),
        ["error_code"] = null,
    };

    public static string TempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "sli-agent-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    public static JsonObject ExpiredReceipt(SignedPacket packet) => new()
    {
        ["contract_id"] = Sli.Agent.Protocol.Receipt.ContractId, ["packet_id"] = packet.Envelope.PacketId,
        ["payload_sha256"] = packet.Envelope.PayloadSha256, ["status"] = "rejected",
        ["error_code"] = "agent_packet_expired", ["committed_cursor"] = null,
        ["evidence_ref"] = null, ["committed_at_utc"] = null,
    };

    public static FilePacketQueue Queue(string directory, IDurableFiles? files = null, long maxBytes = 10_000_000, long maxAgeSeconds = 7 * 86400) =>
        new(directory, files ?? new PhysicalDurableFiles(), maxBytes, maxAgeSeconds);
}

/// <summary>Fails chosen operations to prove the queue survives a crash between its steps.</summary>
public sealed class FaultyFiles(IDurableFiles inner) : IDurableFiles
{
    public Func<string, bool>? FailWrite { get; set; }

    public Func<string, bool>? FailDelete { get; set; }

    public void WriteAtomic(string path, ReadOnlySpan<byte> data)
    {
        if (FailWrite?.Invoke(path) == true) throw new IOException("injected");
        inner.WriteAtomic(path, data);
    }

    public void Delete(string path)
    {
        if (FailDelete?.Invoke(path) == true) throw new IOException("injected");
        inner.Delete(path);
    }

    public byte[]? ReadAll(string path) => inner.ReadAll(path);

    public long Length(string path) => inner.Length(path);

    public IReadOnlyList<string> List(string directory, string searchPattern) => inner.List(directory, searchPattern);

    public void EnsureDirectory(string directory) => inner.EnsureDirectory(directory);
}
