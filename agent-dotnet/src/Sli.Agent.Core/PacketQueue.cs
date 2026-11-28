using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Globalization;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

public interface IPacketQueue
{
    /// <summary>Where the module's last capture ended, or null for a new stream.</summary>
    CapturedPosition? Captured(string moduleId);

    /// <summary>Signs and stores one sample. Only a durable write lets the caller advance its source.</summary>
    SignedPacket Capture(IPacketSigner signer, string agentId, Sample sample, DateTimeOffset now);

    IReadOnlyList<SignedPacket> Pending();

    SignedPacket PrepareDelivery(SignedPacket packet, IPacketSigner? signer);

    /// <summary>Closes the oldest packet on exact proof or a final refusal; module disable closes that module's queue.</summary>
    bool Acknowledge(SignedPacket packet, JsonNode? receipt);

    long MaxBytes { get; set; }
}

/// <summary>
/// The durable, ordered packet queue. The size limit pauses capture and never evicts evidence;
/// a packet is deleted only after the server's exact receipt, and the delivery checkpoint is saved before the file is removed.
/// A second process on the same directory is refused.
/// </summary>
public sealed class FilePacketQueue : IPacketQueue, IDisposable
{
    public const string HistoryModuleId = "sli.windows.ad-dc-history";
    private const int QuarantineRetention = 64;
    private readonly string _root;
    private readonly IDurableFiles _files;
    private readonly FileStream _lock;
    private readonly object _gate = new();
    private Dictionary<string, ModuleState> _state = [];

    public FilePacketQueue(string root, IDurableFiles files, long maxBytes, long maxAgeSeconds)
    {
        if (maxBytes <= 0 || maxAgeSeconds <= 0) throw new AgentException("agent_spool_limits_invalid");
        _root = root;
        _files = files;
        MaxBytes = maxBytes;
        files.EnsureDirectory(root);
        try
        {
            _lock = new FileStream(Path.Combine(root, ".lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException)
        {
            throw new AgentException("agent_state_locked");
        }
        try
        {
            lock (_gate) Recover();
        }
        catch
        {
            // A queue that cannot start must not keep the directory locked.
            _lock.Dispose();
            throw;
        }
    }

    public long MaxBytes { get; set; }

    public void Dispose() => _lock.Dispose();

    private sealed class ModuleState
    {
        public long Committed { get; set; }

        public Envelope? Captured { get; set; }

        public bool GapPending { get; set; }
        public string? ExpiredFromUtc { get; set; }
        public string? ExpiredToUtc { get; set; }
        public long Quarantined { get; set; }
        public string? LastRejectionReason { get; set; }
        public string? HardwareDigest { get; set; }

        public ModuleState Clone() => new() { Committed = Committed, Captured = Captured,
            GapPending = GapPending, ExpiredFromUtc = ExpiredFromUtc, ExpiredToUtc = ExpiredToUtc,
            Quarantined = Quarantined, LastRejectionReason = LastRejectionReason, HardwareDigest = HardwareDigest };
    }

    private string StatePath => Path.Combine(_root, "checkpoints.json");

    private string PacketPath(string packetId) => Path.Combine(_root, packetId + ".packet");

    private List<(string Path, SignedPacket Packet)> Entries()
    {
        try
        {
            var entries = new List<(string, SignedPacket)>();
            foreach (var path in _files.List(_root, "*.packet"))
            {
                var packet = SignedPacket.FromJson(JsonNode.Parse(_files.ReadAll(path)!));
                if (Path.GetFileNameWithoutExtension(path) != packet.Envelope.PacketId) throw new AgentException("agent_spool_corrupt");
                entries.Add((path, packet));
            }
            return [.. entries.OrderBy(item => item.Item2.Envelope.ModuleId, StringComparer.Ordinal).ThenBy(item => item.Item2.Envelope.Sequence)];
        }
        catch (Exception exception) when (exception is JsonException or ProtocolException or IOException or ArgumentException or InvalidOperationException)
        {
            throw new AgentException("agent_spool_corrupt");
        }
    }

    private void Recover()
    {
        var state = LoadState();
        var changed = false;
        foreach (var (path, packet) in Entries())
        {
            var envelope = packet.Envelope;
            if (!state.TryGetValue(envelope.ModuleId, out var module)) state[envelope.ModuleId] = module = new ModuleState();
            if (envelope.Sequence <= module.Committed)
            {
                // Crash after the delivery checkpoint but before the delete: the receipt already authorized it.
                _files.Delete(path);
                continue;
            }
            if (module.Captured is null || envelope.Sequence > module.Captured.Sequence)
            {
                module.Captured = envelope;
                changed = true;
            }
        }
        if (changed) SaveState(state);
        _state = state;
    }

    private Dictionary<string, ModuleState> LoadState()
    {
        var raw = _files.ReadAll(StatePath);
        var state = new Dictionary<string, ModuleState>();
        if (raw is null) return state;
        try
        {
            if (JsonNode.Parse(raw) is not JsonObject root) throw new AgentException("agent_spool_corrupt");
            foreach (var (moduleId, node) in root)
            {
                if (node is not JsonObject item || !JsonRead.TryInteger(item["committed"], out var committed) || committed < 0 || committed > long.MaxValue)
                    throw new AgentException("agent_spool_corrupt");
                state[moduleId] = new ModuleState
                {
                    Committed = (long)committed,
                    Captured = JsonRead.IsNull(item["captured"]) ? null : Envelope.Parse(item["captured"]),
                    GapPending = item["gap_pending"]?.GetValue<bool>() ?? false,
                    ExpiredFromUtc = item["expired_from_utc"]?.GetValue<string>(),
                    ExpiredToUtc = item["expired_to_utc"]?.GetValue<string>(),
                    Quarantined = item["quarantined"]?.GetValue<long>() ?? 0,
                    LastRejectionReason = item["last_rejection_reason"]?.GetValue<string>(),
                    HardwareDigest = item["hardware_digest"]?.GetValue<string>(),
                };
            }
            return state;
        }
        catch (Exception exception) when (exception is JsonException or ProtocolException)
        {
            throw new AgentException("agent_spool_corrupt");
        }
    }

    private void SaveState(Dictionary<string, ModuleState> state)
    {
        var root = new JsonObject();
        foreach (var (moduleId, module) in state)
        {
            root[moduleId] = new JsonObject
            {
                ["committed"] = module.Committed,
                ["captured"] = module.Captured?.ToJson(),
                ["gap_pending"] = module.GapPending,
                ["expired_from_utc"] = module.ExpiredFromUtc,
                ["expired_to_utc"] = module.ExpiredToUtc,
                ["quarantined"] = module.Quarantined,
                ["last_rejection_reason"] = module.LastRejectionReason,
            };
            if (module.HardwareDigest is not null) root[moduleId]!["hardware_digest"] = module.HardwareDigest;
        }
        _files.WriteAtomic(StatePath, CanonicalJson.ToBytes(root));
    }

    public CapturedPosition? Captured(string moduleId)
    {
        lock (_gate)
        {
            Recover();
            var captured = _state.GetValueOrDefault(moduleId)?.Captured;
            return captured is null ? null : new CapturedPosition(captured.Generation, captured.CursorAfter);
        }
    }

    public IReadOnlyList<SignedPacket> Pending()
    {
        lock (_gate)
        {
            // Disk usage, not packet age, limits capture.
            Recover();
            return Entries().Select(item => item.Packet).ToList();
        }
    }

    public string? WorkstationHardwareDigest()
    {
        lock (_gate)
        {
            Recover();
            return _state.GetValueOrDefault(WorkstationsModule.ModuleId)?.HardwareDigest;
        }
    }

    public (long Count, string? Reason) FileAuditQuarantine()
    {
        lock (_gate)
        {
            var state = _state.GetValueOrDefault(FileAuditPolicy.ModuleId);
            return state is null ? (0,null) : (state.Quarantined,state.LastRejectionReason);
        }
    }

    public SignedPacket Capture(IPacketSigner signer, string agentId, Sample sample, DateTimeOffset now)
    {
        lock (_gate)
        {
            Recover();
            // An interrupted atomic write was never a captured packet.
            foreach (var temporary in _files.List(_root, ".*.tmp")) _files.Delete(temporary);
            var state = _state.ToDictionary(pair => pair.Key, pair => pair.Value.Clone());
            if (!state.TryGetValue(sample.ModuleId, out var module)) state[sample.ModuleId] = module = new ModuleState();
            var previous = module.Captured;
            if (previous is not null)
            {
                if (previous.AgentId != agentId) throw new AgentException("agent_spool_identity_mismatch");
                if (previous.SourceInstanceId != sample.SourceInstanceId || previous.Channel != sample.Channel) throw new AgentException("agent_capture_stream_changed");
                if (previous.Generation == sample.Generation && previous.CursorAfter != sample.CursorBefore) throw new AgentException("agent_capture_cursor_mismatch");
            }
            if (module.GapPending && (previous?.Sequence ?? 0) == module.Committed) sample = sample with { ContinuityState = "gap" };
            var packet = Packets.Make(signer, agentId, previous is null ? 1 : previous.Sequence + 1, sample, now);
            var entries = Entries();
            var raw = Encoding.ASCII.GetBytes(packet.ToCanonical());
            if (entries.Sum(item => _files.Length(item.Path)) + raw.Length > MaxBytes) throw new QueueFullException("agent_spool_size_limit");
            _files.WriteAtomic(PacketPath(packet.Envelope.PacketId), raw);
            module.Captured = packet.Envelope;
            SaveState(state); // the packet is stored before the captured cursor
            _state = state;
            return packet;
        }
    }

    public SignedPacket PrepareDelivery(SignedPacket packet, IPacketSigner? signer)
    {
        lock (_gate)
        {
            Recover();
            if (_state.GetValueOrDefault(packet.Envelope.ModuleId)?.GapPending != true || packet.Envelope.ContinuityState == "gap") return packet;
            if (signer is null) throw new AgentException("agent_gap_signer_required");
            var envelope = packet.Envelope with { ContinuityState = "gap" };
            var updated = packet with { Envelope = envelope, Signature = Convert.ToBase64String(signer.Sign(Packets.SignedMessage(envelope))) };
            _files.WriteAtomic(PacketPath(envelope.PacketId), Encoding.ASCII.GetBytes(updated.ToCanonical()));
            return updated;
        }
    }

    public bool Acknowledge(SignedPacket packet, JsonNode? receipt)
    {
        var envelope = packet.Envelope;
        var expired = Receipt.IsExpired(envelope, receipt);
        var disabled = Receipt.IsModuleDisabled(envelope, receipt);
        var rejected = Receipt.IsFinalFileAuditRejection(envelope, receipt);
        if (!expired && !disabled && !rejected && !Receipt.IsDeliveryProof(envelope, receipt)) return false;
        lock (_gate)
        {
            Recover();
            var entries = Entries().Where(item => item.Packet.Envelope.ModuleId == envelope.ModuleId).ToList();
            if (entries.Count == 0 || entries[0].Packet.ToCanonical() != packet.ToCanonical()) return false;
            var state = _state.ToDictionary(pair => pair.Key, pair => pair.Value.Clone());
            var module = state[envelope.ModuleId];
            if (envelope.Sequence != module.Committed + 1) return false;
            module.Committed = disabled ? entries[^1].Packet.Envelope.Sequence : envelope.Sequence;
            if (expired || disabled || rejected)
            {
                if (!module.GapPending) module.ExpiredFromUtc = envelope.ObservedAtUtc;
                module.ExpiredToUtc = disabled ? entries[^1].Packet.Envelope.ObservedAtUtc : envelope.ObservedAtUtc;
                module.GapPending = true;
            }
            else if (envelope.ContinuityState == "gap") module.GapPending = false;
            if (!expired && !disabled && !rejected && WorkstationHardware.IsPacket(envelope, packet.Payload))
                module.HardwareDigest = Packets.Digest(packet.Payload["records"]![0]!["payload"]!);
            if (rejected)
            {
                var name = envelope.Sequence.ToString("D19",CultureInfo.InvariantCulture) + "-" + envelope.PacketId + ".rejected";
                _files.WriteAtomic(Path.Combine(_root,name),Encoding.ASCII.GetBytes(packet.ToCanonical()));
                module.Quarantined++;
                module.LastRejectionReason = Receipt.FileAuditRejectionReason(receipt);
            }
            SaveState(state); // the delivery checkpoint before the evidence is deleted
            _state = state;
            foreach(var entry in disabled ? entries : entries.Take(1)) _files.Delete(entry.Path);
            if (rejected)
                foreach (var path in _files.List(_root,"*.rejected").Reverse().Skip(QuarantineRetention)) _files.Delete(path);
            return true;
        }
    }
}
