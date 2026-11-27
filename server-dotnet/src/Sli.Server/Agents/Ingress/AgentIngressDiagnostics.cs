using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Ingress;

public sealed record AgentQuotaRejection(Guid AgentId, string ModuleId, string Code,
    IReadOnlyDictionary<string,long> Usage, long Limit, long PacketBytes);

/// <summary>Bounded source-compatible diagnostics; caller invokes rejection logging only after commit.</summary>
public sealed partial class AgentIngressDiagnostics(string dataDirectory, ILogger<AgentIngressDiagnostics> logger, TimeProvider clock, long maxBytes=10_000_000)
{
    private const int Capacity=1024;
    private static readonly TimeSpan Interval=TimeSpan.FromSeconds(60);
    private static readonly string[] UsageFields=["agent_count","agent_bytes","module_count","module_bytes","global_count","global_bytes","storage_bytes"];
    private static readonly HashSet<string> SafeCodes=BuildCodes();
    private static readonly object FileLock=new();
    private readonly object sync=new();
    private readonly Dictionary<(Guid,string,string), LinkedListNode<((Guid,string,string) Key,long When)>> entries=[];
    private readonly LinkedList<((Guid,string,string) Key,long When)> order=[];
    private long? windowStart;
    private int windowCount;

    private static HashSet<string> BuildCodes()
    {
        HashSet<string> codes=["agent_inbox_disk_bytes_limit","agent_inbox_disk_unavailable","agent_delivery_rejected","agent_receipt_invalid","agent_transport_failed","agent_packet_invalid",
            "agent_sequence_gap","agent_sequence_replayed","agent_sequence_conflict","agent_packet_id_conflict","agent_cursor_mismatch",
            "agent_identity_mismatch","agent_stream_identity_changed","agent_reset_invalid","agent_replay_window","agent_packet_expired","agent_history_pending",
            "agent_source_not_bound","agent_module_not_assigned","agent_module_unsupported","agent_heartbeat_invalid",
            "agent_collection_packet_invalid","agent_workstations_packet_invalid","agent_workstations_rate_limit",
            "agent_file_audit_packet_invalid","agent_nps_packet_invalid","agent_snapshot_chunk_invalid","agent_snapshot_cycle_conflict","agent_snapshot_chunk_conflict"];
        foreach (string kind in new[]{"inbox_","snapshot_"}) foreach(string name in UsageFields) codes.Add("agent_"+kind+name+"_limit");
        return codes;
    }

    public static string ResolveDataDirectory(string repositoryRoot, Func<string,string?>? environment=null)
    {
        environment ??= Environment.GetEnvironmentVariable;
        string? configured=environment("ADLOG_DATA_DIR");
        if (string.IsNullOrWhiteSpace(configured)) configured=environment("SLI_DATA_DIR");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            string path=configured.Trim();
            if (path == "~" || path.StartsWith("~/",StringComparison.Ordinal) || path.StartsWith("~\\",StringComparison.Ordinal))
                path=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),path.Length==1 ? "" : path[2..]);
            return Path.GetFullPath(path,repositoryRoot);
        }
        string sibling=Path.Combine(Path.GetDirectoryName(Path.GetFullPath(repositoryRoot))!,"sli_data");
        return Directory.Exists(sibling) ? sibling : Path.Combine(repositoryRoot,"data");
    }

    private bool Allow((Guid,string,string) key)
    {
        lock(sync)
        {
            long now=clock.GetTimestamp();
            if (windowStart is null || clock.GetElapsedTime(windowStart.Value,now) >= Interval) { windowStart=now; windowCount=0; }
            if (windowCount>=Capacity) return false;
            if (entries.TryGetValue(key,out var old) && clock.GetElapsedTime(old.Value.When,now) < Interval) return false;
            windowCount++;
            if (old is not null) { order.Remove(old); entries.Remove(key); }
            var node=order.AddLast((key,now)); entries.Add(key,node);
            while(order.Count>Capacity) { var first=order.First!; entries.Remove(first.Value.Key); order.RemoveFirst(); }
            return true;
        }
    }

    public bool RejectionAfterCommit(AgentIdentity identity, Envelope envelope, JsonObject receipt)
    {
        try
        {
            var valid=Envelope.Parse(envelope.ToJson());
            if (!JsonRead.TryString(receipt["status"],out var status) || status is not ("rejected" or "retry_later")) return false;
            string code=JsonRead.TryString(receipt["error_code"],out var input) && SafeCodes.Contains(input) ? input : "agent_delivery_rejected";
            var reason=Receipt.FileAuditRejectionReason(receipt);
            if (!Allow((identity.Id,valid.ModuleId,reason ?? code))) return false;
            logger.LogWarning("agent_packet_delivery_rejected agent_id={AgentId} module_id={ModuleId} packet_id={PacketId} sequence={Sequence} receipt_status={ReceiptStatus} error_code={ErrorCode} error_reason={ErrorReason}",
                identity.Id.ToString("D"),valid.ModuleId,valid.PacketId,valid.Sequence,status,code,reason);
            return true;
        }
        catch (Exception) { return false; }
    }

    public void QuotaRejected(AgentQuotaRejection rejection)
    {
        if (!ModulePattern().IsMatch(rejection.ModuleId) || !SafeCodes.Contains(rejection.Code)
            || !rejection.Code.StartsWith("agent_inbox_",StringComparison.Ordinal)) return;
        try
        {
            var usage=UsageFields.ToDictionary(name=>name,name=>rejection.Usage.TryGetValue(name,out var value) ? value : 0);
            var payload=new Dictionary<string,object?> { ["ts"]=Iso8601.Format(clock.GetUtcNow()),["level"]="INFO",["component"]="agents",
                ["event"]="packet_quota_rejected",["action"]="agent_packet_admission",["status"]="retry_later",["pid"]=Environment.ProcessId,
                ["thread"]=Thread.CurrentThread.Name ?? "",["agent_id"]=rejection.AgentId.ToString("D"),["module_id"]=rejection.ModuleId,
                ["error_code"]=rejection.Code,["usage"]=usage,["limit"]=rejection.Limit,["packet_bytes"]=rejection.PacketBytes };
            byte[] line=Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload,new JsonSerializerOptions { Encoder=JavaScriptEncoder.UnsafeRelaxedJsonEscaping })+"\n");
            string directory=Path.Combine(dataDirectory,"logs"); Directory.CreateDirectory(directory);
            string path=Path.Combine(directory,"audit-actions.log");
            lock(FileLock)
            {
                using var fileLock=AcquireLock(path+".lock");
                long size=File.Exists(path) ? new FileInfo(path).Length : 0;
                if (size>0 && size+line.Length>Math.Max(1,maxBytes))
                {
                    for (int n=4;n>=1;n--) if (File.Exists(path+"."+n)) File.Move(path+"."+n,path+"."+(n+1),true);
                    if (File.Exists(path+".1")) File.Delete(path+".1");
                    if (File.Exists(path)) File.Move(path,path+".1");
                }
                using var stream=new FileStream(path,FileMode.Append,FileAccess.Write,FileShare.Read);
                stream.Write(line);
            }
        }
        catch (Exception)
        {
            try { logger.LogInformation("packet_quota_rejected agent_id={AgentId} module_id={ModuleId} error_code={ErrorCode}",rejection.AgentId,rejection.ModuleId,rejection.Code); }
            catch (Exception) { }
        }
    }

    private static FileStream AcquireLock(string path)
    {
        long start=Environment.TickCount64;
        while (true)
        {
            try { return new FileStream(path,FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None); }
            catch (IOException) when (Environment.TickCount64-start<2000) { Thread.Sleep(10); }
        }
    }

    [GeneratedRegex(@"\A[a-z][a-z0-9_.-]{0,127}\z",RegexOptions.CultureInvariant)]
    private static partial Regex ModulePattern();
}

