using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Core;
using Sli.Agent.Protocol;

namespace Sli.Agent.Windows;

/// <summary>Bounded file evidence. No durable position lives outside the existing signed queue.</summary>
public sealed class FileAuditModule(string hostId, FileAuditPolicy policy, IFileAuditEventSource source,
    Action<string,string> pathCheck, Func<string,bool>? accountCheck = null, Func<TimeSpan>? clock = null, Func<Guid>? newId = null)
{
    public const string ModuleId = FileAuditPolicy.ModuleId;
    public static bool ValidGeneration(string g, string host) => g == host || g.StartsWith(host + ":",StringComparison.Ordinal)
        && Guid.TryParseExact(g[(host.Length+1)..],"D",out var id) && id.ToString() == g[(host.Length+1)..];
    public Sample Collect(CapturedPosition? captured, DateTimeOffset now)
    {
        static AgentException Invalid() => new("file_audit_cursor_invalid");
        now = Iso8601.Truncate(now);
        var before = captured?.CursorAfter ?? Cursor.Start("bookmark");
        var progress = new JsonObject { ["record_id"]=null,["bookmark"]="",["generation"]=hostId };
        if (before.Strategy != "bookmark") throw Invalid();
        if (before.Token != "")
        {
            try { progress = JsonNode.Parse(before.Token)!.AsObject(); }
            catch (Exception e) when (e is System.Text.Json.JsonException or InvalidOperationException or NullReferenceException) { throw Invalid(); }
            if (progress.Any(p => !new[] {"record_id","bookmark","generation","anchor_sha256","since_utc"}.Contains(p.Key))
                || !progress.ContainsKey("record_id") || !JsonRead.TryString(progress["bookmark"],out var bookmark) || bookmark.Length > 3000
                || !JsonRead.TryString(progress["generation"],out var g) || !ValidGeneration(g,hostId)
                || progress["record_id"] is null && bookmark != "" || progress["record_id"] is not null && (!JsonRead.TryInteger(progress["record_id"],out var id) || id < 1 || id > long.MaxValue || bookmark == "")
                || progress.ContainsKey("anchor_sha256") && (!JsonRead.TryString(progress["anchor_sha256"],out var hash) || !Regex.IsMatch(hash,"\\A[0-9a-f]{64}\\z"))
                || progress.ContainsKey("since_utc") && !Iso8601.TryParseUtc(progress["since_utc"]?.ToString(),out _)) throw Invalid();
        }
        var generation = progress["generation"]!.ToString();
        if (captured is not null && (!ValidGeneration(captured.Generation,hostId) || captured.Generation != generation)) throw new AgentException("file_audit_generation_invalid");
        long? start = progress["record_id"]?.GetValue<long>();
        void InitialBound()
        {
            if (progress["record_id"] is null && !progress.ContainsKey("since_utc") && JsonRead.TryInteger(policy.Value["initial_read_hours"],out var hours))
                progress["since_utc"] = Iso8601.Format(now.AddHours(-(int)hours));
        }
        InitialBound();
        var timer = System.Diagnostics.Stopwatch.StartNew();
        TimeSpan Clock() => clock?.Invoke() ?? timer.Elapsed;
        var deadline = Clock() + TimeSpan.FromSeconds(policy.Number("wall_seconds"));
        var filtered = 0; long lost = 0; string? error = null;
        SourceBatch batch;
        try { batch = source.Read((JsonObject)progress.DeepClone(),Math.Min(policy.Number("max_events"),256)); }
        catch (FileAuditJournalGap)
        {
            generation = hostId + ":" + (newId ?? Guid.NewGuid)(); before = Cursor.Start("bookmark"); start = null;
            progress = new JsonObject { ["record_id"]=null,["bookmark"]="",["generation"]=generation }; InitialBound();
            batch = new([]); error = "file_audit_journal_gap";
        }
        catch (Exception e) when (e is EventLogReadException or IOException) { batch = new([]); error = "file_audit_read_failed"; }
        if (batch.BookmarkRecovered) throw new AgentException("file_audit_unproven_gap");
        if (batch.Rows.Count > Math.Min(policy.Number("max_events"),256)) throw new AgentException("file_audit_range_invalid");
        var records = new List<PacketRecord>(); var previous = start;
        var sourceName = policy.Value["source_name"]?.ToString() ?? hostId;
        JsonObject Packet(IReadOnlyList<PacketRecord> items) => CollectionPacket.Make(sourceName,"Security",generation,
            new JsonObject { ["after_record_id"]=start,["last_record_id"]=progress["record_id"]?.DeepClone() },items,"not_proven",
            new JsonObject { ["policy_revision"]=policy.Revision,["filtered_count"]=filtered,["lost_count"]=error is null ? lost : null,["read_error"]=error },now);
        foreach (var raw in batch.Rows)
        {
            if (Clock() >= deadline) break;
            var (row,data) = FileAuditEvents.Parse(raw.Xml,sourceName);
            if (!JsonRead.TryInteger(row["record_id"],out var id) || id <= 0 || id > long.MaxValue || previous is not null && id <= previous
                || raw.Bookmark.Length is < 1 or > 3000) throw new AgentException("file_audit_range_invalid");
            previous = (long)id;
            var (allowed,scopes,path) = FileAuditEvents.Admit(row,data,policy);
            var unavailable = false;
            try
            {
                if (allowed && policy.Workstation && !FileAuditPolicy.ContextEvents.Contains(row["event_id"]!.GetValue<int>()))
                    allowed = (accountCheck ?? throw new AgentException("file_audit_account_unavailable"))(data["SubjectUserSid"]);
                if (allowed && path is not null) foreach (var scope in scopes) pathCheck(path,scope["path"]!.ToString());
            }
            catch (Exception e) when (e is not OperationCanceledException) { allowed = false; unavailable = true; lost++; }
            if (allowed)
            {
                var oldError = error;
                if (row["event_id"]!.GetValue<int>() == 1102) error = "file_audit_journal_gap";
                var masked = FileAuditEvents.Mask(raw.Xml,scopes.Length > 0);
                var candidate = new PacketRecord("event_xml",id,FileAuditEvents.Parse(masked,sourceName).Row);
                if (CanonicalJson.ToBytes(Packet(records.Append(candidate).ToArray())).Length + 128 > Math.Min(policy.Number("max_bytes"),44*1024))
                {
                    if (records.Count == 0 && filtered == 0 && lost == 0) throw new AgentException("file_audit_event_size_limit");
                    error = oldError; break;
                }
                records.Add(candidate);
            }
            else if (!unavailable) filtered++;
            progress["record_id"]=(long)id; progress["bookmark"]=raw.Bookmark; progress["generation"]=generation;
            progress["anchor_sha256"]=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(raw.Xml)));
        }
        var payload = Packet(records);
        if (CanonicalJson.ToBytes(payload).Length > Math.Min(policy.Number("max_bytes"),44*1024)) throw new AgentException("file_audit_event_size_limit");
        var after = progress["record_id"] is not null || generation != hostId || progress.ContainsKey("since_utc") ? new Cursor("bookmark",CanonicalJson.Serialize(progress)) : before;
        return new(ModuleId,hostId,"Security",generation,before,after,payload,PolicyRevision:policy.Revision,
            FilteredCount:filtered,LostCount:error is null ? lost : null,ContinuityState:error is not null || lost > 0 ? "gap" : filtered > 0 ? "filtered" : "not_proven");
    }
}
