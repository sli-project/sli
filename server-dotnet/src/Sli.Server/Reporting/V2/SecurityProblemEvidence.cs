using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Access;
using Sli.Server.Infrastructure;
using Sli.Server.Semantic;

namespace Sli.Server.Reporting.V2;

public interface ISecurityProblemEvidence
{
    Task<JsonObject> PageAsync(ReportQueryContext context, long finding, JsonObject? cursor, CancellationToken ct);
}
public sealed class SecurityProblemEvidence(ISemanticDatabase database) : ISecurityProblemEvidence
{
    public async Task<JsonObject> PageAsync(ReportQueryContext c, long finding, JsonObject? cursor, CancellationToken ct) {
        int limit = Math.Clamp(c.Paging.Limit, 1, 200);
        string? watermark = null; JsonObject? position = null; long after = 0;
        DateTimeOffset? afterTime=null; string? afterRole=null;
        if (cursor is not null) {
            if (cursor["version"]?.ToString() == "2") {
                if (cursor.Count != 3 || cursor["position"] is not JsonObject p || p.Count != 2 || !p.ContainsKey("native_key") || p["storage_kind"]?.ToString() is not ("core_event" or "file_audit_snapshot")) throw new ReportRequestException("invalid_cursor");
                string kind = p.Text("storage_kind"), key = p.Text("native_key");
                if(kind=="core_event") {
                    try {
                        var parts=JsonNode.Parse(key)!.AsArray();
                        if(parts.Count!=3||parts[0]!.GetValue<long>()<=0||!DateTimeOffset.TryParse(parts[1]!.GetValue<string>(),CultureInfo.InvariantCulture,DateTimeStyles.None,out var time)) throw new FormatException();
                        after=parts[0]!.GetValue<long>();afterTime=time;afterRole=parts[2]!.GetValue<string>();
                    }
                    catch(Exception e) when(e is System.Text.Json.JsonException or InvalidOperationException or FormatException or NullReferenceException) { throw new ReportRequestException("invalid_cursor"); }
                }
                else if (!Regex.IsMatch(key,"\\A[a-f0-9]{64}\\z")) throw new ReportRequestException("invalid_cursor");
                position = p; watermark = cursor["watermark"]?.ToString();
                if (watermark is null || !DateTimeOffset.TryParse(watermark, CultureInfo.InvariantCulture, DateTimeStyles.None, out _)) throw new ReportRequestException("invalid_cursor");
            } else {
                // Old positions identify a retired link row, not a copied event.
                throw new ReportRequestException("invalid_cursor");
            }
        }
        await using var session = await database.OpenAsync(false, ct);
        Task<JsonArray> Rows(string sql, params object?[] values) => session.QueryAsync(sql, ct, values);
        watermark ??= (await Rows("select clock_timestamp()::text as watermark"))[0]!["watermark"]!.ToString();
        var allowed = new JsonArray();
        if (c.FieldAccess(["security", "raw_evidence", "identity_basic", "technical"])) {
            var resources = (await Rows("select public.read_file_acl_finding_resources_v265($1::bigint,$2::bigint[]) as resources", finding, c.DomainIds))[0]!["resources"] as JsonArray ?? [];
            if (resources.Count > 128) throw new ReportRequestException("file_audit_access_denied", 403);
            foreach (var resource in resources.OfType<JsonObject>()) {
                string agent = resource.Text("agent_id"), source = resource.Text("source_instance_id"), collection = resource.Text("collection_scope_id");
                if (new[] { agent, source, collection }.Any(s => string.IsNullOrWhiteSpace(s) || s.Length > 256)) continue;
                var group = new AccessResource("plugin") { PluginId = "sli.file-audit", DeviceId = agent, SourceInstanceId = source, CollectionScopeId = collection };
                if (c.Access.Capabilities.DecideForResourceGroups(c.Action == "export" ? "file-audit.export" : "file-audit.view", [[group]]).Allowed) allowed.Add(resource.DeepClone());
            }
        }
        // Copies have source-event time, not insertion time. Do not hide a copy
        // because the source clock was ahead of the server clock.
        long coreCount = (await Rows("select count(*) as total from (select 1 from finding_event_details337 where finding_id=$1 limit 10001) counted", finding))[0]!["total"]!.GetValue<long>();
        var core = new JsonArray();
        if (position is null || position.Text("storage_kind") == "core_event") core = await Rows("""
            select e.event_db_id as evidence_id,e.event_db_id,e.event_id,e.channel,e.time_created_utc,
                   e.event_record_id,e.hostname,e.evidence_role,e.note
            from finding_event_details337 e
            where e.finding_id=$1
              and (e.event_db_id>$2 or e.event_db_id=$2 and $4::timestamptz is not null
                and (e.time_created_utc,e.evidence_role collate "C")>($4::timestamptz,$5::text collate "C"))
            order by e.event_db_id,e.time_created_utc,e.evidence_role collate "C" limit $3
            """, finding, after, limit + 1,afterTime,afterRole);
        var native = new JsonObject { ["items"] = new JsonArray(), ["total"] = 0, ["has_more"] = false };
        if (allowed.Count > 0) native = (await Rows("select public.read_file_acl_finding_evidence($1::bigint,$2::jsonb,$3::text,$4::integer,$5::timestamptz,$6::bigint[]) as evidence", finding, allowed, position?.Text("storage_kind") == "file_audit_snapshot" ? position.Text("native_key") : null, core.Count > limit ? 1 : limit, watermark, c.DomainIds))[0]!["evidence"]!.DeepClone().AsObject();
        foreach (var row in core.OfType<JsonObject>()) { row["storage_kind"] = "core_event"; row["_native_key"] = new JsonArray(row["event_db_id"]!.DeepClone(),row["time_created_utc"]?.DeepClone(),row["evidence_role"]?.DeepClone()).ToJsonString(); }
        var combined = core.Concat(native["items"]!.AsArray()).OfType<JsonObject>().ToArray(); var items = new JsonArray(); int bytes = 0; JsonObject? next = null;
        foreach (var row in combined) {
            int size = Encoding.UTF8.GetByteCount(row.ToJsonString()); if (items.Count >= limit || bytes + size > 4194304) break;
            var clean = row.DeepClone().AsObject(); string key = clean.Text("_native_key"); clean.Remove("_native_key"); items.Add(clean); bytes += size;
            next = new() { ["storage_kind"] = clean["storage_kind"]!.DeepClone(), ["native_key"] = key };
        }
        long? nativeCount = long.TryParse(native["total"]?.ToString(), out long total) ? total : null;
        long? count = nativeCount.HasValue && coreCount <= 10000 && coreCount + nativeCount <= 10000 ? coreCount + nativeCount : null;
        bool more = combined.Length > items.Count || native.Flag("has_more");
        var result = new JsonObject { ["items"] = items, ["total"] = count, ["has_more"] = more, ["watermark"] = watermark, ["next_position"] = more ? next : null };
        if (count is null) result["total_lower_bound"] = coreCount + (nativeCount ?? (long.TryParse(native["total_lower_bound"]?.ToString(), out long lower) ? lower : 0));
        await session.CommitAsync(ct); return result;
    }
}
