using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Npgsql;
using Sli.Agent.Core;
using Sli.Server.Semantic;

namespace Sli.Server.Reporting.V2;

public sealed partial class FileAuditReportReader
{
    private static Guid? SnapshotId(JsonNode? node)
    {
        if (node is null) return null;
        if (!Guid.TryParseExact(node.ToString(), "D", out var id) || id == Guid.Empty)
            throw new ReportRequestException("file_audit_snapshot_invalid");
        return id;
    }

    private static DateTime WindowEnd(ReportQueryContext context) =>
        DateTimeOffset.Parse(context.Params["period"]!["to_utc"]!.GetValue<string>(), CultureInfo.InvariantCulture).UtcDateTime;

    private static async Task<JsonObject> ObjectRows(ISemanticSession session, ReportQueryContext context,
        JsonArray roots, JsonObject? after, CancellationToken ct)
    {
        var id = SnapshotId(context.Params["snapshot_id"]);
        var result = await session.QueryAsync(
            "select public.read_file_audit_objects416($1::jsonb,$2::uuid,$3::timestamptz,$4,$5,$6,$7,$8::jsonb,$9) as data", ct,
            roots, id, WindowEnd(context), context.Params["path"]?.GetValue<string>(),
            context.Params.Text("include_nested", "true") == "true", context.Params["employee"]?.GetValue<string>(),
            context.Params["operation"]?.GetValue<string>(), after, context.Paging.Limit);
        return result[0]!["data"]!.AsObject();
    }

    public async Task<JsonObject> DetailAsync(ReportQueryContext context, string rowId, CancellationToken ct)
    {
        if (context.Definition.Key != "file-audit.permissions")
            throw new ReportRequestException("report_detail_not_available", 404);
        if (!Guid.TryParseExact(rowId, "D", out var snapshot) || snapshot == Guid.Empty)
            throw new ReportRequestException("file_audit_snapshot_not_found", 404);
        var selected = Array(context.Params["share"]);
        if (selected.Count != 1) throw new ReportRequestException("file_audit_resource_required");
        var compared = SnapshotId(context.Params["compare_snapshot_id"]);
        try
        {
            await using var session = await database.OpenAsync(false, ct);
            var discovered = Array((await session.QueryAsync("select sli_plugin_file_audit.report_roots() as roots", ct))[0]!["roots"]);
            if (discovered.Count > 1000) throw new ReportRequestException("file_audit_root_limit");
            var root = discovered.OfType<JsonObject>().SingleOrDefault(r => Admitted(context, r)
                && ShareKey(r) == selected[0]!.GetValue<string>()
                && (context.Params["source_kind"] is null || (Text(r, "source_kind") ?? "server") == context.Params.Text("source_kind")));
            if (root is null) throw new ReportRequestException("file_audit_snapshot_not_found", 404);
            string path;
            try
            {
                path = FileAuditPolicy.LocalPath(context.Params["path"]?.GetValue<string>() ?? root["path"]!.GetValue<string>());
                if (!FileAuditPolicy.InRoot(path, root["path"]!.GetValue<string>()))
                    throw new ReportRequestException("file_audit_object_not_found", 404);
            }
            catch (AgentException) { throw new ReportRequestException("file_audit_object_not_found", 404); }
            async Task<JsonObject?> Read(Guid id) => (await session.QueryAsync(
                "select public.read_file_audit_snapshot416($1::jsonb,$2::uuid,$3::timestamptz,$4) as snapshot", ct,
                root, id, WindowEnd(context), path))[0]!["snapshot"] as JsonObject;
            var current = await Read(snapshot) ?? throw new ReportRequestException("file_audit_snapshot_not_found", 404);
            var prior = compared is { } before ? await Read(before) : null;
            var detail = SnapshotDetail(current);
            detail["comparison"] = CompareSnapshots(current, prior, compared is not null);
            var coverage = new JsonObject
            {
                ["state"] = "unknown", ["completeness"] = "not_proven",
                ["inventory_scope"] = "retained_snapshot_page",
                ["object_state"] = current["object_state"]?.DeepClone(),
                ["snapshots_has_more"] = current["snapshots_has_more"]?.DeepClone() ?? JsonValue.Create(false),
                ["objects_has_more"] = current["objects_has_more"]?.DeepClone() ?? JsonValue.Create(false),
                ["observed_at_utc"] = current["snapshot"]?["observed_at"]?.DeepClone()
            };
            var result = ReportResult.Create(context.Definition.Key, "partial", coverage: coverage,
                collections: new JsonObject
                {
                    ["objects"] = current["objects"]?.DeepClone() ?? new JsonArray(),
                    ["snapshots"] = current["snapshots"]?.DeepClone() ?? new JsonArray()
                });
            result["detail"] = detail;
            result["window"] = context.Params["period"]!.DeepClone();
            result["window"]!["timezone"] = context.Paging.Timezone;
            result["window"]!["export_row_limit"] = 10000;
            await session.CommitAsync(ct);
            return result;
        }
        catch (PostgresException e) when (e.SqlState == "57014")
        { return ReportResult.Create(context.Definition.Key, "error", coverage: new() { ["reason"] = "source_timeout" }); }
        catch (PostgresException e) when (e.SqlState is "42883" or "42P01" or "42501") { return Unreadable(context); }
        catch (NpgsqlException) { return Unreadable(context); }
    }

    internal static JsonObject SnapshotDetail(JsonObject raw)
    {
        var obj = raw["object"] as JsonObject;
        var share = raw["share"] as JsonObject;
        return new JsonObject
        {
            ["snapshot"] = raw["snapshot"]?.DeepClone(),
            ["resource"] = raw["root"]?.DeepClone(),
            ["object"] = obj is null ? null : new JsonObject
            {
                ["path"] = obj["path"]?.DeepClone(), ["object_type"] = obj["object_type"]?.DeepClone(),
                ["owner_sid"] = obj["owner_sid"]?.DeepClone(), ["file_id"] = obj["object_id"]?.DeepClone(),
                ["dacl"] = DescribeAcl(Text(obj, "dacl"), "D"),
                ["sacl"] = DescribeAcl(Text(obj, "sacl"), "S"),
                ["sacl_protected"] = obj["sacl_protected"]?.DeepClone()
            },
            ["share"] = new JsonObject
            {
                ["name"] = share?["name"]?.DeepClone() ?? raw["root"]?["share_name"]?.DeepClone(),
                ["path"] = share?["path"]?.DeepClone() ?? raw["root"]?["path"]?.DeepClone(),
                ["complete"] = share?["complete"]?.DeepClone(),
                ["dacl"] = DescribeAcl(Text(share, "dacl"), "D", share?["complete"]?.ToString() == "true")
            }
        };
    }

    internal static JsonObject CompareSnapshots(JsonObject current, JsonObject? prior, bool requested)
    {
        JsonObject Unavailable(string reason) => new()
            { ["state"] = "unavailable", ["reason"] = reason, ["identity_basis"] = null };
        if (!requested) return new() { ["state"] = "not_requested", ["reason"] = null, ["identity_basis"] = null };
        if (prior is null) return Unavailable("snapshot_unavailable");
        if (Text(current["snapshot"], "id") == Text(prior["snapshot"], "id")) return Unavailable("same_snapshot");
        if (current["root"] is not JsonObject currentRoot || prior["root"] is not JsonObject priorRoot
            || ShareKey(currentRoot) != ShareKey(priorRoot))
            return Unavailable("source_generation_mismatch");
        var currentGeneration = Text(current["snapshot"], "source_generation");
        var priorGeneration = Text(prior["snapshot"], "source_generation");
        if (currentGeneration != priorGeneration) return Unavailable("source_generation_mismatch");
        var a = current["object"] as JsonObject; var b = prior["object"] as JsonObject;
        if (a is null || b is null) return Unavailable("object_unavailable");
        if (!string.Equals(Text(a, "path"), Text(b, "path"), StringComparison.OrdinalIgnoreCase))
            return Unavailable("path_mismatch");
        if (Text(a, "object_type") != Text(b, "object_type")) return Unavailable("object_type_mismatch");
        var currentPolicy = current["policy"]?.DeepClone() as JsonObject;
        var priorPolicy = prior["policy"]?.DeepClone() as JsonObject;
        currentPolicy?.Remove("policy_revision"); priorPolicy?.Remove("policy_revision");
        if (currentPolicy is null || priorPolicy is null || !JsonNode.DeepEquals(currentPolicy, priorPolicy))
            return Unavailable("policy_incompatible");
        string? currentId = Text(a, "object_id"), priorId = Text(b, "object_id");
        bool stableIds = !string.IsNullOrWhiteSpace(currentId) && !string.IsNullOrWhiteSpace(priorId);
        if (stableIds && currentId != priorId) return Unavailable("object_replaced");
        var before = prior; var after = current;
        if (DateTimeOffset.Parse(Text(prior["snapshot"], "observed_at")!, CultureInfo.InvariantCulture)
            > DateTimeOffset.Parse(Text(current["snapshot"], "observed_at")!, CultureInfo.InvariantCulture))
            (before, after) = (after, before);
        return new JsonObject
        {
            ["state"] = "available", ["reason"] = null, ["identity_basis"] = stableIds ? "file_id" : "path",
            ["generation_basis"] = currentGeneration is null ? "source_instance_id" : "source_generation",
            ["before"] = SnapshotDetail(before), ["after"] = SnapshotDetail(after)
        };
    }

    // Presentation only. Preserve ACE order, flags, raw masks and unsupported
    // records; this parser never makes an effective-access decision.
    internal static JsonObject DescribeAcl(string? raw, string layer, bool sourceComplete = true)
    {
        var aces = new JsonArray();
        JsonObject Result(string state) => new() { ["state"] = state, ["raw"] = raw, ["aces"] = aces };
        if (raw is null) return Result("missing");
        if (raw.Length > 65536 || !raw.StartsWith(layer + ":", StringComparison.Ordinal)) return Result("unsupported");
        int first = raw.IndexOf('(');
        string header = first < 0 ? raw[2..] : raw[2..first];
        bool supported = Regex.IsMatch(header, @"\A(?:P|AI|AR)*\z");
        int offset = first < 0 ? raw.Length : first;
        while (offset < raw.Length)
        {
            if (raw[offset] != '(') { supported = false; break; }
            int end = offset + 1, depth = 1; bool quoted = false;
            for (; end < raw.Length && depth > 0; end++)
            {
                if (raw[end] == '\\' && quoted && end + 1 < raw.Length) { end++; continue; }
                if (raw[end] == '"') { quoted = !quoted; continue; }
                if (!quoted && raw[end] == '(') depth++;
                else if (!quoted && raw[end] == ')') depth--;
            }
            if (depth != 0) { supported = false; break; }
            string original = raw[offset..end];
            string[] fields = original[1..^1].Split(';');
            if (fields.Length < 6) { supported = false; break; }
            string kind = fields[0], flags = fields[1], maskRaw = fields[2], sid = fields[5];
            var flagArray = new JsonArray();
            for (int n = 0; n < flags.Length; n += 2) flagArray.Add(flags.Substring(n, Math.Min(2, flags.Length - n)));
            var flagValues = flagArray.Select(n => n!.ToString()).ToHashSet(StringComparer.Ordinal);
            var knownFlags = new HashSet<string>(["OI", "CI", "NP", "IO", "ID", "SA", "FA"], StringComparer.Ordinal);
            uint? mask = AclMask(maskRaw);
            supported &= fields.Length == 6 && fields[3].Length == 0 && fields[4].Length == 0
                && kind is "A" or "D" or "AU" or "AL" && mask is not null && flagValues.IsSubsetOf(knownFlags);
            sid = AclSidAliases.GetValueOrDefault(sid, sid);
            supported &= Regex.IsMatch(sid, @"\AS-1-(?:[0-9]+-)*[0-9]+\z");
            aces.Add(new JsonObject
            {
                ["ordinal"] = aces.Count + 1, ["type"] = kind switch { "A" => "allow", "D" => "deny", "AU" or "AL" => "audit", _ => "unknown" },
                ["ace_type"] = kind, ["sid"] = sid, ["mask"] = mask is { } value ? JsonValue.Create(value) : null,
                ["mask_raw"] = maskRaw, ["flags"] = flagArray, ["flags_raw"] = flags,
                ["inherited"] = flagValues.Contains("ID"), ["inherit_only"] = flagValues.Contains("IO"), ["raw"] = original
            });
            offset = end;
        }
        var result = Result(!supported ? "unsupported" : !sourceComplete ? "partial" : "complete");
        result["flags_raw"] = header;
        return result;
    }

    private static readonly Dictionary<string, string> AclSidAliases = new(StringComparer.Ordinal)
    {
        ["WD"] = "S-1-1-0", ["AU"] = "S-1-5-11", ["SY"] = "S-1-5-18", ["BA"] = "S-1-5-32-544",
        ["BU"] = "S-1-5-32-545", ["AN"] = "S-1-5-7", ["CO"] = "S-1-3-0", ["CG"] = "S-1-3-1"
    };
    private static readonly Dictionary<string, uint> AclRights = new(StringComparer.Ordinal)
    {
        ["FA"] = 0x1f01ff, ["FR"] = 0x120089, ["FW"] = 0x120116, ["FX"] = 0x1200a0,
        ["SD"] = 0x10000, ["RC"] = 0x20000, ["WD"] = 0x40000, ["WO"] = 0x80000,
        ["GA"] = 0x10000000, ["GR"] = 0x80000000, ["GW"] = 0x40000000, ["GX"] = 0x20000000
    };
    private static uint? AclMask(string value)
    {
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return uint.TryParse(value[2..], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var hex) ? hex : null;
        uint mask = 0;
        for (int i = 0; i < value.Length; i += 2)
        {
            if (i + 2 > value.Length || !AclRights.TryGetValue(value.Substring(i, 2), out uint bits)) return null;
            mask |= bits;
        }
        return mask;
    }
}
