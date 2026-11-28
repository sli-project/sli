using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

public static class AdSecurity
{
    internal static readonly string[] ChangeViews = ["all", "accounts", "groups", "passwords", "audit"];
    internal static Guid? OwnAuditGpo(IConfiguration? configuration, long domain)
    {
        var identity = configuration?.GetSection($"Sli:OwnActions:AuditGpo:{domain}");
        return Guid.TryParse(identity?["Guid"], out var id) && id != Guid.Empty
            && identity?["Name"] is { Length: > 0 and <= 256 } ? id : null;
    }

    internal static int[] ChangeEventIds() => AdReportStore.EventIds("security")
        .Where(id => ChangeView(id) is not null)
        .Concat([4739, 5136, 5137, 5141]).Distinct().Order().ToArray();
    internal static string? ChangeView(long id) => id switch
    {
        5136 or 5137 or 5141 => "accounts",
        4739 => "audit",
        1102 => null,
        _ => Family(id) switch
        {
            "account_lock" or "account_lifecycle" or "account_change" => "accounts",
            "group_membership" or "group_lifecycle" => "groups",
            "password_operation" => "passwords",
            "audit_configuration" => "audit",
            _ => null
        }
    };

    internal static string? Family(long id) => AdHistory.Map("_SECURITY_EVENT_FAMILY_BY_EVENT_ID")[id.ToString()]?.GetValue<string>();
    public static JsonObject Normalize(IQueryCollection query, bool domainChanges = false)
    {
        var filters = new JsonObject();
        bool changes = domainChanges && query.ContainsKey("changes_view");
        foreach (string key in new[] { "category", "event_id", "outcome", "actor", "target", "group", "source", "q", "entity_id", "event_db_id" })
        {
            string? value = query[key].FirstOrDefault()?.Trim(); if (string.IsNullOrEmpty(value)) continue;
            if (value.EnumerateRunes().Count() > 256) throw new AdInputException("security_events_filter_invalid");
            string name = key switch { "target" => "target_account", "source" => "source_host", _ => key };
            if (key is "event_id" or "entity_id" or "event_db_id")
            {
                if (!long.TryParse(value, out long id) || id <= 0 || key == "event_id" && Family(id) is null && !(changes && (ChangeView(id) is not null || id is 4697 or 7045))) throw new AdInputException("security_events_filter_invalid");
                filters[name] = id;
            }
            else filters[name] = key is "category" or "outcome" ? value.ToLowerInvariant() : value;
        }
        if (filters.Text("category") is {} category && !AdHistory.Map("_SECURITY_EVENT_FAMILY_BY_EVENT_ID").Any(p => p.Value!.GetValue<string>() == category)
            || filters["event_id"] is not null && filters.Text("category") is {} selected && Family(filters.Int("event_id")) != selected
            || filters.Text("outcome") is {} outcome && outcome is not ("success" or "failure" or "unknown")) throw new AdInputException("security_events_filter_invalid");
        if (changes && query["changes_view"].FirstOrDefault() is {} view)
        {
            if (!ChangeViews.Contains(view)) throw new AdInputException("security_events_filter_invalid");
            filters["changes_view"] = view;
            string mode = query["repeat_mode"].FirstOrDefault() ?? "collapsed";
            if (mode is not ("collapsed" or "individual")) throw new AdInputException("security_events_filter_invalid");
            filters["repeat_mode"] = mode;
            string order = query["changes_order"].FirstOrDefault() ?? "desc";
            if (order is not ("asc" or "desc")) throw new AdInputException("security_events_filter_invalid");
            filters["changes_order"] = order;
            if (query["batch"].FirstOrDefault() is {} batch)
            {
                if (mode != "collapsed" || !long.TryParse(batch, out long anchor) || anchor <= 0)
                    throw new AdInputException("security_events_filter_invalid");
                filters["batch"] = anchor;
            }
        }
        return filters;
    }
    private static readonly byte[] CursorPrefix = Encoding.UTF8.GetBytes("sli.security-events.v1\0");
    public static string EncodeCursor(long domain, AdPeriod p, JsonObject filters, DateTimeOffset time, long id, string summaryKey = "")
    {
        var body = new JsonArray("v1", domain, Iso(p.Start), Iso(p.End), Iso(time), id, filters.DeepClone());
        if (summaryKey.Length > 0) body.Add(summaryKey);
        byte[] payload = Encoding.UTF8.GetBytes(body.ToJsonString(new JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
        byte[] signature = SHA256.HashData([.. CursorPrefix, .. payload])[..12];
        return Convert.ToBase64String([.. signature, .. payload]).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
    public static (DateTimeOffset Time, long Id) DecodeCursor(string cursor, long domain, AdPeriod p, JsonObject filters)
    {
        var decoded = DecodeGroupCursor(cursor,domain,p,filters);
        return (decoded.Time,decoded.Id);
    }
    internal static (DateTimeOffset Time, long Id, string Group) DecodeGroupCursor(string cursor, long domain, AdPeriod p, JsonObject filters)
    {
        try
        {
            if (cursor.Length > 16384) throw new FormatException();
            string base64 = cursor.Replace('-', '+').Replace('_', '/');
            byte[] raw = Convert.FromBase64String(base64.PadRight((base64.Length + 3) / 4 * 4, '='));
            if (raw.Length <= 12 || !CryptographicOperations.FixedTimeEquals(raw[..12], SHA256.HashData([.. CursorPrefix, .. raw[12..]])[..12])) throw new FormatException();
            var body = JsonNode.Parse(raw[12..])!.AsArray();
            if (body.Count is not (7 or 8) || body[0]!.GetValue<string>() != "v1" || body[1]!.GetValue<long>() != domain || body[2]!.GetValue<string>() != Iso(p.Start) || body[3]!.GetValue<string>() != Iso(p.End) || !JsonNode.DeepEquals(body[6], filters) || (body[5]!.GetValue<long>() < 0 || body[5]!.GetValue<long>() == 0 && (body.Count != 8 || body[7]?.ToString().Length != 64))) throw new FormatException();
            return (DateTimeOffset.Parse(body[4]!.GetValue<string>(), CultureInfo.InvariantCulture), body[5]!.GetValue<long>(), body.Count == 8 ? body[7]!.GetValue<string>() : "");
        }
        catch (Exception e) when (e is FormatException or JsonException or InvalidOperationException or ArgumentException or NullReferenceException) { throw new AdInputException("invalid_cursor"); }
    }
    internal static string OutcomeValue(JsonObject row)
    {
        long id = row.Int("event_id");
        if (AdHistory.Map("_SECURITY_EVENT_STATIC_OUTCOME_BY_EVENT_ID")[id.ToString()] is {} value) return value.GetValue<string>();
        if (!AdHistory.Ids("SECURITY_EVENTS_MIXED_OUTCOME_EVENT_IDS").Contains((int)id)) return "unknown";
        string keywords = (row.Text("audit_keywords") ?? "").ToLowerInvariant();
        foreach (string outcome in new[] { "success", "failure" })
            if (AdHistory.Taxonomy["SECURITY_AUDIT_" + outcome.ToUpperInvariant() + "_KEYWORDS"]!.AsArray().Any(k => k!.GetValue<string>() == keywords) || keywords.Replace(" ", "").Contains("audit" + outcome)) return outcome;
        if (ulong.TryParse(keywords.StartsWith("0x") ? keywords[2..] : keywords, keywords.StartsWith("0x") ? NumberStyles.HexNumber : NumberStyles.Integer, CultureInfo.InvariantCulture, out ulong bits))
        { bool success = (bits & 0x0020000000000000) != 0, failure = (bits & 0x0010000000000000) != 0; if (success != failure) return success ? "success" : "failure"; }
        return "unknown";
    }
    public static JsonObject Compose(AdReportRequest request, IReadOnlyList<JsonObject> events, bool history, bool more, JsonObject categories)
    {
        var items = new List<JsonObject>();
        foreach (var e in events)
        {
            long id = e.Int("event_id");
            string? family = request.Filters["changes_view"] is not null ? id switch
            {
                5136 or 5137 or 5141 => "directory_change",
                4739 => "domain_configuration",
                _ => Family(id),
            } : Family(id);
            if (family is null) throw new AdInputException("security_events_event_invalid");
            if(e["day"] is not null)throw new AdInputException("security_events_event_identity_invalid");
            if (e.Int("event_db_id") <= 0 || items.Any(i => i.Int("event_db_id") == e.Int("event_db_id"))) throw new AdInputException("security_events_event_identity_invalid");
            if (e.Time("time_created_utc") < request.Period!.Start || e.Time("time_created_utc") >= request.Period.End) throw new AdInputException("security_events_event_outside_bounds");
            bool group = AdHistory.Ids("SECURITY_EVENTS_GROUP_EVENT_IDS").Contains((int)id);
            var row = new JsonObject();
            foreach (string k in new[] { "event_db_id", "event_record_id", "event_id" }) row[k] = e[k]?.DeepClone();
            row["domain_id"] = e["domain_id"]?.DeepClone() ?? JsonValue.Create(request.Domain);
            row["event_family"] = family; row["time_created_utc"] = Iso(e.Time("time_created_utc"));
            row["actor"] = Principal(e, "subject_user_sid", "subject_user_name");
            row["member"] = Principal(e, "membership_member_sid", "membership_member_name");
            row["group"] = group ? Principal(e, "target_user_sid", "target_user_name") : Unknown();
            row["affected_account"] = group ? Unknown() : Principal(e, "target_user_sid", "target_user_name");
            foreach (var (part, entity) in new[] { ("actor", "actor_entity_id"), ("member", "member_entity_id"), (group ? "group" : "affected_account", "target_entity_id") })
                if (e.Int(entity) > 0 && row[part]!.Text("state") == "observed") row[part]!["entity_id"] = e.Int(entity);
            row["source_host"] = e.WindowsText("source_host") is {} host ? Obj(new { state = "observed", hostname = host }) : Unknown();
            if (id == 4740) row["caller_computer"] = e.WindowsText("caller_computer") is {} caller ? Obj(new { state = "observed", hostname = caller }) : Unknown();
            string outcome = OutcomeValue(e);
            row["outcome"] = outcome == "unknown" ? Unknown("event_outcome_not_proven_by_scoped_contract") : Obj(new { state = "observed", value = outcome, basis = AdHistory.Map("_SECURITY_EVENT_STATIC_OUTCOME_BY_EVENT_ID").ContainsKey(id.ToString()) ? "event_id" : "audit_keywords" });
            if (e.WindowsText("result_code") is {} result && !AdHistory.Map("_SECURITY_EVENT_STATIC_OUTCOME_BY_EVENT_ID").ContainsKey(id.ToString())) row["outcome"]!["result_code"] = result;
            row["evidence"] = Evidence(e, true);
            if (e["related_event_db_ids"] is {} related) row["evidence"]!["related_event_db_ids"] = related.DeepClone();
            foreach(string key in new[]{"read_representation","source_event_state","authentication_session"})if(e[key] is {} value)row[key]=value.DeepClone();
            string? kind = AdHistory.Map("_SECURITY_EVENT_CHANGE_KIND_BY_EVENT_ID")[id.ToString()]?.GetValue<string>();
            row["change"] = e["source_native_change"]?.DeepClone() ?? AdSecurityHydration.Change(id, e)
                ?? (AdHistory.Kind(id) is not null ? AccountChange(e) : kind is not null ? Obj(new { state = "observed", kind }) : Unknown("source_change_not_established"));
            if (AdHistory.Kind(id) is not null) row["account_change"] = AdHistory.AccountObservation(e);
            if (e.Text("archive_field_state") is {} archive && archive.StartsWith("partial_archive_")) row["archive_fields"] = Obj(new { state = "partial", reason = "archive_" + archive[16..] });
            if (e["event_count"] is not null && family == "authentication") {
                foreach (string key in new[] { "day","event_count","first_seen_utc","last_seen_utc","summary_key","target","source","computer" }) row[key] = e[key]?.DeepClone();
                row["read_representation"] = "short_event";
            }
            items.Add(row);
        }
        foreach (var group in items.GroupBy(r => r.Int("domain_id"))) AdHistory.Prior(group.Where(r => r["account_change"] is not null), "affected_account", "sid", "account_change");
        if (request.Filters.Text("changes_order") != "asc")
            items = items.OrderByDescending(r => r.Time("time_created_utc")).ThenByDescending(r => r.Int("event_db_id")).ThenByDescending(r => r.Text("summary_key"),StringComparer.Ordinal).ToList();
        if (items.Count > request.Limit || items.Count > 0 && !history) throw new AdInputException("security_events_collection_coverage_invalid");
        string state = items.Count > 0 ? "available" : history ? "empty_unverified" : "not_collected";
        var payload = AdHistory.Base("security", request.Domain, request.Period!, request.Limit, false);
        payload["items"] = Array(items); payload["state"] = state; payload["has_more"] = more; payload["filters"] = request.Filters.DeepClone();
        payload["collection_coverage"] = Obj(new { state, history_event_present = history, source_completeness = "not_proven" }); payload["category_coverage"] = categories;
        payload["next_cursor"] = more && items.Count > 0 ? EncodeCursor(request.Domain, request.Period!, request.Filters, items[^1].Time("time_created_utc"), items[^1].Int("event_db_id"), items[^1].Text("summary_key") ?? "") : null;
        payload["limitations"] = Array(new[] { "Rows are source-event observations, not reconstructed account, membership, or audit state.", "Unknown identity and outcome fields were not present in the scoped Storage V2 contract.", "An empty window does not prove complete source coverage." });
        return payload;
    }
    private static JsonObject AccountChange(JsonObject row)
    { var change = (JsonObject)AdHistory.AccountObservation(row)["change"]!.DeepClone(); change["state"] = "observed"; return change; }
    public static string Csv(JsonObject payload)
    {
        var output = new StringBuilder(); var items = payload["items"]!.AsArray(); bool more = payload["has_more"]!.GetValue<bool>();
        bool incomplete = more || payload.Text("state") != "available" || items.Any(i => i!["evidence"]!.Text("state") != "complete");
        string Cell(string? text) { text ??= ""; if (text.StartsWith('\t') || text.StartsWith('\r') || text.StartsWith('\n') || text.TrimStart().StartsWith('=') || text.TrimStart().StartsWith('+') || text.TrimStart().StartsWith('-') || text.TrimStart().StartsWith('@')) text = "'" + text; return text.IndexOfAny([',', '"', '\r', '\n']) >= 0 ? "\"" + text.Replace("\"", "\"\"") + "\"" : text; }
        void Write(IEnumerable<string?> cells) => output.AppendJoin(',', cells.Select(Cell)).Append('\n');
        Write([$"# has_more={more.ToString().ToLowerInvariant()}", $"incomplete={incomplete.ToString().ToLowerInvariant()}", "# category_coverage=" + Sli.Agent.Protocol.CanonicalJson.Serialize(payload["category_coverage"]??new JsonObject(),false)]);
        string[] fields = ["event_db_id", "event_id", "event_family", "time_created_utc", "actor.sid", "actor.name", "affected_account.sid", "affected_account.name", "member.sid", "member.name", "group.sid", "group.name", "source_host.hostname", "caller_computer.hostname", "change.state", "change.kind", "change.observed_value", "outcome.state", "outcome.value", "outcome.result_code", "evidence.state"];
        Write(["event_db_id", "event_id", "event_family", "time_created_utc", "actor_sid", "actor_name", "affected_account_sid", "affected_account_name", "member_sid", "member_name", "group_sid", "group_name", "source_host", "caller_computer", "change_state", "change_kind", "change_observed_value", "outcome_state", "outcome_value", "outcome_result_code", "evidence_state", "has_more", "incomplete"]);
        foreach (var row in items) Write(fields.Select(path => path.Split('.').Aggregate(row, (node, key) => node is JsonObject obj ? obj[key] : null)?.ToString()).Concat([more.ToString().ToLowerInvariant(), incomplete.ToString().ToLowerInvariant()]));
        return output.ToString();
    }
    internal static async Task<JsonObject> ReadAsync(NpgsqlConnection db, AdReportRequest request, CancellationToken ct,Sli.Server.Storage.EventReports.IEventReadService details,IConfiguration? config=null, ILogger? logger=null)
    {
        bool maintenance = request.Filters["changes_view"] is not null
            && (await AdJson.ReadAsync(db,
                "select to_regprocedure('public.sli_audit_apply421(bigint,timestamptz)') is not null as available", ct))
                .Single()["available"]!.GetValue<bool>();
        var query = AdSecurityQuery.Create(request,config:config,maintenance:maintenance);
        var rows = await AdJson.ReadAsync(db, query.SelectSql, ct, query.Args.ToArray());
        var counts = query.ChangeCounts ? rows[0] : null;
        if (counts is not null) rows = rows.Where(r => r["event_db_id"] is not null).ToList();
        bool more = rows.Count > request.Limit; rows = rows.Take(request.Limit).ToList();
        await AdSecurityQuery.ResolveEntitiesAsync(db, rows.Where(r=>r["day"] is null).ToList(), request.Domain, ct);
        bool history = rows.Count > 0 || counts?.Int("all") > 0 || await AdReportStore.Presence(db, "security", request.Domain, ct,query.Selected,config:config);
        var categories = counts is null ? await query.CategoriesAsync(db, ct) : new JsonObject();
        foreach(var row in rows.Where(r=>r["day"] is null)) {
            var fields=JsonNode.Parse(row.Text("compact_fields")!)!.AsObject();
            if(fields["channel"] is {} channel)fields["Channel"]=channel.DeepClone();
            if(AdSecurityHydration.Change(row.Int("event_id"),fields) is {} change)row["source_native_change"]=change;
            if (query.ChangeCounts && row.Int("event_id") == 5136 && fields.WindowsText("AttributeLDAPDisplayName") is {} attribute)
            {
                var directoryChange = new JsonObject { ["state"] = "observed", ["kind"] = "directory_attribute", ["attribute"] = attribute };
                if (attribute.Equals("description", StringComparison.OrdinalIgnoreCase) || attribute.Equals("displayName", StringComparison.OrdinalIgnoreCase)
                    || attribute.Equals("userPrincipalName", StringComparison.OrdinalIgnoreCase))
                    directoryChange["observed_value"] = fields.WindowsText("AttributeValue");
                row["source_native_change"] = directoryChange;
            }
            else if (query.ChangeCounts && row.Int("event_id") == 4739)
            {
                var attributes = new JsonObject();
                foreach (var (source, key) in new[] {
                    ("MinPasswordLength", "minimum_password_length"), ("PasswordHistoryLength", "password_history_length"),
                    ("LockoutThreshold", "lockout_threshold"),
                })
                    if (fields.WindowsText(source) is {} value) attributes[key] = value;
                row["source_native_change"] = Obj(new { state = "observed", kind = "domain_policy_changed", attributes });
            }
        }
        var result = Compose(request, rows.Where(r=>r["day"] is null).ToArray(), history, more, categories);
        if (counts is not null)
        {
            result["change_counts"] = new JsonObject(ChangeViews.Select(key =>
                KeyValuePair.Create(key, (JsonNode?)JsonValue.Create(counts.Int(key)))));
            result["filtered_count"] = counts.Int("display_count");
            result["change_columns"] = Obj(new
            {
                field = counts["column_field"]!.GetValue<bool>(),
                value = counts["column_value"]!.GetValue<bool>(),
                result = counts["column_outcomes"] is JsonArray outcomes
                    && outcomes.OfType<JsonObject>().Any(row => OutcomeValue(row) is "success" or "failure"),
            });
            var sourceById = rows.ToDictionary(row => row.Int("event_db_id"));
            foreach (var item in result["items"]!.AsArray().OfType<JsonObject>())
            {
                var source = sourceById[item.Int("event_db_id")];
                if (source.Int("repeat_count") > 1 && request.Filters["batch"] is null)
                {
                    item["repeat_count"] = source.Int("repeat_count");
                    item["first_seen_utc"] = source["first_seen_utc"]?.DeepClone();
                }
                item["channel"] = source["event_channel"]?.DeepClone();
                if (source.Text("directory_object") is {} objectName)
                    item["affected_account"] = Obj(new { state = "observed", name = objectName });
            }
            if (request.IncludeChangeSnapshotValues)
                await DomainChangeSnapshotValues.AddAsync(db, request.Domain, result["items"]!.AsArray().OfType<JsonObject>().ToArray(), ct);
        }
        result["daily_summaries"] = Array(rows.Where(r=>r["day"] is not null).Select(r => new {
            day=r.Time("time_created_utc").ToString("yyyy-MM-dd",CultureInfo.InvariantCulture),
            event_id=r.Int("event_id"),domain_id=r.Int("domain_id"),actor=r.Text("actor"),target=r.Text("target"),
            source=r.Text("source"),computer=r.Text("computer"),event_count=r.Int("event_count"),
            first_seen_utc=r["first_seen_utc"]?.DeepClone(),last_seen_utc=r["last_seen_utc"]?.DeepClone(),summary_key=r.Text("summary_key") }));
        if(rows.Count>0){result["state"]="available";result["collection_coverage"]!["state"]="available";}
        result["next_cursor"] = more && rows.Count>0 ? EncodeCursor(request.Domain,request.Period!,request.Filters,
            rows[^1].Time("time_created_utc"),rows[^1].Int("event_db_id"),rows[^1].Text("summary_key")??"") : null;
        return result;
    }
}
