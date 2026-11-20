using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Access;

namespace Sli.Server.Entities;

public sealed partial class EntityReader(IEntityReadStore store, EntityDirectoryReader directory, IServiceProvider services)
{
    internal static string Text(JsonObject row, string key, string fallback = "") => row[key]?.ToString() ?? fallback;
    internal static long Number(JsonObject row, string key) => long.Parse(row[key]!.ToString(), CultureInfo.InvariantCulture);
    internal static JsonArray Array(IEnumerable<JsonObject> rows) => new(rows.Select(r => (JsonNode)r.DeepClone()).ToArray());
    internal static JsonArray Strings(IEnumerable<string> values) => new(values.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray());
    internal static JsonObject Pick(JsonObject row, params string[] keys)
    {
        var result = new JsonObject();
        foreach (var key in keys) result[key] = row[key]?.DeepClone();
        return result;
    }
    internal static IReadOnlyList<AccessResource> Resources(JsonObject row)
    {
        var resources = new List<AccessResource>();
        if (row["server_id"] is not null) resources.Add(new("server", Number(row, "server_id")));
        if (row["domain_id"] is not null) resources.Add(new("domain", Number(row, "domain_id")));
        if (resources.Count == 0) resources.Add(new("unscoped", Value: "global"));
        if (row["channel"] is not null) resources.Add(new("channel", Value: Text(row, "channel")));
        return resources;
    }
    internal static bool Allows(CapabilityDecisionSet caps, string key, JsonObject row) => ResourceAccessDecisions.Capability(caps, key, [Resources(row)]).Allowed;
    internal static bool TimedOut(Exception error) => error is TimeoutException || error is OperationCanceledException || error is PostgresException { SqlState: "57014" };
    internal Task<JsonArray> Read(string sql, Dictionary<string, object> args, CancellationToken ct, int seconds = 3) => store.ReadAsync(sql, args, seconds, ct);
    public async Task<JsonObject?> Preflight(long id, CancellationToken ct)
    {
        if (id is < int.MinValue or > int.MaxValue) return null;
        return (await Read("""
            select entity.id,entity_type.value as entity_type,entity.domain_id,entity.server_id
            from entities_v2_active entity join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
            where entity.id=resolve_entity_identity_v2(@id) limit 1
            """, new() { ["id"] = (int)id }, ct)).OfType<JsonObject>().FirstOrDefault();
    }
    const string EntityColumns = """
        entity.id,entity_type.value as entity_type,entity.natural_key,entity.display_name,entity.first_seen_utc,entity.last_seen_utc,
        state.status as latest_state_status,state.summary as latest_state_summary,
        state.observed_at_utc as latest_state_observed_at_utc,state.evidence_event_id as latest_state_event_db_id
        """;
    const string EntityTables = """
        from entities_v2_active entity join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
        left join lateral (select status,summary,observed_at_utc,evidence_event_id from entity_states
          where entity_id=entity.id order by observed_at_utc desc,id desc limit 1) state on true
        """;
    internal static JsonObject EntityItem(JsonObject row)
    {
        var item = Pick(row, "id", "natural_key", "display_name", "first_seen_utc", "last_seen_utc");
        item["type"] = Text(row, "entity_type", "unknown");
        item["natural_key"] ??= "";
        item["latest_state"] = row["latest_state_status"] is not null && row["latest_state_event_db_id"] is not null ? new JsonObject
        {
            ["status"] = row["latest_state_status"]!.DeepClone(), ["summary"] = row["latest_state_summary"]?.DeepClone(),
            ["observed_at_utc"] = row["latest_state_observed_at_utc"]?.DeepClone(), ["evidence_event_db_id"] = row["latest_state_event_db_id"]!.DeepClone()
        } : null;
        return item;
    }
    public async Task<JsonObject> Entities(IQueryCollection query, CancellationToken ct)
    {
        string q = (EntityReadInput.First(query, "q") ?? "").Trim();
        int rawLimit = EntityReadInput.Limit(EntityReadInput.First(query, "limit"), 50, "invalid_entity_limit", true);
        int limit = Math.Clamp(rawLimit == 0 ? 50 : rawLimit, 1, 100);
        string[] Types(string name) => query[name].SelectMany(v => (v ?? "").Split(',')).Select(s => s.Trim().ToLowerInvariant()).Where(s => s.Length > 0).Distinct().ToArray();
        var types = Types("entity_type"); var excluded = Types("exclude_entity_type");
        var counts = await Read("""
            select entity_type.value as entity_type,count(*)::bigint as entity_count
            from entities_v2_active entity join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
            group by entity_type.value order by entity_count desc,entity_type.value
            """, [], ct, 5);
        var known = counts.OfType<JsonObject>().Select(r => Text(r, "entity_type").ToLowerInvariant()).ToHashSet();
        var unknown = types.Concat(excluded).Distinct().Where(t => !known.Contains(t)).Order(StringComparer.Ordinal).ToArray();
        if (unknown.Length > 0) throw new EntityInputException("unknown_entity_type", Strings(unknown));
        var args = new Dictionary<string, object> { ["limit"] = limit + 1 };
        var conditions = new List<string>();
        if (q.Length > 0) { conditions.Add("(lower(entity.natural_key) like lower(@q) or lower(coalesce(entity.display_name,'')) like lower(@q))"); args["q"] = "%" + q + "%"; }
        if (types.Length > 0) { conditions.Add("entity_type.value=any(@types)"); args["types"] = types; }
        if (excluded.Length > 0) { conditions.Add("not(entity_type.value=any(@excluded))"); args["excluded"] = excluded; }
        string where = conditions.Count == 0 ? "" : "where " + string.Join(" and ", conditions);
        var rows = await Read($"select {EntityColumns} {EntityTables} {where} order by entity.last_seen_utc desc nulls last,entity.id desc limit @limit", args, ct, 5);
        return new()
        {
            ["api_version"] = "v1", ["query"] = q, ["state"] = rows.Count == 0 ? "empty" : "ok", ["items"] = new JsonArray(rows.OfType<JsonObject>().Take(limit).Select(r => (JsonNode)EntityItem(r)).ToArray()),
            ["has_more"] = rows.Count > limit, ["filters"] = new JsonObject { ["entity_types"] = Strings(types), ["exclude_entity_types"] = Strings(excluded) },
            ["type_counts"] = new JsonArray(counts.OfType<JsonObject>().Select(r => (JsonNode)new JsonObject { ["entity_type"] = Text(r, "entity_type"), ["count"] = Number(r, "entity_count") }).ToArray()),
            ["type_counts_scope"] = "all_entities", ["total_entities"] = counts.OfType<JsonObject>().Sum(r => Number(r, "entity_count")),
            ["limits"] = new JsonObject { ["items"] = limit, ["full_history"] = false, ["total_count"] = "not_calculated" }
        };
    }
    public async Task<JsonObject?> Detail(JsonObject preflight, EntityReadOptions options, CapabilityDecisionSet caps, bool objectFacade, CancellationToken ct)
    {
        int id = checked((int)Number(preflight, "id")), limit = Math.Clamp(options.Limit == 0 ? 50 : options.Limit, 1, 100);
        var entity = (await Read($"select {EntityColumns} {EntityTables} where entity.id=@id limit 1", new() { ["id"] = id }, ct)).OfType<JsonObject>().FirstOrDefault();
        if (entity is null) return null;
        var item = EntityItem(entity);
        bool security = Allows(caps, "field.security", preflight), technical = Allows(caps, "field.technical", preflight);
        var current = new JsonArray(); string currentState = "available", contextState = "available";
        try
        {
            current = await Read("""
                select current.state_type,current.status,current.projection_status,current.observed_at as observed_at_utc,
                  current.source_event_db_id as evidence_event_db_id,current.rule_id,current.rule_version,history.summary
                from entity_state_current current left join entity_states history on history.entity_id=current.entity_id
                  and history.state_type=current.state_type and history.evidence_event_id=current.source_event_db_id
                where current.entity_id=@id order by current.observed_at desc,current.state_type asc limit 64
                """, new() { ["id"] = id }, ct);
        }
        catch (Exception ex) when (TimedOut(ex) && !ct.IsCancellationRequested) { currentState = "temporarily_unavailable"; }
        JsonObject context;
        try { context = await directory.ReadAsync(id, ct); }
        catch (Exception ex) when ((TimedOut(ex) && !ct.IsCancellationRequested) || ex is InvalidOperationException { Message: "plugin_update_draining" or "plugin_not_installed" })
        { context = new() { ["entity_id"] = id, ["resolution"] = "temporarily_unavailable", ["items"] = new JsonArray(), ["returned_count"] = 0, ["bounded"] = true }; contextState = "temporarily_unavailable"; }
        context = EntityDirectoryReader.Project(context, caps, preflight, objectFacade);
        var events = new JsonArray(); string eventsState = "available"; bool filtered = false, truncated = false;
        try
        {
            var candidates = await EvidenceCandidates(id, options, limit + 1, ct);
            truncated = candidates.Count > limit;
            var permitted = new List<(long Id, string Group, bool Technical, bool Security)>();
            foreach (var candidate in candidates.OfType<JsonObject>())
            {
                if (!Allows(caps, "evidence.exact", candidate) || objectFacade && !Allows(caps, "evidence.exact", preflight)) { filtered = true; continue; }
                long eventId = candidate["event_db_id"] is null ? 0 : Number(candidate, "event_db_id");
                string group = Text(candidate,"summary_key");
                if (eventId <= 0 && !(eventId==0 && group.Length==64)) throw new InvalidDataException("entity_evidence_identity_invalid");
                permitted.Add((eventId, group, Allows(caps, "field.technical", candidate), Allows(caps, "field.security", candidate)));
            }
            var byId = new Dictionary<(long,string), JsonObject>();
            foreach (var projection in permitted.GroupBy(p => (p.Technical, p.Security)))
            {
                var hydrated = await ShortEvidence(id,projection.Where(p=>p.Id>0).Select(p=>p.Id).ToArray(),projection.Where(p=>p.Group.Length>0).Select(p=>p.Group).ToArray(),projection.Key.Technical,projection.Key.Security,limit+1,objectFacade,ct);
                foreach (var ev in hydrated.OfType<JsonObject>()) {
                    var key = (ev["event_db_id"] is null ? 0 : Number(ev,"event_db_id"),Text(ev,"summary_key"));
                    if(!projection.Any(p=>p.Id==key.Item1 && p.Group==key.Item2)) throw new InvalidDataException("entity_evidence_identity_mismatch");
                    ev.Remove("sort_time_utc");
                    if(projection.Key.Security && ev["event_id"] is not null) ev["label"]=EntityEventLabels.Label(checked((int)Number(ev,"event_id")));
                    if(!objectFacade) foreach(string field in new[] { "server","channel","event_id","label","time_utc","provider_name","link_role","confidence","actor","target" })
                        if(!ev.ContainsKey(field)) ev[field]=null;
                    byId[key] = ev;
                }
            }
            foreach (var candidate in candidates.OfType<JsonObject>())
                if (byId.TryGetValue((candidate["event_db_id"] is null ? 0 : Number(candidate,"event_db_id"),Text(candidate,"summary_key")), out var ev)) events.Add(ev.DeepClone());
            if (candidates.Count > 0 && events.Count == 0 && filtered) eventsState = "forbidden";
        }
        catch (Exception ex) when (TimedOut(ex) && !ct.IsCancellationRequested) { events.Clear(); eventsState = "temporarily_unavailable"; }
        bool more = events.Count > limit || truncated;
        while (events.Count > limit) events.RemoveAt(events.Count - 1);
        JsonObject? cursor = more && events.LastOrDefault() is JsonObject tail ? new() { ["time_utc"] = tail["time_utc"]?.DeepClone(), ["event_db_id"] = tail["event_db_id"]?.DeepClone() } : null;
        if(cursor is not null && events.LastOrDefault()?["summary_key"] is { } summaryKey && summaryKey.ToString().Length>0) {
            cursor["event_db_id"]=0; cursor["summary_key"]=summaryKey.DeepClone();
        }
        if (!technical) item["natural_key"] = "";
        if (!security) { item["latest_state"] = null; current.Clear(); }
        return new()
        {
            ["api_version"] = "v1", ["entity"] = item, ["current_states"] = current, ["current_states_state"] = currentState,
            ["ad_context"] = context, ["ad_context_state"] = contextState, ["events"] = events, ["events_state"] = eventsState, ["events_scope_filtered"] = filtered,
            ["has_more"] = more, ["next_cursor"] = cursor,
            ["context"] = new JsonObject { ["time_from_utc"] = options.From, ["time_to_utc_exclusive"] = options.To, ["timezone"] = options.Timezone },
            ["limits"] = new JsonObject { ["events"] = limit, ["current_states"] = 64, ["full_history"] = false, ["total_count"] = "not_calculated" }
        };
    }
    Task<JsonArray> EvidenceCandidates(int id, EntityReadOptions options, int limit, CancellationToken ct) =>
        ShortEvidenceCandidates(id,options,limit,ct);
}
