using System.Globalization;
using System.Text.Json.Nodes;
using Sli.Server.Storage.Archive;
using Sli.Server.Storage.History;

namespace Sli.Server.Semantic;

internal sealed partial class SemanticProduction
{
    internal async Task<IReadOnlyDictionary<long, JsonObject>> LoadContextSources(ISemanticSession session, IReadOnlyList<JsonObject> identities, CancellationToken ct)
    {
        var cache = new Dictionary<ArchiveBlock, IReadOnlyList<JsonObject>>();
        var sources = new Dictionary<long, JsonObject>();
        foreach (var identity in identities)
        {
            long id = identity.Number("id");
            // Reuse the archive/native-inbox integrity checks. A missing row in a published block never falls back.
            sources.Add(id, await LoadSource(session, id, identity, ct, cache));
        }
        return sources;
    }

    internal static async Task<int> HydrateDispatchContext(ISemanticSession session, SemanticCorrelation rule, SemanticEvent trigger, string partition,
        DateTimeOffset start, DateTimeOffset end,
        Func<IReadOnlyList<JsonObject>, CancellationToken, Task<IReadOnlyDictionary<long, JsonObject>>> loadSources, CancellationToken ct)
    {
        if (end < start) throw new ArgumentException("semantic context window is inverted");
        if (!long.TryParse(partition.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out long host) || host <= 0)
            throw new InvalidDataException("semantic_context_numeric_host_required");
        var summaries = new List<JsonObject>();
        foreach (var identity in SemanticNormalization.IdentitiesForTypes(rule.Inputs).Where(x => x.Noise == "context"))
        {
            var filters = ContextRoleFilters(identity.Type, rule.Roles, trigger.Roles);
            if (filters is null) continue;
            var values = new List<object?> { 1, SemanticEvent.Normalizer, SemanticEvent.Version, host, start, end,
                int.Parse(identity.EventKey, CultureInfo.InvariantCulture), identity.Stream, identity.Provider };
            var clauses = new List<string> { "core.event_id=$7", "lower(core.channel)=lower($8)", "lower(coalesce(core.provider_name,''))=lower($9)" };
            foreach (var (primary, fallback, value) in filters)
            {
                // Field names come only from the fixed source-owned mapping below, never from a role or event value.
                string expression = fallback is null ? $"btrim(core.{primary})" : $"case when nullif(btrim(core.{primary}), '') is not null then btrim(core.{primary}) else btrim(core.{fallback}) end";
                values.Add(value); string parameter = "$" + values.Count;
                clauses.Add(primary == "ip_address" ? expression + "=" + parameter : $"lower({expression})=lower({parameter})");
            }
            values.Add(start + (end - start) / 2);
            var rows = await session.QueryAsync("""
                select core.id,core.server_id,core.domain_id,core.log_source_id,core.event_id,core.time_created_utc,
                  encode(core.normalized_hash,'hex') as normalized_hash,core.correlation_id,core.migrated_at,
                  core.noise_class as stored_noise_class,core.noise_catalog_version as stored_noise_catalog_version,
                  core.provider_name,core.channel,core.computer
                from public.semantic_event_source355 core
                left join normalized_events normalized on normalized.source_event_id=core.id
                  and normalized.semantic_contract_version=$1 and normalized.normalizer_id=$2 and normalized.normalizer_version=$3
                where core.server_id=$4 and core.time_created_utc between $5 and $6 and (
                """ + string.Join(" and ", clauses) + $" ) and normalized.source_event_id is null order by abs(extract(epoch from (core.time_created_utc-${values.Count}))),core.time_created_utc,core.id", ct, values.ToArray());
            summaries.AddRange(rows.Select(x => x!.AsObject()));
        }
        // This is the existing matcher input contract, not a new operational batch/time threshold.
        if (summaries.Count > 5000) throw new InvalidDataException("semantic_context_limit_exceeded");
        if (summaries.Count == 0) return 0;
        if (summaries.Select(x => x.Number("id")).Distinct().Count() != summaries.Count)
            throw new InvalidDataException("semantic_context_duplicate_identity");
        var payloads = await loadSources(summaries, ct);
        foreach (var identity in summaries.OrderBy(x => x.Number("id")))
        {
            ct.ThrowIfCancellationRequested();
            var payload = payloads[identity.Number("id")].DeepClone().AsObject();
            EventDetailIdentity.Verify(identity, payload);
            foreach (string field in new[] { "provider_name", "channel", "computer" }) payload[field] ??= identity[field].Copy();
            payload["source_host_id"] = identity["server_id"].Copy();
            payload["source_ingested_at"] = identity["migrated_at"].Copy();
            payload["source_event_sha256"] = identity["normalized_hash"].Copy();
            var ev = SemanticNormalization.Normalize(payload);
            if (!rule.Inputs.Contains(ev.Type)) throw new InvalidDataException("semantic_context_type_mismatch");
            await PersistNormalized(session, ev, identity, SemanticEvent.Version, ct);
        }
        return summaries.Count;
    }

    private static List<(string Primary, string? Fallback, string Value)>? ContextRoleFilters(string type, string[] roles, JsonObject trigger)
    {
        if (type is not ("authentication.session.created" or "authentication.explicit_credentials.used" or "authentication.privileged_session.created")) return null;
        var filters = new List<(string, string?, string)>();
        foreach (string role in roles.Where(x => x != "source_host"))
        {
            string? raw = trigger.Text(role)?.Trim(); if (string.IsNullOrEmpty(raw)) return null;
            (string Primary, string? Fallback)? fields = role switch {
                "affected_entity" when type != "authentication.privileged_session.created" => ("target_user_sid", "target_user_name"),
                "actor" when type != "authentication.session.created" => ("subject_user_sid", "subject_user_name"),
                "session_principal" => ("logon_id", null), "source_ip" => ("ip_address", null), _ => null
            };
            if (fields is null) return null;
            string value = raw;
            int separator = raw.IndexOf(':');
            if (role == "session_principal") {
                if (separator < 0 || separator == raw.Length - 1) return null;
                value = raw[(separator + 1)..];
            }
            else if (separator >= 0 && raw[..separator] is "sid" or "guid" or "upn" or "sam" or "name")
                value = raw[((raw[..separator] is "sam" or "sid" ? raw.LastIndexOf(':') : separator) + 1)..];
            filters.Add((fields.Value.Primary, fields.Value.Fallback, value));
        }
        return filters;
    }

    internal async Task<int> HydrateDispatchContext(ISemanticSession session, string[] types, string[] roles,
        JsonObject triggerRoles, string partition, DateTimeOffset start, DateTimeOffset end, CancellationToken ct)
    {
        if (end < start) throw new InvalidDataException("semantic_context_window_inverted");
        if (!long.TryParse(partition.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out long host) || host <= 0)
            throw new InvalidDataException("semantic_context_source_host_required");

        // The AD/DC adapter supports these compact role predicates, as in
        // windows_ad_dc/semantics.py. Other descriptors cannot use this adapter.
        var summaries = new Dictionary<long, JsonObject>();
        foreach (var entry in SemanticNormalization.Catalog.OfType<JsonObject>().Where(e => e.Text("source") == "sli.windows.ad-dc" && e.Text("noise_class") == "context"))
        {
            if (!int.TryParse(entry.Text("event_key"), out int eventId)) continue;
            string? type = eventId switch { 4624 => "authentication.session.created", 4648 => "authentication.explicit_credentials.used", 4672 => "authentication.privileged_session.created", _ => null };
            if (type is null || !types.Contains(type)) continue;
            var args = new List<object?> { host, start, end, eventId, entry.Text("stream"), entry.Text("provider_name"), SemanticEvent.Version };
            var predicates = new List<string>(); bool supported = true;
            foreach (string role in roles)
            {
                if (role == "source_host") continue;
                string? raw = triggerRoles.Text(role)?.Trim();
                (string? field, string? fallback) = role switch {
                    "affected_entity" when eventId is 4624 or 4648 => ("target_user_sid", "target_user_name"),
                    "actor" when eventId is 4648 or 4672 => ("subject_user_sid", "subject_user_name"),
                    "session_principal" => ("logon_id", null), "source_ip" => ("ip_address", null), _ => (null, null) };
                if (string.IsNullOrEmpty(raw) || field is null) { supported = false; break; }
                string value = raw;
                int colon = raw.IndexOf(':');
                if (role == "session_principal") {
                    if (colon < 0 || colon == raw.Length - 1) { supported = false; break; }
                    value = raw[(colon + 1)..];
                }
                else if (colon >= 0 && raw[..colon] is "sid" or "guid" or "upn" or "sam" or "name")
                    value = raw[..colon] is "sam" or "sid" ? raw[(raw.LastIndexOf(':') + 1)..] : raw[(colon + 1)..];
                args.Add(value);
                string expression = fallback is null ? $"btrim(core.{field})" : $"case when nullif(btrim(core.{field}),'') is not null then btrim(core.{field}) else btrim(core.{fallback}) end";
                predicates.Add(field == "ip_address" ? $"{expression}=${args.Count}" : $"lower({expression})=lower(${args.Count})");
            }
            if (!supported) continue;
            string filter = predicates.Count == 0 ? "" : " and " + string.Join(" and ", predicates);
            var rows = await session.QueryAsync("""
                select core.id,core.server_id,core.domain_id,core.log_source_id,core.event_id,core.event_record_id,
                       core.time_created_utc,encode(core.normalized_hash,'hex') as normalized_hash,core.migrated_at,
                       core.correlation_id,core.provider_name,core.channel,core.computer
                from public.semantic_event_source355 core
                where core.server_id=$1 and core.time_created_utc between $2 and $3 and core.event_id=$4
                  and lower(core.channel)=lower($5) and lower(coalesce(core.provider_name,''))=lower($6)
                  and not exists(select 1 from normalized_events n where n.source_event_id=core.id
                    and n.semantic_contract_version=1 and n.normalizer_id='windows.named-eventdata' and n.normalizer_version=$7)
                """ + filter + " order by core.time_created_utc,core.id", ct, args.ToArray());
            foreach (var row in rows.OfType<JsonObject>())
                if (!summaries.TryAdd(row.Number("id"), row)) throw new InvalidDataException("semantic_context_duplicate_identity");
        }
        foreach (var (id, identity) in summaries.OrderBy(x => x.Key))
        {
            var source = await LoadSource(session, id, identity, ct);
            var normalized = SemanticNormalization.Normalize(source);
            if (!types.Contains(normalized.Type)) throw new InvalidDataException("semantic_context_descriptor_type_mismatch");
            await PersistNormalized(session, normalized, identity, SemanticEvent.Version, ct);
        }
        return summaries.Count;
    }
}
