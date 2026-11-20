using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Agents.Control;
using Sli.Server.Agents.FileAudit;

namespace Sli.Server.Entities;

public sealed class EntityDirectoryReader(IEntityReadStore store, IHostEnvironment host)
{
    const string ContextSql = """

        (
        select evidence.id as context_evidence_id, evidence.evidence_type,
               evidence.source_pack_id, evidence.source_run_id,
               evidence.observed_at_utc, encode(evidence.integrity_sha256,'hex') as integrity_sha256,
               'entity' as context_kind, version.entity_id as subject_entity_id,
               current_entity.display_name as subject_display_name,
               null::bigint as related_entity_id, null::text as related_display_name,
               version.valid_from_utc, version.valid_to_utc,
               version.last_observed_at_utc, version.current,
               version.source_section, version.attributes_json
        from (
            select *, (valid_to_utc is null) as current
            from ad_context_entity_versions where entity_id=@id
            order by (valid_to_utc is null) desc, last_observed_at_utc desc offset 0
        ) version
        join lateral (
            select display_name from entities_v2_active
            where id=version.entity_id limit 1
        ) current_entity on true
        join lateral (
            select * from ad_context_evidence evidence
            where evidence.source_run_id=version.source_run_id
         and evidence.evidence_type='entity_observation'
         and evidence.locator_json->>'record_key'=version.attributes_json->>'record_key'
            order by evidence.observed_at_utc desc, evidence.id desc limit 100
        ) evidence on true
        order by current desc, last_observed_at_utc desc, observed_at_utc desc, context_evidence_id desc
        limit 100
        )
        union all
        (
        select evidence.id as context_evidence_id, evidence.evidence_type,
               evidence.source_pack_id, evidence.source_run_id,
               evidence.observed_at_utc, encode(evidence.integrity_sha256,'hex') as integrity_sha256,
               'relation' as context_kind,
               case when relation.source_entity_id=@id then relation.source_entity_id else relation.target_entity_id end as subject_entity_id,
               case when relation.source_entity_id=@id then source_entity.display_name else target_entity.display_name end as subject_display_name,
               case when relation.source_entity_id=@id then relation.target_entity_id else relation.source_entity_id end as related_entity_id,
               case when relation.source_entity_id=@id then target_entity.display_name else source_entity.display_name end as related_display_name,
               relation.valid_from_utc, relation.valid_to_utc,
               relation.last_observed_at_utc, relation.current,
               relation.source_section, relation.attributes_json
        from (
            select *, (valid_to_utc is null) as current
            from ad_context_relation_versions where source_entity_id=@id or target_entity_id=@id
            order by (valid_to_utc is null) desc, last_observed_at_utc desc offset 0
        ) relation
        join lateral (
            select display_name from entities_v2_active
            where id=relation.source_entity_id limit 1
        ) source_entity on true
        join lateral (
            select display_name from entities_v2_active
            where id=relation.target_entity_id limit 1
        ) target_entity on true
        join lateral (
            select * from ad_context_evidence evidence
            where evidence.source_run_id=relation.source_run_id
         and evidence.evidence_type='relation_observation'
         and evidence.locator_json->>'record_key'=relation.relation_key
            order by evidence.observed_at_utc desc, evidence.id desc limit 100
        ) evidence on true
        order by current desc, last_observed_at_utc desc, observed_at_utc desc, context_evidence_id desc
        limit 100
        )
        order by current desc, last_observed_at_utc desc, observed_at_utc desc, context_evidence_id desc
        limit @limit
        
        """;
    public async Task<JsonObject> ReadAsync(int id, CancellationToken ct)
    {
        if (!new FileAuditHookAdmission(host).Present("sli.ad")) throw new InvalidOperationException("plugin_not_installed");
        using var admission = AgentAssignmentPluginAdmission.Enter("sli.ad", Environment.GetEnvironmentVariable("SLI_PLUGIN_RUNTIME_DIR"), Environment.GetEnvironmentVariable("SLI_PLUGIN_LOCK_DIR"));
        var direct = await Context(id, ct);
        if (((JsonArray)direct["items"]!).Count > 0) { direct["ad_context_entity_id"] = id; direct["resolution"] = "shared_entity_id"; return direct; }
        var runtime = (await store.ReadAsync("""
            select entity.id,entity.domain_id,entity.natural_key,entity.display_name,details.attributes_json
            from entities_v2 entity left join entity_details_v2 details on details.entity_id=entity.id where entity.id=@id limit 1
            """, new Dictionary<string, object> { ["id"] = id }, 3, ct)).OfType<JsonObject>().FirstOrDefault();
        JsonObject Empty(string resolution) => new() { ["entity_id"] = id, ["resolution"] = resolution, ["items"] = new JsonArray(), ["returned_count"] = 0, ["bounded"] = true };
        if (runtime is null) return Empty("not_found");
        var aliases = new List<(string Kind, string Value)>();
        string sid = runtime["attributes_json"]?["sid"]?.ToString().Trim() ?? "";
        if (sid.Length > 0) aliases.Add(("object_sid", sid));
        foreach (var value in new[] { EntityReader.Text(runtime, "display_name").Split('\\').Last().Trim(), EntityReader.Text(runtime, "natural_key").Split(':').Last().Trim() })
            if (value.Length > 0 && !aliases.Any(a => a.Kind == "sam_account_name" && a.Value.Equals(value, StringComparison.OrdinalIgnoreCase))) aliases.Add(("sam_account_name", value));
        if (runtime["domain_id"] is null || aliases.Count == 0) return Empty("no_exact_alias");
        var args = new Dictionary<string, object> { ["domain"] = EntityReader.Number(runtime, "domain_id") };
        var terms = new List<string>();
        for (int i = 0; i < aliases.Count; i++) { terms.Add($"(alias_type=@kind{i} and normalized_value=lower(@value{i}))"); args[$"kind{i}"] = aliases[i].Kind; args[$"value{i}"] = aliases[i].Value; }
        var resolved = await store.ReadAsync($"select distinct entity_id from ad_context_entity_aliases where domain_id=@domain and ({string.Join(" or ", terms)}) order by entity_id limit 2", args, 3, ct);
        if (resolved.Count != 1) return Empty(resolved.Count == 0 ? "not_observed" : "ambiguous");
        int contextId = checked((int)EntityReader.Number((JsonObject)resolved[0]!, "entity_id"));
        var context = await Context(contextId, ct); context["entity_id"] = id; context["ad_context_entity_id"] = contextId; context["resolution"] = "exact_alias";
        return context;
    }
    async Task<JsonObject> Context(int id, CancellationToken ct)
    {
        var rows = await store.ReadAsync(ContextSql, new Dictionary<string, object> { ["id"] = id, ["limit"] = 50 }, 5, ct);
        foreach (var row in rows.OfType<JsonObject>())
        {
            row["attributes"] = row["attributes_json"] is JsonObject attrs ? attrs.DeepClone() : new JsonObject();
            row.Remove("attributes_json"); row["current"] = row["valid_to_utc"] is null;
            row["supplemental_context_only"] = true; row["changes_entity_state"] = false;
        }
        return new() { ["entity_id"] = id, ["items"] = rows, ["returned_count"] = rows.Count, ["bounded"] = true, ["limit"] = 50, ["source_pack_optional"] = true, ["absence_closes_state"] = false };
    }
    static readonly Dictionary<string, string> Categories = new()
    {
        ["display_name"]="identity_basic",["record_key"]="identity_basic",["kind"]="identity_basic",["object_class"]="identity_basic",
        ["enabled"]="security",["locked"]="security",["locked_out"]="security",["lockout_time"]="security",["last_logon_utc"]="security",
        ["is_inactive"]="security",["password_never_expires"]="security",["password_last_set_utc"]="security",["account_expiration_utc"]="security",
        ["inactive_threshold_days"]="security",["operating_system"]="security",["operating_system_version"]="security",
        ["admin_count"]="privilege",["privileged"]="privilege",["member_of"]="privilege",["membership_type"]="privilege",
        ["department"]="hr",["title"]="hr",["employee_id"]="hr",["email"]="contact",["mail"]="contact",["telephone_number"]="contact",
        ["object_guid"]="technical",["object_sid"]="technical",["domain_sid"]="technical",["distinguished_name"]="technical",["dns_host_name"]="technical",
        ["source_section"]="technical",["relation_type"]="technical"
    };
    internal static JsonObject Project(JsonObject context, CapabilityDecisionSet caps, JsonObject entity, bool facade)
    {
        bool Allows(string key) => EntityReader.Allows(caps, key, entity);
        bool privilege = Allows("field.privilege") && Allows("objects.privileges");
        bool relations = privilege || facade && Allows("objects.groups");
        var result = (JsonObject)context.DeepClone(); var items = new JsonArray();
        foreach (var source in ((JsonArray)context["items"]!).OfType<JsonObject>())
        {
            bool relation = EntityReader.Text(source, "context_kind") == "relation";
            if (relation && (!relations || facade && !privilege && EntityReader.Text(source, "source_section") == "privileged_membership")) continue;
            var item = (JsonObject)source.DeepClone(); var attrs = new JsonObject();
            void ProjectAttributes(JsonObject? record)
            {
                if (record is null) return;
                foreach (var (key, value) in record) if (Categories.TryGetValue(key, out var category) && Allows("field." + category)) attrs[key] = value?.DeepClone();
            }
            var record = item["attributes"] as JsonObject;
            ProjectAttributes(record?["attributes"] as JsonObject); ProjectAttributes(record?["identity"] as JsonObject); ProjectAttributes(record);
            item["attributes"] = attrs;
            if (relation) item["relation_class"] = EntityReader.Text(source, "source_section") switch { "privileged_membership" => "privileged", "vpn_membership" => "vpn", _ => "group" };
            item.Remove("integrity_sha256");
            if (!Allows("field.technical")) foreach (string key in new[] { "source_run_id", "context_evidence_id", "subject_entity_id", "related_entity_id", "source_section" }) item.Remove(key);
            if (!Allows("field.identity_basic")) { item.Remove("subject_display_name"); item.Remove("related_display_name"); }
            items.Add(item);
        }
        result["items"] = items; result["returned_count"] = items.Count;
        if (!Allows("field.technical")) result.Remove("ad_context_entity_id");
        if (!facade)
        {
            foreach (string key in new[] { "ad_context_entity_id", "limit", "source_pack_optional", "absence_closes_state" })
                if (!result.ContainsKey(key)) result[key] = null;
            foreach (var item in items.OfType<JsonObject>())
            {
                item.Remove("last_observed_at_utc"); item.Remove("relation_class");
                foreach (string key in new[] { "context_evidence_id", "source_run_id", "observed_at_utc", "integrity_sha256", "subject_entity_id", "subject_display_name", "related_entity_id", "related_display_name", "valid_from_utc", "valid_to_utc" })
                    if (!item.ContainsKey(key)) item[key] = null;
                if (!item.ContainsKey("source_section")) item["source_section"] = "";
            }
        }
        return result;
    }
}
