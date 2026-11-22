using System.Text.Json.Nodes;
using Npgsql;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

internal static class DomainChangeSnapshotValues
{
    private static readonly (string EventField, string SnapshotField)[] Fields =
        [("user_principal_name", "userPrincipalName"), ("display_name", "displayName"), ("sam_account_name", "samAccountName")];

    internal static async Task AddAsync(NpgsqlConnection db, long domain, JsonObject[] rows, CancellationToken ct)
    {
        var requests = new JsonArray();
        foreach (var row in rows)
        {
            if (row.Int("event_id") != 4738 || row.Int("repeat_count") > 1
                || row["affected_account"].Int("entity_id") is not > 0) continue;
            foreach (var (eventField, snapshotField) in Fields)
                if (row["change"]?["attributes"].WindowsText(eventField) is {} value)
                    requests.Add(Obj(new
                    {
                        event_id = row.Int("event_db_id"), entity_id = row["affected_account"].Int("entity_id"),
                        observed_at = row.Text("time_created_utc"), field = eventField, attribute = snapshotField, value
                    }));
        }
        if (requests.Count == 0) return;

        var matches = await ReadAsync(db, """
            with requested as (
                select * from jsonb_to_recordset($1::jsonb)
                  as r(event_id bigint,entity_id bigint,observed_at timestamptz,field text,attribute text,value text)
            ), identities as (
                select entity_id,min(lower(trim(both '{}' from normalized_value))) as guid
                from ad_context_entity_aliases
                where domain_id=$2 and alias_type='object_guid' and entity_id in (select entity_id from requested)
                group by entity_id having count(distinct normalized_value)=1
            )
            select r.event_id,r.field,r.value,prior.observed_at as previous_observed_at,
                   change.batch_id,change.record_id,change.payload_json,change.before_value
            from requested r
            join identities i on i.entity_id=r.entity_id
            join public.ad_snapshot_history_confirmations next
                on next.domain_id=$2 and next.family='users_v2' and next.coverage_state='complete'
                and next.observed_at>=r.observed_at
            join public.ad_snapshot_history_confirmations prior
                on prior.manifest_id=next.previous_manifest_id and prior.domain_id=next.domain_id
                and prior.family=next.family and prior.observed_at<r.observed_at
            join public.ad_snapshot_change_history change
                on change.domain_id=next.domain_id and change.family=next.family and change.observed_at=next.observed_at
                and change.batch_id=next.batch_id and change.manifest_id=next.manifest_id and change.record_kind='history'
                and lower(trim(both '{}' from change.object_id))=i.guid and change.attribute=r.attribute and change.after_value=r.value
                and change.payload_json::jsonb->>'object_type'='ad_user' and change.payload_json::jsonb->>'kind'='attribute_changed'
            """, ct, requests.ToJsonString(), domain);

        var byId = rows.ToDictionary(row => row.Int("event_db_id"));
        foreach (var group in matches.GroupBy(match => (Id: match.Int("event_id"), Field: match.Text("field")!)))
        {
            var candidates = group.Take(2).ToArray();
            if (candidates.Length != 1 || SnapshotValue(candidates[0]) is not {} before) continue;
            var change = byId[group.Key.Id]["change"]!.AsObject();
            change["previous_attributes"] ??= new JsonObject();
            change["previous_attributes"]![group.Key.Field] = Obj(new { value = before, observed_at_utc = candidates[0].Text("previous_observed_at") });
        }
    }

    internal static string? SnapshotValue(JsonObject match)
    {
        if (match.Text("before_value") is not {} before || match.Text("value") is not {} after
            || match.Text("payload_json") is not {} json || JsonNode.Parse(json) is not JsonObject payload
            || AdJobPlugin.Digest(new JsonArray(match.Text("batch_id"), payload.DeepClone())) != match.Text("record_id")
            || AdJobPlugin.Digest(JsonValue.Create(before)!) != payload.Text("before_sha256")
            || AdJobPlugin.Digest(JsonValue.Create(after)!) != payload.Text("after_sha256"))
            return null;
        return before;
    }
}
