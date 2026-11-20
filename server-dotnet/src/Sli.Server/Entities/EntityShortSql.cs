using Sli.Server.Storage.EventReports;

namespace Sli.Server.Entities;

// Shared SQL fragments follow the event reader's whole-UTC-day boundary.
// Facts remain individual after hot retention; daily groups never acquire IDs.
internal static class EntityShortSql
{
    internal static string Source(string boundary,bool daily=true)
    {
        string facts = EventReadService.ShortSource(boundary, daily:false)
            .Replace($"from event_hot h where h.time_created_utc>={boundary}",
                $"from event_cold_facts h where (h.time_created_utc<{boundary} or not exists(select 1 from event_hot hot where hot.event_id=h.event_id and hot.time_created_utc>={boundary}))", StringComparison.Ordinal);
        // A dimension digest repeats on different days. Entity hydration uses
        // the key independently of the cursor time, so include the UTC day.
        return EventReadService.ShortSource(boundary,daily).Replace("encode(d.grouping_key,'hex')",
            "encode(sha256(convert_to(to_char(d.day,'YYYY-MM-DD')||':'||encode(d.grouping_key,'hex'),'UTF8')),'hex')",StringComparison.Ordinal)
            + "\nunion all\n" + facts;
    }

    internal static string Cte(string boundary, string entity,bool daily=true)
    {
        string Filter(string alias, bool daily = false) => $"""
            (keys.domain_id is null or {alias}.domain_id=keys.domain_id)
            and public.short_event_entity_keys339({alias}.event_kind,{alias}.actor,{alias}.target,{alias}.source,{alias}.computer,{alias}.method,{(daily ? "'{}'::jsonb" : alias+".fields")}) && keys.natural_keys
            """;
        string source = Source(boundary,daily)
            .Replace("from event_hot h where", "from event_hot h cross join entity_keys keys where " + Filter("h") + " and", StringComparison.Ordinal)
            .Replace("from event_cold_facts h where", "from event_cold_facts h cross join entity_keys keys where " + Filter("h") + " and", StringComparison.Ordinal)
            .Replace("from event_cold_daily d where", "from event_cold_daily d cross join entity_keys keys where " + Filter("d",true) + " and", StringComparison.Ordinal);
        return $"with entity_keys as materialized (select * from public.entity_event_keys339({entity}::integer)),short_events as ({source}) ";
    }

    internal static string Matches(string entity, string alias = "event", bool allowGlobal = false) => $"""
        exists(select 1 from public.entity_event_keys339({entity}::integer) keys
            where {(allowGlobal ? $"(keys.domain_id is null or keys.domain_id={alias}.domain_id)" : $"keys.domain_id={alias}.domain_id")}
              and public.short_event_entity_keys339({alias}.event_id,{alias}.actor,{alias}.target,{alias}.source,{alias}.computer,{alias}.method,{alias}.fields) && keys.natural_keys)
        """;

    internal static string MatchesStored(string entity,string boundary,string alias="event") =>
        "exists("+Cte(boundary,entity,daily:false)+$"select 1 from short_events selected where selected.id={alias}.id and selected.domain_id={alias}.domain_id)";
}
