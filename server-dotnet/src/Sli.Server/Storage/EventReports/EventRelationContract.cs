using System.Text.Json.Nodes;

namespace Sli.Server.Storage.EventReports;
internal sealed record RelationCandidate(long RelatedId,int EventId,string? Time,string EntityType,string Entity,string Rule,decimal Delta);
internal static class EventRelationContract
{
    internal static JsonObject Build(long anchor,IReadOnlyList<RelationCandidate> rows,int limit)
    {
        limit=Math.Clamp(limit,1,200);
        var distinct=new List<RelationCandidate>(); var seen=new HashSet<long>();
        // The reader orders the merged evidence; projection preserves that selection order.
        foreach(var row in rows) if(row.RelatedId>0 && row.RelatedId!=anchor && seen.Add(row.RelatedId)) distinct.Add(row);
        var items=new JsonArray();
        foreach(var row in distinct.Take(limit))
        {
            bool logon=row.Rule=="same_logon_id_same_server"; long seconds=checked((long)row.Delta);
            string reason=logon ? $"Совпали LogonId и сервер; разница во времени {seconds} с." : $"Совпали имя задания и сервер; разница во времени {seconds} с.";
            string explanation=logon ? $"Совпали LogonId и сервер: {(row.Entity.Length==0 ? "без значения" : row.Entity)}." : $"Совпали задание и сервер: {(row.Entity.Length==0 ? "без имени" : row.Entity)}.";
            items.Add(new JsonObject { ["relation_type"]="computed_correlation",["relation_origin"]="computed",["confidence_kind"]="rule_policy_score",["related_event_db_id"]=row.RelatedId,["source_event_db_id"]=anchor,["target_event_db_id"]=row.RelatedId,["rule_id"]=row.Rule,["confidence"]=logon ? 0.95 : 0.80,["related_event_id"]=row.EventId,["related_time_utc"]=row.Time,["relation_strength"]=logon ? "strong" : "medium",["relation_rule"]=row.Rule,["time_delta_seconds"]=seconds,["entity"]=row.Entity,["entity_type"]=row.EntityType,["source_role"]="context",["related_role"]="context",["reason_code"]=row.Rule,["reason_params"]=new JsonObject { ["time_delta_seconds"]=seconds },["reason"]=reason,["explanation"]=explanation,["evidence_fields"]=logon ? new JsonArray("LogonId","server_id","time_created_utc") : new JsonArray("TaskName","server_id","time_created_utc") });
        }
        bool more=distinct.Count>limit; var last=more ? distinct[limit-1] : null;
        return new JsonObject { ["next_cursor"]=last is null ? null : EventRelationCursor.Encode(anchor,last.Delta,last.RelatedId),["api_version"]="v1",["event_db_id"]=anchor,["items"]=items,["truncated"]=more,["contract"]="explicit_event_link_or_rule_based_correlation",["confidence_contract"]=new JsonObject { ["stored_link_value"]="Значение сохранённой явной связи.",["rule_policy_score"]="Оценка силы правила корреляции; не вероятность и не доказательство причинности." } };
    }
}
