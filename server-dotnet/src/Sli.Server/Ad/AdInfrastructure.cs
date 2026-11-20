using System.Globalization;
using System.Text.Json.Nodes;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

internal static class AdInfrastructure
{
    internal static long[] SemanticEntityIds(IReadOnlyList<JsonObject> entities, JsonObject parameters)
    {
        var filters = (JsonObject)parameters.DeepClone(); filters.Remove("q");
        bool restrictControls = parameters.Text("qualification") is not null || parameters.Text("view") is not (null or "overview");
        var eligible = restrictControls ? Compose(entities, filters).Select(r => r.Int("entity_id")).ToHashSet() : null;
        string? EntityType(JsonObject entity) => entity.Text("entity_type") == "ad_computer"
            && entity.Text("source_section") == "domain_health"
            && JsonNode.Parse(entity.Text("record")!)?["attributes"].Text("infrastructure_role") == "domain_controller"
                ? "domain_controller" : entity.Text("entity_type");
        return (restrictControls ? entities : entities.Take(200)).Where(e => (eligible is null || eligible.Contains(e.Int("entity_id")))
            && (parameters.Text("entity_type") is not {} kind || EntityType(e) == kind))
            .Select(e => e.Int("entity_id")).Distinct().ToArray();
    }
    internal static JsonArray SemanticRows(IEnumerable<JsonObject> findings, IReadOnlyList<JsonObject> entities, JsonObject parameters)
    {
        var eligible = SemanticEntityIds(entities, parameters).ToHashSet();
        var rows = new List<JsonObject>();
        foreach (var finding in findings.Where(f => eligible.Contains(f.Int("entity_id"))))
        {
            var entity = entities.First(e => e.Int("entity_id") == finding.Int("entity_id"));
            var row = (JsonObject)finding.DeepClone();
            row["entity_name"] = entity["display_name"]?.DeepClone();
            row["domain_id"] = entity["domain_id"]?.DeepClone(); row["domain_name"] = entity["domain_name"]?.DeepClone();
            if (parameters.Text("q") is not {} query || new[] { "entity_name", "title", "summary", "why_it_matters", "recommended_action" }
                .Any(k => row.Text(k)?.Contains(query, StringComparison.OrdinalIgnoreCase) == true)) rows.Add(row);
        }
        return Array(rows);
    }
    internal static JsonArray Limitations(JsonObject coverage)
    {
        var limitations = new JsonArray(Obj(new { code = "unknown_not_safe", text = "Отсутствующие и недоступные параметры не считаются безопасным нулём: «Не оценено» — не «Пройдено»." }));
        int count = new[] { "missing", "stale", "failed", "partial" }.Sum(key => (coverage[key] as JsonArray)?.Count ?? 0);
        if (count > 0) limitations.Add(Obj(new { code = "coverage", @params = new { count }, text = $"Ограничений покрытия источников: {count}. Пустой список не доказывает безопасное состояние." }));
        return limitations;
    }
    internal static string CsvControls(JsonArray rows)
    {
        var output=new System.Text.StringBuilder();void Write(IEnumerable<string> cells)=>output.AppendJoin(';',cells.Select(v=>AdV2Endpoints.CsvCell(v,';'))).Append("\r\n");
        Write(["Параметр","Объект","Тип объекта","Контекст","Фактическое значение","Ожидаемое условие","Результат","Источник правила","Секция","Наблюдалось"]);
        foreach(var row in rows)Write(new[]{"label","entity_name","entity_type","object_context","actual_value","expected_condition","qualification","authority","source_section","observed_at_utc"}.Select(key=>row?[key] is JsonObject or JsonArray?AdCursors.PythonSpaced(row[key]!,false):AdV2Endpoints.PythonText(row?[key])));return output.ToString();
    }
    static readonly JsonObject Templates = AdV2Store.Resource("control-templates");
    static readonly JsonObject Metadata=AdV2Store.Resource("control-context");
    static string? TextValue(JsonNode? value)
    {
        if(value is null)return null;if(value is JsonArray array)return array.Count>0?string.Join(", ",array.Select(n=>n?.ToString())):null;
        if(value is JsonObject obj)return obj.Text("source") is {} from&&obj.Text("destination") is {} to?from+" → "+to:Sli.Agent.Protocol.CanonicalJson.Serialize(obj,false);
        return AdInventoryRows.Bool(value) switch{true=>"Да",false=>"Нет",_=>value.ToString()};
    }
    static string? ValueCode(JsonNode? value)=>AdInventoryRows.Bool(value) switch{true=>"reports.boolean.yes",false=>"reports.boolean.no",_=>value?.GetValueKind()==System.Text.Json.JsonValueKind.String?"reports.values."+value.ToString():null};
    public static List<JsonObject> Compose(IReadOnlyList<JsonObject> entities, JsonObject parameters)
    {
        var rows = new List<JsonObject>();
        foreach (var entity in entities)
        {
            var record = JsonNode.Parse(entity.Text("record")!)!; var attrs = record["attributes"]!.AsObject(); string kind = entity.Text("entity_type")!;
            if (kind == "ad_computer") {if(entity.Text("source_section")!="domain_health"||attrs.Text("infrastructure_role")!="domain_controller")continue;kind="domain_controller";}
            foreach (var (identity, templateNode) in Templates)
            {
                var pair = identity.Split(':'); if (pair[0] != kind || !attrs.ContainsKey(pair[1])) continue;
                string field = pair[1]; var template = templateNode!.AsObject(); var actual = attrs[field]; string? value = actual?.ToString();
                string qualification = template.Text("authority") == "not_defined" ? "policy_not_defined" : field switch
                {
                    "ldap_signing_requirement" => value == "require_signing" ? "passed" : value == "not_required" ? "failed" : "not_evaluated",
                    "ldap_channel_binding_requirement" => value is "always" or "when_supported" ? "passed" : value == "never" ? "failed" : "not_evaluated",
                    "last_replication_result" or "consecutive_failure_count" => attrs.Int(field) == 0 ? "passed" : "failed",
                    "last_replication_success_utc" => AdInventoryRows.Date(actual) is {} stamp ? entity.Time("observed_at_utc") - stamp > TimeSpan.FromHours(24) ? "failed" : "passed" : "not_evaluated",
                    _ => string.IsNullOrEmpty(value) || new[] { "unknown", "unavailable", "timeout", "not_collected", "not_evaluated", "partial" }.Contains(value.ToLowerInvariant()) ? "not_evaluated" : value.Equals("passed", StringComparison.OrdinalIgnoreCase) ? "passed" : "failed"
                };
                if (qualification == "policy_not_defined" && actual is null) continue;
                var row = (JsonObject)template.DeepClone();
                row["row_id"] = entity.Int("entity_id").ToString(CultureInfo.InvariantCulture) + ":" + template.Text("control_id");
                foreach (string key in new[] { "entity_id", "domain_id", "domain_name", "source_section", "observed_at_utc" }) row[key] = entity[key]?.DeepClone();
                row["entity_type"] = kind; row["entity_name"] = entity["display_name"]?.DeepClone(); row["actual_value"] = actual?.DeepClone(); row["actual_text"] = Metadata["ENUM_LABELS"]?[value??""]?.ToString()??TextValue(actual);
                row["qualification"] = qualification; row["authority_text"] = template.Text("authority") switch { "collector_diagnostic" => "Диагностика сборщика", "report_rule_v1" => "Правило отчёта v1", _ => "Политика организации не задана" };
                var context=new JsonObject();foreach(var node in Metadata["_CONTROL_CONTEXT_FIELDS"]?[kind] as JsonArray??[]){string key=node!.ToString();if(attrs[key] is not null)context[key]=attrs[key]!.DeepClone();}row["object_context"]=context;
                row["context"] = Array(context.Select(p=>
                {var item=Obj(new{code=p.Key,label=Metadata["CONTEXT_LABELS"]?.Text(p.Key)??p.Key,value=TextValue(p.Value)});var messages=new JsonObject();if(AdPresentation.Message("reports.v2.ad.infrastructure.context_labels."+p.Key) is {} label)messages["label"]=label;if((AdInventoryRows.Bool(p.Value) is not null||p.Key is "trust_type" or "trust_direction")&&ValueCode(p.Value) is {} code&&AdPresentation.Message(code) is {} msg)messages["value"]=msg;if(messages.Count>0)item["presentation_messages"]=messages;return item;}));
                if(row.Text("expected_condition")=="Сборщик должен вернуть passed")row["expected_condition"]="Проверка репликации должна завершиться успешно";
                bool unset=row.Text("authority")=="not_defined",zero=row.Text("control_id") is "replication.result_code" or "replication.consecutive_failures";
                var messages=new JsonObject();foreach(var(target,code)in new[]{("label","controls."+row.Text("control_id")+".label"),("expected_condition","controls."+(unset?"policy_unset":zero?"zero.expected":row.Text("control_id")+".expected")),("authority_text","authority."+row.Text("authority"))})if(AdPresentation.Message("reports.v2.ad.infrastructure."+code) is {} message)messages[target]=message;
                if(ValueCode(actual) is {} actualCode&&AdPresentation.Message(actualCode) is {} actualMessage)messages["actual_text"]=actualMessage;if(messages.Count>0)row["presentation_messages"]=messages;
                string view = parameters.Text("view") ?? "overview";
                if (view == "risks" && qualification != "failed" || view is not ("risks" or "overview") && template.Text("category") != view) continue;
                if (parameters.Text("qualification") is {} selected && selected != qualification || parameters.Text("entity_type") is {} entityType && entityType != kind) continue;
                if(parameters.Text("row_id") is {} rowId&&rowId!=row.Text("row_id"))continue;
                if (parameters.Text("q") is {} query && !string.Join(' ', new[]{"label","entity_name","actual_text","control_id"}.Select(row.Text)).Contains(query, StringComparison.OrdinalIgnoreCase)) continue;
                rows.Add(row);
            }
        }
        return rows.OrderBy(r=>r.Text("qualification") switch{"failed"=>0,"not_evaluated"=>1,"policy_not_defined"=>2,"passed"=>3,_=>9}).ThenBy(r=>r.Text("entity_name"),StringComparer.Ordinal).ThenBy(r=>r.Text("label"),StringComparer.Ordinal).ToList();
    }
}
