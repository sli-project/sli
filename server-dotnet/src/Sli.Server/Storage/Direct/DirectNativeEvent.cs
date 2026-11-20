using System.Text.Json.Nodes;
using System.Xml.Linq;
using Sli.Agent.Core;
using Sli.Agent.Protocol.Compatibility;

namespace Sli.Server.Storage.Direct;

// import_event_jsonl_to_postgres.parse_event_data and source-pack resolution.
internal static class DirectNativeEvent
{
    internal static string? Text(XElement? element) => element?.Nodes().TakeWhile(n=>n is not XElement)
        .OfType<XText>().Select(n=>n.Value).Aggregate((string?)null,(a,b)=>(a??"")+b);

    internal static JsonObject Data(JsonObject row)
    {
        var result=new JsonObject();
        string? xml=row["xml"]?.GetValue<string>();
        if(string.IsNullOrEmpty(xml))return result;
        XElement root;
        try { root=EventXml.ParseBounded(xml); }
        catch(EventXmlException error) {
            // Preserve the Python importer's data-quality result, never XML or parser diagnostics.
            return new JsonObject { ["_sli_data_quality"]=new JsonObject {
                ["event_data_parse_status"]="failed",
                ["error_type"]=error.Code switch {
                    "xml_malformed"=>"ParseError",
                    "xml_not_utf8"=>"UnicodeEncodeError",
                    _=>"UnsafeXmlError"
                }
            }};
        }
        XNamespace ns=EventXml.Namespace;
        foreach(var item in root.Descendants(ns+"EventData").SelectMany(e=>e.Elements(ns+"Data"))) {
            string? name=(string?)item.Attribute("Name");
            if(!string.IsNullOrEmpty(name))result[name]=Text(item);
            else {
                if(!result.ContainsKey("Data"))result["Data"]=new JsonArray();
                if(result["Data"] is not JsonArray list)throw new InvalidDataException("storage_v2_event_profile_pending");
                list.Add(Text(item));
            }
        }
        foreach(var item in root.Descendants(ns+"UserData").SelectMany(e=>e.Elements()))result[item.Name.LocalName]=Text(item);
        var execution=root.Descendants(ns+"System").SelectMany(e=>e.Elements(ns+"Execution")).FirstOrDefault();
        if((string?)execution?.Attribute("ProcessID") is {Length:>0} pid)result["SystemExecutionProcessId"]=pid;
        return result;
    }

    private static readonly (string Name,JsonObject Document)[] Catalogs=Load();
    private static (string,JsonObject)[] Load()=>new[]{"event_catalog","file_audit_event_catalog","radius_event_catalog"}.Select(name=>{
        using var stream=typeof(DirectNativeEvent).Assembly.GetManifestResourceStream("Sli.Server.Semantic.Risk."+name+".json")!;
        return(name,JsonNode.Parse(stream)!.AsObject());
    }).ToArray();
    internal static JsonObject Card(JsonObject row)
    {
        var entry=Catalogs.SelectMany(c=>c.Document["entries"]!.AsArray().OfType<JsonObject>()).FirstOrDefault(e=>
            (int?)e["event_id"]==(int?)row["event_id"] && string.Equals(e["channel"]?.ToString(),row["channel"]?.ToString(),StringComparison.OrdinalIgnoreCase) &&
            string.Equals(e["provider_name"]?.ToString(),row["provider_name"]?.ToString(),StringComparison.OrdinalIgnoreCase));
        var item=(JsonObject)row.DeepClone();item["event_data"]=Data(row);
        return Sli.Server.Storage.EventReports.EventCardSemantics.Build(item,entry,null);
    }
    internal static string? Initiator(JsonObject row,IReadOnlyDictionary<string,string> data)
    {
        foreach(var (_,document) in Catalogs) {
            var entry=document["entries"]!.AsArray().OfType<JsonObject>().FirstOrDefault(e=>
                (int?)e["event_id"]==(int?)row["event_id"] && string.Equals(e["channel"]?.ToString(),row["channel"]?.ToString(),StringComparison.OrdinalIgnoreCase) &&
                string.Equals(e["provider_name"]?.ToString(),row["provider_name"]?.ToString(),StringComparison.OrdinalIgnoreCase));
            if(entry is null)continue;
            foreach(var key in (entry["card"]?["field_roles"]?["initiator"] as JsonArray??[])) {
                string field=key!.ToString();string? value=row.ContainsKey(field)?row[field]?.ToString():data.GetValueOrDefault(field);
                value=Sli.Server.Compatibility.PythonText.Strip(value??"");
                if(value.Length>0 && value is not ("-" or "—"))return value;
            }
            return entry["card"]?["field_roles"]?["initiator"] is not null?"":null;
        }
        return null;
    }
    internal static (string Normalizer,string Noise,string Version) Profile(string channel,string provider,int kind)
    {
        string Fold(string value)=>UnicodeLower.Lower(Sli.Server.Compatibility.PythonText.Strip(value));
        foreach(var (name,document) in Catalogs) {
            var entry=document["entries"]!.AsArray().OfType<JsonObject>().FirstOrDefault(e=>
                (int?)e["event_id"]==kind && Fold(e["channel"]?.ToString()??"")==Fold(channel) &&
                Fold(e["provider_name"]?.ToString()??"")==Fold(provider));
            if(entry is not null)return(name,entry["noise_class"]?.ToString() is "signal" or "context" or "noise" ? entry["noise_class"]!.ToString():"not_classified",document["version"]!.ToString());
        }
        return("","not_classified",Catalogs[0].Document["version"]!.ToString());
    }
}
