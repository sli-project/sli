using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

internal static class AdPresentation
{
    static readonly JsonObject Catalog=JsonNode.Parse(new StreamReader(typeof(AdPresentation).Assembly.GetManifestResourceStream("Sli.Server.Access.Administration.server.ru.json")!).ReadToEnd())!.AsObject();
    internal static JsonObject? Message(string key,JsonObject? parameters=null)
    {
        if(Catalog[key] is not {} value)return null;parameters??=new();string text=value.ToString();
        foreach(Match match in Regex.Matches(text,@"\{(\w+)\}"))if(parameters[match.Groups[1].Value] is null)return null;
        var used=new JsonObject();foreach(Match match in Regex.Matches(text,@"\{(\w+)\}")){string name=match.Groups[1].Value;used[name]=parameters[name]!.DeepClone();text=text.Replace(match.Value,parameters[name]!.ToString(),StringComparison.Ordinal);}
        return Sli.Server.Reporting.V2.ReportPresentation.Message(key,false,used);
    }
}
