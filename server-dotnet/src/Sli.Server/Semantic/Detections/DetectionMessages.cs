using System.Globalization;
using System.Text.Json;

namespace Sli.Server.Semantic.Detections;

internal static class DetectionMessages
{
    private static readonly IReadOnlyDictionary<string,string> Ru=Load("ru"),En=Load("en");
    private static IReadOnlyDictionary<string,string> Load(string language){using var stream=typeof(DetectionMessages).Assembly.GetManifestResourceStream("Sli.Server.Access.Administration.server."+language+".json")!;return JsonSerializer.Deserialize<Dictionary<string,string>>(stream)!;}
    internal static string Text(string key,bool english=false,IReadOnlyDictionary<string,object?>? parameters=null)
    {
        string result=(english?En:Ru)[key];foreach(var (name,value) in parameters??new Dictionary<string,object?>())result=result.Replace("{"+name+"}",Convert.ToString(value,CultureInfo.InvariantCulture));return result;
    }
}
