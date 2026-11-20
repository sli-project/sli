using System.Text;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Sli.Agent.Core;
using Sli.Server.Access.Administration;

namespace Sli.Server.Storage.Direct;

// An immutable conflicting source representation, not an infrastructure failure.
internal sealed class DirectSourceConflict(bool published, int ordinal = 0) : Exception
{
    internal bool Published => published;
    internal string Reason => published ? "published_source_event_hash_mismatch" : "source_event_allocation_hash_mismatch";
    internal int Ordinal => ordinal;
}

internal static class DirectRepresentationConflict
{
    // Source preferred_representation: only classify shapes whose retained and
    // incoming rows passed this producer's bounded source-identity validator.
    internal static bool IsProven(JsonObject retained, JsonObject incoming)
    {
        string oldIdentity=DirectEventIdentity.Hash(retained), newIdentity=DirectEventIdentity.Hash(incoming);
        if(oldIdentity!=newIdentity) return true;
        var old=Fields(EventXml.ParseBounded(retained["xml"]!.GetValue<string>()));
        var next=Fields(EventXml.ParseBounded(incoming["xml"]!.GetValue<string>()));
        if(old.Any(x=>next.TryGetValue(x.Key,out var value) && value!=x.Value))return true;
        int oldCount=retained["properties"]!.AsArray().Count, newCount=incoming["properties"]!.AsArray().Count;
        bool oldContains=next.Keys.All(old.ContainsKey) && oldCount>=newCount;
        bool newContains=old.Keys.All(next.ContainsKey) && newCount>=oldCount;
        return !oldContains && !newContains;
    }
    private static Dictionary<string,string> Fields(XElement root)
    {
        var fields=new Dictionary<string,string>(StringComparer.Ordinal);
        static string Enc(string? s)=>s is null ? "-" : Convert.ToBase64String(Encoding.UTF8.GetBytes(s));
        static bool HasText(string s)=>AssignmentValidation.Strip(s).Length!=0;
        void Visit(XElement node,string path)
        {
            foreach(var a in node.Attributes().Where(a=>!a.IsNamespaceDeclaration)) fields[path+"/@"+Enc(a.Name.ToString())]=a.Value;
            var text=new StringBuilder();foreach(var n in node.Nodes()) { if(n is XElement)break; if(n is XText t)text.Append(t.Value); }
            if(text.Length>0 && (!node.HasElements || HasText(text.ToString()))) fields[path+"/#text"]=text.ToString();
            var tail=new StringBuilder();for(var n=node.NextNode;n is XText;n=n.NextNode)tail.Append(((XText)n).Value);
            if(tail.Length>0 && HasText(tail.ToString())) fields[path+"/#tail"]=tail.ToString();
            var counts=new Dictionary<(string,string?),int>();
            foreach(var child in node.Elements()) {
                var key=(child.Name.ToString(),(string?)child.Attribute("Name"));int index=counts.GetValueOrDefault(key);counts[key]=index+1;
                Visit(child,path+"/"+Enc(key.Item1)+":"+Enc(key.Item2)+":"+index.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
        }
        Visit(root,Enc(root.Name.ToString())+":"+Enc((string?)root.Attribute("Name"))+":0");return fields;
    }
}
