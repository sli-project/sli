using System.Globalization;
using System.Numerics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Ingress;

/// <summary>Python JSON equality for signed metadata, not payload integer validation.</summary>
internal static class PythonMetadataEquality
{
    private static bool Integer(JsonNode? node,out BigInteger value)
    {
        if(node is JsonValue b && b.GetValueKind() is JsonValueKind.True or JsonValueKind.False)
        { value=b.GetValue<bool>() ? BigInteger.One : BigInteger.Zero; return true; }
        return JsonRead.TryInteger(node,out value);
    }
    private static bool Float(JsonNode? node,out double result)
    {
        result=0;
        return node is JsonValue v && v.GetValueKind()==JsonValueKind.Number
            && double.TryParse(node.ToJsonString(),NumberStyles.Float,CultureInfo.InvariantCulture,out result) && double.IsFinite(result);
    }
    public static bool Equal(JsonNode? left,JsonNode? right)
    {
        if(left is null || right is null) return left is null && right is null;
        if(left is JsonObject x && right is JsonObject y) return x.Count==y.Count && x.All(p=>y.ContainsKey(p.Key) && Equal(p.Value,y[p.Key]));
        if(left is JsonArray a && right is JsonArray b) return a.Count==b.Count && a.Zip(b).All(p=>Equal(p.First,p.Second));
        bool li=Integer(left,out var l), ri=Integer(right,out var r);
        if(li && ri) return l==r;
        if(li && Float(right,out var rf)) return Math.Truncate(rf)==rf && new BigInteger(rf)==l;
        if(ri && Float(left,out var lf)) return Math.Truncate(lf)==lf && new BigInteger(lf)==r;
        if(Float(left,out var dl) && Float(right,out var dr)) return dl==dr;
        return JsonNode.DeepEquals(left,right);
    }
}
