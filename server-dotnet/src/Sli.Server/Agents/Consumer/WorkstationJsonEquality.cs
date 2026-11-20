using System.Globalization;
using System.Numerics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Server.Agents.Consumer;

// Python JSON equality for received/stored receipt and packet evidence.
internal static class WorkstationJsonEquality
{
    public static bool Equals(JsonNode? a,JsonNode? b)
    {
        if(a is null || b is null) return a is null && b is null;
        if(Number(a,out var ai,out var af) && Number(b,out var bi,out var bf)) {
            if(ai is not null && bi is not null) return ai==bi;
            if(ai is null && bi is null) return af==bf;
            BigInteger integer=ai??bi!.Value; double number=ai is null?af:bf;
            return double.IsFinite(number) && Math.Truncate(number)==number && new BigInteger(number)==integer;
        }
        if(a is JsonObject x && b is JsonObject y) return x.Count==y.Count && x.All(p=>y.ContainsKey(p.Key)&&Equals(p.Value,y[p.Key]));
        if(a is JsonArray l && b is JsonArray r) return l.Count==r.Count && l.Zip(r).All(p=>Equals(p.First,p.Second));
        return JsonNode.DeepEquals(a,b);
    }
    private static bool Number(JsonNode node,out BigInteger? integer,out double floating)
    {
        integer=null;floating=0;
        if(node is not JsonValue value) return false;
        if(value.GetValueKind() is JsonValueKind.True or JsonValueKind.False) {integer=value.GetValue<bool>()?BigInteger.One:BigInteger.Zero;return true;}
        if(JsonRead.TryInteger(node,out var i)) {integer=i;return true;}
        return value.GetValueKind()==JsonValueKind.Number && double.TryParse(node.ToJsonString(),NumberStyles.Float,CultureInfo.InvariantCulture,out floating);
    }
}
