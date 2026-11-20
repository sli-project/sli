using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sli.Server.Agents.SnapshotPublication;

// Python int() for JSON primitives used by section metadata.
internal static class GovernanceInteger
{
    public static BigInteger Parse(JsonNode? node)
    {
        if (node is null) throw new InvalidDataException("agent_gpo_governance_invalid");
        var kind=node.GetValueKind();
        if (kind == JsonValueKind.True) return BigInteger.One;
        if (kind == JsonValueKind.False) return BigInteger.Zero;
        string text=kind == JsonValueKind.String ? node.GetValue<string>().Trim() : node.ToJsonString();
        if (kind == JsonValueKind.Number && (text.Contains('.') || text.Contains('e') || text.Contains('E')))
        {
            if (!double.TryParse(text,NumberStyles.Float,CultureInfo.InvariantCulture,out var n) || !double.IsFinite(n)) throw new InvalidDataException("agent_gpo_governance_invalid");
            return new BigInteger(n);
        }
        if (kind is not (JsonValueKind.Number or JsonValueKind.String) || text.Length == 0) throw new InvalidDataException("agent_gpo_governance_invalid");
        int offset=0, sign=1; if (text[0] is '+' or '-') { if (text[0]=='-') sign=-1; offset++; }
        if (offset==text.Length) throw new InvalidDataException("agent_gpo_governance_invalid");
        BigInteger result=0; bool previousDigit=false;
        while (offset<text.Length)
        {
            if (text[offset]=='_') { if (!previousDigit || offset+1>=text.Length) throw new InvalidDataException("agent_gpo_governance_invalid"); previousDigit=false; offset++; continue; }
            if (!Rune.TryGetRuneAt(text,offset,out var rune) || Rune.GetUnicodeCategory(rune)!=UnicodeCategory.DecimalDigitNumber) throw new InvalidDataException("agent_gpo_governance_invalid");
            int digit=CharUnicodeInfo.GetDecimalDigitValue(text,offset); if (digit<0) throw new InvalidDataException("agent_gpo_governance_invalid");
            result=result*10+digit; previousDigit=true; offset+=rune.Utf16SequenceLength;
        }
        if (!previousDigit) throw new InvalidDataException("agent_gpo_governance_invalid");
        return sign*result;
    }
}
