using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol.Compatibility;
using Sli.Gpo.SnapshotModel;

namespace Sli.Server.Agents.SnapshotPublication;

// Source: server/sli/plugins/gpo/context_contracts.py:_gpo_settings.
internal static class GpoGovernanceSettings
{
    public static JsonArray Normalize(JsonNode? input)
    {
        if (input is not JsonArray values || values.Count > 2048) throw Invalid();
        var result=new JsonArray();
        foreach (var value in values)
        {
            if (value is not JsonObject item || item.Any(x=>!Keys.Contains(x.Key))) throw Invalid();
            string scope=Text(item["scope"]),kind=Text(item["kind"]),path=Text(item["path"]);
            if (scope is not ("computer" or "user") || Count(kind)>128 || Count(path)>512 || item["properties"] is not JsonObject properties || properties.Count>64) throw Invalid();
            var normalized=new JsonObject();
            foreach (var (rawKey,rawValue) in properties)
            {
                var key=UnicodeLower.Lower(Text(JsonValue.Create(rawKey)));
                if (Count(key)>128 || GpoSnapshotDocument.IsSensitiveField(key) || rawValue?.GetValueKind()!=JsonValueKind.String || Count(rawValue.GetValue<string>())>4096) throw Invalid();
                normalized[key]=rawValue.DeepClone();
            }
            var redacted=Names(item["redacted_fields"]); var truncated=Names(item["truncated_fields"]);
            if (redacted.Any(x=>!GpoSnapshotDocument.IsSensitiveField(x)) || truncated.Any(x=>!normalized.ContainsKey(x))) throw Invalid();
            var sensitive=item["sensitive_value_present"];
            if (sensitive?.GetValueKind() is not (JsonValueKind.True or JsonValueKind.False) || sensitive.GetValue<bool>() != (redacted.Count>0)) throw Invalid();
            var sha=UnicodeLower.Lower(Text(item["sha256"]));
            if (!Regex.IsMatch(sha,@"\A[0-9a-f]{64}\z",RegexOptions.CultureInvariant)) throw Invalid();
            result.Add(new JsonObject { ["scope"]=scope,["kind"]=kind,["path"]=path,["properties"]=normalized,
                ["redacted_fields"]=new JsonArray(redacted.Select(x=>(JsonNode?)JsonValue.Create(x)).ToArray()),
                ["truncated_fields"]=new JsonArray(truncated.Select(x=>(JsonNode?)JsonValue.Create(x)).ToArray()),
                ["sensitive_value_present"]=sensitive.DeepClone(),["sha256"]=sha });
        }
        return result;
    }
    private static readonly HashSet<string> Keys=new(["scope","kind","path","properties","redacted_fields","truncated_fields","sensitive_value_present","sha256"],StringComparer.Ordinal);
    private static List<string> Names(JsonNode? node)
    {
        if (node is not JsonArray arr || arr.Count>64) throw Invalid();
        return arr.Select(x=>UnicodeLower.Lower(Text(x))).Distinct(StringComparer.Ordinal).OrderBy(x=>x,Comparer<string>.Create(CompareCodepoints)).ToList();
    }
    internal static string Text(JsonNode? value)
    {
        bool truth=IsTruthy(value);
        string text=truth ? GpoSnapshotDocument.PythonString(JsonSerializer.SerializeToElement(value)) : "";
        text=PythonTrim(text);
        if (text.Length==0 || Count(text)>4096) throw Invalid();
        return text;
    }
    internal static bool IsTruthy(JsonNode? value) => value switch { null=>false, JsonObject o=>o.Count!=0, JsonArray a=>a.Count!=0, _=>value.GetValueKind() switch { JsonValueKind.False or JsonValueKind.Null=>false, JsonValueKind.String=>value.GetValue<string>().Length!=0, JsonValueKind.Number=>!double.TryParse(value.ToJsonString(),System.Globalization.NumberStyles.Float,System.Globalization.CultureInfo.InvariantCulture,out var n) || n != 0, _=>true } };
    internal static string PythonTrim(string text)
    {
        static bool Space(char c) => char.IsWhiteSpace(c) || c is >= '\u001c' and <= '\u001f';
        int a=0,b=text.Length; while (a<b && Space(text[a])) a++; while (b>a && Space(text[b-1])) b--; return text[a..b];
    }
    internal static int CompareCodepoints(string x,string y)
    {
        var a=x.EnumerateRunes().GetEnumerator(); var b=y.EnumerateRunes().GetEnumerator();
        while (true) { bool aa=a.MoveNext(),bb=b.MoveNext(); if (!aa || !bb) return aa.CompareTo(bb); int c=a.Current.Value.CompareTo(b.Current.Value); if(c!=0) return c; }
    }
    internal static int Count(string s)=>s.EnumerateRunes().Count();
    private static InvalidDataException Invalid()=>new("agent_gpo_governance_invalid");
}
