using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;

namespace Sli.Gpo.SnapshotModel;

// Source: server/sli/sources/gpo_v2_source.py redaction and canonical snapshot.
public static class GpoSnapshotDocument
{
    private const string Hidden="значение скрыто";
    private static readonly string[] Sensitive=["password","cpassword","passwd","pwd","secret","privatekey","token","credential","apikey","accesskey","sharedkey","presharedkey","psk","encryptionkey","decryptionkey","symmetrickey","signingkey","keymaterial","passphrase","connectionstring"];
    private static readonly HashSet<string> Named=new(["name","key","valuename","property"],StringComparer.Ordinal);
    private static readonly HashSet<string> ValueFields=new(["value","values","value_display","data","text","valuedata","defaultvalue","properties"],StringComparer.Ordinal);
    private static readonly Regex PrivateKey=new(@"-----BEG[iİı]N .*PR[iİı]VATE [kK]EY-----",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant,TimeSpan.FromSeconds(1));
    private static readonly UTF8Encoding Utf8=new(false,true);
    public static string PythonString(JsonElement value)=>GpoPythonText.Str(value);
    public static JsonElement Redact(JsonElement snapshot)
    {
        var node=JsonNode.Parse(snapshot.GetRawText());
        return JsonSerializer.SerializeToElement(RedactNode(node,false));
    }
    public static byte[] CanonicalUtf8(JsonElement snapshot)
    {
        GpoSnapshotValidator.Validate(snapshot);
        return Utf8.GetBytes(CanonicalJson.Serialize(JsonNode.Parse(snapshot.GetRawText()),ensureAscii:false));
    }
    public static byte[] CanonicalSha256(JsonElement snapshot)=>SHA256.HashData(CanonicalUtf8(snapshot));
    private static JsonNode? RedactNode(JsonNode? node,bool sensitive)
    {
        if(node is JsonObject obj) {
            bool named=obj.Any(p => p.Value is JsonValue v && v.GetValueKind()==JsonValueKind.String
                && (Named.Contains(Lower(p.Key)) || Lower(p.Key) is "setting_name" or "path" or "source_xml_path") && IsSensitiveField(v.GetValue<string>()));
            var result=new JsonObject();
            foreach(var (key,value) in obj) {
                var lower=Lower(key);
                if(named && !sensitive && lower=="source_state" && value is JsonObject state) {
                    var stateResult=new JsonObject();
                    foreach(var (field,data) in state) stateResult[field]=RedactNode(data,Lower(field) is "value" or "detail" or "error");
                    result[key]=stateResult;
                } else result[key]=RedactNode(value,sensitive || IsSensitiveField(key) || named && ValueFields.Contains(lower));
            }
            return result;
        }
        if(node is JsonArray array) { var result=new JsonArray();foreach(var item in array) result.Add(RedactNode(item,sensitive));return result; }
        if(sensitive) return node is null?null:JsonValue.Create(Hidden);
        if(node is JsonValue scalar && scalar.GetValueKind()==JsonValueKind.String && SensitiveValue(scalar.GetValue<string>())) return JsonValue.Create(Hidden);
        return node?.DeepClone();
    }
    private static string Lower(string text)=>UnicodeLower.Lower(text);
    public static bool IsSensitiveField(string text)
    {
        var lowered=Lower(text);var clean=new StringBuilder();
        foreach(char c in lowered) if(c is >= 'a' and <= 'z' or >= '0' and <= '9') clean.Append(c);
        string value=clean.ToString();return Sensitive.Any(value.Contains);
    }
    // Exact bounded recognition of the source assignment pattern; no value is logged or returned.
    private static bool SensitiveValue(string value)
    {
        int position=0;
        while(position<value.Length) {
            int first=position; bool boundary=position==0 || IsBoundary(value,position,out _);
            if(boundary) {
                if(position==0 && Match(value,position,out int end,out string name,out string? label)) {
                    if(IsSensitiveField(name) || Named.Contains(Lower(name)) && label is not null && IsSensitiveField(label)) return true;
                    position=end;continue;
                }
                if(IsBoundary(value,position,out int width) && Match(value,position+width,out int end2,out string name2,out string? label2)) {
                    if(IsSensitiveField(name2) || Named.Contains(Lower(name2)) && label2 is not null && IsSensitiveField(label2)) return true;
                    position=end2;continue;
                }
            }
            _=RuneAt(value,first,out int advance);position=first+advance;
        }
        return PrivateKey.IsMatch(value);
    }
    private static bool Match(string text,int start,out int end,out string name,out string? label)
    {
        end=start;name="";label=null;int p=start;
        if(p<text.Length && text[p] is '\'' or '"') p++;
        int nameStart=p; var ends=new List<int>();
        while(p<text.Length && IsWord(text,p,out int width)){p+=width;ends.Add(p);}
        for(int i=ends.Count-1;i>=0;i--) {
            int q=ends[i]; if(q<text.Length && text[q] is '\'' or '"') q++;
            while(q<text.Length && IsSpace(text,q,out int ws)) q+=ws;
            if(q>=text.Length || text[q] is not ('=' or ':')) continue;
            q++;while(q<text.Length && IsSpace(text,q,out int ws)) q+=ws;
            if(q<text.Length && text[q] is '\'' or '"') q++;
            int labelStart=q;while(q<text.Length && IsWord(text,q,out int w)) q+=w;
            name=text[nameStart..ends[i]];label=q>labelStart?text[labelStart..q]:null;end=q;return true;
        }
        return false;
    }
    private static Rune RuneAt(string s,int index,out int width)
    {
        var status=Rune.DecodeFromUtf16(s.AsSpan(index),out var rune,out width);
        if(status!=System.Buffers.OperationStatus.Done){rune=Rune.ReplacementChar;width=1;}
        return rune;
    }
    private static bool IsWord(string s,int index,out int width)
    {
        var r=RuneAt(s,index,out width);var category=Rune.GetUnicodeCategory(r);
        return r.Value is '_' or '.' or ':' or '-' || category is UnicodeCategory.UppercaseLetter or UnicodeCategory.LowercaseLetter or UnicodeCategory.TitlecaseLetter or UnicodeCategory.ModifierLetter or UnicodeCategory.OtherLetter or UnicodeCategory.DecimalDigitNumber or UnicodeCategory.LetterNumber or UnicodeCategory.OtherNumber;
    }
    private static bool IsBoundary(string s,int index,out int width)
    {
        var r=RuneAt(s,index,out width);return r.Value is ';' or ',' or '{' or '<' || IsPythonSpace(r.Value);
    }
    private static bool IsSpace(string s,int index,out int width) {var r=RuneAt(s,index,out width);return IsPythonSpace(r.Value);}
    private static bool IsPythonSpace(int c)=>c is >= 0x09 and <=0x0D or >=0x1C and <=0x20 or 0x85 or 0xA0 or 0x1680 or >=0x2000 and <=0x200A or 0x2028 or 0x2029 or 0x202F or 0x205F or 0x3000;
}
