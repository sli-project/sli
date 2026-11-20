using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

internal static class AdCursors
{
    internal static string ComputerEncode(string sort,string direction,long entity)
    {
        byte[] payload=Encoding.UTF8.GetBytes(new JsonArray("v1",sort,direction,entity).ToJsonString());byte[] signature=SHA256.HashData([..Encoding.UTF8.GetBytes("sli.computers-report.v6\0"),..payload])[..12];return Convert.ToBase64String([..signature,..payload]).TrimEnd('=').Replace('+','-').Replace('/','_');
    }
    internal static long ComputerDecode(string token,string sort,string direction)
    {
        try{if(token.Length>2048)throw new FormatException();string b64=token.Replace('-','+').Replace('_','/');byte[] raw=Convert.FromBase64String(b64.PadRight((b64.Length+3)/4*4,'='));if(raw.Length<=12||!CryptographicOperations.FixedTimeEquals(raw[..12],SHA256.HashData([..Encoding.UTF8.GetBytes("sli.computers-report.v6\0"),..raw[12..]])[..12]))throw new FormatException();var value=JsonNode.Parse(raw[12..])!.AsArray();if(value.Count!=4||value[0]!.ToString()!="v1"||value[1]!.ToString()!=sort||value[2]!.ToString()!=direction||value[3]!.GetValue<long>()<=0)throw new FormatException();return value[3]!.GetValue<long>();}
        catch(Exception e)when(e is FormatException or System.Text.Json.JsonException or InvalidOperationException or NullReferenceException){throw new AdInputException("invalid_computers_v6_cursor");}
    }
    static string Hash(string text)=>Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    static string Token(JsonNode value)=>Convert.ToBase64String(CanonicalJson.ToBytes(value)).TrimEnd('=').Replace('+','-').Replace('/','_');
    static JsonObject Decode(string token)
    {
        if(token.Length is 0 or >16384||token.Any(c=>!(char.IsAsciiLetterOrDigit(c)||c is '-' or '_')))throw new FormatException();
        string b64=token.Replace('-','+').Replace('_','/');return JsonNode.Parse(Convert.FromBase64String(b64.PadRight((b64.Length+3)/4*4,'=')))!.AsObject();
    }
    internal static string LogonBinding(string kind,JsonObject values)
    {var input=(JsonObject)values.DeepClone();input["kind"]=kind;return Hash(CanonicalJson.Serialize(input,false));}
    internal static string LogonEncode(string kind,string binding,JsonObject position)
    {var body=Obj(new{v=1,kind,binding,position});return Token(new JsonObject{["body"]=body,["checksum"]=Hash("sli-computer-logons:"+CanonicalJson.Serialize(body,false))});}
    internal static JsonObject LogonDecode(string token,string kind,string binding)
    {
        try{var envelope=Decode(token);var body=envelope["body"]!.AsObject();if(envelope.Text("checksum")!=Hash("sli-computer-logons:"+CanonicalJson.Serialize(body,false))||body.Int("v")!=1||body.Text("kind")!=kind||body.Text("binding")!=binding)throw new FormatException();return body["position"]!.AsObject();}
        catch(Exception e)when(e is FormatException or System.Text.Json.JsonException or InvalidOperationException or NullReferenceException){throw new AdInputException("invalid_cursor");}
    }
    internal static string PythonSpaced(JsonNode context,bool ensureAscii=true)
    {
        string compact=CanonicalJson.Serialize(context,ensureAscii);var output=new StringBuilder();bool quoted=false,escaped=false;
        foreach(char c in compact){output.Append(c);if(quoted){if(escaped)escaped=false;else if(c=='\\')escaped=true;else if(c=='"')quoted=false;}else if(c=='"')quoted=true;else if(c is ':' or ',')output.Append(' ');}return output.ToString();
    }
    internal static string Encode(JsonObject context,JsonObject position)=>Token(Obj(new{binding=Hash(PythonSpaced(context)),position}));
    internal static JsonObject Read(string token,JsonObject context)
    {
        try{if(token.Length>2048)throw new FormatException();var value=Decode(token);if(value.Text("binding")!=Hash(PythonSpaced(context)))throw new FormatException();return value["position"]!.AsObject();}
        catch(Exception e)when(e is FormatException or System.Text.Json.JsonException or InvalidOperationException or NullReferenceException){throw new AdInputException("invalid_cursor");}
    }
}
