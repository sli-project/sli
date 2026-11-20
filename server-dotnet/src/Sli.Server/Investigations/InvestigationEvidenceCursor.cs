using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Sli.Server.Investigations;

public static class InvestigationEvidenceCursor
{
    public static long? Event(string? value)
    {
        if (value is null) return null;
        if (value.Length is < 1 or > 19 || value.Any(c => c is < '0' or > '9') ||
            !long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long id) || id <= 0)
            throw new InvestigationException("invalid_cursor", "Invalid evidence cursor or anchor");
        return id;
    }
    public static (string Kind,long Domain,string Reference)? Reference(string? token)
    {
        if (token is null) return null;
        try
        {
            if(token.Length is < 1 or > 1024 || token.Any(c => c > 127 || !(char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '-' or '_' or '='))) throw new FormatException();
            var bytes=Convert.FromBase64String(token.Replace('-','+').Replace('_','/'));
            using var doc=JsonDocument.Parse(DecodeJson(bytes)); var key=doc.RootElement;
            if(key.ValueKind!=JsonValueKind.Array || key.GetArrayLength()!=3 || key[0].ValueKind!=JsonValueKind.String || key[0].GetString()!="vpn_accounting_session" ||
               key[1].ValueKind!=JsonValueKind.Number || !key[1].TryGetInt64(out long domain) || domain<=0 || key[2].ValueKind!=JsonValueKind.String) throw new FormatException();
            string reference=key[2].GetString()!;
            if(reference.EnumerateRunes().Count()>200) throw new FormatException();
            return ("vpn_accounting_session",domain,reference);
        }
        catch(Exception ex) when(ex is FormatException or JsonException or InvalidOperationException or DecoderFallbackException)
        { throw new InvestigationException("invalid_cursor","Invalid reference cursor"); }
    }
    private static string DecodeJson(byte[] data)
    {
        // json.loads(bytes) detects UTF-8/16/32 from BOM or zero-byte pattern.
        Encoding enc; int skip=0;
        if(data.AsSpan().StartsWith(new byte[]{0,0,0xfe,0xff})) {enc=new UTF32Encoding(true,false,true);skip=4;}
        else if(data.AsSpan().StartsWith(new byte[]{0xff,0xfe,0,0})) {enc=new UTF32Encoding(false,false,true);skip=4;}
        else if(data.AsSpan().StartsWith(new byte[]{0xfe,0xff})) {enc=new UnicodeEncoding(true,false,true);skip=2;}
        else if(data.AsSpan().StartsWith(new byte[]{0xff,0xfe})) {enc=new UnicodeEncoding(false,false,true);skip=2;}
        else if(data.AsSpan().StartsWith(new byte[]{0xef,0xbb,0xbf})) {enc=new UTF8Encoding(false,true);skip=3;}
        else if(data.Length>=4 && data[0]==0 && data[1]==0 && data[2]==0) enc=new UTF32Encoding(true,false,true);
        else if(data.Length>=4 && data[1]==0 && data[2]==0 && data[3]==0) enc=new UTF32Encoding(false,false,true);
        else if(data.Length>=2 && data[0]==0) enc=new UnicodeEncoding(true,false,true);
        else if(data.Length>=2 && data[1]==0) enc=new UnicodeEncoding(false,false,true);
        else enc=new UTF8Encoding(false,true);
        return enc.GetString(data,skip,data.Length-skip);
    }
    public static string EncodeReference(string kind,long domain,string reference)
    {
        // Python json.dumps defaults to ensure_ascii=True and lower-case hex escapes.
        var quoted=new StringBuilder("\"");
        foreach(char c in reference)
        {
            switch(c)
            {
                case '"': quoted.Append("\\\""); break;
                case '\\': quoted.Append("\\\\"); break;
                case '\b': quoted.Append("\\b"); break;
                case '\f': quoted.Append("\\f"); break;
                case '\n': quoted.Append("\\n"); break;
                case '\r': quoted.Append("\\r"); break;
                case '\t': quoted.Append("\\t"); break;
                default: if(c < 32 || c >= 127) quoted.Append("\\u").Append(((int)c).ToString("x4",CultureInfo.InvariantCulture)); else quoted.Append(c); break;
            }
        }
        quoted.Append('"');
        string json="[\""+kind+"\","+domain.ToString(CultureInfo.InvariantCulture)+","+quoted+"]";
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(json)).Replace('+','-').Replace('/','_');
    }
}
