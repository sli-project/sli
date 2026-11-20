using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sli.Server.Storage.EventReports;

internal static class EventRelationCursor
{
    static string Binding(long anchor) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("[\"event-relations\", " + anchor.ToString(CultureInfo.InvariantCulture) + "]")));
    internal static string Encode(long anchor, decimal delta, long id)
    {
        if (anchor <= 0 || delta < 0 || id <= 0) throw new InvalidDataException("invalid_cursor");
        var data=JsonSerializer.SerializeToUtf8Bytes(new { binding=Binding(anchor),position=new { delta=delta.ToString(CultureInfo.InvariantCulture), id } });
        return Convert.ToBase64String(data).TrimEnd('=').Replace('+','-').Replace('/','_');
    }
    internal static (decimal Delta,long Id) Decode(long anchor,string token)
    {
        try
        {
            if (anchor <= 0 || token.Length is < 1 or > 2048 || token.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_' or '+' or '/' or '='))) throw new FormatException();
            string encoded=token.Replace('-','+').Replace('_','/'); encoded += new string('=',(4-encoded.Length%4)%4);
            using var document=JsonDocument.Parse(Convert.FromBase64String(encoded));
            var root=document.RootElement;
            if(root.ValueKind!=JsonValueKind.Object || !root.TryGetProperty("binding",out var bind) || bind.GetString()!=Binding(anchor) ||
               !root.TryGetProperty("position",out var position) || position.ValueKind!=JsonValueKind.Object ||
               !position.TryGetProperty("delta",out var deltaJson) || !position.TryGetProperty("id",out var idJson) ||
               idJson.ValueKind!=JsonValueKind.Number || !idJson.TryGetInt64(out long id) || id<=0 ||
               !decimal.TryParse(deltaJson.ToString(),NumberStyles.Float,CultureInfo.InvariantCulture,out decimal delta) || delta<0) throw new FormatException();
            return (delta,id);
        }
        catch(Exception e) when(e is FormatException or JsonException or InvalidOperationException or OverflowException)
        { throw new InvalidDataException("invalid_cursor",e); }
    }
}
