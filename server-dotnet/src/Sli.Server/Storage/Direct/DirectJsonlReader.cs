using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Sli.Server.Storage.Direct;

// iter_jsonl's object stream: hash source bytes before decoding or trimming them.
internal static class DirectJsonlReader
{
    internal static IEnumerable<JsonObject> Read(string path, IncrementalHash? digest = null)
    {
        if (!File.Exists(path)) yield break;
        using var stream = File.OpenRead(path);
        foreach (var row in Read(stream, digest)) yield return row;
    }

    internal static IEnumerable<JsonObject> Read(Stream stream, IncrementalHash? digest = null)
    {
        var buffer = new byte[64 * 1024];
        using var line = new MemoryStream();
        bool first = true;
        JsonObject? Parse()
        {
            byte[] raw = line.ToArray();
            digest?.AppendData(raw);
            string text = new UTF8Encoding(false, true).GetString(raw);
            if (first) text = text.TrimStart('\uFEFF');
            first = false;
            line.SetLength(0);
            text = text.Trim();
            if (text.Length == 0) return null;
            return JsonNode.Parse(text) as JsonObject ?? throw new InvalidDataException("jsonl_row_must_be_object");
        }
        int count;
        while ((count = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            int start = 0;
            for (int i = 0; i < count; i++)
            {
                if (buffer[i] != (byte)'\n') continue;
                line.Write(buffer, start, i - start + 1);
                if (Parse() is { } row) yield return row;
                start = i + 1;
            }
            line.Write(buffer, start, count - start);
        }
        if (line.Length > 0 && Parse() is { } last) yield return last;
    }
}
