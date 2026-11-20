using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;

namespace Sli.Server.Semantic;

// The reviewed atomic dialect needs only mappings, sequences and bounded scalar strings.
// Aliases, anchors, tags, duplicate members and multiple documents are refused.
internal static class SigmaYaml
{
    private sealed record Line(int Indent, string Text);
    internal static JsonObject Parse(string yaml)
    {
        if (Encoding.UTF8.GetByteCount(yaml) > 1048576) throw new InvalidDataException("yaml_size_limit");
        var lines = new List<Line>(); bool document = false;
        foreach (string raw in yaml.Replace("\r\n", "\n").Split('\n'))
        {
            if (raw.TakeWhile(char.IsWhiteSpace).Contains('\t')) throw new InvalidDataException("yaml_mapping_invalid");
            string text = StripComment(raw.TrimStart()); if (text.Length == 0) continue;
            if (text == "---") { if (document || lines.Count > 0) throw new InvalidDataException("yaml_multiple_documents"); document = true; continue; }
            if (text.StartsWith('%') || text == "...") throw new InvalidDataException("yaml_mapping_invalid");
            lines.Add(new(raw.Length - raw.TrimStart().Length, text));
        }
        int position = 0, nodes = 0;
        JsonNode? Block(int indent, int depth)
        {
            if (++nodes > 4096 || depth > 48) throw new InvalidDataException("complexity_limit");
            if (position >= lines.Count || lines[position].Indent < indent) return null;
            bool sequence = lines[position].Text == "-" || lines[position].Text.StartsWith("- ", StringComparison.Ordinal); var array = new JsonArray(); var map = new JsonObject();
            void Member(JsonObject target, string text, int parent)
            {
                int colon = Separator(text); if (colon < 1) throw new InvalidDataException("yaml_mapping_invalid");
                string key = Scalar(text[..colon].Trim())?.GetValue<string>() ?? throw new InvalidDataException("yaml_mapping_invalid");
                if (target.ContainsKey(key)) throw new InvalidDataException("yaml_mapping_invalid"); string value = text[(colon + 1)..].Trim();
                if (value is "|" or ">" or "|-" or ">-" or "|+" or ">+")
                {
                    var pieces = new List<string>(); while (position < lines.Count && lines[position].Indent > parent) pieces.Add(lines[position++].Text);
                    target[key] = string.Join(value.StartsWith('>') ? " " : "\n", pieces) + (value.EndsWith('-') ? "" : "\n");
                }
                else target[key] = value.Length > 0 ? Scalar(value) : position < lines.Count && lines[position].Indent > parent ? Block(lines[position].Indent, depth + 1) : null;
            }
            while (position < lines.Count && lines[position].Indent == indent)
            {
                string text = lines[position++].Text;
                if (sequence)
                {
                    if (!(text == "-" || text.StartsWith("- ", StringComparison.Ordinal))) throw new InvalidDataException("yaml_mapping_invalid");
                    string value = text[1..].Trim();
                    if (Separator(value) > 0)
                    {
                        var item = new JsonObject(); Member(item, value, indent + 2);
                        while (position < lines.Count && lines[position].Indent == indent + 2) Member(item, lines[position++].Text, indent + 2);
                        array.Add(item);
                    }
                    else array.Add(value.Length > 0 ? Scalar(value) : position < lines.Count && lines[position].Indent > indent ? Block(lines[position].Indent, depth + 1) : null);
                }
                else Member(map, text, indent);
            }
            return sequence ? array : map;
        }
        var result = Block(0, 0); if (position != lines.Count || result is not JsonObject obj) throw new InvalidDataException("yaml_mapping_invalid"); return obj;
    }
    private static int Separator(string value)
    {
        char quote = '\0'; bool escaped = false; int brackets = 0;
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i]; if (quote != '\0') { if (!escaped && c == quote) quote = '\0'; escaped = !escaped && c == '\\' && quote == '"'; continue; }
            if (c is '\'' or '"') quote = c; else if (c is '[' or '{') brackets++; else if (c is ']' or '}') brackets--; else if (c == ':' && brackets == 0 && (i + 1 == value.Length || char.IsWhiteSpace(value[i + 1]))) return i;
        }
        return -1;
    }
    private static string StripComment(string value)
    {
        char quote = '\0'; bool escaped = false;
        for (int i = 0; i < value.Length; i++) { char c = value[i]; if (quote != '\0') { if (!escaped && c == quote) quote = '\0'; escaped = !escaped && c == '\\' && quote == '"'; } else if (c is '\'' or '"') quote = c; else if (c == '#' && (i == 0 || char.IsWhiteSpace(value[i - 1]))) return value[..i].TrimEnd(); }
        return value.TrimEnd();
    }
    private static JsonNode? Scalar(string value)
    {
        if (value.StartsWith('&') || value.StartsWith('*') || value.StartsWith('!') || value.Contains("<<:", StringComparison.Ordinal)) throw new InvalidDataException("yaml_alias_unsupported");
        if (value.StartsWith('\'')) { if (!value.EndsWith('\'')) throw new InvalidDataException("yaml_mapping_invalid"); return JsonValue.Create(value[1..^1].Replace("''", "'")); }
        if (value.StartsWith('"')) { try { return JsonNode.Parse(value); } catch { throw new InvalidDataException("yaml_mapping_invalid"); } }
        if (value.StartsWith('['))
        {
            if (!value.EndsWith(']')) throw new InvalidDataException("yaml_mapping_invalid");
            var array = new JsonArray(); var part = new StringBuilder(); char quote = '\0'; bool escaped = false;
            foreach (char c in value[1..^1] + ",")
            {
                if (quote == '\0' && c == ',') { if (part.ToString().Trim() is { Length: > 0 } text) array.Add(Scalar(text)); part.Clear(); continue; }
                part.Append(c); if (quote == '\0' && c is '\'' or '"') quote = c; else if (!escaped && c == quote) quote = '\0'; escaped = !escaped && c == '\\' && quote == '"';
            }
            return array;
        }
        if (value == "{}") return new JsonObject(); if (value.StartsWith('{')) { try { return JsonNode.Parse(value); } catch { throw new InvalidDataException("yaml_mapping_invalid"); } }
        if (value is "null" or "Null" or "NULL" or "~") return null;
        if (value is "true" or "True" or "TRUE") return JsonValue.Create(true); if (value is "false" or "False" or "FALSE") return JsonValue.Create(false);
        if (long.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long number)) return JsonValue.Create(number);
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && long.TryParse(value[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out number)) return JsonValue.Create(number);
        return JsonValue.Create(value);
    }
}
