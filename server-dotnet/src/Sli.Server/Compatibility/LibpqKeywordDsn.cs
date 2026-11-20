using System.Text;

namespace Sli.Server.Compatibility;

internal static class LibpqKeywordDsn
{
    internal static Dictionary<string,string> Parse(string input)
    {
        var values = new Dictionary<string,string>(StringComparer.Ordinal); int i = 0;
        while (true)
        {
            while (i < input.Length && char.IsWhiteSpace(input[i])) i++;
            if (i == input.Length) return values;
            int start = i;
            while (i < input.Length && !char.IsWhiteSpace(input[i]) && input[i] != '=') i++;
            string key = input[start..i];
            while (i < input.Length && char.IsWhiteSpace(input[i])) i++;
            if (key.Length == 0 || i == input.Length || input[i++] != '=') throw new ArgumentException();
            while (i < input.Length && char.IsWhiteSpace(input[i])) i++;
            var value = new StringBuilder(); bool quoted = i < input.Length && input[i] == '\'';
            if (quoted) i++;
            bool closed = !quoted;
            while (i < input.Length)
            {
                char c = input[i++];
                if (c == '\\') { if (i == input.Length) throw new ArgumentException(); value.Append(input[i++]); continue; }
                if (quoted && c == '\'') { closed = true; break; }
                if (!quoted && char.IsWhiteSpace(c)) break;
                value.Append(c);
            }
            if (!closed || (quoted && i < input.Length && !char.IsWhiteSpace(input[i]))) throw new ArgumentException();
            values[key] = value.ToString();
        }
    }
}
