using System.Security.Cryptography;
using System.Globalization;
using Sli.Agent.Protocol.Compatibility;
using System.Text;
using System.Text.RegularExpressions;

namespace Sli.Agent.Core;

/// <summary>Port of sli_agent/script_secrets.py; shared vectors guard parity.</summary>
public static class ScriptSecrets
{
    public const string MaskFailed = "[скрыто:mask_failed]";
    // These replacements apply only to the fixed source patterns below. Python re.I adds
    // four Unicode aliases to ASCII letters; Python \w is letters/numbers/underscore.
    private const string Word = @"[\p{L}\p{N}_]";
    private static readonly string Boundary = $@"(?:(?<!{Word})(?={Word})|(?<={Word})(?!{Word}))";
    private static readonly Regex IgnoreCaseWords = new(@"ConvertTo-SecureString|SharedAccessKey|aws_secret_access_key|SecretAccessKey|client_secret|ClientSecret|AccountKey|refresh_token|access_token|AsPlainText|Credential|Password|Bearer|api_key|ApiKey|Force|Basic|String|token|Pwd",RegexOptions.CultureInvariant,TimeSpan.FromMilliseconds(100));
    private static Regex Pattern(string pattern)
    {
        if(pattern.Contains("(?i)",StringComparison.Ordinal)) {
            pattern=IgnoreCaseWords.Replace(pattern,m=>string.Concat(m.Value.Select(c=>c switch {
                'i' or 'I'=>"[iİı]", 's' or 'S'=>"[sſ]", 'k' or 'K'=>"[kK]", _=>c.ToString()
            })));
            pattern=pattern.Replace("[A-Za-z0-9+/_", "[A-Za-zİıſK0-9+/_",StringComparison.Ordinal);
        }
        pattern=pattern.Replace(@"\w",@"\p{L}\p{N}_",StringComparison.Ordinal).Replace(@"\b",Boundary,StringComparison.Ordinal);
        return new(pattern,RegexOptions.CultureInvariant,TimeSpan.FromMilliseconds(100));
    }
    // .NET Regex sees UTF-16 code units. Replace only supplementary word runes by
    // two BMP word chars in a same-length scan copy; all captured spans index the original.
    private static string WordShadow(string text)
    {
        var result=new StringBuilder(text.Length);
        foreach(var rune in text.EnumerateRunes()) {
            var category=Rune.GetUnicodeCategory(rune);
            bool word=category is UnicodeCategory.UppercaseLetter or UnicodeCategory.LowercaseLetter or UnicodeCategory.TitlecaseLetter or UnicodeCategory.ModifierLetter or UnicodeCategory.OtherLetter or UnicodeCategory.DecimalDigitNumber or UnicodeCategory.LetterNumber or UnicodeCategory.OtherNumber;
            if(rune.Utf16SequenceLength==2 && word) result.Append('ª',2);else result.Append(rune.ToString());
        }
        return result.ToString();
    }
    private static bool SourceSpace(char c)=>char.IsWhiteSpace(c) || c is '\u001c' or '\u001d' or '\u001e' or '\u001f';

    // Contexts only: literal endpoints are indexed once, without backtracking.
    private static readonly (string Kind, string Mode, Regex Pattern)[] Patterns =
    [
        ("password", "connection", Pattern("""(?i)(?<=[;'"\n])(?:Password|Pwd)[ \t]*=[ \t]*""")),
        ("password", "value", Pattern("""(?i)(?<![\w-])-(?:Password|Pwd)\b[ \t]*:?[ \t]*""")),
        ("credential", "value", Pattern("""(?i)(?<![\w-])-Credential\b[ \t]*:?[ \t]*""")),
        ("password", "value", Pattern("""(?i)\b(?:Password|Pwd)\b['"]?[ \t]*[=:][ \t]*""")),
        ("cloud_key", "value", Pattern("""(?i)\b(?:aws_secret_access_key|SecretAccessKey|AccountKey|client_secret|ClientSecret|SharedAccessKey)\b['"]?[ \t]*[=:][ \t]*""")),
        ("token", "value", Pattern("""(?i)\b(?:access_token|refresh_token|api_key|ApiKey|token)\b['"]?[ \t]*[=:][ \t]*""")),
        ("plaintext", "plain_after", Pattern("""(?i)\bConvertTo-SecureString\b(?:[ \t]+-Force\b)*[ \t]+(?:-String[ \t]+)?""")),
        ("plaintext", "value", Pattern("""(?i)\bConvertTo-SecureString\b(?:[ \t]+-Force\b)*[ \t]+-AsPlainText\b(?:[ \t]+-(?:AsPlainText|Force)\b)*[ \t]+(?:-String[ \t]+)?""")),
    ];
    private static readonly Regex PrivateKey = Pattern("""-----BEGIN (?<label>(?:[A-Z0-9]+ )*PRIVATE KEY)-----(?<value>[\s\S]*?)(?=-----END \k<label>-----|\z)""");
    private static readonly Regex Auth = Pattern("""(?i)\b(?<kind>Basic|Bearer)[ \t]+(?<value>[A-Za-z0-9+/_\-.=]+)(?![\w+/.=\-])""");
    private static readonly Regex Aws = Pattern("""\b(?<value>AKIA[A-Z0-9]{16})\b""");
    private static readonly Regex Cmdlet = Pattern("""\A[A-Za-z][A-Za-z0-9]*-[A-Za-z][A-Za-z0-9_-]*\z""");
    private static readonly Regex Pipe = Pattern("""(?i)\|[ \t]*ConvertTo-SecureString\b""");
    private static readonly Regex Plain = Pattern("""(?i)-AsPlainText\b""");

    public static (string Text, int Count, bool Truncated) Mask(string script)
    {
        try { return MaskCore(script); }
        catch (Exception)
        {
            // Preserve 4104 even on timeout; no native text or exception message.
            var raw = Encoding.UTF8.GetBytes(script);
            return (MaskFailed + " bytes=" + raw.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)
                + " sha256=" + Convert.ToHexStringLower(SHA256.HashData(raw)), 1, true);
        }
    }

    private static (string Text, int Count, bool Truncated) MaskCore(string script)
    {
        var bounded = WorkstationsModule.BoundedUtf8(script, 8192);
        var n = bounded.Length;
        var shadow = WordShadow(bounded);
        var expression = new int[n + 1];
        expression[n] = n;
        for (var i = n - 1; i >= 0; i--)
            expression[i] = "$`(".Contains(bounded[i]) ? i : expression[i + 1];
        int[] Table() => Enumerable.Repeat(n, n + 2).ToArray();
        var single = Table(); var doubleQuoted = Table(); var bare = Table(); var connection = Table(); var values = Table();
        var hereSingle = n; var hereDouble = n;
        var quoted = new Dictionary<int, int>();
        bool At(string value, int i) => bounded.AsSpan(i).StartsWith(value, StringComparison.Ordinal);
        for (var i = n - 1; i >= 0; i--)
        {
            var c = bounded[i];
            single[i] = At("''", i) ? single[i + 2] : c == '\'' ? i + 1 : single[i + 1];
            doubleQuoted[i] = c == '`' ? doubleQuoted[i + 2] : c == '"' ? i + 1 : doubleQuoted[i + 1];
            bare[i] = SourceSpace(c) || ";'\"|,)}]&".Contains(c) ? i : bare[i + 1];
            connection[i] = ";'\"\r\n".Contains(c) ? i : connection[i + 1];
            if (c is '\'' or '"')
            {
                values[i] = (c == '\'' ? single : doubleQuoted)[i + 1];
                quoted[values[i]] = i;
            }
            else if (c == '@' && i + 2 < n && bounded[i + 1] is '\'' or '"'
                     && (bounded[i + 2] == '\n' || At("\r\n", i + 2)))
            {
                values[i] = bounded[i + 1] == '\'' ? hereSingle : hereDouble;
                quoted[values[i]] = i;
            }
            else values[i] = bare[i];
            if (At("\n'@", i)) hereSingle = i + 3;
            if (At("\n\"@", i)) hereDouble = i + 3;
        }
        var inside = new bool[n];
        for (var i = 0; i < n;)
        {
            if (bounded[i] is '\'' or '"' || At("@'\n", i) || At("@\"\n", i) || At("@'\r\n", i) || At("@\"\r\n", i))
            {
                var end = values[i];
                Array.Fill(inside, true, i, end - i);
                i = end;
            }
            else i++;
        }
        var plainStarts = Plain.Matches(shadow).Select(m => m.Index).ToHashSet();
        var plainAfter = new bool[n + 1];
        for (var i = n - 1; i >= 0; i--)
            plainAfter[i] = plainStarts.Contains(i) || !";\r\n|".Contains(bounded[i]) && plainAfter[i + 1];

        int Literal(int start, string mode = "value")
        {
            if (start >= n) return start;
            if (bounded[start] is '\'' or '"' || At("@'\n", start) || At("@\"\n", start)
                || At("@'\r\n", start) || At("@\"\r\n", start)) return values[start];
            var end = bare[start];
            if (end == start || "$@(-[".Contains(bounded[start]) || expression[start] < end
                || Cmdlet.IsMatch(bounded.AsSpan(start, end - start)) && !(mode == "connection" && inside[start])) return start;
            return mode == "connection" ? connection[start] : end;
        }

        var spans = new List<(int Start, int End, string Replacement)>();
        var occupied = new bool[n];
        void Add(string kind, int start, int end)
        {
            if (start >= end || occupied[start]) return;
            var value = bounded[start..end];
            var prefix = ""; var suffix = "";
            if (kind == "private_key")
            {
                prefix = value[..(value.Length - value.TrimStart().Length)];
                suffix = value[value.TrimEnd().Length..];
            }
            else if (value.StartsWith("@'", StringComparison.Ordinal) || value.StartsWith("@\"", StringComparison.Ordinal))
            {
                prefix = value[..2] + "\n";
                suffix = value.EndsWith(value[1] + "@", StringComparison.Ordinal) ? "\n" + value[1] + "@" : "";
            }
            else if (value[0] is '\'' or '"')
            {
                prefix = value[..1];
                suffix = value.Length > 1 && value.EndsWith(prefix, StringComparison.Ordinal) ? prefix : "";
            }
            var content = value.StartsWith(prefix, StringComparison.Ordinal) ? value[prefix.Length..] : value;
            if (content.StartsWith("[скрыто:", StringComparison.Ordinal)) return;
            for (var i = start; i < end; i++) if (occupied[i]) return;
            Array.Fill(occupied, true, start, end - start);
            spans.Add((start, end, prefix + "[скрыто:" + kind + "]" + suffix));
        }
        void AddGroup(string kind, Match match)
        {
            var group = match.Groups["value"];
            Add(kind, group.Index, group.Index + group.Length);
        }

        foreach (Match match in PrivateKey.Matches(shadow)) AddGroup("private_key", match);
        foreach (var (kind, mode, pattern) in Patterns)
        foreach (Match match in pattern.Matches(shadow))
        {
            var start = match.Index + match.Length;
            if (start < n && occupied[start]) continue;
            var end = Literal(start, mode);
            if (mode != "plain_after" || plainAfter[end]) Add(kind, start, end);
        }
        foreach (Match match in Auth.Matches(shadow))
        {
            var value = bounded.Substring(match.Groups["value"].Index, match.Groups["value"].Length);
            var kind = UnicodeLower.Lower(bounded.Substring(match.Groups["kind"].Index, match.Groups["kind"].Length));
            var core = value.TrimEnd('=');
            var valid = value.Length - core.Length <= 2 && !core.Contains('=');
            if (kind == "basic") valid = valid && value.Length % 4 == 0 && !core.Any(c => "-_.".Contains(c));
            else valid = valid && (!core.Contains('.') || core.Count(c => c == '.') == 2 && core.Split('.').All(s => s.Length > 0));
            if (valid && value.Length >= 16 && (value.Length >= 32 || value.Any(c => char.IsAsciiDigit(c) || "+/=.".Contains(c))
                || value.Count(char.IsUpper) >= 3 && value.Any(char.IsLower))) AddGroup(kind, match);
        }
        foreach (Match match in Aws.Matches(shadow)) AddGroup("aws_access_key", match);
        foreach (Match match in Pipe.Matches(shadow))
        {
            if (!plainAfter[match.Index + match.Length]) continue;
            var end = match.Index;
            while (end > 0 && bounded[end - 1] is ' ' or '\t') end--;
            if (!quoted.TryGetValue(end, out var start))
            {
                start = end;
                while (start > 0 && !SourceSpace(bounded[start - 1])) start--;
            }
            if (Literal(start) == end) Add("plaintext", start, end);
        }
        var output = new StringBuilder();
        var previous = 0;
        foreach (var span in spans.OrderBy(s => s.Start))
        {
            output.Append(bounded, previous, span.Start - previous).Append(span.Replacement);
            previous = span.End;
        }
        output.Append(bounded, previous, n - previous);
        var masked = output.ToString();
        var result = WorkstationsModule.BoundedUtf8(masked, 8192);
        return (result, spans.Count, bounded != script || result != masked);
    }
}
