using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Auth.Lifecycle;

namespace Sli.Server.Access.Administration;

internal static class AssignmentValidation
{
    internal static readonly string[] Dimensions = ["plugin_ids", "source_instance_ids", "device_ids", "entity_ids", "collection_scope_ids"];
    internal static AssignmentValues Parse(JsonElement payload, bool package)
    {
        string type = Strip(Text(payload, "subject_type")).ToLowerInvariant();
        if (type is not ("user" or "group")) throw Error("invalid_subject_type");
        var idValue = payload.Get("subject_id");
        BigInteger id = AuthJsonBody.Truthy(idValue) ? Integer(idValue) : 0;
        string key = Strip(Text(payload, package ? "package_key" : "report_key"));
        string effect = Strip(Text(payload, "effect", "allow")).ToLowerInvariant();
        string source = Strip(Text(payload, "source_type", "direct")).ToLowerInvariant();
        string reason = Strip(Text(payload, "business_reason"));
        if (id <= 0 || key.Length == 0 || effect is not ("allow" or "deny") || source is not ("group" or "direct" or "temporary" or "system") || reason.Length == 0)
            throw Error(package ? "invalid_package_assignment" : "invalid_report_assignment");
        string[] fields = [], actions = [];
        JsonElement scope = default;
        string kind = "";
        if (!package)
        {
            fields = Sequence(payload.Get("field_categories"), []).Where(s => s.Length > 0).Distinct().Order(StringComparer.Ordinal).Take(32).ToArray();
            actions = Sequence(payload.Get("allowed_actions"), ["view"]).Where(s => s.Length > 0).Distinct().Order(StringComparer.Ordinal).Take(32).ToArray();
            scope = Dictionary(payload.Get("scope"));
            kind = scope.Get("mode").ValueKind != JsonValueKind.Undefined ? "scope" : Strip(Text(scope, "kind")).ToLowerInvariant();
            if (kind == "scope")
            {
                if (!scope.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(["mode", "clauses"])) throw Error("invalid_report_scope_values");
                ValidateGeneric(scope);
                if (scope.Text("mode") == "none") throw Error("invalid_report_scope_values");
            }
            if (kind is not ("all" or "domain" or "server" or "channel" or "scope")) throw Error("unsupported_report_scope");
            if (kind is not ("all" or "scope"))
            {
                var values = scope.Get(kind == "channel" ? "values" : "ids");
                if (values.ValueKind != JsonValueKind.Array || values.GetArrayLength() is < 1 or > 100) throw Error("invalid_report_scope_values");
            }
        }
        var from = Timestamp(payload.Get("valid_from"), "invalid_valid_from");
        var until = Timestamp(payload.Get("valid_until"), "invalid_valid_until");
        if (from.HasValue && until <= from) throw Error("invalid_assignment_window");
        if (source == "temporary" && until is null) throw Error("temporary_assignment_requires_expiry");
        string approved = Strip(Text(payload, "approved_by"));
        return new(type, id, key, effect, source, reason, approved.Length == 0 ? null : approved, from, until, fields, actions, scope, kind);
    }

    internal static string Text(JsonElement obj, string key, string fallback = "")
    {
        var value = obj.Get(key);
        return AuthJsonBody.Truthy(value) ? String(value) : fallback;
    }

    internal static string String(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Null) return "None";
        if (value.ValueKind == JsonValueKind.False) return "False";
        if (value.ValueKind == JsonValueKind.Number && !AuthJsonBody.Truthy(value)) return value.GetRawText().Contains('.') || value.GetRawText().Contains('e', StringComparison.OrdinalIgnoreCase) ? "0.0" : "0";
        if (value.ValueKind == JsonValueKind.String) return value.GetString()!;
        if (value.ValueKind is JsonValueKind.Array or JsonValueKind.Object && !AuthJsonBody.Truthy(value)) return value.ValueKind == JsonValueKind.Array ? "[]" : "{}";
        return AuthJsonBody.CredentialString(JsonSerializer.SerializeToElement(new Dictionary<string, JsonElement> { ["v"] = value }), "v");
    }

    internal static BigInteger Integer(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.True) return 1;
        if (value.ValueKind == JsonValueKind.False) return 0;
        if (value.ValueKind == JsonValueKind.Number)
        {
            if (BigInteger.TryParse(value.GetRawText(), out var integer)) return integer;
            return new BigInteger(Math.Truncate(value.GetDouble()));
        }
        if (value.ValueKind != JsonValueKind.String) throw new InvalidOperationException("assignment_integer_type_invalid");
        string original = value.GetString()!, input = original.Trim();
        var digits = new StringBuilder();
        bool previous = false;
        int count = 0;
        foreach (var rune in input.EnumerateRunes())
        {
            if (digits.Length == 0 && rune.Value is '+' or '-') { digits.Append((char)rune.Value); continue; }
            if (rune.Value == '_' && previous) { previous = false; continue; }
            if (Rune.GetUnicodeCategory(rune) != UnicodeCategory.DecimalDigitNumber) return InvalidInteger(original);
            digits.Append((char)('0' + (int)Rune.GetNumericValue(rune))); previous = true; count++;
        }
        if (count > 4300) throw Error($"Exceeds the limit (4300 digits) for integer string conversion: value has {count} digits; use sys.set_int_max_str_digits() to increase the limit");
        return previous && BigInteger.TryParse(digits.ToString(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var parsed) ? parsed : InvalidInteger(original);
    }

    private static BigInteger InvalidInteger(string input)
    {
        char quote = input.Contains('\'') && !input.Contains('"') ? '"' : '\'';
        var repr = new StringBuilder().Append(quote);
        foreach (var rune in input.EnumerateRunes())
        {
            int c = rune.Value;
            if (c == quote || c == '\\') repr.Append('\\').Append((char)c);
            else if (c is '\n' or '\r' or '\t') repr.Append(c == '\n' ? "\\n" : c == '\r' ? "\\r" : "\\t");
            else if (Rune.GetUnicodeCategory(rune) is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.Surrogate
                or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator
                || c != ' ' && Rune.GetUnicodeCategory(rune) == UnicodeCategory.SpaceSeparator)
                repr.Append(c < 256 ? "\\x" + c.ToString("x2", CultureInfo.InvariantCulture) : c < 65536
                    ? "\\u" + c.ToString("x4", CultureInfo.InvariantCulture) : "\\U" + c.ToString("x8", CultureInfo.InvariantCulture));
            else repr.Append(rune.ToString());
        }
        repr.Append(quote);
        throw Error("invalid literal for int() with base 10: " + string.Concat(repr.ToString().EnumerateRunes().Take(200).Select(r => r.ToString())));
    }

    private static IEnumerable<string> Sequence(JsonElement value, string[] fallback)
    {
        if (!AuthJsonBody.Truthy(value)) return fallback;
        return value.ValueKind switch
        {
            JsonValueKind.Array => value.EnumerateArray().Select(String).ToArray(),
            JsonValueKind.Object => value.EnumerateObject().Select(p => p.Name).ToArray(),
            JsonValueKind.String => value.GetString()!.EnumerateRunes().Select(r => r.ToString()).ToArray(),
            _ => throw new InvalidOperationException("assignment_iterable_required")
        };
    }

    private static JsonElement Dictionary(JsonElement value)
    {
        if (!AuthJsonBody.Truthy(value)) return JsonSerializer.SerializeToElement(new { kind = "all" });
        if (value.ValueKind == JsonValueKind.Object) return value.Clone();
        if (value.ValueKind is not (JsonValueKind.Array or JsonValueKind.String)) throw new InvalidOperationException("assignment_scope_mapping_required");
        var result = new JsonObject();
        var entries = value.ValueKind == JsonValueKind.Array ? value.EnumerateArray().ToArray() : value.GetString()!.EnumerateRunes().Select(r => JsonSerializer.SerializeToElement(r.ToString())).ToArray();
        for (int i = 0; i < entries.Length; i++)
        {
            var entry = entries[i];
            JsonElement[] pair = entry.ValueKind == JsonValueKind.Array ? entry.EnumerateArray().ToArray()
                : entry.ValueKind == JsonValueKind.String ? entry.GetString()!.EnumerateRunes().Select(r => JsonSerializer.SerializeToElement(r.ToString())).ToArray()
                : throw new InvalidOperationException("assignment_scope_mapping_required");
            if (pair.Length != 2) throw Error($"dictionary update sequence element #{i} has length {pair.Length}; 2 is required");
            if (pair[0].ValueKind is JsonValueKind.Array or JsonValueKind.Object) throw new InvalidOperationException("assignment_scope_key_invalid");
            string key = pair[0].ValueKind switch { JsonValueKind.Null => "null", JsonValueKind.True => "true", JsonValueKind.False => "false", _ => String(pair[0]) };
            result[key] = JsonNode.Parse(pair[1].GetRawText());
        }
        return JsonSerializer.SerializeToElement(result);
    }

    private static void ValidateGeneric(JsonElement scope)
    {
        var clauses = scope.Get("clauses");
        if (clauses.ValueKind != JsonValueKind.Array || clauses.GetArrayLength() > 100) throw Error("invalid_access_scope");
        foreach (var clause in clauses.EnumerateArray())
        {
            if (clause.ValueKind != JsonValueKind.Object || clause.EnumerateObject().Any(p => !Dimensions.Contains(p.Name))) throw Error("invalid_scope_clause");
            bool populated = false;
            foreach (var property in clause.EnumerateObject())
            {
                var values = property.Value;
                if (values.ValueKind != JsonValueKind.Array || values.GetArrayLength() > 100) throw Error("invalid_scope_dimension");
                populated |= values.GetArrayLength() > 0;
                if (property.Name == "entity_ids")
                {
                    if (values.EnumerateArray().Any(v => v.ValueKind != JsonValueKind.Number || !BigInteger.TryParse(v.GetRawText(), out var n) || n <= 0)
                        || values.EnumerateArray().Select(v => BigInteger.Parse(v.GetRawText())).Distinct().Count() != values.GetArrayLength()) throw Error("invalid_scope_dimension");
                }
                else if (values.EnumerateArray().Any(v => v.ValueKind != JsonValueKind.String || v.GetString()!.EnumerateRunes().Count() is < 1 or > 256 || Strip(v.GetString()!) != v.GetString())
                    || values.EnumerateArray().Select(v => v.GetString()).Distinct().Count() != values.GetArrayLength()) throw Error("invalid_scope_dimension");
            }
            if (!populated) throw Error("empty_scope_clause");
        }
        string mode = scope.Text("mode");
        if (mode is not ("all" or "none" or "restricted") || (mode == "restricted") != (clauses.GetArrayLength() > 0)) throw Error("invalid_access_scope");
    }

    internal static DateTimeOffset? Timestamp(JsonElement value, string error)
    {
        if (value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined || value.ValueKind == JsonValueKind.String && value.GetString() == "") return null;
        string text = String(value).Replace("Z", "+00:00", StringComparison.Ordinal);
        var match = Regex.Match(text, @"\A(?<date>[0-9]{4}(?:[0-9]{4}|-[0-9]{2}-[0-9]{2}|W[0-9]{2}[1-7]?|-W[0-9]{2}(?:-[1-7])?))(?:[\uD800-\uDBFF][\uDC00-\uDFFF]|[\s\S])(?<h>[0-9]{2})(?:(?<tc>:?)(?<m>[0-9]{2})(?:(?<tc2>:?)(?<s>[0-9]{2}))?)?(?:[.,](?<f>[0-9]+))?(?<sign>[+-])(?<zh>[0-9]{2})(?:(?<zc>:?)(?<zm>[0-9]{2})(?:(?<zc2>:?)(?<zs>[0-9]{2}))?)?(?:[.,](?<zf>[0-9]+))?\z", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
        if (!match.Success) throw Error(error);
        if (match.Groups["s"].Success && match.Groups["tc"].Value != match.Groups["tc2"].Value
            || match.Groups["zs"].Success && match.Groups["zc"].Value != match.Groups["zc2"].Value
            || match.Groups["f"].Success && !match.Groups["s"].Success
            || match.Groups["zf"].Success && !match.Groups["zs"].Success) throw Error(error);
        int Part(string name) => match.Groups[name].Success ? int.Parse(match.Groups[name].Value, CultureInfo.InvariantCulture) : 0;
        long Fraction(string name) => match.Groups[name].Success ? long.Parse((match.Groups[name].Value + "000000")[..6], CultureInfo.InvariantCulture) * 10 : 0;
        DateTime local;
        TimeSpan offset;
        try
        {
            string date = match.Groups["date"].Value.Replace("-", "");
            DateTime day;
            if (date[4] == 'W')
            {
                int year = int.Parse(date[..4]), week = int.Parse(date.Substring(5, 2));
                if (week > ISOWeek.GetWeeksInYear(year)) throw Error(error);
                day = ISOWeek.ToDateTime(year, week, date.Length == 8 ? (DayOfWeek)(int.Parse(date[7..]) % 7) : DayOfWeek.Monday);
            }
            else day = new DateTime(int.Parse(date[..4]), int.Parse(date.Substring(4, 2)), int.Parse(date.Substring(6, 2)));
            int zh = Part("zh"), zm = Part("zm"), zs = Part("zs");
            if (zh * 3600 + zm * 60 + zs >= 86400) throw Error(error);
            local = new DateTime(day.Year, day.Month, day.Day, Part("h"), Part("m"), Part("s"), DateTimeKind.Utc).AddTicks(Fraction("f"));
            offset = new TimeSpan(zh, zm, zs);
            if (zh != 0 || zm != 0 || zs != 0) offset = offset.Add(TimeSpan.FromTicks(Fraction("zf")));
            if (match.Groups["sign"].Value == "-") offset = -offset;
        }
        catch (ArgumentException) { throw Error(error); }
        // Source astimezone overflow is not a ValueError and remains a server error.
        return new DateTimeOffset(local.Subtract(offset));
    }

    internal static string Strip(string value)
    {
        int start = 0, end = value.Length;
        static bool Space(char c) => char.IsWhiteSpace(c) || c is >= '\u001c' and <= '\u001f';
        while (start < end && Space(value[start])) start++;
        while (end > start && Space(value[end - 1])) end--;
        return value[start..end];
    }
    internal static AssignmentValidationException Error(string code) => new(code);
}
