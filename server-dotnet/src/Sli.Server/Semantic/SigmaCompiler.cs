using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Semantic;

internal sealed record SigmaExpression(string Op, SigmaExpression[] Args, string? Field = null, string? ValueKind = null, JsonNode? Value = null)
{
    internal IEnumerable<string> Fields => Op == "compare" ? [Field!] : Args.SelectMany(x => x.Fields);
}
internal sealed record SigmaRule(string Id, string Sha, string LogSource, SigmaExpression Expression, string[] Fields, JsonObject Document, string SourceUri = "", string UpstreamCommit = "", string? License = null)
{
    internal static JsonObject MatchLimits => new() { ["max_nodes"] = 4096, ["max_depth"] = 48, ["max_pattern_chars"] = 4096, ["max_field_chars"] = 262144, ["max_values"] = 64, ["max_steps"] = 2000000, ["max_regex_calls"] = 32, ["regex_timeout_seconds"] = 0.25, ["timeout_seconds"] = 2.0 };
    internal const string CompilerVersion = "sli.sigma.compiler.v1", MappingVersion = "sli.sigma.windows-fields.v2";
    private static readonly Dictionary<string, HashSet<string>> Allowed = new()
    {
        ["security"] = ["EventID", "Provider_Name", "AuditPolicyChanges", "SubcategoryGuid", "AuthenticationPackageName", "IpAddress", "IpPort", "KeyLength", "LogonProcessName", "LogonType", "NewTargetUserName", "PreAuthType", "SamAccountName", "ServiceFileName", "ServiceName", "ServiceStartType", "ServiceType", "Status", "SubStatus", "SubjectUserName", "SubjectUserSid", "TargetSid", "TargetUserName", "TargetUserSid", "TaskContent", "TaskContentNew", "TicketEncryptionType", "TicketOptions"],
        ["system"] = ["EventID", "Provider_Name", "ServiceName", "ImagePath"], ["process_creation"] = ["Image", "ParentImage", "CommandLine"]
    };
    internal static SigmaRule Compile(string yaml, string? license = null, string sourceUri = "", string upstreamCommit = "")
    {
        var doc = SigmaYaml.Parse(yaml);
        if (doc.ContainsKey("correlation") || doc.ContainsKey("action") || doc.ContainsKey("scope")) throw new InvalidDataException("rule_type_unsupported");
        if ((doc.Text("taxonomy") ?? "sigma") != "sigma") throw new InvalidDataException("taxonomy_unsupported");
        if (!Guid.TryParse(doc.Text("id"), out var id) || string.IsNullOrWhiteSpace(doc.Text("author"))) throw new InvalidDataException("metadata_missing");
        if (license is not null && doc.Text("license") is { } declared && declared != license) throw new InvalidDataException("license_mismatch");
        var source = doc["logsource"]!.AsObject(); string logsource = source.Text("category") == "process_creation" && !source.ContainsKey("service") ? "process_creation" : !source.ContainsKey("category") ? source.Text("service") ?? "" : "";
        if (source.Text("product") != "windows" || source.Any(x => x.Key is not ("product" or "service" or "category" or "definition")) || !Allowed.ContainsKey(logsource)) throw new InvalidDataException("logsource_unsupported");
        var detection = doc["detection"]!.AsObject(); var named = new Dictionary<string, SigmaExpression>(StringComparer.Ordinal); int nodes = 0, expandedValues = 0, expandedBytes = 0;
        // Match compiler.py's aggregate input budget before allocating any
        // windash variants, including selections unused by the condition.
        void ValidateInput(JsonNode? selection, int depth)
        {
            if (depth > 48) throw new InvalidDataException("complexity_limit");
            if (selection is JsonArray alternatives)
            {
                if (alternatives.Count == 0 || alternatives.Any(x => x is not JsonObject)) throw new InvalidDataException("keyword_unsupported");
                foreach (var alternative in alternatives) ValidateInput(alternative, depth + 1);
                return;
            }
            if (selection is not JsonObject { Count: > 0 } fields) throw new InvalidDataException("keyword_unsupported");
            foreach (var pair in fields)
            {
                var pieces = pair.Key.Split('|'); string field = pieces[0]; string[] modifiers = pieces.Skip(1).ToArray();
                if (field.Length == 0) throw new InvalidDataException("keyword_unsupported");
                if (!Allowed[logsource].Contains(field)) throw new InvalidDataException("field_unsupported");
                if (modifiers.Except(["contains", "endswith", "startswith", "all", "re", "windash"]).Any()) throw new InvalidDataException("modifier_unsupported");
                var values = pair.Value is JsonArray array ? array.ToArray() : [pair.Value];
                if (values.Length == 0) throw new InvalidDataException("empty_list_unsupported");
                string chain = string.Join(",", modifiers.Where(x => x != "all"));
                if (modifiers.Distinct().Count() != modifiers.Length || chain is not ("" or "contains" or "endswith" or "startswith" or "re" or "contains,windash" or "windash,contains")) throw new InvalidDataException("modifier_chain_unsupported");
                foreach (var value in values)
                {
                    int expansions = 1, size = 16;
                    if (value is JsonValue scalar && scalar.TryGetValue<string>(out var text))
                    {
                        if (text.EnumerateRunes().Count() > 4096) throw new InvalidDataException("complexity_limit");
                        if (modifiers.Contains("windash"))
                        {
                            int dashes = text.Count(c => c is '-' or '/');
                            if (dashes > 4) throw new InvalidDataException("complexity_limit");
                            for (int i = 0; i < dashes; i++) expansions *= 5;
                        }
                        size = Encoding.UTF8.GetByteCount(text) + 2;
                    }
                    else if (value is not null && !(value is JsonValue number && number.TryGetValue<long>(out _))) throw new InvalidDataException("value_unsupported");
                    expandedValues += expansions; expandedBytes += size * expansions;
                    if (expandedValues > 4096 || expandedBytes > 4 * 1048576) throw new InvalidDataException("complexity_limit");
                }
            }
        }
        foreach (var pair in detection.Where(x => x.Key != "condition")) ValidateInput(pair.Value, 0);
        SigmaExpression Combine(string op, IEnumerable<SigmaExpression> values) { var all = values.ToArray(); if (all.Length == 0) throw new InvalidDataException("condition_selector_empty"); if (++nodes > 4096) throw new InvalidDataException("complexity_limit"); return all.Length == 1 ? all[0] : new(op, all); }
        SigmaExpression Selection(JsonNode? selection, int depth)
        {
            if (depth > 48 || ++nodes > 4096) throw new InvalidDataException("complexity_limit");
            if (selection is JsonArray alternatives) return Combine("or", alternatives.Select(x => Selection(x, depth + 1)));
            if (selection is not JsonObject { Count: > 0 } fields) throw new InvalidDataException("keyword_unsupported");
            var expressions = new List<SigmaExpression>();
            foreach (var pair in fields)
            {
                var pieces = pair.Key.Split('|'); string field = pieces[0]; string[] modifiers = pieces.Skip(1).ToArray();
                var values = pair.Value is JsonArray array ? array.ToArray() : [pair.Value];
                var compares = new List<SigmaExpression>();
                foreach (var value in values)
                {
                    if (++nodes > 4096) throw new InvalidDataException("complexity_limit");
                    if (value is null) compares.Add(new("compare", [], field, "null"));
                    else if (value is JsonValue scalar && scalar.TryGetValue<long>(out long number)) compares.Add(new("compare", [], field, "number", JsonValue.Create(number)));
                    else if (value is JsonValue text && text.TryGetValue<string>(out var s))
                    {
                        if (modifiers.Contains("re")) compares.Add(new("compare", [], field, "regex", JsonValue.Create(s)));
                        else
                        {
                            if (modifiers.Contains("startswith") || modifiers.Contains("contains")) s += "*";
                            if (modifiers.Contains("endswith") || modifiers.Contains("contains")) s = "*" + s;
                            var expanded = new List<string> { s };
                            if (modifiers.Contains("windash"))
                            {
                                // Copy complete patterns only at dash positions;
                                // appending every character to every variant is quadratic.
                                for (int i = 0; i < s.Length; i++)
                                    if (s[i] is '-' or '/')
                                    {
                                        int position = i;
                                        expanded = expanded.SelectMany(p => new[] { '-', '/', '\u2013', '\u2014', '\u2015' }.Select(d => p[..position] + d + p[(position + 1)..])).ToList();
                                    }
                            }
                            compares.Add(Combine("or", expanded.Select(pattern => new SigmaExpression("compare", [], field, "pattern", JsonValue.Create(pattern)))));
                        }
                    }
                    else throw new InvalidDataException("value_unsupported");
                }
                expressions.Add(Combine(modifiers.Contains("all") ? "and" : "or", compares));
            }
            return Combine("and", expressions);
        }
        foreach (var pair in detection.Where(x => x.Key != "condition")) named.Add(pair.Key, Selection(pair.Value, 0));
        var conditions = detection["condition"] is JsonArray list ? list.Select(x => x!.GetValue<string>()).ToArray() : [detection.Text("condition") ?? ""];
        var roots = new List<SigmaExpression>();
        foreach (string condition in conditions)
        {
            if (condition.Length is < 1 or > 4096) throw new InvalidDataException("condition_unsupported");
            var tokens = Regex.Matches(condition, @"\(|\)|[A-Za-z0-9_*?]+", RegexOptions.CultureInvariant).Select(x => x.Value).ToArray();
            if (string.Concat(tokens) != Regex.Replace(condition, @"\s", "")) throw new InvalidDataException("condition_unsupported"); int at = 0;
            SigmaExpression Expr(int precedence = 0, int depth = 0)
            {
                if (depth > 48 || at >= tokens.Length) throw new InvalidDataException("condition_unsupported");
                string token = tokens[at++]; SigmaExpression left;
                if (token == "not") left = new("not", [Expr(3, depth + 1)]);
                else if (token == "(") { left = Expr(0, depth + 1); if (at >= tokens.Length || tokens[at++] != ")") throw new InvalidDataException("condition_unsupported"); }
                else if (token is "1" or "any" or "all" && at < tokens.Length && tokens[at] == "of")
                {
                    at++; if (at >= tokens.Length) throw new InvalidDataException("condition_unsupported"); string pattern = tokens[at++];
                    string regex = "\\A" + Regex.Escape(pattern).Replace("\\*", ".*").Replace("\\?", ".") + "\\z";
                    left = Combine(token == "all" ? "and" : "or", named.Where(x => pattern == "them" || Regex.IsMatch(x.Key, regex, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(250))).Select(x => x.Value));
                }
                else left = named.TryGetValue(token, out var selection) ? selection : throw new InvalidDataException("condition_identifier_missing");
                while (at < tokens.Length && tokens[at] is "and" or "or")
                {
                    string op = tokens[at]; int power = op == "and" ? 2 : 1; if (power <= precedence) break; at++; left = Combine(op, [left, Expr(power, depth + 1)]);
                }
                return left;
            }
            var root = Expr(); if (at != tokens.Length) throw new InvalidDataException("condition_unsupported"); roots.Add(root);
        }
        var expression = Combine("or", roots);
        // Count every reference in the materialized tree, rather than only
        // selections built once. The source lowerer ticks both node and value.
        nodes = 0;
        void ValidateTree(SigmaExpression node, int depth)
        {
            if (++nodes > 4096 || depth > 48) throw new InvalidDataException("complexity_limit");
            if (node.Op == "compare" && (++nodes > 4096 || depth + 1 > 48)) throw new InvalidDataException("complexity_limit");
            foreach (var child in node.Args) ValidateTree(child, depth + 1);
        }
        // The condition-list OR is created after lowering in the reference.
        foreach (var root in roots) ValidateTree(root, 0);
        return new(id.ToString(), SemanticProposal.HashText(yaml), logsource, expression, expression.Fields.Distinct().Order(StringComparer.Ordinal).ToArray(), doc, sourceUri, upstreamCommit, doc.Text("license") ?? license);
    }
    internal string PlanSha => SemanticJson.Hash(PlanDocument);
    internal JsonObject PlanDocument
    {
        get
        {
            JsonObject ExpressionJson(SigmaExpression e)
            {
                JsonObject? value = null;
                if (e.Op == "compare")
                {
                    var parts = new JsonArray();
                    if (e.ValueKind == "pattern")
                    {
                        var literal = new StringBuilder(); string pattern = e.Value!.GetValue<string>();
                        void Flush() { if (literal.Length > 0) { parts.Add(new JsonObject { ["kind"] = "literal", ["text"] = literal.ToString() }); literal.Clear(); } }
                        for (int i = 0; i < pattern.Length; i++)
                        {
                            char c = pattern[i]; if (c == '\\' && i + 1 < pattern.Length && pattern[i + 1] is '*' or '?' or '\\') { literal.Append(pattern[++i]); continue; }
                            if (c is '*' or '?') { Flush(); parts.Add(new JsonObject { ["kind"] = c == '*' ? "any" : "one", ["text"] = "" }); } else literal.Append(c);
                        }
                        Flush();
                    }
                    value = new JsonObject { ["kind"] = e.ValueKind, ["scalar"] = e.ValueKind == "pattern" ? null : e.Value.Copy(), ["parts"] = parts };
                }
                return new JsonObject { ["op"] = e.Op, ["args"] = new JsonArray(e.Args.Select(x => (JsonNode)ExpressionJson(x)).ToArray()), ["field"] = e.Field, ["value"] = value };
            }
            return new JsonObject { ["rule_id"] = Id, ["source_sha256"] = Sha, ["logsource"] = LogSource, ["expression"] = ExpressionJson(Expression), ["required_fields"] = new JsonArray(Fields.Select(x => JsonValue.Create(x)).ToArray()), ["author"] = Document["author"].Copy(), ["license"] = License, ["source_uri"] = SourceUri, ["upstream_commit"] = UpstreamCommit, ["compiler_version"] = CompilerVersion, ["ir_version"] = "sli.sigma.ir.v1", ["parser_version"] = "1.3.3", ["mapping_version"] = MappingVersion };
        }
    }
    internal string Match(JsonObject fields, IReadOnlySet<string>? unavailable = null)
        => Evaluate(fields, unavailable).Status;
    internal (string Status, string[] Reasons, string ReplaySha) Evaluate(JsonObject fields, IReadOnlySet<string>? unavailable = null)
    {
        var clock = Stopwatch.StartNew(); int steps = 0, regexCalls = 0;
        var reasons = new HashSet<string>();
        void Tick(int n = 1) { if ((steps += n) > 2000000) throw new InvalidDataException("work_limit"); if (clock.Elapsed.TotalSeconds >= 2) throw new InvalidDataException("time_limit"); }
        bool Glob(string pattern, string text)
        {
            pattern = UnicodeCaseFold.Fold(pattern); text = UnicodeCaseFold.Fold(text); int p = 0, t = 0, star = -1, resume = 0;
            while (t < text.Length)
            {
                Tick(); if (p < pattern.Length && pattern[p] == '\\' && p + 1 < pattern.Length && pattern[p + 1] is '*' or '?' or '\\') { if (pattern[p + 1] == text[t]) { p += 2; t++; continue; } }
                else if (p < pattern.Length && (pattern[p] == '?' || pattern[p] == text[t])) { p++; t++; continue; }
                else if (p < pattern.Length && pattern[p] == '*') { star = p++; resume = t; continue; }
                if (star < 0) return false; p = star + 1; t = ++resume;
            }
            while (p < pattern.Length && pattern[p] == '*') p++; return p == pattern.Length;
        }
        bool? Eval(SigmaExpression expr)
        {
            Tick();
            if (expr.Op == "not") return Eval(expr.Args[0]) is { } boolean ? !boolean : null;
            if (expr.Op is "and" or "or") { bool unknown = false; foreach (var child in expr.Args) { bool? value = Eval(child); if (expr.Op == "and" && value == false) return false; if (expr.Op == "or" && value == true) return true; unknown |= value is null; } return unknown ? null : expr.Op == "and"; }
            string name = expr.Field!; if (unavailable?.Contains(name) == true) { reasons.Add("field_unavailable"); return null; } if (!fields.ContainsKey(name)) { reasons.Add("field_missing"); return null; }
            var natives = fields[name] is JsonArray values ? values.ToArray() : [fields[name]]; if (natives.Length == 0) { reasons.Add("field_empty_collection"); return null; } if (natives.Length > 64) throw new InvalidDataException("field_value_limit"); bool missing = false;
            foreach (var native in natives)
            {
                if (expr.ValueKind == "null") { if (native is null) return true; continue; }
                if (native is null) { reasons.Add("field_null"); missing = true; continue; }
                string text = native.ToString(); if (text.Length > 262144) throw new InvalidDataException("field_size_limit"); Tick(text.Length);
                if (expr.ValueKind == "number") { if (text.Length <= 21 && Regex.IsMatch(text, @"\A[+-]?[0-9]+\z") && System.Numerics.BigInteger.TryParse(text, out var n) && n == expr.Value!.GetValue<long>()) return true; }
                else if (expr.ValueKind == "regex") { if (++regexCalls > 32) throw new InvalidDataException("regex_call_limit"); if (Regex.IsMatch(text, expr.Value!.GetValue<string>(), RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(250))) return true; }
                else if (Glob(expr.Value!.GetValue<string>(), text)) return true;
            }
            return missing ? null : false;
        }
        var limits = MatchLimits;
        var fingerprint = new JsonObject { ["matcher"] = "sli.sigma.matcher.v1", ["limits"] = limits, ["plan"] = PlanSha }; var snapshot = new JsonObject();
        string status;
        try
        {
            foreach (string name in Fields)
            {
                Tick(); snapshot[name] = unavailable?.Contains(name) == true ? new JsonArray("unavailable") : !fields.ContainsKey(name) ? new JsonArray("missing") : new JsonArray("present", fields[name].Copy());
                if (fields[name] is JsonArray { Count: > 64 }) throw new InvalidDataException("field_value_limit");
                if (fields[name]?.ToString().Length > 262144) throw new InvalidDataException("field_size_limit");
            }
            fingerprint["fields"] = snapshot; status = Eval(Expression) switch { true => "matched", false => "not_matched", _ => "not_evaluable" }; if (status != "not_evaluable") reasons.Clear();
        }
        catch (Exception e) when (e is InvalidDataException or RegexMatchTimeoutException or ArgumentException)
        { status = "not_evaluable"; reasons.Clear(); reasons.Add(e is RegexMatchTimeoutException ? "regex_timeout" : e is ArgumentException ? "regex_invalid_or_resource_limit" : e.Message); }
        string[] sorted = reasons.Order(StringComparer.Ordinal).ToArray(); fingerprint["status"] = status; fingerprint["reasons"] = new JsonArray(sorted.Select(x => JsonValue.Create(x)).ToArray());
        return (status, sorted, Password.PasswordJson.Hash(fingerprint));
    }
}
