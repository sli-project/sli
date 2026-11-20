using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Semantic;

internal sealed record SemanticRelation(string Kind, IReadOnlyList<SemanticEvent> Evidence, string Key, string Confidence, string Explanation, string? Partition);
internal sealed record SemanticCorrelation(string Id, int Version, string Kind, string[] Inputs, string[] Roles, string PartitionKind, bool Strict, string Continuation, int Window, int Minimum, string Output, string Confidence, string Explanation, string Sha)
{
    internal static IReadOnlyList<SemanticRelation> SessionPrivilegeObservations(IEnumerable<SemanticEvent> events)
    {
        var result = new List<SemanticRelation>();
        foreach (var group in events.Where(e => !string.IsNullOrEmpty(e.Roles.Text("session_principal")))
                     .GroupBy(e => e.Roles.Text("session_principal")!).OrderBy(g => g.Key, StringComparer.Ordinal))
            foreach (var session in group.Where(e => e.Type == "authentication.session.created").OrderBy(e => e.Source))
                foreach (var privilege in group.Where(e => e.Type == "authentication.privileged_session.created").OrderBy(e => e.Source))
                {
                    if ((privilege.At - session.At).Duration() > TimeSpan.FromMinutes(15)) continue;
                    var evidence = new[] { session, privilege }.OrderBy(e => e.Source).ToArray();
                    result.Add(new("authentication.session.has_special_privileges", evidence,
                        $"session-special-privileges:{group.Key}:{evidence[0].Source}:{evidence[1].Source}", "high",
                        "Связь подтверждена совпадением source_host и LogonId; она описывает сессию, не повышение прав.", null));
                }
        return result;
    }

    internal static SemanticCorrelation Compile(JsonNode row)
    {
        var d = row["definition_json"]!.AsObject(); string kind = row.Text("rule_kind")!;
        string[] List(string key, int max, bool empty = false)
        {
            if (d[key] is null && empty) return [];
            if (d[key] is not JsonArray array) throw new InvalidDataException("correlation_list_invalid");
            var values = array.Select(x => x!.GetValue<string>().Trim()).ToArray();
            if ((!empty && values.Length == 0) || values.Length > max || values.Distinct().Count() != values.Length || values.Any(x => x.Length is < 1 or > 200)) throw new InvalidDataException("correlation_list_invalid"); return values;
        }
        SemanticCorrelationRepository.ValidateDefinition(row.Text("rule_id") ?? "", (int)row.Number("rule_version"), kind, d);
        if (kind is not ("all_of" or "count" or "count_then" or "sequence") || d.Text("type") != kind) throw new InvalidDataException("correlation_kind_invalid");
        var inputs = List("inputs", 8); string partition = d.Text("partition_kind") ?? "source_host"; var roles = List("join_roles", 4, partition != "source_host");
        if (partition is not ("source_host" or "domain_account_sid" or "domain_member_group_sid" or "domain_account_member_sid") || partition == "source_host" && !roles.Contains("source_host") || partition != "source_host" && roles.Length > 0 || roles.Except(SemanticPolicy.CanonicalRoles).Any()) throw new InvalidDataException("correlation_partition_invalid");
        int minimum = d["minimum_count"] is null ? inputs.Length : (int)d.Number("minimum_count"), window = (int)d.Number("window_seconds");
        bool strict = d.Flag("strict_time_order"); string continuation = d.Text("continuation_policy") ?? "first_admissible";
        if (window is < 1 or > 86400 || kind == "count" && inputs.Length != 1 || kind is "count_then" && inputs.Length != 2 || kind is "all_of" or "sequence" && inputs.Length < 2 || kind is "count" or "count_then" && minimum is < 2 or > 1000 || kind is "all_of" or "sequence" && minimum != inputs.Length || continuation is not ("first_admissible" or "anchor_all_admissible") || continuation == "anchor_all_admissible" && (kind != "sequence" || inputs.Length != 2 || !strict)) throw new InvalidDataException("correlation_definition_invalid");
        string output = SemanticGovernance.Required(d, "output_relation_kind", 1, 200, "correlation_output_required"), confidence = d.Text("confidence") ?? "medium", explanation = SemanticGovernance.Required(d, "explanation", 1, 2000, "correlation_explanation_required");
        if (confidence is not ("low" or "medium" or "high")) throw new InvalidDataException("correlation_confidence_invalid");
        string hash = SemanticJson.Hash(d); if (row.Text("definition_sha256") is { } expected && expected != hash) throw new InvalidDataException("correlation_definition_hash_mismatch");
        return new(row.Text("rule_id")!, (int)row.Number("rule_version"), kind, inputs, roles, partition, strict, continuation, window, minimum, output, confidence, explanation, hash);
    }
    internal string? Partition(SemanticEvent ev)
    {
        string? Exact(string? sid) => sid is { Length: <= 184 } && Regex.IsMatch(sid, @"\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\z") ? sid : null;
        string? Account() => ev.Quality["relation_account_identity"].Text("state") == "exact" && Exact(ev.Facts.Text("relation_account_sid")) is { } exact ? exact : ev.Roles.Text("affected_entity") is { } role && role.StartsWith("sid:", StringComparison.Ordinal) ? Exact(role[4..]) : null;
        if (PartitionKind == "source_host") return ev.Roles.Text("source_host") is { Length: > 0 and <= 160 } host ? host : null;
        long domain = ev.Facts.Number("domain_id"); if (domain <= 0) return null;
        string? account = Account(), member = Exact(ev.Facts.Text("relation_member_sid")), group = Exact(ev.Facts.Text("relation_group_sid"));
        bool membership = ev.Quality["relation_membership_identity"].Text("state") == "exact";
        return PartitionKind switch { "domain_account_sid" => account is null ? null : $"domain:{domain}|account_sid:{account}", "domain_member_group_sid" => membership && member is not null && group is not null ? $"domain:{domain}|member_sid:{member}|group_sid:{group}" : null, "domain_account_member_sid" => (account ?? (membership ? member : null)) is { } sid ? $"domain:{domain}|account_member_sid:{sid}" : null, _ => null };
    }
    internal IReadOnlyList<SemanticRelation> Match(IReadOnlyList<SemanticEvent> events)
    {
        var groups = new SortedDictionary<string, (string[] Key, List<SemanticEvent> Events)>(StringComparer.Ordinal);
        foreach (var ev in events.Where(x => Inputs.Contains(x.Type)))
        {
            string? partition = Partition(ev); if (partition is null) continue;
            string[] groupKey = PartitionKind == "source_host" ? Roles.Select(x => ev.Roles.Text(x) ?? "").ToArray() : [partition]; if (groupKey.Any(string.IsNullOrWhiteSpace)) continue;
            string serialized = new JsonArray(groupKey.Select(x => JsonValue.Create(x)).ToArray()).ToJsonString();
            if (!groups.TryGetValue(serialized, out var group)) groups[serialized] = group = (groupKey, new()); group.Events.Add(ev);
        }
        var result = new List<SemanticRelation>();
        foreach (var (_, group) in groups)
        {
            var ordered = group.Events.OrderBy(x => x.At).ThenBy(x => x.Source).ToArray(); int index = 0;
            while (index < ordered.Length)
            {
                var first = ordered[index]; int end = index + 1; while (end < ordered.Length && ordered[end].At - first.At <= TimeSpan.FromSeconds(Window)) end++;
                var selected = new List<SemanticEvent>(); int next = index + 1;
                if (Kind == "count") { if (end - index >= Minimum) { selected.AddRange(ordered[index..end]); next = end; } }
                else if (Kind == "count_then")
                {
                    if (first.Type == Inputs[^1]) { var preceding = ordered.Take(index).Where(x => x.Type == Inputs[0] && x.At < first.At && first.At - x.At <= TimeSpan.FromSeconds(Window)).ToArray(); if (preceding.Length >= Minimum) { selected.AddRange(preceding); selected.Add(first); } }
                }
                else if (Kind == "all_of")
                {
                    int last = index; foreach (string input in Inputs) { int position = Array.FindIndex(ordered, index, end - index, x => x.Type == input); if (position < 0 || Strict && selected.Count > 0 && ordered[position].At <= selected[^1].At) { selected.Clear(); break; } selected.Add(ordered[position]); last = Math.Max(last, position); } next = last + 1;
                }
                else if (first.Type == Inputs[0])
                {
                    selected.Add(first);
                    if (Continuation == "anchor_all_admissible") { selected.AddRange(ordered[(index + 1)..end].Where(x => x.Type == Inputs[1] && x.At > first.At)); if (selected.Count == 1) selected.Clear(); }
                    else
                    {
                        int prior = index;
                        foreach (string input in Inputs.Skip(1)) { int position = Array.FindIndex(ordered, prior + 1, end - prior - 1, x => x.Type == input); if (position < 0 || Strict && ordered[position].At <= selected[^1].At) { selected.Clear(); break; } selected.Add(ordered[position]); prior = position; } next = prior + 1;
                    }
                }
                if (selected.Count == 0) { index++; continue; }
                string key = "dispatch:" + Password.PasswordJson.Hash(new JsonObject { ["rule_id"] = Id, ["rule_version"] = Version, ["group"] = new JsonArray(group.Key.Select(x => JsonValue.Create(x)).ToArray()), ["anchor_event_id"] = first.Source, ["anchor_time"] = SemanticJson.Stamp(first.At) });
                result.Add(new(Output, selected.DistinctBy(x => x.Source).ToArray(), key, Confidence, Explanation, PartitionKind == "source_host" ? null : group.Key[0])); index = next;
            }
        }
        return result;
    }
}
