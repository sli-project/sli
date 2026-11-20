using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Access;

namespace Sli.Server.Semantic;

public sealed record SemanticScope(string Installation, string Plugin, string Source, string Generation, string Collection)
{
    public JsonObject Document => new() { ["installation_id"] = Installation, ["plugin_id"] = Plugin, ["source_instance_id"] = Source, ["source_generation"] = Generation, ["collection_scope_id"] = Collection };
    public object?[] Parameters => [Guid.Parse(Installation), Plugin, Source, Generation, Collection];
    public static SemanticScope Parse(SemanticQuery query, string code)
    {
        string Raw(string key) => query.Values.TryGetValue(key, out var v) && v.Length == 1 ? v[0] : "";
        string installation = Raw("installation_id"), plugin = Raw("plugin_id"), source = Raw("source_instance_id"), generation = Raw("source_generation"), collection = Raw("collection_scope_id");
        bool Valid(string s, int min, int max) => s == s.Trim() && s.EnumerateRunes().Count() >= min && s.EnumerateRunes().Count() <= max;
        if (!Guid.TryParseExact(installation, "D", out var id) || id.ToString() != installation || !Valid(plugin, 1, 128) || !Valid(source, 1, 256) || !Valid(generation, 1, 512) || !Valid(collection, 0, 256)) throw new SemanticInputException(code);
        return new(installation, plugin, source, generation, collection);
    }
}

public sealed class SigmaProjection(ISemanticDatabase database)
{
    internal static readonly string[] Capabilities = ["semantic.review", "events.view", "field.security"];
    internal static bool Available(CapabilityDecisionSet access) => access.IsOwner || Capabilities.All(c => access.Capabilities.Contains(c) || access.ResourceCapabilities.Contains(c) || access.Policies.Any(p => p.CapabilityKey == c && p.Valid && p.Effect == "allow"));
    internal static bool Authorized(CapabilityDecisionSet access, JsonNode? resources)
    {
        if (resources is not JsonArray { Count: > 0 } rows) return false;
        if (access.IsOwner) return true;
        var groups = new List<IReadOnlyList<AccessResource>>();
        foreach (var resource in rows)
        {
            if (resource is not JsonObject row) return false;
            var group = new List<AccessResource>();
            foreach (string kind in new[] { "server", "domain" }) if (row.Number(kind + "_id") > 0) group.Add(new(kind, row.Number(kind + "_id")));
            if (row.Text("channel") is { Length: > 0 } channel) group.Add(new("channel", Value: channel));
            group.Add(new(row.Text("kind") ?? "", row["id"] is null ? null : row.Number("id"), row.Text("value"))
            { PluginId = row.Text("plugin_id"), SourceInstanceId = row.Text("source_instance_id"), CollectionScopeId = row.Text("collection_scope_id"), DeviceId = row.Text("device_id"), EntityId = row["entity_id"] is null ? null : row.Number("entity_id"), DomainId = row["domain_id"] is null ? null : row.Number("domain_id") });
            groups.Add(group);
        }
        foreach (var deny in access.Policies.Where(p => p.Effect == "deny" && Capabilities.Contains(p.CapabilityKey)))
        {
            if (deny.Scope.ValueKind != System.Text.Json.JsonValueKind.Object) continue;
            var scope = JsonNode.Parse(deny.Scope.GetRawText());
            string? dimension = scope.Text("kind") switch { "server" => "server_id", "domain" => "domain_id", "channel" => "channel", _ => null };
            if (dimension is not null && rows.Any(x => x?[dimension] is null || x[dimension]!.ToString().Length == 0)) return false;
            if (scope?["clauses"] is JsonArray clauses && clauses.Any(c => c?["device_ids"] is JsonArray { Count: > 0 } || c?["entity_ids"] is JsonArray { Count: > 0 })) return false;
        }
        return Capabilities.All(cap => access.DecideForResourceGroups(cap, groups).Allowed);
    }
    public async Task<JsonObject> ReadAsync(string kind, SemanticQuery q, CapabilityDecisionSet access, CancellationToken ct)
    {
        bool coverage = kind == "attack-coverage"; string code = coverage ? "sigma_attack_filter_invalid" : "sigma_rule_filter_invalid";
        string[] scopeKeys = ["installation_id", "plugin_id", "source_instance_id", "source_generation", "collection_scope_id"];
        q.Only(code, coverage ? [.. scopeKeys, "since", "until", "catalog_sha256"] : scopeKeys);
        if (!coverage && q.Values.Count > 0 && scopeKeys.Any(k => !q.Values.ContainsKey(k))) throw new SemanticInputException(code);
        SemanticScope? scope = coverage || q.Values.Count > 0 ? SemanticScope.Parse(q, code) : null;
        DateTimeOffset? start = null, end = null; string? catalogHash = null;
        if (coverage)
        {
            foreach (string key in new[] { "installation_id", "plugin_id", "source_instance_id", "source_generation", "since", "until", "catalog_sha256" }) if (!q.Values.ContainsKey(key)) throw new SemanticInputException(code);
            if (!Regex.IsMatch(q.Get("since") ?? "", @"(?:Z|[+-]\d{2}:?\d{2})$") || !Regex.IsMatch(q.Get("until") ?? "", @"(?:Z|[+-]\d{2}:?\d{2})$")) throw new SemanticInputException(code);
            start = SemanticQuery.Time(q.Get("since")!, "UTC", code); end = SemanticQuery.Time(q.Get("until")!, "UTC", code); catalogHash = q.Get("catalog_sha256");
            if (end <= start || end - start > TimeSpan.FromDays(31) || !Regex.IsMatch(catalogHash ?? "", @"\A[a-f0-9]{64}\z")) throw new SemanticInputException(code);
        }
        var result = new JsonObject { ["api_version"] = "v1", ["contract"] = coverage ? "sli.sigma.attack-coverage.v1" : "sli.sigma.rules.v1", ["read_only"] = true,
            ["state"] = "available", ["reason"] = null, ["scope"] = scope?.Document, ["since"] = start is { } s ? SemanticJson.Stamp(s) : null, ["until"] = end is { } e ? SemanticJson.Stamp(e) : null,
            ["window_basis"] = coverage ? "occurrence_time" : "latest_retained_test_history", ["rules"] = new JsonArray() };
        if (coverage) { result["denominator"] = "visible_registered_rule_revisions"; result["catalog_sha256"] = catalogHash; result["items"] = new JsonArray(); result["unmapped"] = new JsonArray(); }
        else { result["sources"] = new JsonArray(); result["metadata_state"] = "unavailable"; }
        JsonObject Unavailable(string reason) { result["state"] = "unavailable"; result["reason"] = reason; return result; }
        if (!Available(access)) return Unavailable("source_unavailable_or_denied");
        try
        {
            await using var session = await database.OpenAsync(false, ct);
            if (scope is null)
            {
                var sources = await session.QueryAsync("select installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id,resources from sli_sigma.attack_source_scopes order by installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id limit 201", ct);
                if (sources.Count > 200) return Unavailable("projection_limit");
                var visible = new JsonArray(); foreach (var row in sources.Where(x => Authorized(access, x?["resources"]))) { var item = new JsonObject(); foreach (string key in scopeKeys) item[key] = row![key].Copy(); visible.Add(item); }
                result["sources"] = visible; return visible.Count == 0 ? Unavailable("source_unavailable_or_denied") : result;
            }
            var source = (await session.QueryAsync("select resources from sli_sigma.attack_source_scopes where installation_id=$1 and plugin_id=$2 and source_instance_id=$3 and source_generation=$4 and collection_scope_id=$5", ct, scope.Parameters)).FirstOrDefault();
            if (!Authorized(access, source?["resources"])) return Unavailable("source_unavailable_or_denied");
            JsonNode? catalog = null;
            if (coverage)
            {
                catalog = (await session.QueryAsync("select document_json from sli_sigma.attack_catalogs where stix_sha256=$1", ct, catalogHash)).FirstOrDefault()?["document_json"];
                if (catalog is null) return Unavailable("catalog_unavailable");
            }
            string labels = coverage ? "" : ",labels.title,labels.description,labels.rule_id is not null as labels_available";
            string labelJoin = coverage ? "" : "left join lateral sli_sigma.read_rule_labels(r.installation_id,r.plugin_id,r.source_instance_id,r.rule_id,r.raw_sha256) labels on true";
            var revisions = await session.QueryAsync($"select r.rule_id,r.raw_sha256,r.canonical_sha256,r.upstream_commit,r.status,r.tags{labels} from sli_sigma.sigma_rule_revisions r {labelJoin} where r.installation_id=$1 and r.plugin_id=$2 and r.source_instance_id=$3 order by r.rule_id,r.raw_sha256 limit 5001", ct, Guid.Parse(scope.Installation), scope.Plugin, scope.Source);
            var observations = await session.QueryAsync("select rule_id,raw_sha256,time_from,time_to,document_json,created_at,coverage_sha256 from sli_sigma.attack_history_coverage where installation_id=$1 and plugin_id=$2 and source_instance_id=$3 and source_generation=$4 and collection_scope_id=$5" + (coverage ? " and time_from<$6 and time_to>$7" : "") + " order by created_at desc,coverage_sha256 desc limit 5001", ct,
                coverage ? [.. scope.Parameters, end, start] : scope.Parameters);
            if (Math.Max(revisions.Count, observations.Count) > 5000) return Unavailable("projection_limit");
            if (!coverage && observations.Count > 0)
            {
                end = observations.Max(x => At(x!, "time_to")); start = observations.Min(x => At(x!, "time_from")); if (start < end!.Value.AddDays(-31)) start = end.Value.AddDays(-31);
                result["since"] = SemanticJson.Stamp(start!.Value); result["until"] = SemanticJson.Stamp(end.Value);
            }
            var matches = start is null ? new JsonArray() : await session.QueryAsync("select * from sli_sigma.read_attack_live_matches($1,$2,$3,$4,$5,$6,$7)", ct, [.. scope.Parameters, start, end]);
            if (matches.Count > 5000) return Unavailable("projection_limit");
            if (coverage) return Aggregate(result, catalog!.AsObject(), revisions, observations, matches, start!.Value, end!.Value);
            var policies = access.IsOwner ? await session.QueryAsync("select p.policy_id,p.policy_version,p.lifecycle_status,p.definition_json->>'title' as policy_title,p.definition_json->'source_selector' as selector,coalesce(a.enabled,false) as admitted,semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status) as effective_mode from semantic_risk_policies p left join semantic_policy_admission a using(policy_id,policy_version) where p.source_kind='detection_match' and p.definition_json#>'{source_selector,execution,scope}'=$1::jsonb order by p.policy_id,p.policy_version limit 5001", ct, scope.Document) : new JsonArray();
            if (policies.Count > 5000) return Unavailable("projection_limit");
            var rules = new JsonArray();
            foreach (var revision in revisions)
            {
                string ruleId = revision.Text("rule_id")!, hash = revision.Text("raw_sha256")!;
                var history = observations.Where(x => Same(x!, ruleId, hash, "raw_sha256") && start is not null && At(x!, "time_from") < end && At(x!, "time_to") > start).ToArray();
                var inputs = matches.Where(x => Same(x!, ruleId, hash, "rule_sha256")).ToArray();
                var bound = new JsonArray();
                foreach (var candidate in policies.Where(x => x?["selector"].Text("rule_id") == ruleId && x?["selector"]?["execution"].Text("rule_sha256") == hash))
                {
                    var pin = candidate!["selector"]!["execution"]!.AsObject();
                    if (!ValidPin(pin, ruleId) || !JsonNode.DeepEquals(pin["scope"], scope.Document)) continue;
                    var policy = candidate!.DeepClone().AsObject(); policy.Remove("selector"); policy["execution"] = pin.Copy(); bound.Add(policy);
                }
                var item = revision!.DeepClone().AsObject(); item.Remove("labels_available"); item["metadata_state"] = revision.Flag("labels_available") ? "available" : "unavailable";
                item["executions"] = start is null ? new JsonArray() : Executions(history, start.Value, end!.Value);
                item["admission"] = new JsonObject { ["state"] = access.IsOwner ? "available" : "unavailable", ["reason"] = access.IsOwner ? null : "owner_required", ["policies"] = bound };
                var runtime = new JsonObject { ["state"] = start is null ? "unmeasured" : "measured", ["basis"] = "eligible_atomic_detection_inputs" };
                foreach (string mode in new[] { "enabled", "shadow", "test" }) runtime[mode] = start is null ? null : inputs.Where(x => x.Text("evaluation_mode") == mode).Sum(x => x.Number("matches"));
                item["runtime"] = runtime; rules.Add(item);
            }
            result["rules"] = rules; result["metadata_state"] = rules.All(x => x.Text("metadata_state") == "available") ? "available" : "unavailable"; return result;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return Unavailable("projection_unavailable"); }
    }
    internal static bool ValidPin(JsonObject pin, string ruleId)
    {
        string[] hashes = ["rule_sha256", "manifest_sha256", "overlay_sha256"];
        string[] keys = ["version", "rule_id", "rule_sha256", "manifest_sha256", "compiler_version", "mapping_version", "overlay_sha256", "scope"];
        if (!pin.Select(x => x.Key).Order().SequenceEqual(keys.Order()) || pin.Text("version") != "sli.sigma.execution.v1" || pin.Text("rule_id") != ruleId || pin["scope"] is not JsonObject scope || !hashes.All(x => Regex.IsMatch(pin.Text(x) ?? "", @"\A[a-f0-9]{64}\z")) || !new[] { "compiler_version", "mapping_version" }.All(x => Regex.IsMatch(pin.Text(x) ?? "", @"\A[a-zA-Z0-9_.-]{1,80}\z"))) return false;
        try
        {
            var query = new SemanticQuery("?" + string.Join("&", scope.Select(x => System.Net.WebUtility.UrlEncode(x.Key) + "=" + System.Net.WebUtility.UrlEncode(x.Value?.GetValue<string>() ?? ""))), true);
            var parsed = SemanticScope.Parse(query, "sigma_scope_invalid"); return JsonNode.DeepEquals(parsed.Document, scope);
        }
        catch (Exception e) when (e is SemanticInputException or InvalidOperationException) { return false; }
    }
    internal static DateTimeOffset At(JsonNode row, string key) => SemanticQuery.Time(row.Text(key)!, "UTC", "sigma_attack_filter_invalid");
    private static bool Same(JsonNode row, string rule, string hash, string field) => row.Text("rule_id") == rule && row.Text(field) == hash;

    internal static JsonArray Executions(IEnumerable<JsonNode?> rows, DateTimeOffset start, DateTimeOffset end)
    {
        string[] pinKeys = ["manifest_sha256", "plan_sha256", "compiler_version", "mapping_version", "overlay_sha256"];
        var output = new JsonArray();
        var groups = rows.GroupBy(row => new JsonArray(pinKeys.Select(k => row!["document_json"]![k].Copy()).ToArray()).ToJsonString()).OrderBy(x => x.Key, StringComparer.Ordinal);
        foreach (var group in groups)
        {
            var selected = new List<JsonNode>(); var intervals = new List<(DateTimeOffset Left, DateTimeOffset Right)>(); bool excluded = false;
            foreach (var row in group.OrderByDescending(x => At(x!, "created_at")).ThenByDescending(x => x.Text("coverage_sha256"), StringComparer.Ordinal))
            {
                var left = At(row!, "time_from"); var right = At(row!, "time_to");
                if (!(start <= left && left < right && right <= end)) { excluded = true; continue; }
                if (intervals.Any(x => left < x.Right && x.Left < right)) { if (!intervals.Contains((left, right))) excluded = true; continue; }
                intervals.Add((left, right)); selected.Add(row!);
            }
            var counts = new JsonObject(); foreach (string key in new[] { "scanned", "evaluable", "matched", "suppressed", "unknown", "skipped" }) counts[key] = selected.Sum(x => x["document_json"]!["counts"].Number(key));
            var ordered = intervals.OrderBy(x => x.Left).ToArray(); bool covered = ordered.Length > 0 && ordered[0].Left == start && ordered[^1].Right == end && ordered.Zip(ordered.Skip(1)).All(x => x.First.Right == x.Second.Left);
            bool complete = covered && !excluded && selected.All(x => x["document_json"].Flag("partition_complete") && x["document_json"].Text("status") == "completed");
            string state = !complete ? "incomplete" : counts.Number("scanned") == 0 ? "no_data" : counts.Number("unknown") > 0 || counts.Number("skipped") > 0 || counts.Number("evaluable") == 0 ? counts.Number("evaluable") == 0 ? "not_evaluable" : "degraded" : counts.Number("matched") > 0 ? "matched" : "no_matches";
            var first = group.First()!["document_json"]!; var item = new JsonObject(); foreach (string key in pinKeys) item[key] = first[key].Copy();
            item["mode"] = "test"; item["state"] = state; item["complete"] = complete; item["counts"] = counts;
            item["required_fields"] = new JsonArray(selected.SelectMany(x => x["document_json"]?["required_fields"]?.AsArray().Select(f => f!.GetValue<string>()) ?? []).Distinct().Order(StringComparer.Ordinal).Select(x => JsonValue.Create(x)).ToArray());
            item["logsources"] = new JsonArray(selected.Select(x => x["document_json"].Text("logsource")).Where(x => x is not null).Distinct().Order(StringComparer.Ordinal).Select(x => JsonValue.Create(x)).ToArray());
            item["evaluable_percent"] = counts.Number("scanned") > 0 ? 100.0 * counts.Number("evaluable") / counts.Number("scanned") : null;
            item["matches_per_1000_evaluable"] = counts.Number("evaluable") > 0 ? 1000.0 * counts.Number("matched") / counts.Number("evaluable") : null;
            item["evaluation_intervals"] = new JsonArray(ordered.Select(x => (JsonNode)new JsonObject { ["since"] = SemanticJson.Stamp(x.Left), ["until"] = SemanticJson.Stamp(x.Right) }).ToArray());
            item["observed_intervals"] = new JsonArray(selected.Where(x => x["document_json"]!["counts"].Number("scanned") > 0 && x["document_json"]!["counts"]!["first_occurred_at"] is not null).Select(x => (JsonNode)new JsonObject { ["first_occurred_at"] = x["document_json"]!["counts"]!["first_occurred_at"].Copy(), ["last_occurred_at"] = x["document_json"]!["counts"]!["last_occurred_at"].Copy() }).ToArray());
            var quality = new JsonArray();
            foreach (var row in selected)
            {
                var doc = row["document_json"]!; var q = new JsonObject { ["since"] = SemanticJson.Stamp(At(row, "time_from")), ["until"] = SemanticJson.Stamp(At(row, "time_to")), ["published_at"] = SemanticJson.Stamp(At(row, "created_at")), ["coverage_sha256"] = row["coverage_sha256"].Copy() };
                foreach (string key in new[] { "status", "request_sha256", "snapshot_sha256", "high_watermark" }) q[key] = doc[key].Copy();
                foreach (string key in new[] { "reasons", "unknown_fields", "first_occurred_at", "last_occurred_at" }) q[key] = doc["counts"]![key].Copy(); quality.Add(q);
            }
            item["quality"] = quality; output.Add(item);
        }
        return output;
    }
    internal static JsonObject Aggregate(JsonObject result, JsonObject catalog, JsonArray revisions, JsonArray observations, JsonArray matches, DateTimeOffset start, DateTimeOffset end)
    {
        var cells = new SortedDictionary<string, JsonObject>(StringComparer.Ordinal); var unmapped = new JsonArray(); var rules = new JsonArray();
        var techniques = catalog["techniques"]!.AsObject(); var tactics = techniques.SelectMany(x => x.Value!["tactics"]!.AsArray().Select(t => t!.GetValue<string>())).ToHashSet();
        foreach (var revision in revisions)
        {
            string rule = revision.Text("rule_id")!, hash = revision.Text("raw_sha256")!;
            var executions = Executions(observations.Where(x => Same(x!, rule, hash, "raw_sha256")), start, end);
            var inputs = SemanticJson.Array(matches.Where(x => Same(x!, rule, hash, "rule_sha256")));
            var item = new JsonObject { ["rule_id"] = rule, ["raw_sha256"] = hash, ["canonical_sha256"] = revision!["canonical_sha256"].Copy(), ["upstream_commit"] = revision["upstream_commit"].Copy(), ["upstream_status"] = revision["status"].Copy(), ["upstream_tags"] = revision["tags"].Copy(), ["executions"] = executions,
                ["compiled"] = executions.Count + inputs.Count > 0, ["compile_state"] = executions.Count + inputs.Count > 0 ? "supported" : revision.Text("status") == "unsupported" ? "unsupported" : "not_checked", ["fixture_validation"] = "not_checked", ["telemetry_continuity"] = "unknown", ["detection_inputs"] = inputs,
                ["eligible_detection_matches"] = inputs.Sum(x => x.Number("matches")), ["match_basis"] = "eligible_atomic_detection_inputs", ["current_admission"] = "not_measured", ["lifecycle"] = executions.Count > 0 ? "test" : "not_checked", ["upstream_tactics"] = new JsonArray() };
            rules.Add(item);
            var tags = revision["tags"]!.AsArray().Select(x => x!.GetValue<string>()).Where(x => x.StartsWith("attack.", StringComparison.Ordinal)).Distinct().Order(StringComparer.Ordinal).ToArray(); var mapped = new SortedSet<string>(StringComparer.Ordinal);
            void Unmapped(string? tag, string reason) => unmapped.Add(new JsonObject { ["rule_id"] = rule, ["raw_sha256"] = hash, ["tag"] = tag, ["reason"] = reason });
            foreach (string tag in tags)
            {
                string technique = tag[7..].ToUpperInvariant(), tactic = tag[7..].Replace('_', '-');
                if (tactics.Contains(tactic)) { item["upstream_tactics"]!.AsArray().Add(tactic); continue; }
                if (!Regex.IsMatch(technique, @"\AT[0-9]{4}(?:\.[0-9]{3})?\z") || !techniques.ContainsKey(technique)) { Unmapped(tag, "not_a_catalog_technique"); continue; }
                mapped.Add(technique);
            }
            if (tags.Length == 0) Unmapped(null, "missing_attack_tag"); else if (mapped.Count == 0 && item["upstream_tactics"]!.AsArray().Count == tags.Length) Unmapped(null, "missing_technique_tag");
            foreach (string technique in mapped)
            {
                if (!cells.TryGetValue(technique, out var cell)) { cell = techniques[technique]!.DeepClone().AsObject(); cell["technique_id"] = technique; cell["mapping_provenance"] = "upstream_tag_exact"; cell["rules"] = new JsonArray(); cells[technique] = cell; }
                cell["rules"]!.AsArray().Add(new JsonObject { ["rule_id"] = rule, ["raw_sha256"] = hash });
            }
        }
        foreach (var cell in cells.Values)
        {
            var members = rules.Where(r => cell["rules"]!.AsArray().Any(x => x.Text("rule_id") == r.Text("rule_id") && x.Text("raw_sha256") == r.Text("raw_sha256"))).ToArray();
            cell["counts"] = new JsonObject { ["library"] = members.Length, ["compiled"] = members.Count(x => x.Flag("compiled")), ["fixture_verified"] = 0, ["telemetry_verified"] = 0, ["shadow"] = null, ["enabled"] = null, ["eligible_detection_matches"] = members.Sum(x => x.Number("eligible_detection_matches")) };
            var states = new JsonObject(); foreach (string state in new[] { "no_data", "no_matches", "matched", "degraded", "not_evaluable", "incomplete" }) states[state] = members.Count(x => x!["executions"]!.AsArray().Any(e => e.Text("state") == state)); cell["history_states"] = states;
        }
        var metadata = catalog.DeepClone().AsObject(); metadata.Remove("techniques"); result["catalog"] = metadata; result["items"] = new JsonArray(cells.Values.Select(x => (JsonNode)x).ToArray()); result["unmapped"] = unmapped; result["rules"] = rules; return result;
    }
}
