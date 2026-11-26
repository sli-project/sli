using System.Globalization;
using System.Net;
using System.Text.Json.Nodes;
using Sli.Server.Agents.Registry;
using Sli.Server.Semantic.Password;

namespace Sli.Server.Semantic.Detections;

public sealed record PasswordThresholdPolicy(int SprayAccounts = 10, int BruteAttempts = 20, int WindowSeconds = 600)
{
    public JsonObject Document => new() { ["spray_accounts"] = SprayAccounts, ["brute_attempts"] = BruteAttempts, ["window_seconds"] = WindowSeconds };

    public void Validate() => D.Require(SprayAccounts is >= 1 and <= 256 && BruteAttempts is >= 1 and <= 10000 &&
        WindowSeconds is >= 1 and <= 600, "password_threshold_policy_invalid");

    public static PasswordThresholdPolicy Read(JsonNode? document)
    {
        if (document is null) return new();
        D.Require(document is JsonObject { Count: 3 }, "password_threshold_policy_invalid");
        var policy = new PasswordThresholdPolicy(document["spray_accounts"]!.GetValue<int>(),
            document["brute_attempts"]!.GetValue<int>(), document["window_seconds"]!.GetValue<int>());
        policy.Validate();
        return policy;
    }
}

internal static class PasswordAttacks
{
    internal const string Brute = "qw.password-brute-force", Spray = "qw.password-spray";
    internal const int QuietSeconds = 1800;
    internal static bool IsRule(string? rule) => rule is Brute or Spray;
    internal static readonly string[] Rules = [Brute, Spray];

    internal static JsonObject Execution(PasswordScope scope, string rule, PasswordThresholdPolicy policy)
    {
        policy.Validate();
        D.Require(IsRule(rule), "password_threshold_rule_invalid");
        var definition = new JsonObject { ["version"] = "sli.password-threshold.1", ["rule_id"] = rule, ["policy"] = policy.Document };
        return new() { ["version"] = "sli.qw.execution.v1", ["kind"] = "threshold", ["rule_id"] = rule,
            ["rule_version"] = 1, ["rule_sha256"] = D.Hash(definition), ["scope"] = scope.Document };
    }

    internal static JsonObject PolicyDefinition(PasswordScope scope, string rule, PasswordThresholdPolicy policy)
    {
        string prefix = "security.problems.presentation." + (rule == Spray ? "spray" : "brute");
        return new() { ["type"] = "scenario_policy", ["source_selector"] = new JsonObject { ["rule_id"] = rule, ["execution"] = Execution(scope, rule, policy) },
            ["scenario_kind"] = rule, ["result_class"] = "security_incident", ["merge_window_seconds"] = QuietSeconds,
            ["title"] = DetectionMessages.Text(prefix + "_title", english: true), ["explanation"] = DetectionMessages.Text(prefix + "_threshold_what", english: true),
            ["risk"] = new JsonObject { ["class"] = "high", ["raw_score"] = "60", ["display_points"] = 60, ["rationale"] = DetectionMessages.Text(prefix + "_threshold_what", english: true) } };
    }

    private sealed record Event(DetectionRow Row, string Account, string Name, long DomainId, string ReportedDomain,
        string? Address, bool New, int Replaced = 0)
    {
        internal long Id => long.Parse(Row.Ref.NativeId, CultureInfo.InvariantCulture);
        internal bool Success => Row.EventId == 4624;
        internal long Second => Row.At.ToUnixTimeSeconds();
    }

    private static string Clean(string value) => value.Length <= 256 &&
        !value.Any(c => char.IsControl(c) || char.GetUnicodeCategory(c) == UnicodeCategory.Format) ? value.Trim() : "";

    private static string? Client(string value)
    {
        if (!PasswordNative.StrictIp(value, out var address, out _)) return null;
        if (address!.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        return IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)
            ? null : PasswordNative.CanonicalAddress(address);
    }

    private static Event? Normalize(DetectionRow row, long cursor)
    {
        string name = Clean(row.Get("TargetUserName"));
        if (name is "" or "-") return null;
        long domain = D.Number(row.Fields?["domain_id"]) ?? 0;
        string account = domain.ToString(CultureInfo.InvariantCulture) + '\0' + UnicodeCaseFold.Fold(name);
        return new(row, account, name, domain, Clean(row.Get("TargetDomainName")), Client(row.Get("IpAddress")),
            long.Parse(row.Ref.NativeId, CultureInfo.InvariantCulture) > cursor);
    }

    internal static string? ScenarioPartition(string rule, JsonObject facts) =>
        rule == Brute && D.Number(facts["domain_id"]) is > 0 and var domain
            ? "password-domain:" + domain.ToString(CultureInfo.InvariantCulture) : null;

    // State belongs to the existing identity-attack episode. Evidence is taken
    // from this pass and merged into the finding's bounded set at publication.
    internal sealed record Episode(string Key, DateTimeOffset First, DateTimeOffset LastFailure, DateTimeOffset Last,
        long Attempts, bool Successful, JsonObject Facts)
    {
        internal DateTimeOffset? ClosedAt { get; init; }
        internal static Episode Read(string key, JsonObject facts) => new(key, D.Time(facts["first"]),
            D.Time(facts["last_failure"]), D.Time(facts["last"]), facts["attempts"]!.GetValue<long>(),
            facts["password_success"]!.GetValue<bool>(), facts);
    }

    internal static IEnumerable<JsonObject> Evaluate(PasswordScope scope, string rule, PasswordThresholdPolicy policy,
        IReadOnlyList<DetectionRow> rows, long cursor, IReadOnlyDictionary<string, Episode> active, DateTimeOffset now)
    {
        bool spray = rule == Spray;
        var events = rows.Select(row => Normalize(row, cursor)).OfType<Event>();
        if (spray) events = events.Where(e => e.Address is not null && e.Row.EventId is 4624 or 4625);
        else events = BruteEvents(events.Where(e => e.DomainId > 0 && !e.Name.EndsWith('$')), policy.WindowSeconds);
        foreach (var group in events.GroupBy(e => spray ? e.Address! : e.Account))
        {
            if (!group.Any(e => e.New)) continue;
            string entity = spray ? D.Hash(JsonValue.Create(group.Key)) :
                SemanticProposal.HashText(group.Key);
            active.TryGetValue(entity, out var episode);
            var closedAt = episode?.ClosedAt;
            if (closedAt.HasValue) episode = null;
            Episode? previousBurst = null;
            var window = new Queue<Event>();
            var reportedDomains = new List<string>(20);
            var accounts = new Dictionary<string, int>(StringComparer.Ordinal);
            var firstRefs = new List<Event>(10);
            var recentRefs = new Queue<Event>(40);
            Event[] dimensions = [];
            Event? last = null;
            int fresh = 0, primary = 0;
            bool changed = false;
            var span = TimeSpan.FromSeconds(policy.WindowSeconds);
            var quiet = TimeSpan.FromSeconds(QuietSeconds);
            IEnumerable<Event> Counted() => !spray && primary > 0 ? window.Where(e => e.Row.EventId == 4625) : window;
            Event[] CurrentDimensions() => Dimensions(Counted().Where(e => e.Row.At >= episode!.First), spray);

            void Keep(Event e)
            {
                if (reportedDomains.Count < 20 && e.ReportedDomain is not ("" or "-") && !reportedDomains.Contains(e.ReportedDomain))
                    reportedDomains.Add(e.ReportedDomain);
                if (firstRefs.Count < 10) firstRefs.Add(e);
                else
                {
                    if (recentRefs.Count == 40) recentRefs.Dequeue();
                    recentRefs.Enqueue(e);
                }
            }

            JsonObject Emit()
            {
                var current = episode!;
                var facts = new JsonObject { ["version"] = 1, ["attempts"] = current.Attempts,
                    ["first"] = D.Stamp(current.First), ["last_failure"] = D.Stamp(current.LastFailure), ["last"] = D.Stamp(current.Last),
                    ["password_success"] = current.Successful };
                var priorDomains = (current.Facts["reported_domains"] as JsonArray)?.Select(D.Text)
                    .Where(value => value is not ("" or "-") && Clean(value) == value) ?? [];
                facts["reported_domains"] = D.Array(priorDomains.Concat(reportedDomains).Distinct(StringComparer.Ordinal).Take(20),
                    value => JsonValue.Create(value));
                if (!spray) facts["domain_id"] = last!.DomainId;
                // A success can arrive after the final counts were already published.
                if (dimensions.Length == 0 && current.Facts.Count > 0)
                {
                    foreach (string key in new[] { "account", "source", "account_count", "accounts", "address_count", "addresses" })
                        if (current.Facts[key] is { } value) facts[key] = value.DeepClone();
                }
                else if (spray)
                {
                    facts["source"] = last!.Address;
                    facts["account_count"] = dimensions.Length;
                    facts["accounts"] = D.Array(dimensions.Take(20), e => JsonValue.Create(e.Name));
                }
                else
                {
                    facts["account"] = current.Facts["account"]?.DeepClone() ?? JsonValue.Create(window.LastOrDefault()?.Name ?? last!.Name);
                    var priorAddresses = (current.Facts["addresses"] as JsonArray)?.Select(D.Text) ?? [];
                    var addresses = priorAddresses.Concat(dimensions.Select(e => e.Address!)).Distinct(StringComparer.Ordinal).ToArray();
                    facts["address_count"] = Math.Max(checked((int)(D.Number(current.Facts["address_count"]) ?? 0)), addresses.Length);
                    facts["addresses"] = D.Array(addresses.Take(20), address => JsonValue.Create(address));
                }
                var context = new JsonObject { ["policy"] = policy.Document, ["facts"] = facts };
                string severity = !spray && current.Successful ? "critical" : "high";
                return DetectionSignal.Create(rule, "threshold", D.Text(Execution(scope, rule, policy)["rule_sha256"]), entity,
                    current.Key, firstRefs.Concat(recentRefs).Select(e => e.Row.Ref), current.Last, now, severity,
                    "password_threshold_context", context);
            }

            foreach (var e in group.OrderBy(e => e.Row.At).ThenBy(e => e.Id))
            {
                if (e.Row.At <= closedAt) continue;
                if (episode is not null && e.Row.At - episode.LastFailure >= quiet)
                {
                    if (changed)
                    {
                        dimensions = CurrentDimensions();
                        var signal = Emit();
                        if (!spray) episode = episode with { Facts = signal["password_threshold_context"]!["facts"]!.AsObject() };
                        yield return signal;
                    }
                    if (!spray) previousBurst = episode;
                    firstRefs.Clear(); recentRefs.Clear(); reportedDomains.Clear(); dimensions = []; episode = null; changed = false;
                }
                while (window.TryPeek(out var expired) && e.Row.At - expired.Row.At > span)
                {
                    window.Dequeue();
                    if (expired.New) fresh--;
                    if (expired.Row.EventId == 4625) primary--;
                    if (--accounts[expired.Account] == 0) accounts.Remove(expired.Account);
                }
                if (e.Success)
                {
                    if (!e.New || episode is null || episode.Successful || !accounts.ContainsKey(e.Account)) continue;
                    episode = episode with { Successful = true, Last = Max(e.Row.At, episode.Last) };
                    last = e; Keep(e); changed = true;
                    continue;
                }

                window.Enqueue(e);
                if (e.New) fresh++;
                if (e.Row.EventId == 4625) primary++;
                accounts[e.Account] = accounts.GetValueOrDefault(e.Account) + 1;
                if (episode is null)
                {
                    int count = !spray && primary > 0 ? primary : window.Count;
                    if (fresh == 0 || (spray ? accounts.Count < policy.SprayAccounts : count < policy.BruteAttempts)) continue;
                    var qualifying = Counted().ToArray();
                    if (!qualifying.Any(f => f.New)) continue;
                    var first = qualifying[0];
                    string seed = D.Hash(new JsonArray(rule, entity, first.Id, qualifying[^1].Id));
                    episode = previousBurst is { } open
                        ? open with { LastFailure = qualifying[^1].Row.At, Last = qualifying[^1].Row.At, Attempts = open.Attempts + count }
                        : new(seed, first.Row.At, qualifying[^1].Row.At, qualifying[^1].Row.At, count, false, new());
                    foreach (var failed in qualifying) Keep(failed);
                }
                else
                {
                    if (!e.New || e.Row.At < episode.First || !spray && e.Row.EventId == 4776 && primary > 0) continue;
                    episode = episode with { Attempts = episode.Attempts + (e.Replaced > 0 ? 0 : 1),
                        LastFailure = Max(e.Row.At, episode.LastFailure), Last = Max(e.Row.At, episode.Last) };
                    Keep(e);
                }
                last = e; changed = true;
            }
            if (changed)
            {
                dimensions = CurrentDimensions();
                yield return Emit();
            }
        }
    }

    private static Event[] Dimensions(IEnumerable<Event> events, bool spray) => spray
        ? events.DistinctBy(e => e.Account).ToArray()
        : events.Where(e => e.Address is not null).DistinctBy(e => e.Address).ToArray();

    private static DateTimeOffset Max(DateTimeOffset a, DateTimeOffset b) => a > b ? a : b;

    private static IEnumerable<Event> BruteEvents(IEnumerable<Event> events, int windowSeconds)
    {
        foreach (var group in events.GroupBy(e => e.Account))
        {
            var primary = group.Where(e => e.Row.EventId == 4625).ToLookup(e => e.Second);
            var olderPrimary = group.Where(e => e.Row.EventId == 4625 && !e.New).Select(e => e.Second).Distinct().Order().ToArray();
            var olderFallback = group.Where(e => e.Row.EventId == 4776 && !e.New && D.Number(e.Row.Fields?["Status"]) is long status && status != 0)
                .ToLookup(e => e.Second);
            foreach (var e in group)
            {
                if (e.Success) { yield return e; continue; }
                if (e.Row.EventId == 4776)
                {
                    if (!primary.Contains(e.Second) && D.Number(e.Row.Fields?["Status"]) is long status && status != 0) yield return e;
                    continue;
                }
                int nearest = Array.BinarySearch(olderPrimary, e.Second);
                int replaced = nearest < 0 && (~nearest == 0 || e.Second - olderPrimary[~nearest - 1] > windowSeconds)
                    ? olderFallback[e.Second].Count() : 0;
                // New primaries can replace previously counted NTLM checks when
                // the two event types reached storage in different passes.
                var primaries = primary[e.Second];
                if (replaced > 0 && e.New && primaries.Take(replaced).Contains(e)) yield return e with { Replaced = 1 };
                else yield return e;
            }
        }
    }

    internal static JsonObject Validate(JsonObject signal)
    {
        DetectionSignal.ValidateEnvelope(signal);
        var context = signal["password_threshold_context"]!.AsObject();
        var policy = PasswordThresholdPolicy.Read(context["policy"]);
        var facts = context["facts"]!.AsObject();
        string rule = D.Text(signal["rule_id"]);
        bool spray = rule == Spray, success = facts["password_success"]!.GetValue<bool>();
        string severity = !spray && success ? "critical" : "high";
        var refs = signal["evidence_refs"]!.AsArray().Select(DetectionRef.Read).ToArray();
        var scope = refs[0].Scope;
        long attempts = facts["attempts"]!.GetValue<long>();
        string subject = D.Text(facts[spray ? "source" : "account"]);
        var names = facts[spray ? "accounts" : "addresses"]!.AsArray();
        int total = facts[spray ? "account_count" : "address_count"]!.GetValue<int>();
        var reported = facts["reported_domains"] as JsonArray;
        long? domain = D.Number(facts["domain_id"]);
        bool legacy = facts.Count == 9 && reported is null && domain is null;
        bool newFacts = reported is { Count: <= 20 } && reported.All(value => D.Text(value) is { Length: > 0 } text && Clean(text) == text) &&
            (spray ? facts.Count == 10 && domain is null : facts.Count == 11 && domain > 0 &&
                SemanticProposal.HashText(domain.Value.ToString(CultureInfo.InvariantCulture) + '\0' + UnicodeCaseFold.Fold(subject)) ==
                D.Text(signal["entity_key"]));
        D.Require(context.Count == 2 && (legacy || newFacts) && facts["version"]!.GetValue<int>() == 1 &&
            JsonNode.DeepEquals(DetectionSignal.Execution(signal), Execution(scope, rule, policy)) &&
            scope.PluginId == "sli.windows.ad-dc" && scope.CollectionScopeId == "" && refs.Length <= 50 && refs.All(r => r.Kind == "core_event") &&
            attempts >= (spray ? policy.SprayAccounts : policy.BruteAttempts) && names.Count == Math.Min(total, 20) &&
            total >= 0 && total <= attempts && names.All(n => Clean(D.Text(n)) is { Length: > 0 }) && subject.Length > 0 && Clean(subject) == subject &&
            (!spray || Client(subject) == subject && D.Hash(JsonValue.Create(subject)) == D.Text(signal["entity_key"])) &&
            D.Time(facts["first"]) <= D.Time(facts["last_failure"]) && D.Time(facts["last_failure"]) <= D.Time(facts["last"]) &&
            D.Time(facts["last"]) == D.Time(signal["occurred_at_utc"]) && D.Text(signal["base_severity"]) == severity &&
            D.Text(signal["effective_severity"]) == severity && D.Text(signal["quality"]) == "good", "password_threshold_signal_invalid");
        return facts;
    }
}
