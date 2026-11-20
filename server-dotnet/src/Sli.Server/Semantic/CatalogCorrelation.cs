using System.Globalization;
using System.Text.Json.Nodes;

namespace Sli.Server.Semantic;

internal sealed record CatalogPairRule(string Source, string Stream, string OpenEventKey, string CloseEventKey,
    int OpenEventId, int CloseEventId, string[] KeyFields, int CloseTimeoutSeconds, string Rollup);

// Parity with server/sli/semantic/catalog_correlation.py. Lifecycle descriptors alone do not declare pairs.
internal static class CatalogCorrelation
{
    private static readonly HashSet<string> StorageFields = new(StringComparer.Ordinal) {
        "id", "raw_log_file_id", "server_id", "domain_id", "site_id", "log_source_id",
        "event_record_id", "event_id", "version", "level", "task", "opcode", "keywords_id",
        "provider_id", "channel_id", "computer_id", "time_created_utc", "subject_user_sid",
        "subject_user_name", "subject_domain_id", "target_user_sid", "target_user_name", "target_domain_id",
        "ip_address", "workstation_name", "logon_id", "correlation_id", "normalized_at", "normalized_hash",
        "noise_class", "noise_catalog_version", "source_core_sha256", "process_name", "process_id",
        "target_server_name", "service_name", "task_name", "task_action", "task_author", "run_as",
        "logon_type", "result_code", "object_name", "share_name", "message_sample", "powershell_user_name",
        "powershell_command_name", "powershell_script_block_text", "powershell_process_id", "account_target_sid",
        "account_target_name", "account_name_before", "account_name_after", "membership_member_sid",
        "membership_member_name", "process_parent_id", "process_command_line", "process_user_sid",
        "process_user_name", "process_user_domain", "process_logon_id", "service_file", "service_account",
        "service_start_type", "task_content", "task_change", "native_process_id", "file_audit_facts_json", "source_facts_sha256"
    };

    internal static JsonObject[] ReadEntries()
    {
        using var stream = typeof(CatalogCorrelation).Assembly.GetManifestResourceStream("Sli.Server.Semantic.Risk.event_catalog.json")!;
        return JsonNode.Parse(stream)!["entries"]!.AsArray().Select(e => e!.AsObject()).ToArray();
    }

    internal static CatalogPairRule[] Compile(IEnumerable<JsonObject>? entries = null)
    {
        var sourceEntries = (entries ?? ReadEntries()).ToArray();
        var index = new Dictionary<(string Source, string Stream, string Key), JsonObject>();
        foreach (var entry in sourceEntries) {
            var identity = Identity(entry);
            if (identity.Source.Length == 0 || identity.Stream.Length == 0 || identity.Key.Length == 0) continue;
            if (!index.TryAdd(identity, entry))
                throw new InvalidDataException($"catalog_pair_duplicate_identity:{identity.Source}/{identity.Stream}/{identity.Key}");
        }
        var rules = new List<CatalogPairRule>();
        foreach (var opener in sourceEntries) {
            if (opener["correlation"] is not JsonObject correlation || Text(correlation, "role") != "open" || Text(correlation, "cardinality") != "pair") continue;
            if (correlation["terminators"] is not JsonArray { Count: 1 } terminators)
                throw new InvalidDataException("catalog_pair_opener_requires_exactly_one_terminator");
            var identity = Identity(opener);
            string closeKey = terminators[0]?.ToString().Trim() ?? "";
            if (!index.TryGetValue((identity.Source, identity.Stream, Normalize(closeKey)), out var closer))
                throw new InvalidDataException($"catalog_pair_terminator_missing:{identity.Source}/{identity.Stream}/{closeKey}");
            if (closer["correlation"] is not JsonObject closeCorrelation)
                throw new InvalidDataException("catalog_pair_terminator_has_no_correlation");
            if (Text(closeCorrelation, "role") != "close" || Text(closeCorrelation, "cardinality") != "pair")
                throw new InvalidDataException("catalog_pair_terminator_role_mismatch");
            var keys = KeyFields(correlation);
            if (!keys.SequenceEqual(KeyFields(closeCorrelation))) throw new InvalidDataException("catalog_pair_key_mismatch");
            int timeout = Integer(correlation["close_timeout_seconds"]);
            if (timeout <= 0 || timeout != Integer(closeCorrelation["close_timeout_seconds"])) throw new InvalidDataException("catalog_pair_timeout_mismatch");
            string rollup = Text(opener["lifecycle"] as JsonObject, "rollup").Trim();
            if (rollup.Length == 0 || rollup != Text(closer["lifecycle"] as JsonObject, "rollup").Trim()) throw new InvalidDataException("catalog_pair_rollup_mismatch");
            rules.Add(new(Text(opener, "source"), Text(opener, "stream"), Text(opener, "event_key"), Text(closer, "event_key"),
                EventId(opener), EventId(closer), keys, timeout, rollup));
        }
        return rules.OrderBy(r => Normalize(r.Source), StringComparer.Ordinal).ThenBy(r => Normalize(r.Stream), StringComparer.Ordinal)
            .ThenBy(r => Normalize(r.OpenEventKey), StringComparer.Ordinal).ToArray();
    }

    internal static CatalogPairRule Get(string source, string stream, string openEventKey, IEnumerable<JsonObject>? entries = null)
    {
        var matches = Compile(entries).Where(r => Normalize(r.Source) == Normalize(source) && Normalize(r.Stream) == Normalize(stream) && Normalize(r.OpenEventKey) == Normalize(openEventKey)).ToArray();
        if (matches.Length != 1) throw new InvalidDataException($"catalog_pair_rule_not_unique:{source}/{stream}/{openEventKey}");
        return matches[0];
    }

    private static (string Source, string Stream, string Key) Identity(JsonObject entry) =>
        (Normalize(Text(entry, "source")), Normalize(Text(entry, "stream")), Normalize(Text(entry, "event_key")));
    private static string Normalize(string value) => value.Trim().ToLowerInvariant();
    private static string Text(JsonObject? entry, string key) => entry?[key]?.ToString() ?? "";
    private static int Integer(JsonNode? value) => int.TryParse(value?.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int number) ? number : 0;
    private static int EventId(JsonObject entry) => Integer(entry["event_id"]) is > 0 and var id ? id : throw new InvalidDataException("catalog_pair_event_id_must_be_numeric");
    private static string[] KeyFields(JsonObject correlation)
    {
        var raw = correlation["key"];
        var fields = (raw is JsonArray array ? array.AsEnumerable() : new[] { raw }).Select(v => v?.ToString().Trim() ?? "").ToArray();
        if (fields.Length == 0 || fields.Any(f => !StorageFields.Contains(f))) throw new InvalidDataException("catalog_pair_key_not_in_storage_v2");
        return fields;
    }
}
