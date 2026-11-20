using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Radius;

namespace Sli.Server.Vpn;

public sealed class RadiusReconciliationException(string code) : Exception(code);

// Maintenance-only control: the caller owns the outer PostgreSQL transaction.
// No acquisition, queue leasing, source contact or runtime activation occurs here.
public sealed partial class RadiusReconciliationControl(
    Func<string, object?[], Task<List<JsonObject>>> query, string repositoryRoot, string evidenceRoot,
    Action<string>? progress = null)
{
    public const string Stream = "radius-accounting";
    public const string Transport = "windows-rpc-smb-readonly-tail-v1";
    public const string Resolver = "sli.radius-session-reconciliation-production.v1";
    public const string Confirmation = "APPLY-STAGE10-RADIUS-SESSION-RECONCILIATION";
    internal static readonly Dictionary<int, string> MigrationNames = new()
    {
        [61]="radius_session_consumer_projection", [62]="vpn_session_report_read_boundary",
        [63]="radius_vpn_operations_read_boundary", [64]="vpn_session_canonical_identity_read_boundary",
        [65]="radius_session_reconciliation_overlay", [80]="radius_session_reconciliation_projection"
    };
    internal static readonly string[] BaselineKeys = ["source_instance_sha256", "cursor_revision", "observations",
        "terminal_unresolved_receipts", "nonterminal_deliveries", "attempts_table", "overlays_table", "writer_role",
        "migration_role_can_create_role", "attempt_count", "overlay_count"];
    internal sealed record Scope(string Source, string Organization, string Subscription)
    { public object?[] Binding => [Source, Stream, Transport]; }
    internal sealed record Batch(JsonObject Summary, JsonArray Attempts, Dictionary<string, JsonObject> Proposals);
    static RadiusReconciliationException Error(string suffix) => new("production_reconciliation_" + suffix);
    internal static string Hash(string value) => Hash(Encoding.UTF8.GetBytes(value));
    internal static string Hash(byte[] value) => Convert.ToHexStringLower(SHA256.HashData(value));
    internal static string Digest(JsonNode? value) => Hash(CanonicalJson.Serialize(value));
    internal static string Text(JsonObject row, string key) => row[key]?.GetValue<string>() ?? "";
    internal static long Number(JsonObject row, string key) => row[key] is {} value ? long.Parse(value.ToString(),CultureInfo.InvariantCulture) : 0;
    internal static bool Flag(JsonObject row, string key) => row[key]?.GetValue<bool>() == true;
    Task<List<JsonObject>> Query(string sql, params object?[] args) => query(sql, args);
    string MigrationPath(int version, bool rollback = false) => Path.Combine(repositoryRoot, "config", "postgres_migrations",
        $"{version:000}_{MigrationNames[version]}{(rollback ? ".rollback" : "")}.sql");
    JsonObject MigrationHashes() => new(MigrationNames.Where(x => x.Key != 61)
        .Select(x => KeyValuePair.Create<string, JsonNode?>(x.Key.ToString(CultureInfo.InvariantCulture), JsonValue.Create(Hash(File.ReadAllBytes(MigrationPath(x.Key)))))));

    internal static Dictionary<int, bool> Markers(IEnumerable<JsonObject> rows)
    {
        var result = MigrationNames.Keys.ToDictionary(v => v, _ => false);
        foreach (var row in rows)
        {
            int version = checked((int)Number(row, "version"));
            if (!MigrationNames.TryGetValue(version, out var expected)) continue;
            if (Text(row, "name") != expected) throw Error("migration_version_conflict");
            result[version] = true;
        }
        return result;
    }
    internal static string MigrationState(IReadOnlyDictionary<int, bool> markers, JsonObject baseline)
    {
        int[] core = [62, 63, 64, 65];
        var applied = core.Where(v => markers[v]).ToArray();
        bool present = new[] { "attempts_table", "overlays_table", "writer_role" }.All(k => Flag(baseline, k));
        bool absent = new[] { "attempts_table", "overlays_table", "writer_role" }.All(k => !Flag(baseline, k));
        if (!applied.SequenceEqual(core.Take(applied.Length)) || markers[65] != present ||
            (!markers[65] && !absent) || (markers[80] && !markers[65])) return "inconsistent";
        return markers[80] ? "applied" : "resumable";
    }
    internal static string[] AuthorizedBlockers(IEnumerable<JsonObject> values)
    {
        var batches = values.ToArray();
        if (!batches.Select(b => Number(b, "terminal_receipt_count")).SequenceEqual(new long[] {17, 50, 16}))
            return ["production_reconciliation_batch_scope_invalid"];
        if (batches.Any(b => Number(b, "projected_count") < 0 || Number(b, "still_unresolved_count") < 0 ||
            Number(b, "projected_count") + Number(b, "still_unresolved_count") != Number(b, "terminal_receipt_count")))
            return ["production_reconciliation_partial_count_invalid"];
        return batches.Any(b => Number(b, "projected_count") > 0) ? [] : ["production_reconciliation_no_exact_projection"];
    }
    public static void ValidatePlanBinding(JsonObject plan, JsonObject current)
    {
        if (Number(plan, "plan_schema_version") != 1 || plan["baseline"] is not JsonObject baseline ||
            !baseline.Select(x => x.Key).ToHashSet().SetEquals(BaselineKeys) || !JsonNode.DeepEquals(baseline, current))
            throw new RadiusReconciliationException("production_apply_without_plan_binding");
    }
    internal static string PlanIdentity(JsonObject plan)
    { var copy = (JsonObject)plan.DeepClone(); copy.Remove("plan_identity_sha256"); return Digest(copy); }
    internal static void ValidatePlan(JsonObject plan, JsonObject fresh)
    {
        ValidatePlanBinding(plan, fresh["baseline"]!.AsObject());
        if (Text(plan, "status") != "ready" || PlanIdentity(plan) != Text(plan, "plan_identity_sha256") ||
            Text(fresh, "plan_identity_sha256") != Text(plan, "plan_identity_sha256"))
            throw new RadiusReconciliationException("production_apply_without_plan_binding");
    }
    internal static void ValidateLockedBaseline(JsonObject planned, JsonObject current)
    {
        foreach (string key in BaselineKeys)
            if (!JsonNode.DeepEquals(planned[key], current[key])) throw Error("plan_input_drift");
    }
    internal static string MigrationBody(string source)
    {
        var lines = source.Replace("\r\n", "\n").Split('\n');
        var code = Enumerable.Range(0, lines.Length).Where(i => lines[i].Trim().Length > 0 && !lines[i].TrimStart().StartsWith("--", StringComparison.Ordinal)).ToArray();
        if (code.Length < 2 || !lines[code[0]].Trim().Equals("begin;", StringComparison.OrdinalIgnoreCase) ||
            !lines[code[^1]].Trim().Equals("commit;", StringComparison.OrdinalIgnoreCase)) throw Error("migration_transaction_boundary_invalid");
        return string.Join('\n', lines.Where((_, i) => i != code[0] && i != code[^1]));
    }
    internal async Task<int[]> ApplyMigrationsAsync(Dictionary<int, bool> markers, JsonObject baseline)
    {
        if (MigrationState(markers, baseline) == "inconsistent") throw Error("migration_state_inconsistent");
        var applied = new List<int>();
        foreach (int version in MigrationNames.Keys.Where(v => v != 61 && !markers[v]))
        {
            await Query(MigrationBody(File.ReadAllText(MigrationPath(version))));
            await Query("reset role");
            applied.Add(version);
        }
        return applied.ToArray();
    }
    public JsonObject ValidateDisposableAcceptance(string path)
    {
        if (!File.Exists(path)) throw Error("disposable_acceptance_required");
        try
        {
            byte[] bytes = File.ReadAllBytes(path);
            var value = JsonNode.Parse(bytes)!.AsObject();
            var acceptance = value["acceptance"]!.AsObject();
            string[] safety = ["original_rows_unchanged", "writer_role_restricted_nologin", "original_observation_update_denied",
                "terminal_receipt_update_denied", "evidence_delete_denied", "append_only_output_update_denied", "consumer_overlay_update_denied",
                "outer_transaction_postcondition_readable", "conflicting_second_resolution_blocked", "reader_rollback_guarded_after_evidence", "rollback_guarded_after_evidence"];
            bool valid = Text(value, "status") == "passed" && safety.All(k => Flag(acceptance, k)) &&
                new[] {"production_database_changed", "radius_source_contacted", "runtime_enabled", "autostart_enabled"}.All(k => value[k]?.GetValue<bool>() == false) &&
                Flag(value, "disposable_cluster_removed") && Number(value["database"]!.AsObject(), "server_version_num") / 10000 == 18 &&
                JsonNode.DeepEquals(acceptance["attempt_counts_total_projected_unresolved"], new JsonArray(2, 1, 1)) && Number(acceptance, "projected_session_count") == 1;
            foreach (var (key, version, rollback) in new[] {("forward_sha256",65,false),("rollback_sha256",65,true),
                ("projection_forward_sha256",80,false),("projection_rollback_sha256",80,true)})
                valid &= Text(value, key) == Hash(File.ReadAllBytes(MigrationPath(version, rollback)));
            if (!valid) throw Error("disposable_acceptance_invalid");
            return new JsonObject { ["evidence_sha256"] = Hash(bytes) };
        }
        catch (Exception e) when (e is System.Text.Json.JsonException or InvalidOperationException or NullReferenceException or IOException or FormatException)
        { throw Error("disposable_acceptance_invalid"); }
    }
    async Task<(Scope Scope, JsonObject Baseline, Dictionary<int, bool> Markers)> ReadBaselineAsync(bool locked)
    {
        var sources = await Query(RadiusReconciliationSql.Sources);
        if (sources.Count != 1) throw Error("exact_radius_source_required");
        string source = Text(sources[0], "source_instance_id");
        var subscriptions = await Query(RadiusReconciliationSql.Subscriptions, source, Stream, Transport);
        if (subscriptions.Count != 1) throw Error("exact_subscription_required");
        string subscription = Text(subscriptions[0], "subscription_id");
        var consumer = JsonNode.Parse(File.ReadAllText(Path.Combine(repositoryRoot, "config", "stage9_radius_session_consumer_v1.json")))!.AsObject();
        if (subscription != Text(consumer, "subscription_id")) throw Error("consumer_binding_required");
        var scope = new Scope(source, Text(sources[0], "organization_scope"), subscription);
        var baseline = await ReadScopedBaselineAsync(scope, locked);
        var markers = Markers(await Query(RadiusReconciliationSql.Markers));
        if (!markers[61]) throw Error("migration_061_required");
        return (scope, baseline, markers);
    }
    async Task<JsonObject> ReadScopedBaselineAsync(Scope scope, bool locked)
    {
        var cursor = await Query(locked ? RadiusReconciliationSql.LockedCursor : RadiusReconciliationSql.Cursor, scope.Binding);
        if (cursor.Count != 1) throw Error("plan_input_drift");
        var row = (await Query(locked ? RadiusReconciliationSql.LockedBaseline : RadiusReconciliationSql.Baseline,
            [..scope.Binding, ..scope.Binding, scope.Subscription])).Single();
        row["source_instance_sha256"] = Hash(scope.Source);
        row["cursor_revision"] = cursor[0]["revision"]!.DeepClone();
        row["attempt_count"] = 0L; row["overlay_count"] = 0L;
        return row;
    }
    async Task ReadOutputCountsAsync(Scope scope, JsonObject row)
    {
        if (Flag(row,"attempts_table") && Flag(row,"overlays_table"))
            foreach (var (key,value) in (await Query(RadiusReconciliationSql.OutputCounts, [..scope.Binding, ..scope.Binding])).Single())
                row[key] = value?.DeepClone();
    }
    internal static JsonObject Reconciliation(IReadOnlyList<Batch> batches, JsonObject discovery) => new()
    {
        ["resolver_contract_id"]=Resolver, ["batches"]=new JsonArray(batches.Select(b => (JsonNode)b.Summary.DeepClone()).ToArray()),
        ["terminal_receipt_count"]=batches.Sum(b => Number(b.Summary,"terminal_receipt_count")),
        ["terminal_candidate_count"]=batches.Sum(b => Number(b.Summary,"terminal_receipt_count")),
        ["projected_count"]=batches.Sum(b => Number(b.Summary,"projected_count")),
        ["still_unresolved_count"]=batches.Sum(b => Number(b.Summary,"still_unresolved_count")),
        ["unsupported_inferred_links"]=0, ["identity_evidence_discovery"]=discovery.DeepClone()
    };
    public async Task<JsonObject> BuildPlanAsync(string disposableAcceptance)
    {
        var acceptance = ValidateDisposableAcceptance(disposableAcceptance);
        var (scope, baseline, markers) = await ReadBaselineAsync(false);
        await ReadOutputCountsAsync(scope, baseline);
        var (batches, discovery) = await BuildBatchesAsync(scope);
        return BuildPlan(baseline, markers, batches, discovery, acceptance, MigrationHashes());
    }
    internal static JsonObject BuildPlan(JsonObject baseline, Dictionary<int,bool> markers, IReadOnlyList<Batch> batches,
        JsonObject discovery, JsonObject acceptance, JsonObject migrationHashes)
    {
        var blockers = new List<string>();
        string state = MigrationState(markers, baseline);
        if (state == "inconsistent") blockers.Add("production_reconciliation_migration_state_inconsistent");
        if (!markers[65] && !Flag(baseline,"migration_role_can_create_role")) blockers.Add("production_reconciliation_migration_role_create_role_required");
        blockers.AddRange(AuthorizedBlockers(batches.Select(b => b.Summary)));
        if (Number(baseline,"nonterminal_deliveries") != 0) blockers.Add("production_reconciliation_nonterminal_delivery_present");
        if (Number(baseline,"attempt_count") != 0 || Number(baseline,"overlay_count") != 0) blockers.Add("production_reconciliation_existing_output_present");
        if (Number(baseline,"terminal_unresolved_receipts") != batches.Sum(b => Number(b.Summary,"terminal_receipt_count"))) blockers.Add("production_reconciliation_terminal_receipt_count_mismatch");
        var plan = new JsonObject { ["plan_schema_version"]=1, ["status"]=blockers.Count==0?"ready":"blocked", ["baseline"]=baseline.DeepClone(),
            ["migration_state"]=state, ["migration_sha256"]=migrationHashes.DeepClone(), ["disposable_acceptance"]=acceptance.DeepClone(),
            ["reconciliation"]=Reconciliation(batches,discovery), ["blockers"]=new JsonArray(blockers.Select(b => (JsonNode)JsonValue.Create(b)!).ToArray()),
            ["source_contacted"]=false, ["production_database_changed"]=false, ["cursor_changed"]=false,
            ["queue_or_lease_changed"]=false, ["runtime_enabled"]=false, ["autostart_enabled"]=false };
        plan["plan_identity_sha256"] = PlanIdentity(plan); return plan;
    }
}
