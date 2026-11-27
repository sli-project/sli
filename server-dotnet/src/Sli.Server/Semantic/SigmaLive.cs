using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Agent.Protocol;
using Sli.Server.Storage.Direct;

namespace Sli.Server.Semantic;

internal sealed partial class SemanticProduction
{
    internal const string SigmaStarterPrefix = "default:sigma:";
    internal const int SigmaHourlyMatchLimit = 20;
    private const string SigmaLiveLock = "select pg_advisory_xact_lock(hashtext('sli_sigma_live433_worker'))";

    internal static async Task<JsonObject> ProcessSigma(NpgsqlConnection db, CancellationToken ct)
    {
        await using var tx = await db.BeginTransactionAsync(ct);
        var session = new SemanticSession(db, tx);
        await session.QueryAsync(SigmaLiveLock, ct);
        var rules = new List<(SigmaRule Rule, JsonNode Revision)>();
        int events = 0, rejected = 0, jobs = 0;
        if (await SigmaPluginRunning(session, ct))
        {
            var now = SigmaProjection.At((await session.QueryAsync("select clock_timestamp() as time", ct)).Single()!, "time");
            var hour = new DateTimeOffset(now.Year, now.Month, now.Day, now.Hour, 0, 0, TimeSpan.Zero);
            foreach (var revision in await session.QueryAsync("select * from public.sigma_starter433() where enabled", ct))
            {
                var rule = SigmaRule.Compile(revision.Text("raw_yaml")!, revision.Text("license"), revision.Text("source_uri")!);
                if (rule.Id != revision.Text("rule_id") || rule.Sha != revision.Text("raw_sha256"))
                    throw new InvalidDataException("sigma_starter_revision_mismatch");
                rules.Add((rule, revision!));
            }
            jobs += await PublishDeferredSigma(session, hour, ct);
            var page = await session.QueryAsync("select * from public.read_admitted_sigma_events($1)", ct, 64);
            foreach (var row in page.OfType<JsonObject>())
            {
                var observed = ReadSigmaEvent(row);
                if (observed is null) rejected++;
                else
                {
                    foreach (var (rule, revision) in rules)
                    {
                        if (SigmaProjection.At(row, "collected_at") < SigmaProjection.At(revision, "enabled_at")
                            || !SigmaLogSourceMatches(rule, observed)
                            || rule.Match(observed.Fields, observed.Unavailable) != "matched") continue;
                        jobs += await RecordSigmaHit(session, row, observed, rule, revision.Text("manifest_sha256")!, hour, ct);
                    }
                }
                await session.QueryAsync("delete from public.sigma_live_inbox433 where event_id=$1 and occurred_at=$2", ct,
                    row.Number("source_event_id"), SigmaProjection.At(row, "occurred_at"));
            }
            events = page.Count;
            if (events > 0)
                await session.QueryAsync("""
                    update public.sigma_live_position433 set last_event_id=greatest(last_event_id,$1),
                        processed=processed+$2,rejected=rejected+$3 where singleton
                    """, ct, page.Max(row => row.Number("source_event_id")), events, rejected);
        }
        // Inactive sources and expired evidence must not leave an unbounded queue.
        await session.QueryAsync("""
            delete from public.sigma_live_inbox433 where (event_id,occurred_at) in
                (select event_id,occurred_at from public.sigma_live_inbox433
                 where collected_at<transaction_timestamp()-interval '24 hours' order by collected_at limit 512)
            """, ct);
        await session.QueryAsync("""
            delete from public.sigma_live_hits433 where (rule_id,event_id,occurred_at) in
                (select rule_id,event_id,occurred_at from public.sigma_live_hits433
                 where occurred_at<transaction_timestamp()-interval '24 hours'
                   and hour<transaction_timestamp()-interval '2 hours' and document is null
                 order by occurred_at limit 512)
            """, ct);
        await tx.CommitAsync(ct);
        return new JsonObject { ["policies"] = rules.Count, ["events"] = events, ["rejected"] = rejected, ["jobs"] = jobs,
            ["failed"] = 0, ["last_data_at"] = events > 0 ? SemanticJson.Stamp(DateTimeOffset.UtcNow) : null };
    }

    private static async Task<bool> SigmaPluginRunning(ISemanticSession session, CancellationToken ct)
    {
        var rows = await session.QueryAsync("select * from public.read_sigma_chain_plugin_states_v1()", ct);
        return rows.Any(row => row.Text("plugin_id") == "sli.sigma" && row.Flag("installed")
            && row.Flag("configured") && row.Flag("enabled") && row.Text("component_runtime") == "running");
    }

    private static bool SigmaLogSourceMatches(SigmaRule rule, SigmaEvent observed) => rule.LogSource switch
    {
        "security" => observed.Channel == "Security",
        "system" => observed.Channel == "System",
        "ps_script" => observed.Channel == "Microsoft-Windows-PowerShell/Operational" && observed.Id == 4104,
        _ => false
    };

    private static SigmaEvent? ReadSigmaEvent(JsonObject row)
    {
        if (row.Text("representation") is not { } raw || row["representation_sha256"] is null) return null;
        try
        {
            var representation = JsonNode.Parse(raw)!.AsObject();
            if (DirectEventIdentityStore.RepresentationDigest(representation) != row.Text("representation_sha256")
                || representation.Text("xml") is not { } xml) return null;
            var observed = SigmaEvent.Map(xml);
            var at = SigmaProjection.At(row, "occurred_at");
            if (observed.Id != row.Number("kind") || observed.Channel != row.Text("channel")
                || observed.Fields.Text("Provider_Name") != row.Text("provider")
                || !observed.Fields["EventRecordID"]!.AsValue().TryGetValue<ulong>(out ulong recordId)
                || row.Number("record_id") <= 0 || recordId != (ulong)row.Number("record_id")
                || observed.Computer != representation.Text("machine_name")
                || DirectEventTime.Utc(observed.Fields.Text("TimeCreated")!) != at.UtcDateTime) return null;
            return observed with { At = at };
        }
        catch (Exception error) when (error is JsonException or InvalidDataException or InvalidOperationException or ArgumentException)
        {
            return null;
        }
    }

    private static async Task<int> RecordSigmaHit(ISemanticSession session, JsonObject row, SigmaEvent observed,
        SigmaRule rule, string manifestSha, DateTimeOffset hour, CancellationToken ct)
    {
        var scope = row["scope"]!;
        string scopeKey = Password.PasswordJson.Hash(new JsonArray(scope.Copy(), row["domain_id"].Copy()));
        string? host = SigmaLabel(observed.Computer);
        string? account = observed.Id switch
        {
            4624 or 4720 or 4781 => SigmaAccount(observed.Fields, "Target") ?? SigmaAccount(observed.Fields, "Subject"),
            4732 => SigmaLabel(observed.Fields.Text("MemberName")) ?? SigmaLabel(observed.Fields.Text("MemberSid")),
            7045 => SigmaLabel(observed.Fields.Text("AccountName")),
            4104 => SigmaLabel(observed.Fields.Text("UserID")),
            _ => SigmaAccount(observed.Fields, "Subject")
        };
        string entity = Password.PasswordJson.Hash(new JsonArray("sigma-starter", scopeKey,
            host?.ToUpperInvariant(), account?.ToUpperInvariant()));
        var reference = new JsonObject { ["storage_kind"] = "core_event",
            ["native_id"] = row.Number("source_event_id").ToString(CultureInfo.InvariantCulture),
            ["sha256"] = row["sha256"].Copy(), ["scope"] = scope.Copy() };
        var document = new JsonObject { ["rule_id"] = rule.Id, ["rule_sha256"] = rule.Sha,
            ["manifest_sha256"] = manifestSha, ["compiler_version"] = SigmaRule.CompilerVersion,
            ["mapping_version"] = SigmaRule.MappingVersion,
            ["overlay_sha256"] = Password.PasswordJson.Hash(new JsonObject()), ["evidence"] = reference,
            ["entity_key"] = entity, ["occurred_at_utc"] = SemanticJson.Stamp(observed.At),
            ["evaluation_mode"] = "enabled", ["conclusion_state"] = "observed", ["quality"] = "good", ["suppressed"] = false,
            ["sigma_starter"] = new JsonObject { ["computer"] = host, ["account"] = account,
                ["collected_at"] = row["collected_at"].Copy() } };
        Guid ruleId = Guid.Parse(rule.Id);
        var hit = await session.QueryAsync("""
            insert into public.sigma_live_hits433(rule_id,event_id,occurred_at,scope_key,hour,entity_key)
            values($1,$2,$3,$4,$5,$6) on conflict do nothing returning event_id
            """, ct, ruleId, row.Number("source_event_id"), observed.At, scopeKey, hour, entity);
        if (hit.Count == 0) return 0;
        long count = (await session.QueryAsync("""
            select count(*) as total from (select 1 from public.sigma_live_hits433
                where rule_id=$1 and scope_key=$2 and hour=$3 limit $4) hits
            """, ct, ruleId, scopeKey, hour, SigmaHourlyMatchLimit + 1)).Single().Number("total");
        if (count == 1)
        {
            await session.QueryAsync("""
                update public.sigma_live_hits433 set representative=true where rule_id=$1 and event_id=$2 and occurred_at=$3
                """, ct, ruleId, row.Number("source_event_id"), observed.At);
            return await PublishSigmaHit(session, document, ct);
        }

        // The first representative is immediate. Other subjects are held until
        // the hour closes so a high-volume rule produces only one problem.
        string leader = (await session.QueryAsync("""
            select entity_key from public.sigma_live_hits433 where rule_id=$1 and scope_key=$2 and hour=$3 and representative
            """, ct, ruleId, scopeKey, hour)).Single().Text("entity_key")!;
        if (count > SigmaHourlyMatchLimit)
        {
            var cleared = await session.QueryAsync("""
                update public.sigma_live_hits433 set document=null
                where rule_id=$1 and scope_key=$2 and hour=$3 and document is not null returning event_id
                """, ct, ruleId, scopeKey, hour);
            await AddSigmaRepeats(session, ruleId, leader, 1 + cleared.Count, ct);
        }
        else if (entity == leader)
            await AddSigmaRepeats(session, ruleId, leader, 1, ct);
        else
            await session.QueryAsync("""
                update public.sigma_live_hits433 set document=$1
                where rule_id=$2 and event_id=$3 and occurred_at=$4
                """, ct, document, ruleId, row.Number("source_event_id"), observed.At);
        return 0;
    }

    private static async Task AddSigmaRepeats(ISemanticSession session, Guid rule, string entity, int count, CancellationToken ct)
    {
        await session.QueryAsync("""
            select public.apply_sigma_repeats433(match_id,$3)
                from public.sigma_live_subjects433 where rule_id=$1 and entity_key=$2
            """, ct, rule, entity, count);
    }

    private static async Task<int> PublishDeferredSigma(ISemanticSession session, DateTimeOffset hour, CancellationToken ct)
    {
        var rows = await session.QueryAsync("""
            select rule_id,event_id,occurred_at,document from public.sigma_live_hits433
            where hour<$1 and document is not null order by hour,rule_id,event_id limit 64
            """, ct, hour);
        int jobs = 0;
        foreach (var row in rows)
        {
            var document = row!["document"]!.AsObject();
            var reference = document["evidence"]!;
            var scope = reference["scope"]!;
            var resolution = (await session.QueryAsync("""
                select public.resolve_finding_evidence_ref($1,$2,$3,$4,$5,$6,$7,$8) as allowed
                """, ct, Guid.Parse(scope.Text("installation_id")!), scope.Text("plugin_id"), scope.Text("source_instance_id"),
                scope.Text("source_generation"), scope.Text("collection_scope_id"), reference.Text("storage_kind"),
                reference.Text("native_id"), reference.Text("sha256"))).Single();
            if (resolution.Flag("allowed")) jobs += await PublishSigmaHit(session, document, ct);
            await session.QueryAsync("""
                update public.sigma_live_hits433 set document=null where rule_id=$1 and event_id=$2 and occurred_at=$3
                """, ct, Guid.Parse(row.Text("rule_id")!), row.Number("event_id"), SigmaProjection.At(row, "occurred_at"));
        }
        return jobs;
    }

    private static async Task<int> PublishSigmaHit(ISemanticSession session, JsonObject document, CancellationToken ct)
    {
        string rule = document.Text("rule_id")!, entity = document.Text("entity_key")!;
        var ruleId = Guid.Parse(rule);
        var subject = (await session.QueryAsync("""
            select match_id from public.sigma_live_subjects433 where rule_id=$1 and entity_key=$2
            """, ct, ruleId, entity)).SingleOrDefault();
        if (subject.Text("match_id") is { } representative)
        {
            await session.QueryAsync("select public.apply_sigma_repeats433($1,1)", ct, representative);
            return 0;
        }
        var revision = (await session.QueryAsync("""
            select title,level,author,license,source_uri from public.sigma_starter433() where rule_id=$1 and enabled
            """, ct, ruleId)).SingleOrDefault();
        if (revision is null) return 0;
        var reference = document["evidence"]!;
        var scope = reference["scope"]!;
        var execution = NativeExecution(document, "detection_match");
        string policyId = SigmaStarterPrefix + rule + ":" + Password.PasswordJson.Hash(execution);
        string severity = revision.Text("level") == "informational" ? "info" : revision.Text("level")!;
        int points = severity switch { "critical" => 80, "high" => 60, "medium" => 25, "low" => 10, _ => 0 };
        string credit = $"SigmaHQ: {revision.Text("author")} ({revision.Text("license")}). {revision.Text("source_uri")}";
        var definition = new JsonObject { ["type"] = "scenario_policy", ["scenario_kind"] = "sigma." + rule,
            ["result_class"] = "security_incident", ["merge_window_seconds"] = 3600,
            ["title"] = revision.Text("title"), ["explanation"] = credit,
            ["source_selector"] = new JsonObject { ["rule_id"] = rule, ["execution"] = execution },
            ["risk"] = new JsonObject { ["class"] = severity, ["raw_score"] = points, ["display_points"] = points, ["rationale"] = credit } };
        string policy = CanonicalJson.Serialize(definition, ensureAscii: false);
        if (!(await session.QueryAsync("select public.ensure_sigma_starter_policy433($1,$2) as allowed", ct,
                policyId, policy)).Single().Flag("allowed")) return 0;
        await VerifyNative(session, new JsonArray(reference.Copy()), ct);
        string id = Password.PasswordJson.Hash(document);
        string evidenceKey = Password.PasswordJson.Hash(new JsonArray(scope.Copy(), reference["storage_kind"].Copy(),
            reference["native_id"].Copy(), reference["sha256"].Copy()));
        await session.QueryAsync("""
            insert into semantic_detection_matches(match_id,rule_id,evaluation_mode,occurred_at_utc,evidence_key,document_json)
            values($1,$2,'enabled',$3,$4,$5) on conflict(match_id) do nothing
            """, ct, id, rule, SigmaProjection.At(document, "occurred_at_utc"), evidenceKey, document);
        var saved = (await session.QueryAsync("select document_json from semantic_detection_matches where match_id=$1", ct, id)).Single();
        if (!JsonNode.DeepEquals(saved?["document_json"], document)) throw new InvalidDataException("sigma_input_replay_conflict");
        await session.QueryAsync("insert into public.sigma_live_subjects433(rule_id,entity_key,match_id) values($1,$2,$3)",
            ct, ruleId, entity, id);
        return await EnqueueRiskSource(session, "detection_match", id, ct);
    }

    private static async Task<bool> CanPublishSigmaStarter(ISemanticSession session, string match, CancellationToken ct)
    {
        await session.QueryAsync(SigmaLiveLock, ct);
        var admission = (await session.QueryAsync("""
            select r.enabled and (m.document_json#>>'{sigma_starter,collected_at}')::timestamptz>=r.enabled_at as allowed
            from public.sigma_live_rules433 r join public.semantic_detection_matches m on m.rule_id=r.rule_id::text
            where m.match_id=$1
            """, ct, match)).SingleOrDefault();
        if (admission.Flag("allowed") && await SigmaPluginRunning(session, ct)) return true;
        await session.QueryAsync("delete from public.sigma_live_subjects433 where match_id=$1", ct, match);
        return false;
    }

    private static string? SigmaLabel(string? label)
    {
        var value = label?.Trim();
        return value is { Length: > 0 and <= 240 } && value != "-" && !value.Any(char.IsControl) ? value : null;
    }

    private static string? SigmaAccount(JsonObject fields, string prefix)
    {
        var user = SigmaLabel(fields.Text(prefix + "UserName"));
        var domain = SigmaLabel(fields.Text(prefix + "DomainName"));
        return user is null ? SigmaLabel(fields.Text(prefix + "UserSid")) : domain is null ? user : domain + "\\" + user;
    }
}
