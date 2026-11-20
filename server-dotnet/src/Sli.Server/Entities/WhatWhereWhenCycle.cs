using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Storage.EventReports;

namespace Sli.Server.Entities;

internal interface IWhatWhereWhenTransaction
{
    Task<JsonArray> Query(string sql, Dictionary<string, object> args, CancellationToken ct);
    Task<int> Execute(string sql, Dictionary<string, object> args, CancellationToken ct);
}

internal static class WhatWhereWhenCycle
{
    internal static async Task<JsonObject> Run(IWhatWhereWhenTransaction db, int batchLimit, int retentionLimit, CancellationToken ct, Microsoft.Extensions.Configuration.IConfiguration? configuration = null)
    {
        batchLimit = Math.Clamp(batchLimit, 1, 10000); retentionLimit = Math.Clamp(retentionLimit, 1, 50000);
        var result = new JsonObject(); foreach (string key in new[] { "inserted", "collapsed", "duplicate", "filtered", "unmatched", "ambiguous", "deleted" }) result[key] = 0;
        JsonObject Skipped(string reason) { result["status"] = "skipped"; result["reason"] = reason; result["high_water"] = null; result["backfill_completed"] = false; return result; }
        var setting = await db.Query("select value from platform_settings where key='reports.domain_fqdn'", [], ct);
        string preferred = (setting.FirstOrDefault()?["value"]?.ToString() ?? "").Trim().ToLowerInvariant();
        var observedDomains = await db.Query("""
            select d.id,d.fqdn as display_name,d.is_archived,observed.observed_at_utc from domains d
            left join lateral(select max(run.observed_at_utc) as observed_at_utc from ad_context_runs run where run.domain_id=d.id and run.status='completed') observed on true
            where not d.is_archived order by d.id
            """, [], ct);
        var eligible = observedDomains.OfType<JsonObject>().Where(d => d["is_archived"]?.GetValue<bool>() != true).ToArray();
        var chosen = preferred.Length == 0 ? null : eligible.FirstOrDefault(d => EntityReader.Text(d, "display_name").Equals(preferred, StringComparison.OrdinalIgnoreCase));
        chosen ??= eligible.Select(d => (Row: d, Time: DateTimeOffset.TryParse(EntityReader.Text(d, "observed_at_utc"), CultureInfo.InvariantCulture, DateTimeStyles.None, out var stamp) && (EntityReader.Text(d, "observed_at_utc").EndsWith('Z') || EntityReader.Text(d, "observed_at_utc").LastIndexOf('+') > 9 || EntityReader.Text(d, "observed_at_utc").LastIndexOf('-') > 9) ? (DateTimeOffset?)stamp : null))
            .Where(d => d.Time.HasValue && d.Time <= DateTimeOffset.UtcNow).OrderByDescending(d => d.Time).ThenBy(d => EntityReader.Number(d.Row, "id")).Select(d => d.Row).FirstOrDefault();
        if (chosen is null) return Skipped("report_domain_not_configured");
        string domain = EntityReader.Text(chosen, "display_name").Trim().ToLowerInvariant();
        var locked = await db.Query("select pg_try_advisory_xact_lock(hashtext('ad_log_reports_what_where_when_projection_cycle')) as acquired", [], ct);
        if (locked.FirstOrDefault()?["acquired"]?.GetValue<bool>() != true) return Skipped("lock_busy");
        var domains = await db.Query("select id from domains where lower(fqdn)=@domain order by id", new() { ["domain"] = domain }, ct);
        if (domains.Count != 1) throw new InvalidDataException("what_where_when_requires_one_domain");
        int domainId = checked((int)EntityReader.Number((JsonObject)domains[0]!, "id"));
        var state = (await db.Query("select * from what_where_when_projection_state where singleton for update", [], ct)).OfType<JsonObject>().FirstOrDefault() ?? throw new InvalidDataException("what_where_when_projection_state_missing");
        var computers = (await db.Query("""
            select source.source_snapshot_id,source.domain_id,source.snapshot_uuid,source.collection_status,source.base_inventory_status,
              source.object_count,source.payload_json,encode(source.payload_sha256,'hex') as payload_sha256
            from computers_v6_source_snapshots source join domains domain on domain.id=source.domain_id where lower(domain.fqdn)=lower(@domain)
            order by source.source_completed_at_utc desc,source.source_snapshot_id desc limit 1
            """, new() { ["domain"] = domain }, ct)).OfType<JsonObject>().FirstOrDefault();
        if (computers is null || EntityReader.Text(computers, "base_inventory_status") != "observed") throw new InvalidDataException("what_where_when_computers_population_unavailable");
        var snapshot = WhatWhereWhenSnapshots.Validate(computers["payload_json"] as JsonObject ?? JsonNode.Parse(computers["payload_json"]!.ToString()) as JsonObject ?? throw new InvalidDataException("snapshot_json_invalid"));
        VerifyHash(snapshot, EntityReader.Text(computers, "payload_sha256"), "stored_snapshot_hash_mismatch");
        if (EntityReader.Number(computers, "object_count") != ((JsonArray)snapshot["objects"]!).Count) throw new InvalidDataException("stored_snapshot_object_count_mismatch");
        if (EntityReader.Text(computers, "snapshot_uuid") != snapshot["metadata"]!["snapshot_id"]!.ToString()) throw new InvalidDataException("stored_snapshot_identity_mismatch");
        if (EntityReader.Text(computers, "collection_status") != snapshot["metadata"]!["collection_status"]!.ToString()) throw new InvalidDataException("stored_snapshot_status_mismatch");
        var (userSnapshotId, classifications) = await LoadServiceAccounts(db, domainId, ct);
        var index = WhatWhereWhenProjection.Index(snapshot);
        long oldWater = EntityReader.Number(state, "high_water_event_id");
        var cutoff = WhatWhereWhenSnapshots.Instant(state["initial_cutoff_utc"], "initial_cutoff_utc");
        var boundary = EventReadService.ShortBoundary(configuration).UtcDateTime;
        var rows = await db.Query(HotSql + "where event.domain_id=@domain and event.time_created_utc>=@cutoff and event.id>@after order by event.id limit @limit",
            new() { ["domain"] = domainId, ["cutoff"] = cutoff.UtcDateTime, ["after"] = oldWater, ["limit"] = batchLimit + 1, ["boundary"] = boundary }, ct);
        var events = rows.OfType<JsonObject>().Take(batchLimit).ToList();
        bool backfillComplete = rows.Count <= batchLimit;
        long highWater = events.Count == 0 ? oldWater : Math.Max(oldWater, EntityReader.Number(events[^1], "source_event_id"));
        var reconciliation = await db.Query(HotSql + """
            where event.domain_id=@domain and event.event_id=4624 and event.id<=@high
              and event.time_created_utc>=transaction_timestamp()-interval '24 hours'
              and not exists(select 1 from what_where_when_observations observation where observation.source_event_id=event.id)
            order by event.id desc limit @limit
            """, new() { ["domain"] = domainId, ["high"] = highWater, ["limit"] = Math.Min(batchLimit, 2000), ["boundary"] = boundary }, ct);
        var reconciliationIds = reconciliation.OfType<JsonObject>().Select(r => EntityReader.Number(r, "source_event_id")).ToHashSet();
        var seen = events.Select(r => EntityReader.Number(r, "source_event_id")).ToHashSet();
        foreach (var row in events.Concat(reconciliation.OfType<JsonObject>().Where(r => !seen.Contains(EntityReader.Number(r, "source_event_id")))))
        {
            ct.ThrowIfCancellationRequested();
            var decision = WhatWhereWhenProjection.Project(row, index, classifications);
            string status = decision.Status == "observation" ? await Persist(db, decision.Observation!, EntityReader.Number(computers, "source_snapshot_id"), userSnapshotId, ct) : decision.Status;
            result[status] = result[status]!.GetValue<int>() + 1;
            long id = EntityReader.Number(row, "source_event_id"); if (!reconciliationIds.Contains(id)) highWater = Math.Max(highWater, id);
        }
        result["deleted"] = Math.Max(0, await db.Execute("""
            with doomed as(select projection_id from what_where_when_observations where observed_at_utc<transaction_timestamp()-interval '365 days'
              order by observed_at_utc,projection_id limit @limit)
            delete from what_where_when_observations observation using doomed where observation.projection_id=doomed.projection_id
            """, new() { ["limit"] = retentionLimit }, ct));
        bool completed = state["backfill_completed"]!.GetValue<bool>() || backfillComplete;
        await db.Execute("""
            update what_where_when_projection_state set high_water_event_id=@high,backfill_completed=@complete,computer_source_snapshot_id=@computer,user_snapshot_id=@user,
              filtered_count=filtered_count+@filtered,unmatched_count=unmatched_count+@unmatched,ambiguous_count=ambiguous_count+@ambiguous,
              last_cycle_at_utc=transaction_timestamp(),updated_at=transaction_timestamp() where singleton
            """, new() { ["high"] = highWater, ["complete"] = completed, ["computer"] = EntityReader.Number(computers, "source_snapshot_id"), ["user"] = userSnapshotId,
                ["filtered"] = result["filtered"]!.GetValue<int>(), ["unmatched"] = result["unmatched"]!.GetValue<int>(), ["ambiguous"] = result["ambiguous"]!.GetValue<int>() }, ct);
        result["status"] = "ok"; result["high_water"] = highWater; result["backfill_completed"] = completed; return result;
    }
    internal static async Task<(long SnapshotId, Dictionary<string, bool> Accounts)> LoadServiceAccounts(IWhatWhereWhenTransaction db, int domainId, CancellationToken ct)
    {
        var users = (await db.Query("""
            select snapshot_id,payload_json,encode(payload_sha256,'hex') as payload_sha256 from users_report_v2_snapshots
            where domain_id=@domain and source_state in('complete','partial') order by captured_at_utc desc,snapshot_id desc limit 1
            """, new() { ["domain"] = domainId }, ct)).OfType<JsonObject>().FirstOrDefault() ?? throw new InvalidDataException("what_where_when_users_snapshot_unavailable");
        var userPayload = users["payload_json"] as JsonObject ?? JsonNode.Parse(users["payload_json"]!.ToString()) as JsonObject ?? throw new InvalidDataException("users_snapshot_json_invalid");
        VerifyHash(userPayload, EntityReader.Text(users, "payload_sha256"), "what_where_when_users_snapshot_hash_mismatch");
        var classifications = new Dictionary<string, bool>();
        foreach (var user in (userPayload["users"] as JsonArray ?? new()).OfType<JsonObject>())
        {
            string sam = (EntityReader.Text(user, "samAccountName") is { Length: > 0 } v ? v : EntityReader.Text(user, "sam_account_name")).Trim();
            if (sam.Length > 0) classifications[Sli.Server.Agents.Registry.UnicodeCaseFold.Fold(sam)] = WhatWhereWhenProjection.ServiceAccount(user);
        }
        return (EntityReader.Number(users, "snapshot_id"), classifications);
    }
    internal static void VerifyHash(JsonObject payload, string hash, string code)
    {
        byte[] stored; try { stored = Convert.FromHexString(hash); } catch (FormatException) { throw new InvalidDataException(code); }
        if (!CryptographicOperations.FixedTimeEquals(stored, SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalJson.Serialize(payload, ensureAscii: false))))) throw new InvalidDataException(code);
    }
    internal static async Task<string> Persist(IWhatWhereWhenTransaction db, LogonObservation observation, long computerSnapshot, long userSnapshot, CancellationToken ct)
    {
        var existing = (await db.Query("""
            select source_event_id,source_event_hash,computer_object_guid,computer_name,user_name,observed_at_utc,computer_source_snapshot_id,user_snapshot_id
            from what_where_when_observations where source_event_id=@id
            """, new() { ["id"] = observation.EventId }, ct)).OfType<JsonObject>().FirstOrDefault();
        if (existing is not null)
        {
            string hash = existing["source_event_hash"]!.ToString();
            if (EntityReader.Number(existing, "source_event_id") != observation.EventId || !Convert.FromHexString(hash).AsSpan().SequenceEqual(observation.Hash)
                || !EntityReader.Text(existing, "computer_object_guid").Equals(observation.ComputerGuid, StringComparison.OrdinalIgnoreCase)
                || EntityReader.Text(existing, "computer_name") != observation.ComputerName || EntityReader.Text(existing, "user_name") != observation.UserName
                || WhatWhereWhenSnapshots.Instant(existing["observed_at_utc"], "existing_observation") != observation.Observed
                || EntityReader.Number(existing, "computer_source_snapshot_id") != computerSnapshot || EntityReader.Number(existing, "user_snapshot_id") != userSnapshot)
                throw new InvalidDataException("what_where_when_source_event_identity_conflict");
            return "duplicate";
        }
        var inserted = await db.Query("""
            insert into what_where_when_observations(source_event_id,source_event_hash,computer_object_guid,computer_name,user_name,user_key,observed_at_utc,observed_hour_local,computer_source_snapshot_id,user_snapshot_id)
            values(@id,@hash,@guid,@computer,@user,@key,@observed,@hour,@computer_snapshot,@user_snapshot)
            on conflict(computer_object_guid,user_key,observed_hour_local) do nothing returning source_event_id
            """, new() { ["id"] = observation.EventId, ["hash"] = observation.Hash, ["guid"] = Guid.Parse(observation.ComputerGuid), ["computer"] = observation.ComputerName,
                ["user"] = observation.UserName, ["key"] = observation.UserName.Trim().ToLowerInvariant(), ["observed"] = observation.Observed.UtcDateTime, ["hour"] = WhatWhereWhenProjection.Hour(observation.Observed), ["computer_snapshot"] = computerSnapshot, ["user_snapshot"] = userSnapshot }, ct);
        return inserted.Count > 0 ? "inserted" : "collapsed";
    }
    internal const string HotSql = """
        with event_rows as (
          select event_id as id,time_created_utc,event_kind as event_id,domain_id,method,outcome,source_sha256
          from event_hot where time_created_utc>=@boundary
          union all
          select event_id,time_created_utc,event_kind,domain_id,method,outcome,source_sha256
          from event_cold_facts cold where time_created_utc<@boundary
            or not exists(select 1 from event_hot hot where hot.event_id=cold.event_id and hot.time_created_utc>=@boundary)
        )
        select event.id as source_event_id,encode(event.source_sha256,'hex') as source_event_hash,event.time_created_utc as observed_at_utc,event.event_id,
          coalesce(event.method#>>'{$principals,TargetUserSid}',event.method#>>'{$principals,TargetSid}') as target_user_sid,
          event.method#>>'{$principals,TargetUserName}' as target_user_name,event.method#>>'{$principals,TargetDomainName}' as target_domain_name,
          coalesce(event.method#>>'{$principals,WorkstationName}',event.method#>>'{$principals,Workstation}',event.method->>'WorkstationName',event.method->>'Workstation') as workstation_name,
          coalesce(event.method#>>'{$principals,IpAddress}',event.method#>>'{$principals,ClientAddress}',event.method#>>'{$principals,SourceNetworkAddress}',event.method->>'IpAddress',event.method->>'ClientAddress',event.method->>'SourceNetworkAddress') as ip_address,event.method->>'LogonType' as logon_type
        from event_rows event join servers server on server.id=(event.method->>'$server_id')::bigint
          and server.domain_id=event.domain_id and server.role='domain_controller'
          and lower(event.method->>'$channel')='security'

        """;
}
