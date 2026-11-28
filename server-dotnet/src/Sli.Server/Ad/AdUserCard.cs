using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

internal static class AdUserCard
{
    internal static async Task<JsonObject> ReadAsync(NpgsqlConnection db, AdV2Request request, List<JsonObject> sources,
        Func<IEnumerable<string>, bool> fields, IConfiguration? configuration, CancellationToken ct)
    {
        if (!long.TryParse(request.Row, NumberStyles.None, CultureInfo.InvariantCulture, out long entityId) || entityId <= 0)
            throw new KeyNotFoundException();

        var source = sources.SingleOrDefault(s => (s["snapshot"]?["users"] as JsonArray ?? []).Any(u => u.Int("entityId") == entityId));
        var accounts = source?["snapshot"]?["users"] as JsonArray ?? [];
        var raw = accounts.OfType<JsonObject>().SingleOrDefault(u => u.Int("entityId") == entityId)
            ?? throw new KeyNotFoundException();
        long domain = source.Int("domain_id");
        var safe = raw.DeepClone().AsObject();
        AdInventoryRows.RedactUser(safe, fields);
        var activity = LatestActivity(safe, null);
        var card = new JsonObject
        {
            ["entity_id"] = entityId,
            ["domain_id"] = domain,
            ["domain_name"] = safe.Text("domainName") ?? source.Text("fqdn"),
            ["display_name"] = safe.Text("displayName") ?? safe.Text("name"),
            ["sam"] = safe.Text("samAccountName"),
            ["enabled"] = safe["enabled"]?.DeepClone(),
            ["department"] = safe.Text("department"),
            ["ou"] = safe.Text("ou"),
            ["dn"] = safe.Text("distinguishedName"),
            ["sid"] = safe.Text("sid"),
            ["password_last_set"] = safe["passwordLastSet"]?.DeepClone(),
            ["activity_at"] = activity.Value?.DeepClone(),
            ["activity_source"] = activity.Source
        };

        if (fields(["privilege"]))
        {
            AdUsersTabs.SetPrivileges(card, safe);
            card["direct_memberships"] = AdUsersTabs.DirectMemberships(safe);
        }

        if (fields(["security", "technical"]) && raw.Int("domainId") == domain && safe.Text("sid") is {} sid
            && accounts.Count(u => string.Equals(u.Text("sid"), sid, StringComparison.OrdinalIgnoreCase)) == 1)
        {
            var now = DateTimeOffset.UtcNow;
            var period = request.Params["period"];
            var end = AdInventoryRows.Date(period?["to_utc"]) ?? now;
            var start = AdInventoryRows.Date(period?["from_utc"]) ?? end.AddDays(-30);
            string zone = TimeZoneInfo.TryConvertWindowsIdToIanaId(request.Timezone, out var iana)
                ? iana : request.Timezone;
            string[] names = new[] { safe.Text("userPrincipalName"),
                card.Text("domain_name") is {} dns && safe.Text("samAccountName") is {} sam ? dns + "\\" + sam : null }
                .OfType<string>().Select(s => s.ToLowerInvariant()).Distinct().ToArray();
            var rows = await AdJson.ReadAsync(db, AdAccountEvents.Source(configuration, scope: " and h.domain_id=$4",
                filter: " and h.event_kind in (4624,4625) and (upper(h.actor)=$5 or (h.event_kind=4625 and lower(h.actor)=any($6)))") + ActivitySql, ct,
                new[] { 4624, 4625 }, start, end, domain, sid.ToUpperInvariant(), names, zone);
            foreach (string key in new[] { "timeline", "computers", "logon_days", "logon_totals" })
                card[key] = JsonNode.Parse(rows[0].Text(key) ?? "null");
            activity = LatestActivity(safe, rows[0]["last_logon_utc"]);
            card["activity_at"] = activity.Value?.DeepClone();
            card["activity_source"] = activity.Source;
            var principals = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var principal in accounts)
                if (principal.Text("sid") is {} principalSid && (principal.Text("samAccountName") ?? principal.Text("name")) is {} name)
                    principals.TryAdd(principalSid, name.Length <= 256 ? name : name[..256]);
            foreach (var item in card["timeline"] as JsonArray ?? [])
                foreach (string field in new[] { "actor", "target" })
                    if (item.Text(field) is {} value && principals.TryGetValue(value, out var name)) item![field] = name;
        }
        return AdV2Store.Result(request.Key, "ok", [card]);
    }

    internal static (JsonNode? Value, string? Source) LatestActivity(JsonObject account, JsonNode? journal)
    {
        var candidates = new[]
        {
            (Value: journal, Source: "windows_event"),
            (Value: account["exactLastLogon"], Source: "domain_controllers"),
            (Value: account["lastLogonTimestamp"], Source: "active_directory")
        };
        var newest = candidates.Select(candidate => (candidate, Stamp: AdInventoryRows.Date(candidate.Value)))
            .Where(entry => entry.Stamp.HasValue).OrderByDescending(entry => entry.Stamp).FirstOrDefault();
        return newest.candidate;
    }

    // A retained group that spans local midnight cannot be divided into exact local counts.
    // 4624 and 4625 both store the attempted account in actor.
    internal const string ActivitySql = """
        , activity as materialized (
            select id, event_id, day, event_count, first_seen_utc, last_seen_utc, summary_key,
                   left(actor,256) as actor, left(target,256) as target,
                   left(source,256) as source,
                   left(case when source !~ '^[0-9.]+$' and strpos(source, ':')=0
                       and logon_type in ('2','10','11') then nullif(source,'-') end,256) as workstation,
                   logon_type
              from account_events
             where domain_id=$4 and event_id=any($1) and time_created_utc >= $2 and time_created_utc < $3
               and (upper(actor)=$5 or (event_id=4625 and lower(actor)=any($6)))
        ), daily as (
            select calendar.day,
                   case when not bool_or(uncertain) filter (where event_id=4624) is true
                        then coalesce(sum(event_count) filter (where event_id=4624),0)::bigint end as successes,
                   case when not bool_or(uncertain) filter (where event_id=4625) is true
                        then coalesce(sum(event_count) filter (where event_id=4625),0)::bigint end as failures
              from (select stamp::date as day
                    from generate_series(($2::timestamptz at time zone $7)::date::timestamp,
                         (($3::timestamptz - interval '1 microsecond') at time zone $7)::date::timestamp,
                         interval '1 day') stamp) calendar
              left join lateral (
                  select event_id, event_count, event_count is null or
                         (first_seen_utc at time zone $7)::date <> (last_seen_utc at time zone $7)::date as uncertain
                    from activity
                   where calendar.day between (least(first_seen_utc,last_seen_utc) at time zone $7)::date
                                          and (greatest(first_seen_utc,last_seen_utc) at time zone $7)::date
              ) a on true
             group by calendar.day
        ), totals as (
            select case when count(*) filter (where event_id=4624 and event_count is null)=0
                        then coalesce(sum(event_count) filter (where event_id=4624),0) end as successes,
                   case when count(*) filter (where event_id=4625 and event_count is null)=0
                        then coalesce(sum(event_count) filter (where event_id=4625),0) end as failures
              from activity having count(*)>0
        ), timeline_rows as (
            select id, event_id, last_seen_utc as at_utc, first_seen_utc, event_count, actor, target, source, summary_key
              from activity
        ), recent as (
            select * from timeline_rows order by at_utc desc, id desc nulls last, summary_key limit 50
        ), latest_computers as (
            select distinct on (lower(workstation)) workstation as computer, last_seen_utc as at_utc, id
              from activity where event_id=4624 and workstation is not null
             order by lower(workstation), last_seen_utc desc, id desc nulls last
        ), computers as (
            select * from latest_computers order by at_utc desc, computer limit 50
        )
        select (select jsonb_agg(to_jsonb(r) order by r.at_utc desc, r.id desc nulls last, r.summary_key) from recent r)::text as timeline,
               (select jsonb_agg(to_jsonb(c) order by c.at_utc desc, c.computer) from computers c)::text as computers,
               (select jsonb_agg(to_jsonb(d) order by d.day) from daily d where exists(select 1 from totals))::text as logon_days,
               (select to_jsonb(t) from totals t)::text as logon_totals,
               (select max(last_seen_utc) from activity where event_id=4624) as last_logon_utc
        """;
}
