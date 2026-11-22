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
        var activity = AdInventoryRows.Activity(safe);
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
            var today = new DateTimeOffset(now.UtcDateTime.Date, TimeSpan.Zero);
            string[] names = new[] { safe.Text("userPrincipalName"),
                card.Text("domain_name") is {} dns && safe.Text("samAccountName") is {} sam ? dns + "\\" + sam : null }
                .OfType<string>().Select(s => s.ToLowerInvariant()).Distinct().ToArray();
            var rows = await AdJson.ReadAsync(db, AdAccountEvents.Source(configuration) + ActivitySql, ct,
                new[] { 4624, 4625, 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4740, 4756, 4757, 4767, 4781 },
                now.AddDays(-30), now, domain, sid.ToUpperInvariant(), names, today, fields(["privilege"]));
            foreach (string key in new[] { "timeline", "changes", "computers", "logon_days", "logon_totals" })
                card[key] = JsonNode.Parse(rows[0].Text(key) ?? "null");
            var principals = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var groups = fields(["privilege"]) ? source?["snapshot"]?["groups"] as JsonArray ?? [] : [];
            foreach (var principal in accounts.Concat(groups))
                if (principal.Text("sid") is {} principalSid && (principal.Text("samAccountName") ?? principal.Text("name")) is {} name)
                    principals.TryAdd(principalSid, name.Length <= 256 ? name : name[..256]);
            foreach (var item in (card["timeline"] as JsonArray ?? []).Concat(card["changes"] as JsonArray ?? []))
                foreach (string field in new[] { "actor", "target", "member" })
                    if (item.Text(field) is {} value && principals.TryGetValue(value, out var name)) item![field] = name;
        }
        return AdV2Store.Result(request.Key, "ok", [card]);
    }

    // The day strip uses complete UTC days so a retained daily bucket is never split.
    // 4624 and 4625 both store the attempted account in actor.
    internal const string ActivitySql = """
        , activity as materialized (
            select id, event_id, day, event_count, first_seen_utc, last_seen_utc, summary_key,
                   left(actor,256) as actor, left(target,256) as target,
                   left(membership_member_sid,256) as member, left(source,256) as source,
                   left(case when source !~ '^[0-9.]+$' and strpos(source, ':')=0
                       and logon_type in ('2','10','11') then nullif(source,'-') end,256) as workstation,
                   logon_type
              from account_events
             where domain_id=$4 and event_id=any($1) and time_created_utc >= $2 and time_created_utc < $3
               and (event_id not in (4728,4729,4732,4733,4756,4757) or $8)
               and (upper(actor)=$5 or (event_id=4625 and lower(actor)=any($6))
                 or (event_id not in (4624,4625) and (upper(target)=$5 or upper(membership_member_sid)=$5)))
        ), daily as (
            select calendar.day,
                   coalesce(sum(event_count) filter (where event_id=4624),0)::bigint as successes,
                   coalesce(sum(event_count) filter (where event_id=4625),0)::bigint as failures
              from (select ($7::timestamptz at time zone 'UTC')::date-days as day
                      from generate_series(1,14) offsets(days)) calendar
              left join activity a on coalesce(a.day,(a.first_seen_utc at time zone 'UTC')::date)=calendar.day
                and a.event_id in (4624,4625)
             group by calendar.day
        ), totals as (
            select sum(successes) as successes, sum(failures) as failures,
                   percentile_disc(0.5) within group (order by successes)
                       filter (where day<($7::timestamptz at time zone 'UTC')::date-1) as typical
              from daily having sum(successes+failures)>0
        ), timeline_rows as (
            select id, event_id, last_seen_utc as at_utc, first_seen_utc, event_count, actor, target, member, source, summary_key
              from activity
        ), recent as (
            select * from timeline_rows order by at_utc desc, id desc nulls last, summary_key limit 50
        ), changes as (
            select * from timeline_rows where event_id not in (4624,4625)
             order by at_utc desc, id desc nulls last, summary_key limit 50
        ), latest_computers as (
            select distinct on (lower(workstation)) workstation as computer, last_seen_utc as at_utc, id
              from activity where event_id=4624 and workstation is not null
             order by lower(workstation), last_seen_utc desc, id desc nulls last
        ), computers as (
            select * from latest_computers order by at_utc desc, computer limit 50
        )
        select (select jsonb_agg(to_jsonb(r) order by r.at_utc desc, r.id desc nulls last, r.summary_key) from recent r)::text as timeline,
               (select jsonb_agg(to_jsonb(c) order by c.at_utc desc, c.id desc nulls last, c.summary_key) from changes c)::text as changes,
               (select jsonb_agg(to_jsonb(c) order by c.at_utc desc, c.computer) from computers c)::text as computers,
               (select jsonb_agg(to_jsonb(d) order by d.day) from daily d where exists(select 1 from totals))::text as logon_days,
               (select to_jsonb(t) from totals t)::text as logon_totals
        """;
}
