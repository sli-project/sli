using System.Text.Json.Nodes;
using Sli.Server.Ad;
using Sli.Server.Semantic;

namespace Sli.Server.Reporting.V2;

internal sealed partial class SecurityObservationReader
{
    static bool Usable(JsonObject row) => row["short_event"]?.GetValue<bool>() == true && row["day"] is null || T(row, "processing_status") == "normalized" && T(row, "semantic_type") == (N(row, "event_id") switch { 4725 => "directory.account.disabled", 4726 => "directory.account.deleted", 4722 => "directory.account.enabled", 4624 => "authentication.session.created", 6272 => "remote_access.authentication.allowed", _ => "" });
    internal async Task<JsonObject> Revocation(ReportQueryContext c, ISemanticSession db, long domain, DateTimeOffset start, DateTimeOffset end, CancellationToken ct)
    {
        int follow = checked((int)(c.Params["revocation_window"] is null ? 1440 : N(c.Params, "revocation_window"))), delay = checked((int)N(c.Params, "minimum_delay"));
        if (follow is < 1 or > 1440 || delay < 0) throw new ReportRequestException("security_events_filter_invalid");
        var followEnd = end.AddMinutes(follow);
        Task<JsonArray> Read(int[] codes, DateTimeOffset to) => ShortEvents(db, domain, codes, start, to, configuration, ct, 10001);
        var anchors = await Read([4725, 4726], end); var enables = await Read([4722], followEnd); var activity = await Read([4624, 6272], followEnd);
        bool cut = anchors.Count > 10000 || enables.Count > 10000 || activity.Count > 10000;
        var events = anchors.Take(10000).Concat(enables.Take(10000)).Concat(activity.Take(10000)).OfType<JsonObject>().ToArray();
        var rows = Revocations(events, [], start, end, follow, T(c.Params, "target"), T(c.Params, "source"), T(c.Params, "activity_type"), delay, T(c.Params, "identity_scope") == "exact", cut);
        bool outputCut = rows.Length > 10000; rows = rows.Take(10000).ToArray(); bool partial = cut || outputCut || rows.Length > c.Paging.Limit;
        int missing = events.Count(e => !Usable(e));
        var result = ReportResult.Create(c.Definition.Key, partial || missing > 0 ? "partial" : rows.Length > 0 ? "ok" : "empty",
            coverage: Obj(new { state = partial ? "bounded_slice" : "coverage_unverified", completeness = "not_proven", source_truncated = cut, rows_truncated = outputCut || rows.Length > c.Paging.Limit, accounting_state = "not_checked", missing_current_semantics = missing }),
            collections: new JsonObject { ["account_revocation"] = Array(rows.Take(c.Paging.Limit)) }, limitations: new JsonArray(SecurityEventsReader.Note("revocation_candidates", "Новая аутентификация после отключения — кандидат, а не доказательство обхода. Продолжение старой VPN-сессии Accounting показано отдельно и не доказывает новую аутентификацию."), SecurityEventsReader.Note("revocation_coverage", "Полнота источников не подтверждена. Сопоставление — только точный SID в одном домене и текущая семантика. Неизвестные идентичности показаны отдельно без связи по имени."), SecurityEventsReader.Note("revocation_window", "Период задаёт время отключения/удаления. Accounting показывает отдельно старые сессии, пересекающие момент отключения; время последнего наблюдения может выходить за окно аутентификации.")));
        result["limitations"]!.AsArray().Add(SecurityEventsReader.Note("revocation_accounting", "Accounting недоступен, не содержит сопоставленных строк или не проверен без точных якорей. Отсутствие продолжавшихся VPN-сессий не установлено."));
        if (partial) result["limitations"]!.AsArray().Add(SecurityEventsReader.Note("revocation_truncated", "Достигнут лимит событий, сессий или строк. Счётчики — нижняя граница прочитанного среза; сузьте период."));
        result["metrics"] = Array(new[] { Obj(new { key = "revocation_logons", label = "Аккаунты с последующей 4624 (кандидаты)", value = rows.Where(r => T(r, "activity_type") == "logon").Select(r => T(r, "sid")).Distinct().Count() }), Obj(new { key = "revocation_nps", label = "Разрешения NPS после отключения (кандидаты)", value = rows.Count(r => T(r, "activity_type") == "nps_allow") }), Obj(new { key = "revocation_vpn", label = "Старые сессии Accounting (кандидаты)", value = rows.Where(r => T(r, "activity_type") == "vpn_continuation").Select(r => r["session_id"]?.ToString()).Distinct().Count() }), Obj(new { key = "revocation_unknown", label = "Наблюдения без точного сопоставления", value = rows.Count(r => T(r, "activity_type") == "insufficient") }) });
        result["filtered_count"] = rows.Length; result["window"] = Obj(new { from_utc = AdJson.Iso(start), to_utc_exclusive = AdJson.Iso(end), activity_to_utc_exclusive = AdJson.Iso(followEnd), follow_minutes = follow, idea_key = "security.account-revocation", source_row_limit = 10000 }); return result;
    }
    internal static JsonObject[] Revocations(IEnumerable<JsonObject> input, IEnumerable<JsonObject> sessions, DateTimeOffset start, DateTimeOffset end, int follow,
        string? account = null, string? source = null, string? activityType = null, int delayMinimum = 0, bool exactOnly = false, bool truncated = false)
    {
        var all = input.ToArray();
        var events = all.Where(e => e["day"] is null).DistinctBy(e => N(e, "event_db_id")).OrderBy(e => Time(e)).ThenBy(e => N(e, "event_db_id")).ToArray(); var output = new List<JsonObject>();
        var anchors = events.Where(e => N(e, "event_id") is 4725 or 4726 && Time(e) >= start && Time(e) < end).ToArray();
        var known = anchors.Where(e => Sid(e, true) is not null && Usable(e)).ToArray();
        void Append(JsonObject? anchor, JsonObject? activity, string kind)
        {
            var observation = anchor ?? activity!; string? sid = Sid(observation, true); DateTimeOffset? at = anchor is null ? null : Time(anchor), moment = activity is null ? null : Time(activity, activity["time_created_utc"] is not null ? "time_created_utc" : "last_observed_at_utc");
            var enabled = events.FirstOrDefault(e => sid is not null && N(e, "event_id") == 4722 && Usable(e) && N(e, "domain_id") == N(observation, "domain_id") && Sid(e, true) == sid && at is not null && Time(e) > at && Time(e) < at.Value.AddMinutes(follow));
            string? name = T(observation, N(observation, "event_id") == 6272 ? "subject_user_name" : "target_user_name") ?? sid;
            string? observedSource = T(activity ?? observation, "source"); double? delay = moment is not null && at is not null ? (moment.Value - at.Value).TotalSeconds : null;
            if (account is not null && !string.Equals(account, sid, StringComparison.OrdinalIgnoreCase) && !string.Equals(account, name, StringComparison.OrdinalIgnoreCase) || source is not null && !string.Equals(source, observedSource, StringComparison.OrdinalIgnoreCase) || activityType is not null && activityType != kind || exactOnly && (sid is null || !Usable(observation)) || delayMinimum > 0 && (delay is null || delay < delayMinimum)) return;
            var evidence = new List<JsonNode?>(); if (anchor is not null) evidence.Add(anchor["event_db_id"]?.DeepClone()); if (activity is not null) evidence.Add((activity["event_db_id"] ?? activity["session_row_id"])?.DeepClone()); if (enabled is not null) evidence.Add(enabled["event_db_id"]?.DeepClone());
            string? Iso(DateTimeOffset? value) => value is null ? null : AdJson.Iso(value.Value);
            output.Add(Obj(new { candidate_key = (anchor is null ? "unknown" : N(anchor, "event_db_id").ToString()) + ":" + kind + ":" + (activity is null ? "" : (activity["event_db_id"] ?? activity["session_row_id"])?.ToString()), account = name, sid, qualification = kind == "insufficient" ? "insufficient" : "candidate", disable_event = anchor?["event_db_id"]?.DeepClone(), disable_code = anchor?["event_id"]?.DeepClone(), disabled_at = Iso(at), activity_event = activity?["event_db_id"]?.DeepClone(), activity_at = Iso(moment), activity_type = kind, delay_seconds = delay, source = observedSource, logon_type = activity?["logon_type"]?.DeepClone(), reenabled_at = enabled is null ? null : Iso(Time(enabled)), reenable_event = enabled?["event_db_id"]?.DeepClone(), reenable_relation = enabled is null ? "not_observed" : Time(enabled) < moment ? "before_activity" : Time(enabled) == moment ? "same_time" : "after_activity", evidence,
                quality = sid is null ? "unknown_sid" : truncated || !Usable(observation) ? "partial" : "exact_sid", clock_quality = delay is not null && delay <= 60 ? "uncertain" : "unverified", session_id = activity?["session_row_id"]?.DeepClone(), session_started_at = activity?["started_at_utc"] is null ? null : Iso(Time(activity, "started_at_utc")), session_completeness = activity?["completeness"]?.DeepClone() }));
            foreach(string key in new[]{"read_representation","source_event_state","authentication_session"})if(activity?[key] is {} value)output[^1][key]=value.DeepClone();
        }
        foreach (var anchor in anchors.Except(known)) Append(anchor, null, "insufficient");
        foreach (var activity in events.Where(e => N(e, "event_id") is 4624 or 6272))
        {
            string? sid = Sid(activity, true); if (sid is null || !Usable(activity)) { Append(null, activity, "insufficient"); continue; }
            var anchor = known.LastOrDefault(e => N(e, "domain_id") == N(activity, "domain_id") && Sid(e, true) == sid && Time(e) < Time(activity));
            if (anchor is not null && Time(activity) < Time(anchor).AddMinutes(follow)) Append(anchor, activity, N(activity, "event_id") == 4624 ? "logon" : "nps_allow");
        }
        // A daily group proves activity in an interval, not an individual logon
        // at midnight/first_seen. Keep the group without fabricating an event
        // link, delay, or a precise ordering relative to disable/enable.
        void AppendDaily(JsonObject daily, JsonObject? anchor)
        {
            string? sid = Sid(daily,true), name = T(anchor ?? daily,"target_user_name") ?? sid;
            if (activityType is not (null or "insufficient") || delayMinimum > 0 || exactOnly && sid is null
                || account is not null && !string.Equals(account,sid,StringComparison.OrdinalIgnoreCase) && !string.Equals(account,name,StringComparison.OrdinalIgnoreCase)
                || source is not null && !string.Equals(source,T(daily,"source"),StringComparison.OrdinalIgnoreCase)) return;
            output.Add(Obj(new { candidate_key = (anchor is null ? "unknown" : N(anchor,"event_db_id").ToString()) + ":daily:" + T(daily,"summary_key"), account = name, sid,
                qualification = "insufficient", disable_event = anchor?["event_db_id"]?.DeepClone(), disable_code = anchor?["event_id"]?.DeepClone(),
                disabled_at = anchor is null ? null : AdJson.Iso(Time(anchor)), activity_event = (long?)null, activity_at = (string?)null,
                activity_type = "insufficient", delay_seconds = (double?)null, source = T(daily,"source"),
                logon_type = daily["logon_type"]?.DeepClone(), evidence = anchor is null ? System.Array.Empty<long>() : new[] { N(anchor,"event_db_id") }, quality = sid is null ? "unknown_sid" : "partial",
                read_representation = "daily_summary", day = daily["day"]?.DeepClone(), event_count = N(daily,"event_count"),
                first_seen_utc = daily["first_seen_utc"]?.DeepClone(), last_seen_utc = daily["last_seen_utc"]?.DeepClone(), summary_key = T(daily,"summary_key") }));
        }
        foreach (var daily in all.Where(e => e["day"] is not null && N(e,"event_id") == 4624).DistinctBy(e => T(e,"summary_key")))
        {
            if (Sid(daily,true) is null) AppendDaily(daily,null);
            else foreach (var anchor in known.Where(e => N(e,"domain_id") == N(daily,"domain_id") && Sid(e,true) == Sid(daily,true)
                && Time(daily,"last_seen_utc") > Time(e) && Time(daily,"first_seen_utc") < Time(e).AddMinutes(follow)))
            {
                AppendDaily(daily,anchor);
                if (output.Count >= 10001) return output.ToArray();
            }
            if (output.Count >= 10001) return output.ToArray();
        }
        foreach (var session in sessions.DistinctBy(s => s["session_row_id"]?.ToString()))
            foreach (var anchor in known.Where(e => N(e, "domain_id") == N(session, "domain_id") && Sid(e, true) == Sid(session, true)))
                if (session["started_at_utc"] is not null && Time(session, "started_at_utc") < Time(anchor) && Time(anchor) < Time(session, session["stopped_at_utc"] is not null ? "stopped_at_utc" : "last_observed_at_utc"))
                { var activity = session.Copy(); activity["source"] = "RADIUS Accounting"; Append(anchor, activity, "vpn_continuation"); if (output.Count >= 10001) return output.ToArray(); }
        return output.ToArray();
    }
}
