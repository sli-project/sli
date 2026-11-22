using System.Globalization;
using System.Text.Json.Nodes;
using Sli.Server.Auth;

namespace Sli.Server.Problems;

public sealed record QueueDecision(long[] Ids, string? State, long? Assignee, bool Assign, DateTimeOffset? Until, string? Classification, string? Comment)
{
    public static QueueDecision Parse(JsonObject body, DateTimeOffset now)
    {
        const string invalid = "invalid_queue_decision";
        var ids = ProblemJson.Array(body["ids"]);
        if (ids.Count is < 1 or > 200) throw new ProblemException(invalid);
        var findingIds = ids.Select(id => ProblemJson.Id(id, invalid, ProblemJson.SafeInteger - 1)).Distinct().Order().ToArray();
        string? state = body.ContainsKey("state") ? ProblemJson.StrictText(body["state"], 24, invalid) : null;
        bool assign = body.ContainsKey("assignee_id");
        long? assignee = body["assignee_id"] is {} user ? ProblemJson.Id(user, invalid) : null;
        if (state is not (null or "new" or "active" or "deferred" or "closed" or "false_positive") || state is null && !assign)
            throw new ProblemException(invalid);
        string? classification = body.ContainsKey("classification") ? ProblemJson.StrictText(body["classification"], 24, invalid) : null;
        if (state == "closed" ? classification is not ("fixed" or "expected") :
            state == "false_positive" ? classification != "false_positive" : classification is not null)
            throw new ProblemException(invalid);
        DateTimeOffset? until = null;
        if (state == "deferred")
        {
            if (!ProblemJson.Stamp(body["until"], out var stamp) || stamp <= now) throw new ProblemException("invalid_expiry");
            until = stamp.ToUniversalTime();
        }
        else if (body.ContainsKey("until")) throw new ProblemException(invalid);
        string? comment = body["comment"] is null ? null : ProblemJson.Text(body["comment"]).Trim();
        if (comment is not null && (comment.Length == 0 || comment.EnumerateRunes().Count() > 2000 || comment.Contains('\0')))
            throw new ProblemException(invalid);
        return new(findingIds, state, assignee, assign, until, classification, comment);
    }
}

public sealed partial class ProblemRepository
{
    public async Task<JsonObject> QueueDecisionAsync(QueueDecision input, ProblemAccess access, Principal principal, CancellationToken ct)
    {
        var domains = access.Scope("security.queue").Domains();
        if (input.Assign && !access.Fields("identity_basic")) throw new ProblemException("report_field_categories_not_allowed", 403);
        string actor = ProblemJson.Actor(principal, true).Trim();
        if (actor.Length is < 1 or > 200) throw new ProblemException("actor_required");

        await using var db = await connections.OpenAsync(ct);
        await using var tx = await db.BeginTransactionAsync(ct);
        var args = new Dictionary<string, object?> { ["ids"] = input.Ids, ["domains"] = domains, ["actor"] = actor, ["until"] = input.Until };
        string? assignee = null;
        if (input.Assignee is {} user)
        {
            args["user"] = user;
            var responsible = await One(tx, "select username from auth_users where id=@user and is_active for share", args, ct)
                ?? throw new ProblemException("responsible_not_found");
            assignee = ProblemJson.Text(responsible["username"]);
        }
        var rows = await Rows(tx, """
            select f.id, f.status, f.assigned_to
            from findings f where f.id=any(@ids) and is_semantic_finding_published_v1(f.id)
              and (f.rule_code<>'semantic.qw.file-acl-broad-write' or semantic_finding_in_domains_v265(f.id,null))
              and (@domains::bigint[] is null or semantic_finding_in_domains_v265(f.id,@domains::bigint[]))
            order by f.id for update of f
            """, args, ct);
        if (rows.Count != input.Ids.Length) throw new ProblemException("not_found", 404);
        var deferrals = (await Rows(tx, "select finding_id,until_at from finding_queue_deferrals where finding_id=any(@ids)", args, ct))
            .OfType<JsonObject>().ToDictionary(row => ProblemJson.Long(row["finding_id"]));
        var now = clock.GetUtcNow();
        if (input.Until <= now) throw new ProblemException("invalid_expiry");
        int changed = 0;
        foreach (var row in rows.OfType<JsonObject>())
        {
            long id = ProblemJson.Long(row["id"]);
            string status = ProblemJson.Text(row["status"]);
            args["id"] = id;
            bool hasDeferral = ProblemJson.Stamp(deferrals.GetValueOrDefault(id)?["until_at"], out var oldUntil) && status is "new" or "confirmed" or "repeated";
            bool deferred = hasDeferral && oldUntil > now;
            if (hasDeferral && !deferred)
            {
                args["expired_at"] = oldUntil;
                args["expired_status"] = status;
                await Execute(tx, """
                    insert into finding_status_history(finding_id,old_status,new_status,changed_at,changed_by)
                    values(@id,'deferred',@expired_status,@expired_at,'system');
                    delete from finding_queue_deferrals where finding_id=@id
                    """, args, ct);
            }
            string old = deferred ? "deferred" : status;
            string next = input.State ?? old;
            string stored = input.State == "deferred" ? "new" : input.State ?? status;
            string? oldAssignee = row["assigned_to"]?.GetValue<string>();
            string? newAssignee = input.Assign ? assignee : oldAssignee;
            if (old == next && newAssignee == oldAssignee && (input.Until is null || input.Until == oldUntil)
                && input.Comment is null && input.Classification is null) continue;
            args["status"] = stored;
            args["assignee"] = newAssignee;
            args["reason"] = input.Classification ?? input.Comment;
            args["state_supplied"] = input.State is not null;
            await Execute(tx, """
                update findings set status=@status, assigned_to=@assignee,
                  status_reason=case when @state_supplied then @reason else status_reason end,
                  closed_at=case when @status in ('closed','false_positive') then coalesce(closed_at,now()::text) else null end,
                  updated_at=now() where id=@id
                """, args, ct);
            if (input.Until is not null)
                await Execute(tx, """
                    insert into finding_queue_deferrals(finding_id,until_at) values(@id,@until)
                    on conflict(finding_id) do update set until_at=excluded.until_at
                    """, args, ct);
            else if (input.State is not null)
                await Execute(tx, "delete from finding_queue_deferrals where finding_id=@id", args, ct);
            var decision = new JsonObject { ["classification"] = input.Classification, ["comment"] = input.Comment, ["until"] = input.Until,
                ["assignment_changed"] = newAssignee != oldAssignee, ["old_assignee"] = oldAssignee, ["new_assignee"] = newAssignee };
            args["old"] = old;
            args["next"] = next;
            args["note"] = "sli.queue:" + decision.ToJsonString();
            await Execute(tx, """
                insert into finding_status_history(finding_id,old_status,new_status,changed_by,note)
                values(@id,@old,@next,@actor,@note)
                """, args, ct);
            await Audit(tx, principal, "finding_queue_decision", "finding", id.ToString(CultureInfo.InvariantCulture),
                new JsonObject { ["from"] = old, ["to"] = next, ["decision"] = decision }, ct);
            changed++;
        }
        await tx.CommitAsync(ct);
        return new JsonObject { ["status"] = "ok", ["changed"] = changed };
    }
}
