using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;
using Sli.Server.Access;
using Sli.Server.Access.Administration;
using Sli.Server.Auth;
using Sli.Server.Infrastructure;

namespace Sli.Server.Notifications;

public interface INotificationRecipientAccess { Task RequireAsync(long user, CancellationToken ct); }
public sealed class NotificationRecipientAccess(IPostgresConnectionFactory database, IAccessFactsRepository facts) : INotificationRecipientAccess
{
    public async Task RequireAsync(long user, CancellationToken ct)
    {
        var principal = await new AccessReadService(database).FindUserAsync(user, ct);
        if (principal is not null)
        {
            var loaded = await facts.LoadAsync(principal, ct);
            if (NotificationAccess.Queue(new ReportEligibility().Compose(loaded, new CapabilityComposer().Compose(loaded)))) return;
        }
        throw new NotificationException("notifications_access_denied", 403);
    }
}

public interface INotificationAdministrationRepository
{
    Task<JsonArray> ChannelsAsync(CancellationToken ct);
    Task<JsonArray> SubscriptionsAsync(CancellationToken ct);
    Task<JsonObject> WorkspaceAsync(Principal actor, NotificationWorkspaceQuery query, bool link, bool configure, CancellationToken ct);
    Task<JsonObject> UpdateChannelAsync(Principal actor, string kind, JsonObject body, CancellationToken ct);
    Task<JsonObject> SaveSubscriptionAsync(Principal actor, string? id, JsonObject body, CancellationToken ct, bool channelAudit = false);
    Task<JsonObject> EnqueueAsync(Principal actor, string id, Guid problem, CancellationToken ct, bool channelAudit = false);
    Task AuditSetupAsync(Principal actor, string kind, string operation, string phase, CancellationToken ct);
    Task TelegramChannelAsync(Principal actor, bool enabled, string operation, string phase, CancellationToken ct);
    Task<JsonObject?> LatestTelegramTestAsync(long user, CancellationToken ct);
    Task<JsonArray> DiscoveredTelegramChatsAsync(string generation, CancellationToken ct);
    Task<JsonObject> SmtpStatusAsync(Func<JsonObject, Task<JsonObject>> read, CancellationToken ct);
    Task<long> SmtpSaveAsync(Principal actor, JsonObject metadata, Func<Task> bindSelf, Func<long, Task> publish, CancellationToken ct);
}

public sealed class NotificationAdministrationRepository(IPostgresConnectionFactory database, INotificationRecipientAccess recipients) : INotificationAdministrationRepository
{
    public async Task<JsonArray> DiscoveredTelegramChatsAsync(string generation, CancellationToken ct)
    {
        await using var db = await database.OpenAsync(ct);
        await using var command = new NpgsqlCommand("""
            select chat_id,chat_name from public.telegram_discovered_chats
            where bot_generation=@generation and seen_at >= statement_timestamp() - interval '10 minutes'
            order by seen_at desc,chat_id limit 40
            """, db);
        command.Parameters.AddWithValue("generation", generation);
        await using var rows = await command.ExecuteReaderAsync(ct);
        var chats = new JsonArray();
        while (await rows.ReadAsync(ct))
            chats.Add(new JsonObject { ["id"] = rows.GetInt64(0), ["name"] = rows.GetString(1) });
        return chats;
    }

    public const string ChannelFields = "kind,enabled,tls_mode,secret_ref,state,revision,updated_at";
    public const string SubscriptionFields = "id,owner_user_id,recipient_user_id,channel,enabled,revision,updated_at";
    public const string JobFields = "id,subscription_id,object_id,channel,state,attempts,result_code,created_at,updated_at,delivery_reason,delay_minutes";
    private static NpgsqlCommand Command(NpgsqlConnection db, NpgsqlTransaction? tx, string sql, params (string, object?)[] values)
    {
        var command = new NpgsqlCommand(sql, db, tx);
        foreach (var (name, value) in values)
        {
            if (value is null) command.Parameters.Add(new NpgsqlParameter(name, NpgsqlDbType.Unknown) { Value = DBNull.Value });
            else command.Parameters.AddWithValue(name, value);
        }
        return command;
    }
    private static async Task<JsonArray> Rows(NpgsqlConnection db, NpgsqlTransaction? tx, string sql, CancellationToken ct, params (string, object?)[] values)
    {
        await using var command = Command(db, tx, "select to_jsonb(r) from (" + sql + ") r", values);
        await using var reader = await command.ExecuteReaderAsync(ct);
        var rows = new JsonArray();
        while (await reader.ReadAsync(ct)) rows.Add(StampRow(JsonNode.Parse(reader.GetString(0))!.AsObject()));
        return rows;
    }
    private static JsonObject StampRow(JsonObject row)
    {
        foreach (string key in new[] { "created_at", "updated_at", "available_at", "last_accepted_at", "last_attempt_at", "previous_login_at" })
        {
            if (row[key] is JsonValue value && value.TryGetValue<string>(out var raw) && DateTimeOffset.TryParse(raw, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var time))
            {
                string stamp = AssignmentAudit.Stamp(time);
                row[key] = key == "previous_login_at" ? stamp.Replace(' ', 'T') : stamp;
            }
        }
        return row;
    }
    private static async Task Execute(NpgsqlConnection db, NpgsqlTransaction? tx, string sql, CancellationToken ct, params (string, object?)[] values)
    { await using var command = Command(db, tx, sql, values); await command.ExecuteNonQueryAsync(ct); }
    private static async Task<JsonObject?> Mutate(NpgsqlConnection db, NpgsqlTransaction tx, string sql, CancellationToken ct, params (string, object?)[] values)
    {
        await using var command = Command(db, tx, "with changed as (" + sql + ") select to_jsonb(changed) from changed", values);
        var value = await command.ExecuteScalarAsync(ct);
        return value is string json ? StampRow(JsonNode.Parse(json)!.AsObject()) : null;
    }
    private static JsonObject Project(JsonObject row, string fields) => new(fields.Split(',').Select(k => KeyValuePair.Create(k, row[k]?.DeepClone())));
    private static Task Audit(NpgsqlConnection db, NpgsqlTransaction tx, Principal actor, string action, string target, string key, object details, CancellationToken ct) =>
        Execute(db, tx, """
            insert into access_audit_v4(actor_type,actor_id,action,target_type,target_key,outcome,details_json)
            values(@type,@actor,@action,@target,@key,'ok',@details::jsonb)
            """, ct, ("type", actor.Type.Length == 0 ? "local" : actor.Type), ("actor", actor.Id > 0 ? actor.Id : null),
            ("action", action), ("target", target), ("key", key), ("details", JsonSerializer.Serialize(details)));
    private static Task SetupAudit(NpgsqlConnection db, NpgsqlTransaction tx, Principal actor, string kind, string operation, string phase, CancellationToken ct) =>
        Audit(db, tx, actor, "notification_channel_update", "notification_channel", kind, new { kind, operation, phase }, ct);

    public async Task<JsonArray> ChannelsAsync(CancellationToken ct)
    { await using var db = await database.OpenAsync(ct); return await Rows(db, null, "select " + ChannelFields + " from notification_channels order by kind", ct); }
    public async Task<JsonArray> SubscriptionsAsync(CancellationToken ct)
    { await using var db = await database.OpenAsync(ct); return await Rows(db, null, "select " + SubscriptionFields + " from notification_subscriptions order by id limit 1000", ct); }

    public async Task<JsonObject> UpdateChannelAsync(Principal actor, string kind, JsonObject body, CancellationToken ct)
    {
        await using var db = await database.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        var item = await Mutate(db, tx, """
            update notification_channels set enabled=@enabled,tls_mode=@tls,secret_ref=@secret,revision=revision+1,updated_at=clock_timestamp()
            where kind=@kind and revision=@revision returning *
            """, ct, ("enabled", NotificationInput.Boolean(body, "enabled")), ("tls", NotificationInput.Text(body, "tls_mode")),
            ("secret", NotificationInput.Text(body, "secret_ref")), ("kind", kind), ("revision", NotificationInput.Positive(body, "revision")))
            ?? throw new NotificationException("notification_channel_revision_conflict", 409);
        await Audit(db, tx, actor, "notification_channel_update", "notification_channel", kind,
            new { kind, revision = item["revision"]!.GetValue<long>(), changed_fields = new[] { "enabled", "tls_mode", "secret_ref" } }, ct);
        await tx.CommitAsync(ct); return Project(item, ChannelFields);
    }

    public async Task<JsonObject> SaveSubscriptionAsync(Principal actor, string? id, JsonObject body, CancellationToken ct, bool channelAudit = false)
    {
        bool enabled = NotificationInput.Boolean(body, "enabled"); long recipient = NotificationInput.Positive(body, "recipient_user_id");
        if (enabled) { await recipients.RequireAsync(recipient, ct); if (id is null) await recipients.RequireAsync(actor.Id, ct); }
        var key = id is null ? Guid.NewGuid() : NotificationInput.Id(id);
        await using var db = await database.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        var row = await Mutate(db, tx, id is null ? """
            insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled)
            values(@id,@owner,@recipient,@channel,@enabled) returning *
            """ : """
            update notification_subscriptions set recipient_user_id=@recipient,channel=@channel,enabled=@enabled,
              revision=revision+1,updated_at=clock_timestamp() where id=@id and revision=@revision returning *
            """, ct, ("id", key), ("owner", actor.Id), ("recipient", recipient), ("channel", NotificationInput.Text(body, "channel")),
            ("enabled", enabled), ("revision", id is null ? 0L : NotificationInput.Positive(body, "revision")))
            ?? throw new NotificationException("notification_subscription_conflict", 409);
        if (enabled && id is not null) await recipients.RequireAsync(row["owner_user_id"]!.GetValue<long>(), ct);
        if (id is not null) await Execute(db, tx, """
            update notification_outbox set state='cancelled',result_code='subscription_changed',lease_token=null,lease_until=null,
              updated_at=clock_timestamp() where subscription_id=@id and state in ('pending','sending','retry')
            """, ct, ("id", key));
        await Audit(db, tx, actor, channelAudit ? "notification_channel_update" : "notification_subscription_update", channelAudit ? "notification_channel" : "notification", channelAudit ? "telegram" : key.ToString(), new { id = key, revision = row["revision"]!.GetValue<long>() }, ct);
        await tx.CommitAsync(ct); return Project(row, SubscriptionFields);
    }

    public async Task<JsonObject> EnqueueAsync(Principal actor, string id, Guid problem, CancellationToken ct, bool channelAudit = false)
    {
        await using var db = await database.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        var subscription = (await Rows(db, tx, "select * from notification_subscriptions where id=@id for share", ct, ("id", NotificationInput.Id(id)))).FirstOrDefault()?.AsObject();
        if (subscription is null || !subscription["enabled"]!.GetValue<bool>()) throw new NotificationException("notification_subscription_conflict", 409);
        long recipient = subscription["recipient_user_id"]!.GetValue<long>(); string channel = subscription["channel"]!.GetValue<string>();
        await recipients.RequireAsync(subscription["owner_user_id"]!.GetValue<long>(), ct); await recipients.RequireAsync(recipient, ct);
        await Execute(db, tx, "select pg_advisory_xact_lock(hashtext('notification_outbox_admission'))", ct);
        var row = (await Rows(db, tx, "select * from notification_outbox where object_kind='test_problem' and object_id=@problem and recipient_user_id=@recipient and channel=@channel", ct,
            ("problem", problem), ("recipient", recipient), ("channel", channel))).FirstOrDefault()?.AsObject();
        if (row is null)
        {
            await using var count = Command(db, tx, "select count(*) from notification_outbox where state in ('pending','sending','retry')");
            if ((long)(await count.ExecuteScalarAsync(ct))! >= 10000) throw new NotificationException("notification_queue_full", 429);
            row = await Mutate(db, tx, """
                insert into notification_outbox(id,subscription_id,subscription_revision,object_kind,object_id,recipient_user_id,channel)
                values(@id,@subscription,@revision,'test_problem',@problem,@recipient,@channel) on conflict do nothing returning *
                """, ct, ("id", Guid.NewGuid()), ("subscription", NotificationInput.Id(id)), ("revision", subscription["revision"]!.GetValue<long>()),
                ("problem", problem), ("recipient", recipient), ("channel", channel)) ?? throw new InvalidOperationException();
        }
        await Audit(db, tx, actor, channelAudit ? "notification_channel_update" : "notification_test_enqueue", channelAudit ? "notification_channel" : "notification", channelAudit ? "telegram" : row["id"]!.GetValue<string>(), new { id = row["id"]!.GetValue<string>(), simulated = true }, ct);
        await tx.CommitAsync(ct); return Project(row, JobFields);
    }

    public async Task AuditSetupAsync(Principal actor, string kind, string operation, string phase, CancellationToken ct)
    { await using var db = await database.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct); await SetupAudit(db, tx, actor, kind, operation, phase, ct); await tx.CommitAsync(ct); }
    public async Task TelegramChannelAsync(Principal actor, bool enabled, string operation, string phase, CancellationToken ct)
    {
        await using var db = await database.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
        await Execute(db, tx, "update notification_channels set enabled=@enabled,revision=revision+1,updated_at=clock_timestamp() where kind='telegram'", ct, ("enabled", enabled));
        await SetupAudit(db, tx, actor, "telegram", operation, phase, ct); await tx.CommitAsync(ct);
    }
    public async Task<JsonObject?> LatestTelegramTestAsync(long user, CancellationToken ct)
    {
        await using var db = await database.OpenAsync(ct);
        return (await Rows(db, null, "select id,state,updated_at from notification_outbox where channel='telegram' and recipient_user_id=@user and object_kind='test_problem' order by created_at desc,id desc limit 1", ct, ("user", user))).FirstOrDefault()?.AsObject();
    }

    public async Task<JsonObject> SmtpStatusAsync(Func<JsonObject, Task<JsonObject>> read, CancellationToken ct)
    {
        await using var db = await database.OpenAsync(ct);
        await using var locked = Command(db, null, "select pg_try_advisory_lock_shared(hashtext('sli_smtp_setup'))");
        if (await locked.ExecuteScalarAsync(ct) is not true) throw NotificationException.Setup("smtp_setup_conflict");
        try
        {
            await using var tx = await db.BeginTransactionAsync(ct);
            var row = (await Rows(db, tx, "select enabled,revision,tls_mode from notification_channels where kind='smtp' for share", ct)).FirstOrDefault()?.AsObject()
                ?? throw NotificationException.Setup("smtp_setup_unavailable");
            return await read(row);
        }
        finally { await Execute(db, null, "select pg_advisory_unlock_shared(hashtext('sli_smtp_setup'))", CancellationToken.None); }
    }

    public async Task<long> SmtpSaveAsync(Principal actor, JsonObject metadata, Func<Task> bindSelf, Func<long, Task> publish, CancellationToken ct)
    {
        await using var db = await database.OpenAsync(ct);
        await using var locked = Command(db, null, "select pg_try_advisory_lock(hashtext('sli_smtp_setup'))");
        if (await locked.ExecuteScalarAsync(ct) is not true) throw NotificationException.Setup("smtp_setup_conflict");
        try
        {
            long revision;
            await using (var tx = await db.BeginTransactionAsync(ct))
            {
                var row = await Mutate(db, tx, "update notification_channels set enabled=false,revision=revision+1,updated_at=clock_timestamp() where kind='smtp' and revision=@revision returning revision", ct,
                    ("revision", NotificationInput.Positive(metadata, "revision"))) ?? throw NotificationException.Setup("smtp_setup_conflict");
                revision = row["revision"]!.GetValue<long>();
                await SetupAudit(db, tx, actor, "smtp", "save", "requested", ct); await tx.CommitAsync(ct);
            }
            // The reservation is durable even if publication fails; dispatch stays disabled.
            await bindSelf();
            await using (var tx = await db.BeginTransactionAsync(ct))
            {
                var row = (await Rows(db, tx, "select enabled,revision from notification_channels where kind='smtp' for update", ct)).FirstOrDefault()?.AsObject();
                if (row is null || row["revision"]!.GetValue<long>() != revision || row["enabled"]!.GetValue<bool>()) throw NotificationException.Setup("smtp_setup_conflict");
                await publish(revision);
                await Execute(db, tx, "update notification_channels set enabled=@enabled,tls_mode=@tls,updated_at=clock_timestamp() where kind='smtp'", ct,
                    ("enabled", NotificationInput.Boolean(metadata, "enabled")), ("tls", NotificationInput.Text(metadata, "tls_mode")));
                await SetupAudit(db, tx, actor, "smtp", "save", "completed", ct); await tx.CommitAsync(ct);
            }
            return revision;
        }
        finally { await Execute(db, null, "select pg_advisory_unlock(hashtext('sli_smtp_setup'))", CancellationToken.None); }
    }

    public async Task<JsonObject> WorkspaceAsync(Principal actor, NotificationWorkspaceQuery query, bool link, bool configure, CancellationToken ct)
    {
        await using var db = await database.OpenAsync(ct);
        string? since = null;
        if (actor.Type == "session")
        {
            var baseline = (await Rows(db, null, "select previous_login_at from auth_users where id=@user", ct, ("user", actor.Id))).FirstOrDefault();
            since = baseline?["previous_login_at"]?.GetValue<string>();
        }
        var parameters = new List<(string, object?)> { ("days", query.Days), ("since", since), ("channel", query.Channel), ("finding", query.Finding) };
        string where = "created_at>=clock_timestamp()-(@days * interval '1 day')";
        if (query.Channel is not null) where += " and channel=@channel";
        if (query.Finding is not null) where += " and object_kind='semantic_finding' and public.notification_finding_object(object_id)=@finding";
        var counts = (await Rows(db, null, """
            select count(*) as total,count(*) filter(where state='accepted') as accepted,
              count(*) filter(where state in ('failed','blocked','delivery_unknown')) as errors,
              count(*) filter(where state in ('pending','sending','retry')) as waiting,
              count(*) filter(where state in ('dry_run','cancelled')) as other,
              case when @since::timestamptz is null then null else count(*) filter(where created_at>@since::timestamptz) end as new_count
            from notification_outbox where
            """ + " " + where, ct, parameters.ToArray()))[0]!.DeepClone().AsObject();
        if (query.Status is not null) { where += " and state=any(@states)"; parameters.Add(("states", NotificationWorkspaceQuery.States[query.Status])); }
        if (query.Before is not null)
        { where += " and (created_at,id)<(@before,@before_id)"; parameters.Add(("before", query.Before.Value.UtcDateTime)); parameters.Add(("before_id", query.BeforeId)); }
        string finding = link ? "case when object_kind='semantic_finding' then public.notification_finding_object(object_id) end" : "null::bigint";
        var items = await Rows(db, null, "select " + JobFields + ",object_kind,object_severity,available_at," + finding + " as finding_id from notification_outbox where " + where + " order by created_at desc,id desc limit 101", ct, parameters.ToArray());
        bool more = items.Count > 100; if (more) items.RemoveAt(100);
        var channels = await Rows(db, null, "select " + string.Join(',', ChannelFields.Split(',').Select(k => "c." + k)) + """
            ,(select max(updated_at) from notification_outbox where channel=c.kind and state='accepted') as last_accepted_at,
            (select result_code from notification_outbox where channel=c.kind order by updated_at desc,id desc limit 1) as last_result_code,
            (select updated_at from notification_outbox where channel=c.kind order by updated_at desc,id desc limit 1) as last_attempt_at,
            null::text as secret_status from notification_channels c order by kind
            """, ct);
        return new JsonObject { ["channels"] = channels, ["subscriptions"] = await SubscriptionsAsync(ct), ["counts"] = counts,
            ["items"] = items, ["has_more"] = more, ["next_cursor"] = more ? query.Cursor(items[^1]!.AsObject()) : null,
            ["previous_login_at"] = since, ["can_configure"] = configure };
    }
}
