using System.Text.Json.Nodes;
using Sli.Server.Auth;

namespace Sli.Server.Notifications;

public sealed class NotificationAdministration(INotificationAdministrationRepository repository, INotificationSetupClient setup, INotificationRecipientAccess recipients)
{
    public async Task<JsonObject> TelegramAsync(Principal actor, string action, JsonObject body, CancellationToken ct)
    {
        if (actor.Type != "session" || actor.Id <= 0) throw new NotificationException("notification_channels_access_denied", 403);
        try
        {
            switch (action)
            {
                case "token":
                    if (body.ContainsKey("proxy_url")) { NotificationInput.Keys(body, "token", "proxy_url"); body["proxy_url"] = NotificationInput.Proxy(NotificationInput.Text(body, "proxy_url")); }
                    else NotificationInput.Keys(body, "token");
                    break;
                case "bind": NotificationInput.Keys(body, "choice"); break;
                case "status" or "chats" or "test": NotificationInput.Keys(body); break;
                default: throw new NotificationException("invalid_notification_request");
            }
        }
        catch (NotificationException ex) when (ex.Code == "invalid_notification_request") { throw new NotificationException("invalid_notification_channel_metadata"); }
        if (action != "status") await repository.AuditSetupAsync(actor, "telegram", action, "requested", ct);
        if (action == "token")
        {
            await setup.RequestAsync("verify", actor.Id, body, ct);
            await repository.TelegramChannelAsync(actor, false, action, "verified", ct);
        }
        if (action == "test")
        {
            await setup.RequestAsync("status", actor.Id, new(), ct);
            var own = (await repository.SubscriptionsAsync(ct)).OfType<JsonObject>().FirstOrDefault(s => Self(s, actor.Id, "telegram") && s["enabled"]!.GetValue<bool>())
                ?? throw new NotificationException("invalid_notification_channel_metadata");
            var job = await repository.EnqueueAsync(actor, own["id"]!.GetValue<string>(), Guid.NewGuid(), ct, channelAudit: true);
            return new JsonObject { ["job_id"] = job["id"]!.DeepClone(), ["state"] = job["state"]!.DeepClone() };
        }
        var result = await setup.RequestAsync(action, actor.Id, body, ct);
        if (action is "token" or "chats") await repository.AuditSetupAsync(actor, "telegram", action, "completed", ct);
        if (action == "bind")
        {
            var existing = (await repository.SubscriptionsAsync(ct)).OfType<JsonObject>().FirstOrDefault(s => Self(s, actor.Id, "telegram"));
            var values = new JsonObject { ["recipient_user_id"] = actor.Id, ["channel"] = "telegram", ["enabled"] = true };
            if (existing is not null) values["revision"] = existing["revision"]!.DeepClone();
            await repository.SaveSubscriptionAsync(actor, existing?["id"]!.GetValue<string>(), values, ct, channelAudit: true);
            await repository.TelegramChannelAsync(actor, true, action, "completed", ct);
        }
        if (action == "status")
        {
            NotificationSetupClient.ValidateStatus(result);
            var job = await repository.LatestTelegramTestAsync(actor.Id, ct);
            result["test_state"] = job?["state"]?.DeepClone(); result["test_job_id"] = job?["id"]?.DeepClone();
        }
        return result;
    }
    private static bool Self(JsonObject s, long user, string channel) => s["owner_user_id"]!.GetValue<long>() == user && s["recipient_user_id"]!.GetValue<long>() == user && s["channel"]!.GetValue<string>() == channel;

    public async Task<JsonObject> SmtpAsync(Principal actor, string action, JsonObject body, CancellationToken ct)
    {
        if (actor.Type != "session" || actor.Id <= 0) throw new NotificationException("notification_channels_access_denied", 403);
        try { NotificationInput.Keys(body, action == "status" ? [] : action == "save" ? ["host", "port", "username", "sender", "password", "recipients", "revision", "tls_mode", "enabled"] : ["invalid"]); }
        catch (NotificationException) { throw NotificationException.Setup("smtp_setup_invalid"); }
        var subscriptions = (await repository.SubscriptionsAsync(ct)).OfType<JsonObject>().Where(s => s["channel"]!.GetValue<string>() == "smtp").ToArray();
        var allowed = subscriptions.Select(s => s["recipient_user_id"]!.GetValue<long>()).Append(actor.Id).ToHashSet();
        if (action == "status") return await repository.SmtpStatusAsync(async channel =>
        {
            var status = await setup.RequestAsync("smtp_status", actor.Id, new JsonObject { ["revision"] = channel["revision"]!.DeepClone() }, ct);
            try
            {
                NotificationInput.Keys(status, "host", "port", "username", "sender", "recipients", "secret_set", "needs_save");
                NotificationInput.Boolean(status, "secret_set"); NotificationInput.Boolean(status, "needs_save");
                foreach (var key in new[] { "host", "username", "sender" }) NotificationInput.Text(status, key);
                NotificationInput.Positive(status, "port", 65535);
                if (status["recipients"] is not JsonObject mapping) throw new NotificationException("invalid_notification_request");
                status["recipients"] = new JsonArray(allowed.Order().Select(user => (JsonNode)new JsonObject { ["user_id"] = user, ["mailbox"] = mapping[user.ToString(System.Globalization.CultureInfo.InvariantCulture)]?.DeepClone() ?? JsonValue.Create("") }).ToArray());
                status["self_user_id"] = actor.Id; status["revision"] = channel["revision"]!.DeepClone();
                status["tls_mode"] = channel["tls_mode"]!.DeepClone(); status["enabled"] = channel["enabled"]!.DeepClone();
                return status;
            }
            catch { throw NotificationException.Setup("smtp_setup_unavailable"); }
        }, ct);

        var metadata = new JsonObject { ["revision"] = body["revision"]?.DeepClone(), ["tls_mode"] = body["tls_mode"]?.DeepClone(),
            ["enabled"] = body["enabled"]?.DeepClone(), ["secret_ref"] = NotificationInput.SecretRefs["smtp"] };
        NotificationInput.Channel("smtp", metadata);
        JsonObject recipientsMap;
        try
        {
            if (body["recipients"] is not JsonArray rows || rows.Count != allowed.Count) throw new FormatException();
            var seen = new HashSet<long>(); recipientsMap = new JsonObject();
            foreach (var row in rows)
            {
                if (row is not JsonObject entry) throw new FormatException();
                NotificationInput.Keys(entry, "user_id", "mailbox");
                long user = NotificationInput.Positive(entry, "user_id", long.MaxValue);
                if (!allowed.Contains(user) || !seen.Add(user)) throw new FormatException();
                var mailbox = NotificationInput.Text(entry, "mailbox");
                if (mailbox.Length > 0) { SetupSmtpSnapshot.ValidateMailbox(mailbox); recipientsMap[user.ToString(System.Globalization.CultureInfo.InvariantCulture)] = mailbox; }
            }
            if (!recipientsMap.ContainsKey(actor.Id.ToString(System.Globalization.CultureInfo.InvariantCulture))) throw new FormatException();
            var config = new JsonObject(); foreach (var key in new[] { "host", "port", "username", "sender" }) config[key] = body[key]?.DeepClone();
            config["recipients"] = recipientsMap.DeepClone(); config["base_url"] = "https://validation.invalid/app";
            SetupSmtpSnapshot.ValidateConfig(config);
            string password = NotificationInput.Text(body, "password"); if (password.Length > 0) SetupSmtpSnapshot.ValidatePassword(password);
        }
        catch { throw NotificationException.Setup("smtp_setup_invalid"); }
        foreach (var user in recipientsMap.Select(p => long.Parse(p.Key, System.Globalization.CultureInfo.InvariantCulture))) await recipients.RequireAsync(user, ct);
        foreach (var subscription in subscriptions.Where(s => s["enabled"]!.GetValue<bool>() && recipientsMap.ContainsKey(s["recipient_user_id"]!.ToString())))
            await recipients.RequireAsync(subscription["owner_user_id"]!.GetValue<long>(), ct);
        long revision = await repository.SmtpSaveAsync(actor, metadata, async () =>
        {
            if (!subscriptions.Any(s => Self(s, actor.Id, "smtp")))
                await repository.SaveSubscriptionAsync(actor, null, new JsonObject { ["recipient_user_id"] = actor.Id, ["channel"] = "smtp", ["enabled"] = true }, ct, channelAudit: true);
        }, async reserved =>
        {
            var request = new JsonObject(); foreach (var key in new[] { "host", "port", "username", "sender", "password" }) request[key] = body[key]?.DeepClone();
            request["recipients"] = recipientsMap.DeepClone(); request["previous_revision"] = metadata["revision"]!.DeepClone(); request["revision"] = reserved;
            var response = await setup.RequestAsync("smtp_save", actor.Id, request, ct);
            if (!JsonNode.DeepEquals(response, JsonNode.Parse("{\"secret_set\":true,\"needs_save\":false}"))) throw NotificationException.Setup("smtp_setup_unavailable");
        }, ct);
        return new JsonObject { ["secret_set"] = true, ["needs_save"] = false, ["revision"] = revision };
    }
}
