import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { api, ApiResponseError } from "../../api/client";
import type { NotificationDelivery, NotificationKind, NotificationSubscription } from "../../api/notification-types";
import { Button } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { utcToLocalDateTimeInput } from "../../shared/date-time";
import { useTimeZone } from "../../shared/time-zone";

const resultCodes = new Set(["simulated", "subscription_changed", "recipient_denied", "access_unavailable", "transport_unavailable", "accepted",
  "smtp_not_configured", "smtp_auth_failed", "smtp_rejected", "smtp_unavailable", "smtp_outcome_unknown",
  "telegram_not_configured", "telegram_auth_failed", "telegram_chat_denied", "telegram_rejected", "telegram_rate_limited", "telegram_unavailable", "telegram_outcome_unknown",
  "historical_replay", "history_import"]);
export const resultLabel = (value: string | null) => value && resultCodes.has(value)
  ? t(`reports.v2.notifications.deliveries.columns.result_code.labels.${value}` as MessageKey) : "—";
export const deliveryFinished = (state: string) => ["accepted", "failed", "blocked", "cancelled", "delivery_unknown", "dry_run"].includes(state);
export function useNotificationTime() {
  const { timeZone } = useTimeZone();
  return (value: string | null | undefined) => {
    try { return utcToLocalDateTimeInput(value, timeZone).slice(11, 16) || "—"; }
    catch { return "—"; }
  };
}

/** The existing channel test, shared by both setup panels. */
export function ChannelTest({ channel, enabled, subscriptions = [], destination, onRefresh }: {
  channel: NotificationKind; enabled: boolean; subscriptions?: NotificationSubscription[];
  destination?: (item: NotificationSubscription) => string; onRefresh: () => void;
}) {
  const time = useNotificationTime();
  const bindings = subscriptions.filter((item) => item.enabled && item.channel === channel);
  const [selected, setSelected] = useState("");
  const recipient = selected || bindings[0]?.id || "";
  const [problemId, setProblemId] = useState(() => crypto.randomUUID());
  const [job, setJob] = useState<{ id: string; item?: NotificationDelivery }>();
  const submitting = useRef(false);
  const mutation = useMutation({ mutationFn: async () => {
    if (channel === "telegram") {
      const result = await api.telegramSetup("test");
      if (!result.job_id) throw new Error("invalid_notification_response");
      return { id: result.job_id };
    }
    const result = await api.testNotificationChannel(recipient, problemId);
    return { id: result.item.id, item: result.item };
  }, onSuccess: (result) => { setJob(result); setProblemId(crypto.randomUUID()); onRefresh(); },
  onSettled: () => { submitting.current = false; } });
  const result = useQuery({ queryKey: ["notification-test", channel, job?.id], enabled: !!job,
    queryFn: async () => {
      // Find this job across the server's pages; never substitute another delivery.
      let cursor: string | null = null;
      const seen = new Set<string>();
      do {
        const params = new URLSearchParams({ days: "1", channel });
        if (cursor) params.set("cursor", cursor);
        const page = await api.notificationWorkspace(params);
        const found = page.items.find((item) => item.id === job?.id && item.channel === channel);
        if (found) return found;
        cursor = page.has_more ? page.next_cursor : null;
        if (cursor && seen.has(cursor)) break;
        if (cursor) seen.add(cursor);
      } while (cursor);
      return null;
    }, retry: false,
    refetchInterval: (query) => deliveryFinished(query.state.data?.state ?? job?.item?.state ?? "") ? false : 2000,
  });
  const item = result.data ?? job?.item;
  const refresh = useRef(onRefresh);
  refresh.current = onRefresh;
  useEffect(() => {
    if (item && deliveryFinished(item.state)) refresh.current();
  }, [item?.id, item?.state, item?.updated_at]);
  const pending = !!job && !deliveryFinished(item?.state ?? "");
  const channelLabel = t(`reports.v2.notifications.channels.columns.kind.labels.${channel}`);
  const error = mutation.error instanceof ApiResponseError && mutation.error.status === 403 ? t("notify.denied")
    : mutation.error instanceof ApiResponseError && mutation.error.status === 409 ? t("notify.conflict") : t("notify.testFailed", { channel: channelLabel });
  const send = () => {
    if (!enabled || submitting.current || mutation.isPending || pending || (channel === "smtp" && !recipient)) return;
    submitting.current = true;
    if (job && deliveryFinished(item?.state ?? "")) setJob(undefined);
    mutation.mutate();
  };
  return <section>
    {channel === "smtp" && bindings.length > 1 ? <div className="sli-ds-field">
      <label htmlFor="notify-test-recipient">{t("notify.destination")}</label>
      <select id="notify-test-recipient" value={recipient} disabled={!enabled || mutation.isPending || pending}
        onChange={(event) => { setSelected(event.target.value); setProblemId(crypto.randomUUID()); }}>
        {bindings.map((binding) => <option key={binding.id} value={binding.id}>{destination?.(binding) || "—"}</option>)}
      </select>
    </div> : null}
    <Button disabled={!enabled || mutation.isPending || pending || (channel === "smtp" && !recipient)} onClick={send}>{t("notify.sendTest")}</Button>
    {mutation.isError ? <p role="alert">{error}</p> : null}
    {job ? result.isError ? <p role="alert">{t("notify.testResultFailed", { channel: channelLabel })} <Button onClick={() => void result.refetch()}>{t("notify.smtp.retry")}</Button></p>
      : <p role="status">{!item || !deliveryFinished(item.state) ? t("notify.telegram.waiting")
        : item.state === "accepted" ? t("notify.deliveredAt", { time: time(item.updated_at) })
          : t("notify.channelError", { error: resultLabel(item.result_code) === "—" ? t("notify.deliveryFailed") : resultLabel(item.result_code), time: `, ${time(item.updated_at)}` })}</p> : null}
  </section>;
}
