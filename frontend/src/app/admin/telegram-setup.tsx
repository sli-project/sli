import { useMutation, useQuery } from "@tanstack/react-query";
import { useId, useState } from "react";
import { api, ApiResponseError } from "../../api/client";
import type { NotificationChannel, TelegramSetup, TelegramSetupErrorCode } from "../../api/notification-types";
import { Button, DetailDrawer, useOverlays } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { ChannelTest } from "./channel-test";

const errorMessages: Record<TelegramSetupErrorCode, MessageKey> = {
  telegram_setup_invalid_proxy: "notify.telegram.error.invalidProxy",
  telegram_setup_invalid_token: "notify.telegram.error.invalidToken", telegram_setup_network: "notify.telegram.error.network",
  telegram_setup_tls: "notify.telegram.error.tls", telegram_setup_timeout: "notify.telegram.error.timeout",
  telegram_setup_unavailable: "notify.telegram.error.unavailable", telegram_setup_provider_unavailable: "notify.telegram.error.provider",
  telegram_setup_rate_limited: "notify.telegram.error.rateLimited", telegram_setup_conflict: "notify.telegram.error.conflict",
  telegram_setup_protocol: "notify.telegram.error.protocol", telegram_setup_failed: "notify.telegram.error.failed",
};
export function telegramSetupErrorKey(error: unknown): MessageKey {
  if (error instanceof ApiResponseError) {
    if (error.status === 403) return "notify.denied";
    if (error.code && Object.prototype.hasOwnProperty.call(errorMessages, error.code)) return errorMessages[error.code as TelegramSetupErrorCode];
    if (error.status === 409) return "notify.conflict";
  }
  return "notify.telegram.error.unavailable";
}
type SetupStatusView = { state: "available"; secretSet: boolean; chatBound: boolean; chatName: string | null }
  | { state: "loading" | "unavailable" | "denied" };
export function telegramStatusView(query: {
  data?: TelegramSetup; isPending: boolean; isSuccess: boolean; isError: boolean; error: unknown;
}, canConfigure: boolean): SetupStatusView {
  if (!canConfigure || (query.isError && query.error instanceof ApiResponseError && query.error.status === 403)) return { state: "denied" };
  if (query.isPending) return { state: "loading" };
  const data = query.data;
  if (query.isError || !query.isSuccess || typeof data?.secret_set !== "boolean" || typeof data.chat_bound !== "boolean"
    || (data.chat_name != null && (typeof data.chat_name !== "string" || data.chat_name.length > 128))) return { state: "unavailable" };
  return { state: "available", secretSet: data.secret_set, chatBound: data.chat_bound, chatName: data.chat_name ?? null };
}
export function telegramStatusLabel(view: SetupStatusView): string {
  return t(view.state === "loading" ? "notify.telegram.statusLoading" : view.state === "denied" ? "notify.denied" : "notify.telegram.statusUnavailable");
}
export function telegramDestination(view: SetupStatusView): string {
  return view.state === "available" && view.chatBound ? view.chatName || "—" : "—";
}

export const telegramStatusOptions = {
  queryKey: ["telegram-setup"], queryFn: () => api.telegramSetup("status"), retry: false,
};

export function TelegramSetupPanel({ item, canConfigure, onClose, onRefresh }: {
  item: NotificationChannel; canConfigure: boolean; onClose: () => void; onRefresh: () => void;
}) {
  const overlays = useOverlays();
  const [token, setToken] = useState("");
  const [proxy, setProxy] = useState<string | null>(null);
  const [changing, setChanging] = useState(false);
  const [choice, setChoice] = useState("");
  const [actionError, setActionError] = useState<MessageKey | null>(null);
  const prerequisiteId = useId();
  const actionOptions = { onMutate: () => setActionError(null), onError: (error: Error) => setActionError(telegramSetupErrorKey(error)) };
  const status = useQuery({ ...telegramStatusOptions, enabled: canConfigure });
  const verify = useMutation({ ...actionOptions, mutationFn: (value: string) => api.telegramSetup("token", { token: value, proxy_url: proxy ?? status.data?.proxy_url ?? "" }),
    onSuccess: () => { setChanging(false); chats.reset(); setChoice(""); void status.refetch(); onRefresh(); } });
  const chats = useMutation({ ...actionOptions, mutationFn: () => api.telegramSetup("chats"), onSuccess: () => setChoice("") });
  const bind = useMutation({ ...actionOptions, mutationFn: () => api.telegramSetup("bind", { choice }),
    onSuccess: () => { void status.refetch(); onRefresh(); } });
  const toggle = useMutation({ ...actionOptions, mutationFn: (enabled: boolean) => api.updateNotificationChannel("telegram", {
    enabled, tls_mode: "tls", secret_ref: item.secret_ref, revision: item.revision,
  }), onSuccess: onRefresh });
  const busy = verify.isPending || chats.isPending || bind.isPending || toggle.isPending;
  const view = telegramStatusView(status, canConfigure);
  const available = view.state === "available";
  const saved = available && view.secretSet;
  const bound = available && view.chatBound;
  const canChooseChat = canConfigure && available && saved && !busy;
  const canBindChat = canChooseChat && !!choice;
  const prerequisite = view.state === "loading" ? telegramStatusLabel(view) : available ? !saved ? t("notify.telegram.needToken") : !bound ? t("notify.telegram.needChat") : null : null;
  return <DetailDrawer open title="Telegram" onClose={onClose} footer={<Button onClick={onClose}>{t("notify.cancel")}</Button>}>
    <label><input type="checkbox" role="switch" checked={item.enabled} aria-describedby={prerequisite ? prerequisiteId : undefined} disabled={!canConfigure || busy || !saved || !bound}
      onChange={(event) => { if (event.target.checked) toggle.mutate(true); else overlays.openModal({ title: t("notify.confirmDisable", { name: "Telegram" }),
        body: <Button onClick={() => { overlays.closeModal(); toggle.mutate(false); }}>{t("notify.confirm")}</Button> }); }}/> {t("notify.enabled")}</label>
    {prerequisite ? <span id={prerequisiteId} className="sli-ds-field__help">{prerequisite}</span> : null}
    {canConfigure && !available ? <Button disabled={status.isFetching} onClick={() => void status.refetch()}>{t("notify.telegram.retryStatus")}</Button> : null}
    <section><h3>{t("notify.telegram.step1")}</h3>
      {!available ? null : saved && !changing ? <p>{t("notify.telegram.secretSet")} · <Button disabled={!canConfigure || busy} onClick={() => setChanging(true)}>{t("notify.telegram.change")}</Button></p> :
        <div className="sli-ds-field"><label htmlFor="telegram-token">{t("notify.telegram.token")}</label>
          <input id="telegram-token" type="password" autoComplete="new-password" value={token} disabled={!canConfigure || busy} onChange={(event) => setToken(event.target.value)}/></div>}
      <div className="sli-ds-field"><label htmlFor="telegram-proxy">{t("notify.telegram.proxy")}</label>
        <input id="telegram-proxy" type="text" autoComplete="off" maxLength={1024} value={proxy ?? status.data?.proxy_url ?? ""}
          disabled={!canConfigure || !available || busy} onChange={(event) => setProxy(event.target.value)}/>
      </div>
      {available && (!saved || changing) ? <Button disabled={!canConfigure || busy || !token.trim()} onClick={() => { const value = token; setToken(""); verify.mutate(value); }}>{t("notify.telegram.verify")}</Button> : null}
      {verify.data?.bot_name ? <p>{t("notify.telegram.bot", { name: verify.data.bot_name })}</p> : null}
    </section>
    <section><h3>{t("notify.telegram.step2")}</h3>
      <span>{t("notify.destination")}: {telegramDestination(view)}</span>
      <Button disabled={!canConfigure || busy || !saved} onClick={() => chats.mutate()}>{t("notify.telegram.find")}</Button>
      {chats.data?.chats?.length ? <div className="sli-ds-field"><label htmlFor="telegram-chat">{t("notify.telegram.choose")}</label>
        <select id="telegram-chat" value={choice} disabled={!canChooseChat} onChange={(event) => { if (canChooseChat) setChoice(event.target.value); }}>
          <option value="">{t("notify.telegram.choose")}</option>{chats.data.chats.map((chat) => <option key={chat.choice} value={chat.choice}>{chat.name}</option>)}
        </select><Button disabled={!canBindChat} onClick={() => { if (canBindChat) bind.mutate(); }}>{t("notify.save")}</Button></div> : chats.isSuccess ? <p>{t("notify.telegram.noChats")}</p> : null}
    </section>
    <h3>{t("notify.telegram.step3")}</h3>
    <ChannelTest key={item.revision} channel="telegram" enabled={canConfigure && !busy && item.enabled && saved && bound} onRefresh={onRefresh}/>
    {view.state === "unavailable" || view.state === "denied" ? <p role="alert">{t(status.isError ? telegramSetupErrorKey(status.error) : view.state === "denied" ? "notify.denied" : "notify.telegram.error.unavailable")}</p> : null}
    {actionError ? <p role="alert">{t(actionError)}</p> : null}
  </DetailDrawer>;
}
