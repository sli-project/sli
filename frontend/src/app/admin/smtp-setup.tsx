import { Checkbox } from "../../design-system/Checkbox";
import { Select } from "../../design-system/Select";
import { useQuery } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { api, ApiResponseError } from "../../api/client";
import type { NotificationChannel, NotificationSubscription, SmtpSetup, SmtpSetupSave } from "../../api/notification-types";
import { Button, DetailDrawer, FactList, useOverlays } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { ChannelTest, useNotificationTime } from "./channel-test";

function saveErrorKey(error: unknown): MessageKey {
  if (error instanceof ApiResponseError) {
    if (error.status === 403) return "notify.denied";
    if (error.status === 409) return "notify.conflict";
    if (error.status === 400) return "notify.smtp.invalid";
  }
  return "notify.smtp.saveFailed";
}

export function smtpStatusValid(value: SmtpSetup | undefined): value is SmtpSetup {
  return !!value && [value.host, value.username, value.sender].every((item) => typeof item === "string" && item.length <= 1024)
    && Number.isInteger(value.port) && value.port >= 1 && value.port <= 65535
    && Number.isSafeInteger(value.revision) && value.revision > 0
    && (value.tls_mode === "tls" || value.tls_mode === "starttls")
    && typeof value.enabled === "boolean" && typeof value.secret_set === "boolean" && typeof value.needs_save === "boolean"
    && Array.isArray(value.recipients) && value.recipients.length > 0 && value.recipients.length <= 1000
    && value.recipients.every((item) => item && Number.isSafeInteger(item.user_id) && item.user_id > 0
      && typeof item.mailbox === "string" && item.mailbox.length <= 1024)
    && new Set(value.recipients.map((item) => item.user_id)).size === value.recipients.length
    && value.recipients.some((item) => item.user_id === value.self_user_id);
}

type Props = { item: NotificationChannel; canConfigure: boolean; subscriptions?: NotificationSubscription[]; onClose: () => void; onSave: () => void | Promise<void> };

export function SmtpSetupPanel(props: Props) {
  const [generation, setGeneration] = useState(0);
  const [lastFailure, setLastFailure] = useState<MessageKey | null>(null);
  const [savedAt, setSavedAt] = useState<string>();
  const status = useQuery({ queryKey: ["smtp-setup", props.item.revision], queryFn: () => api.smtpSetupStatus(),
    enabled: props.canConfigure, retry: false, refetchOnWindowFocus: false });
  if (props.canConfigure && status.isSuccess && smtpStatusValid(status.data)) {
    return <SmtpSetupForm key={`${status.data.revision}:${generation}`} {...props} initial={status.data} initialFailure={lastFailure} savedAt={savedAt}
      onSave={async () => {
        setLastFailure(null); setSavedAt(new Date().toISOString());
        await status.refetch(); setGeneration((value) => value + 1); await props.onSave();
      }}
      onFailure={async (failure) => {
        setLastFailure(failure);
        const refreshed = await status.refetch();
        if (refreshed.isSuccess && smtpStatusValid(refreshed.data)) setGeneration((value) => value + 1);
      }}/>;
  }
  return <DetailDrawer open title={t("notify.smtp.title")} onClose={props.onClose}
    footer={<Button onClick={props.onClose}>{t("notify.cancel")}</Button>}>
    {props.canConfigure && status.isPending ? <p role="status">{t("notify.smtp.loading")}</p> : <>
      <p role="alert">{t(!props.canConfigure || status.error instanceof ApiResponseError && status.error.status === 403 ? "notify.denied" : "notify.smtp.loadFailed")}</p>
      {props.canConfigure ? <Button disabled={status.isFetching} onClick={() => void status.refetch()}>{t("notify.smtp.retry")}</Button> : null}
    </>}
  </DetailDrawer>;
}

function SmtpSetupForm({ initial, canConfigure, subscriptions, onClose, onSave, onFailure, initialFailure, savedAt }: Props & {
  initial: SmtpSetup; initialFailure: MessageKey | null; savedAt?: string; onFailure: (failure: MessageKey) => Promise<void>;
}) {
  const time = useNotificationTime();
  const overlays = useOverlays();
  const [host, setHost] = useState(initial.host);
  const [port, setPort] = useState(String(initial.port));
  const [tls, setTls] = useState(initial.tls_mode);
  const [username, setUsername] = useState(initial.username);
  const [password, setPassword] = useState("");
  const [sender, setSender] = useState(initial.sender);
  const [recipients, setRecipients] = useState(initial.recipients.map((recipient) => ({ ...recipient })));
  const [enabled, setEnabled] = useState(initial.enabled);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<MessageKey | null>(initialFailure);
  const [uncertain, setUncertain] = useState(false);
  const submitting = useRef(false);
  const disabled = !canConfigure || busy || uncertain;
  const dirty = initial.needs_save || host !== initial.host || port !== String(initial.port) || tls !== initial.tls_mode
    || username !== initial.username || !!password || sender !== initial.sender || enabled !== initial.enabled
    || recipients.some((recipient, index) => recipient.mailbox !== initial.recipients[index].mailbox);
  const mailbox = (value: string) => /^[^\s@<>]+@[^\s@<>]+$/.test(value);
  const valid = !!host.trim() && !!username.trim() && (initial.secret_set || !!password)
    && /^\d{1,5}$/.test(port) && Number(port) >= 1 && Number(port) <= 65535 && mailbox(sender)
    && recipients.every((recipient) => mailbox(recipient.mailbox) || (recipient.user_id !== initial.self_user_id && recipient.mailbox === ""));
  const save = async () => {
    if (disabled || submitting.current || !dirty || !valid) return;
    submitting.current = true;
    setBusy(true); setFailure(null);
    const body: SmtpSetupSave = { host, port: Number(port), tls_mode: tls, username, password, sender,
      recipients: recipients.map((recipient) => ({ ...recipient })), enabled, revision: initial.revision };
    // Do not put credentials in React Query mutation variables or retained data.
    setPassword("");
    try { await api.smtpSetupSave(body); await onSave(); }
    catch (error) {
      const key = saveErrorKey(error);
      setFailure(key); setUncertain(true);
      // A failed response may follow a committed disable/revision change.
      // Never retry or test against the stale snapshot; reload before editing.
      await onFailure(key);
    }
    finally { body.password = ""; submitting.current = false; setBusy(false); }
  };
  return <DetailDrawer open title={t("notify.smtp.title")} onClose={() => { if (!busy) onClose(); }} footer={<>
    <Button disabled={busy} onClick={onClose}>{t("notify.cancel")}</Button>
    <Button variant="primary" disabled={disabled || !dirty || !valid} onClick={() => {
      if (initial.enabled && !enabled) overlays.openModal({ title: t("notify.confirmDisable", { name: t("notify.smtp.title") }),
        body: <Button onClick={() => { overlays.closeModal(); void save(); }}>{t("notify.confirm")}</Button> });
      else void save();
    }}>{t("notify.save")}</Button>
  </>}>
    <div className="sli-ds-field"><label htmlFor="smtp-host">{t("notify.smtp.host")}</label>
      <input id="smtp-host" value={host} maxLength={253} disabled={disabled} autoComplete="off" onChange={(event) => setHost(event.target.value)}/></div>
    <div className="sli-ds-field"><label htmlFor="smtp-port">{t("notify.smtp.port")}</label>
      <input id="smtp-port" type="number" min="1" max="65535" step="1" value={port} disabled={disabled} onChange={(event) => setPort(event.target.value)}/></div>
    <div className="sli-ds-field"><label htmlFor="smtp-tls">{t("notify.tls")}</label>
      <Select label={t("notify.tls")} id="smtp-tls" value={tls} disabled={disabled} onChange={(selectedValue) => setTls(selectedValue as SmtpSetup["tls_mode"])}
        options={[{ value: "tls", label: "TLS" }, { value: "starttls", label: "STARTTLS" }]}/></div>
    <div className="sli-ds-field"><label htmlFor="smtp-username">{t("notify.smtp.username")}</label>
      <input id="smtp-username" value={username} maxLength={1024} disabled={disabled} autoComplete="off" onChange={(event) => setUsername(event.target.value)}/></div>
    <div className="sli-ds-field"><label htmlFor="smtp-password">{t("notify.smtp.password")}</label>
      <input id="smtp-password" type="password" value={password} maxLength={65536} disabled={disabled} autoComplete="new-password"
        aria-describedby={initial.secret_set ? "smtp-password-help" : undefined} onChange={(event) => setPassword(event.target.value)}/>
      {initial.secret_set ? <span id="smtp-password-help" className="sli-ds-field__help">{t("notify.smtp.keepPassword")}</span> : null}</div>
    <div className="sli-ds-field"><label htmlFor="smtp-sender">{t("notify.smtp.sender")}</label>
      <input id="smtp-sender" type="email" value={sender} maxLength={1024} disabled={disabled} autoComplete="off" onChange={(event) => setSender(event.target.value)}/></div>
    {recipients.map((recipient, index) => <div className="sli-ds-field" key={recipient.user_id}>
      <label htmlFor={`smtp-recipient-${index}`}>{recipient.user_id === initial.self_user_id ? t("notify.smtp.selfRecipient") : t("notify.smtp.recipient", { number: index + 1 })}</label>
      <input id={`smtp-recipient-${index}`} type="email" value={recipient.mailbox} maxLength={1024} disabled={disabled} autoComplete="off"
        onChange={(event) => setRecipients((current) => current.map((item, position) => position === index ? { ...item, mailbox: event.target.value } : item))}/>
    </div>)}
    <Checkbox checked={enabled} disabled={disabled} onChange={(event) => setEnabled(event.target.checked)}> {t("notify.enabled")}</Checkbox>
    {savedAt ? <p role="status">{t("notify.savedAt", { time: time(savedAt) })}</p> : null}
    <ChannelTest channel="smtp" subscriptions={subscriptions} enabled={!disabled && !dirty && initial.enabled && initial.secret_set && valid}
      destination={(item) => initial.recipients.find((recipient) => recipient.user_id === item.recipient_user_id)?.mailbox || "—"} onRefresh={() => undefined}/>
    {failure ? <p role="alert">{t(failure)}</p> : null}
    <FactList facts={initial.recipients.map((recipient) => ({ label: `${recipient.mailbox || t("notify.smtp.selfRecipient")} · ${t("notify.recipientId")}`, value: recipient.user_id }))}/>
  </DetailDrawer>;
}
