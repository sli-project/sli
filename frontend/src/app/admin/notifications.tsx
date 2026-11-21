import { useInfiniteQuery, useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api, ApiResponseError } from "../../api/client";
import type { NotificationChannel, NotificationDelivery, NotificationKind, NotificationStatus, NotificationSubscription, NotificationWorkspace, SmtpSetup } from "../../api/notification-types";
import { Button, DataTable, DetailDrawer, FactList, PageHeader, StateView, TabList, TabPanel, Tabs, useDateFormatters, useOverlays, type TableColumn } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { SmtpSetupPanel, smtpStatusValid } from "./smtp-setup";
import { TelegramSetupPanel, telegramStatusOptions, telegramStatusView, telegramDestination } from "./telegram-setup";
import { resultLabel } from "./channel-test";
import "./notifications.css";

const kindLabel = (kind: NotificationKind) => t(`reports.v2.notifications.channels.columns.kind.labels.${kind}`);
const known = (value: number | null | undefined) => value == null ? "—" : String(value);
const stateCodes = new Set(["pending", "sending", "dry_run", "accepted", "delivery_unknown", "retry", "failed", "blocked", "cancelled"]);
export const deliveryState = (value: string) => stateCodes.has(value) ? t(`reports.v2.notifications.deliveries.columns.state.labels.${value}` as MessageKey) : "—";
const problemLabel = (row: NotificationDelivery) => row.object_kind === "test_problem" ? t("notify.testProblem") : row.finding_id ? t("notify.problem", { id: row.finding_id }) : t("notify.publishedProblems");
const errorCode = (code: string | null) => !!code && !["accepted", "simulated", "historical_replay", "history_import"].includes(code);
const processingLabel = (row: NotificationDelivery) => row.delivery_reason === "pipeline_delay" && Number.isSafeInteger(row.delay_minutes) && (row.delay_minutes ?? 0) >= 15
  ? t("notifications.delivery.delayed", { minutes: row.delay_minutes! })
  : row.delivery_reason && ["live", "historical_replay", "history_import"].includes(row.delivery_reason)
    ? t(`reports.v2.notifications.deliveries.columns.delivery_reason.labels.${row.delivery_reason}` as MessageKey) : "—";
const ruleSaveError = (error: Error | null) => error instanceof ApiResponseError && error.status === 409 ? t("notify.conflict") : error instanceof ApiResponseError && error.status === 403 ? t("notify.denied") : t("notify.ruleSaveFailed");

/** The API, rather than menu visibility, enforces both report grants. */
export function NotificationsPage() {
  const { formatDateTime: stamp } = useDateFormatters();
  const initial = new URLSearchParams(window.location.search);
  const requestedTab = initial.get("nav_view") ?? initial.get("tab");
  const [tab, setTab] = useState(requestedTab === "journal" || requestedTab === "rules" ? requestedTab : "channels");
  const [days, setDays] = useState(7);
  const [channel, setChannel] = useState("");
  const [status, setStatus] = useState<NotificationStatus | "">("");
  const [editing, setEditing] = useState<NotificationKind | null>(null);
  const [binding, setBinding] = useState<NotificationSubscription | "new" | null>(null);
  const [delivery, setDelivery] = useState<NotificationDelivery | null>(null);
  const findingId = initial.get("finding_id");
  const query = useInfiniteQuery({
    queryKey: ["notifications", days, channel, status, findingId], initialPageParam: "",
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams({ days: String(days) });
      if (channel) params.set("channel", channel);
      if (status) params.set("status", status);
      if (pageParam) params.set("cursor", pageParam);
      if (findingId) params.set("finding_id", findingId);
      return api.notificationWorkspace(params);
    },
    getNextPageParam: (last) => last.has_more ? last.next_cursor ?? undefined : undefined,
    retry: false, refetchInterval: 30_000,
  });
  const data = query.data?.pages[0];
  const smtpItem = data?.channels.find((item) => item.kind === "smtp");
  const smtp = useQuery({ queryKey: ["smtp-setup", smtpItem?.revision], queryFn: api.smtpSetupStatus,
    enabled: !!data?.can_configure, retry: false, refetchOnWindowFocus: false });
  const smtpData = smtp.isSuccess && !smtp.isError && smtpStatusValid(smtp.data) ? smtp.data : undefined;
  const smtpConfigured = smtpData ? Boolean(smtpData.host && smtpData.sender && !smtpData.needs_save && smtpData.secret_set) : null;
  const telegram = useQuery({ ...telegramStatusOptions, enabled: !!data?.can_configure && data.channels.some((item) => item.kind === "telegram") });
  const telegramView = telegramStatusView(telegram, !!data?.can_configure);
  const items = [...new Map(query.data?.pages.flatMap((page) => page.items).map((item) => [item.id, item])).values()];
  const destination = (item: NotificationSubscription) => item.channel === "telegram"
    ? item.recipient_user_id === smtpData?.self_user_id ? telegramDestination(telegramView) : "—"
    : smtpData?.recipients.find((recipient) => recipient.user_id === item.recipient_user_id)?.mailbox || "—";
  const ruleName = (item: NotificationSubscription) => `${t("notify.publishedProblems")} → ${kindLabel(item.channel)}${destination(item) === "—" ? "" : ` (${destination(item)})`}`;
  const refresh = () => { void query.refetch(); };
  const channelState = (item: NotificationChannel) => {
    const configured = item.kind === "smtp" ? smtpConfigured : telegramView.state === "available" ? telegramView.secretSet && telegramView.chatBound : null;
    return configured === null ? "—" : t(item.enabled && configured && (item.kind !== "smtp" || smtpData?.enabled) ? "notify.configured" : "notify.disconnected");
  };
  const columns: TableColumn<NotificationChannel>[] = [
    { key: "channel", label: t("notify.channel"), render: (item) => <Button variant="ghost" onClick={() => setEditing(item.kind)}>{kindLabel(item.kind)}</Button> },
    { key: "state", label: t("notify.state"), render: channelState },
    { key: "attempt", label: t("notify.lastAttempt"), mobile: false, render: (item) => item.last_attempt_at ? `${stamp(item.last_attempt_at)}, ${resultLabel(item.last_result_code)}` : "—" },
    { key: "last", label: t("notify.lastDelivery"), mobile: false, render: (item) => item.last_accepted_at ? stamp(item.last_accepted_at) : "—" },
    { key: "actions", label: t("notify.actions"), mobile: false, render: (item) => <div className="notify-channel-actions">
      <Button onClick={(event) => { event.stopPropagation(); setEditing(item.kind); }}>{t("notify.edit")}</Button>
      <Button disabled={!data?.can_configure} onClick={(event) => { event.stopPropagation(); setEditing(item.kind); }}>{t("notify.test")}</Button>
    </div> },
  ];
  return <section className="sli-ds-report">
    <PageHeader title={t("notify.title")} crumbs={[{ label: t("notify.management") }, { label: t("notify.title") }]}
      actions={tab === "rules" ? <Button variant="primary" disabled={!data?.can_configure} onClick={() => setBinding("new")}>{t("notify.addRule")}</Button> : undefined}/>
    {query.isPending ? <StateView state="loading"/> : query.isError ? <div role="alert">
      {t(query.error instanceof ApiResponseError && query.error.status === 403 ? "notify.denied" : "notify.failed")}{" "}
      <Button disabled={query.isFetching} onClick={refresh}>{t("state.retry")}</Button>
    </div> : data ? <>
      <Tabs items={["channels", "rules", "journal"].map((key) => ({ key, label: t(`notify.${key}` as MessageKey) }))} active={tab} onChange={setTab}>
        <TabList label={t("notify.title")}/><TabPanel>
          {tab === "channels" ? <div className="notify-channels"><DataTable columns={columns} rows={data.channels} rowKey={(item) => item.kind} onRowClick={(item) => setEditing(item.kind)} caption={t("notify.channels")}/></div>
            : tab === "rules" ? <NotificationRules data={data} destination={destination} onEdit={setBinding}/>
              : <NotificationJournal data={data} items={items} days={days} channel={channel} status={status} setDays={setDays} setChannel={setChannel} setStatus={setStatus}
                onOpen={setDelivery} hasMore={query.hasNextPage} loadingMore={query.isFetchingNextPage} loadMore={() => void query.fetchNextPage()}/>}
        </TabPanel>
      </Tabs>
      {editing === "telegram" && data.channels.find((item) => item.kind === "telegram") ? <TelegramSetupPanel item={data.channels.find((item) => item.kind === "telegram")!}
        canConfigure={data.can_configure} onClose={() => setEditing(null)} onRefresh={refresh}/>
        : editing === "smtp" && smtpItem ? <SmtpSetupPanel item={smtpItem} subscriptions={data.subscriptions} canConfigure={data.can_configure}
          onClose={() => setEditing(null)} onSave={refresh}/> : null}
      {binding ? <BindingEditor key={binding === "new" ? "new" : `${binding.id}:${binding.revision}`} item={binding === "new" ? null : binding}
        title={binding === "new" ? t("notify.addRule") : ruleName(binding)} smtp={smtpData} telegramDestination={telegramDestination(telegramView)} canConfigure={data.can_configure}
        onClose={() => setBinding(null)} onSave={() => { setBinding(null); refresh(); }}/> : null}
      {delivery ? <DetailDrawer open title={problemLabel(delivery)} subtitle={stamp(delivery.created_at)} onClose={() => setDelivery(null)} footer={<>
        {delivery.finding_id ? <a className="sli-ds-button" href={`/app/report/security.problems?id=${delivery.finding_id}`}>{t("notify.openProblem")}</a> : null}
        <Button onClick={() => { setEditing(delivery.channel); setDelivery(null); }}>{t("notify.editChannel")}</Button>
      </>}><FactList facts={[
        { label: t("notify.channel"), value: kindLabel(delivery.channel) }, { label: t("notify.state"), value: deliveryState(delivery.state) },
        { label: t("notify.reason"), value: resultLabel(delivery.result_code) },
        { label: t("reports.v2.notifications.deliveries.columns.delivery_reason.label"), value: processingLabel(delivery) },
        { label: t("notify.repeats"), value: delivery.attempts == null ? "—" : Math.max(0, delivery.attempts - 1) },
        ...(delivery.state === "retry" ? [{ label: t("notify.when"), value: stamp(delivery.available_at) }] : []),
      ]}/></DetailDrawer> : null}
    </> : null}
  </section>;
}

function NotificationRules({ data, destination, onEdit }: { data: NotificationWorkspace; destination: (item: NotificationSubscription) => string; onEdit: (item: NotificationSubscription | "new") => void }) {
  return data.subscriptions.length ? <DataTable columns={[
    { key: "what", label: t("notify.what"), render: () => t("notify.publishedProblems") },
    { key: "destination", label: t("notify.destination"), render: (item) => `${kindLabel(item.channel)}${destination(item) === "—" ? "" : ` (${destination(item)})`}` },
    { key: "enabled", label: t("notify.enabled"), render: (item) => t(item.enabled ? "reports.boolean.yes" : "reports.boolean.no") },
  ]} rows={data.subscriptions} rowKey={(item) => item.id} caption={t("notify.rules")} onRowClick={onEdit}/>
    : <p role="status">{t("notify.emptyRules")}</p>;
}

function BindingEditor({ item, title, smtp, telegramDestination, canConfigure, onClose, onSave }: {
  item: NotificationSubscription | null; title: string; smtp?: SmtpSetup; telegramDestination: string;
  canConfigure: boolean; onClose: () => void; onSave: () => void;
}) {
  const overlays = useOverlays();
  const [recipient, setRecipient] = useState(item ? String(item.recipient_user_id) : "");
  const [channel, setChannel] = useState<NotificationKind>(item?.channel ?? "smtp");
  const [enabled, setEnabled] = useState(item?.enabled ?? true);
  const mutation = useMutation({ mutationFn: () => api.saveNotificationSubscription(item?.id ?? null, { recipient_user_id: Number(recipient), channel, enabled, ...(item ? { revision: item.revision } : {}) }), onSuccess: onSave });
  const choices = smtp?.recipients.filter((row) => channel === "smtp" ? !!row.mailbox : row.user_id === smtp.self_user_id && telegramDestination !== "—") ?? [];
  const valid = choices.some((row) => String(row.user_id) === recipient) || !!item && recipient === String(item.recipient_user_id) && channel === item.channel;
  const dirty = !item || recipient !== String(item.recipient_user_id) || channel !== item.channel || enabled !== item.enabled;
  const save = () => {
    if (!canConfigure || !valid || !dirty || mutation.isPending) return;
    if (item?.enabled && !enabled) overlays.openModal({ title: t("notify.confirmDisable", { name: title }), body: <Button onClick={() => { overlays.closeModal(); mutation.mutate(); }}>{t("notify.confirm")}</Button> });
    else mutation.mutate();
  };
  return <DetailDrawer open title={title} onClose={onClose} footer={<><Button onClick={onClose}>{t("notify.cancel")}</Button>
    <Button variant="primary" disabled={!canConfigure || !valid || !dirty || mutation.isPending} onClick={save}>{t("notify.save")}</Button></>}>
    <div className="sli-ds-field"><label htmlFor="notify-binding-channel">{t("notify.channel")}</label>
      <select id="notify-binding-channel" value={channel} disabled={!canConfigure || mutation.isPending} onChange={(event) => { setChannel(event.target.value as NotificationKind); setRecipient(""); }}>
        {(["smtp", "telegram"] as const).map((kind) => <option key={kind} value={kind}>{kindLabel(kind)}</option>)}
      </select></div>
    <div className="sli-ds-field"><label htmlFor="notify-recipient">{t("notify.destination")}</label>
      <select id="notify-recipient" value={recipient} disabled={!canConfigure || mutation.isPending} onChange={(event) => setRecipient(event.target.value)}>
        <option value="">—</option>{choices.map((row) => <option key={row.user_id} value={row.user_id}>{channel === "smtp" ? row.mailbox : telegramDestination}</option>)}
        {item && !choices.some((row) => String(row.user_id) === recipient) && recipient ? <option value={recipient}>—</option> : null}
      </select></div>
    <label><input type="checkbox" checked={enabled} disabled={!canConfigure || mutation.isPending} onChange={(event) => setEnabled(event.target.checked)}/> {t("notify.enabled")}</label>
    {mutation.isError ? <p role="alert">{ruleSaveError(mutation.error)}</p> : null}
    {item ? <FactList facts={[{ label: t("notify.recipientId"), value: item.recipient_user_id }]}/> : null}
  </DetailDrawer>;
}

function NotificationJournal({ data, items, days, channel, status, setDays, setChannel, setStatus, onOpen, hasMore, loadingMore, loadMore }: {
  data: NotificationWorkspace; items: NotificationDelivery[]; days: number; channel: string; status: NotificationStatus | "";
  setDays: (days: number) => void; setChannel: (channel: string) => void; setStatus: (status: NotificationStatus | "") => void;
  onOpen: (row: NotificationDelivery) => void; hasMore: boolean; loadingMore: boolean; loadMore: () => void;
}) {
  const { formatDateTime: stamp } = useDateFormatters();
  const filters = ["", "accepted", "errors", "waiting", "other"] as const;
  return <div className="sli-ds-report__views">
    <div className="sli-ds-filters__fields">
      <div className="sli-ds-field"><label htmlFor="notify-period">{t("notify.period")}</label><select id="notify-period" value={days} onChange={(event) => setDays(Number(event.target.value))}><option value="1">{t("notify.day")}</option><option value="7">{t("notify.week")}</option><option value="30">{t("notify.month")}</option></select></div>
      <div className="sli-ds-field"><label htmlFor="notify-channel">{t("notify.channel")}</label><select id="notify-channel" value={channel} onChange={(event) => setChannel(event.target.value)}><option value="">{t("notify.all")}</option><option value="smtp">{kindLabel("smtp")}</option><option value="telegram">{kindLabel("telegram")}</option></select></div>
      {filters.map((key) => <Button key={key} className="sli-ds-chip" aria-pressed={status === key} onClick={() => setStatus(key)}>{t(key ? `notify.${key}` : "notify.all")} {known(data.counts[key || "total"])}</Button>)}
    </div>
    {items.length ? <DataTable rows={items} rowKey={(row) => row.id} caption={t("notify.journal")} onRowClick={onOpen} columns={[
      { key: "time", label: t("notify.time"), render: (row) => stamp(row.created_at) },
      { key: "problem", label: t("notify.problemColumn"), render: (row) => <Button variant="ghost" onClick={() => onOpen(row)}>{problemLabel(row)}</Button> },
      { key: "channel", label: t("notify.channel"), render: (row) => kindLabel(row.channel) },
      { key: "result", label: t("notify.result"), render: (row) => errorCode(row.result_code) || ["historical_replay", "history_import"].includes(row.result_code ?? "") ? resultLabel(row.result_code) : deliveryState(row.state) },
    ]}/> : <p role="status">{t("notify.emptyJournal")}</p>}
    {hasMore ? <Button disabled={loadingMore} onClick={loadMore}>{t(loadingMore ? "table.loadingMore" : "table.loadMore")}</Button> : null}
  </div>;
}

