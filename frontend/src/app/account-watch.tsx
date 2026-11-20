import { useDateFormatters } from "../design-system/useDateFormatters";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ApiResponseError } from "../api/client";
import type { WatchEntry } from "../api/watch-types";
import { Badge, Button, Callout, DataTable, DetailDrawer, FactList, StateView, type TableColumn } from "../design-system";
import { t } from "../i18n";
import { useEffectiveAccess } from "./App";

const errorText = (error: unknown) => error instanceof ApiResponseError && error.status === 403 ? t("watch.denied")
  : error instanceof ApiResponseError && error.status === 409 ? t("watch.conflict") : t("watch.failed");
const localDate = (value: string) => {
  const date = new Date(value);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
};

/** The card and the registry read the same scoped server revisions. */
export function AccountWatch({ entityId }: { entityId?: number }) {
  const { formatDateTime } = useDateFormatters();
  const access = useEffectiveAccess();
  const visible = access?.reports?.some((report) => report.report_key === "watch.registry" && report.allowed);
  const client = useQueryClient();
  const [editing, setEditing] = useState<WatchEntry | "new" | null>(null);
  const [history, setHistory] = useState<WatchEntry | null>(null);
  const query = useInfiniteQuery({ queryKey: ["watch", entityId ?? "registry"], initialPageParam: "", enabled: Boolean(visible),
    queryFn: ({ pageParam }) => api.watchEntries(new URLSearchParams({ ...(entityId ? { entity_id: String(entityId) } : {}), ...(pageParam ? { cursor: pageParam } : {}) })),
    getNextPageParam: (page) => page.has_more ? page.next_cursor : undefined, retry: false });
  if (!visible) return null;
  const items = query.data?.pages.flatMap((page) => page.items) ?? [];
  const columns: TableColumn<WatchEntry>[] = [
    { key: "account", label: t("watch.account"), render: (row) => <a href={`/app/entities/${row.identity.entity_id}`}>{row.identity.sid}</a> },
    { key: "owner", label: t("watch.owner") }, { key: "reason", label: t("watch.reason") },
    { key: "expires_at", label: t("watch.expiresAt"), render: (row) => formatDateTime(row.expires_at) },
    { key: "status", label: t("watch.status"), render: (row) => <Badge tone={row.status === "active" ? "neutral" : "warning"}>{t(`watch.${row.status}`)}</Badge> },
    { key: "revision", label: t("watch.revision"), kind: "number" },
    { key: "actions", label: t("watch.actions"), render: (row) => <><Button disabled={!row.can_manage} onClick={() => setEditing(row)}>{t("watch.edit")}</Button>
      <Button onClick={() => setHistory(row)}>{t("watch.history")}</Button></> },
  ];
  return <section id="watch" className="sli-ds-filters" aria-label={t("watch.title")}>
    <h2 className="sli-ds-section-title">{t("watch.title")}</h2><Callout>{t("watch.description")}</Callout>
    {entityId && !items.length ? <Button disabled={!query.data?.pages[0].can_manage || query.isFetching || query.isError}
      onClick={() => setEditing("new")}>{t("watch.start")}</Button> : null}
    {query.isLoading ? <StateView state="loading"/> : query.isError ? <StateView state={query.error instanceof ApiResponseError && query.error.status === 403 ? "denied" : "unavailable"} onRetry={() => void query.refetch()}/> : <>
      {!items.length ? <StateView state="empty"/> : null}
      <DataTable columns={columns} rows={items} rowKey={(row) => row.id} caption={t("watch.title")}
        hasMore={query.hasNextPage} loadingMore={query.isFetchingNextPage} onLoadMore={() => void query.fetchNextPage()}/>
    </>}
    {editing ? <WatchEditor item={editing === "new" ? null : editing} entityId={entityId!} onClose={() => setEditing(null)} onSaved={() => {
      setEditing(null); void client.invalidateQueries({ queryKey: ["watch"] });
    }}/> : null}
    {history ? <WatchHistory item={history} onClose={() => setHistory(null)}/> : null}
  </section>;
}

function WatchEditor({ item, entityId, onClose, onSaved }: { item: WatchEntry | null; entityId: number; onClose: () => void; onSaved: () => void }) {
  const [owner, setOwner] = useState(item?.owner ?? "");
  const [reason, setReason] = useState("");
  const [active, setActive] = useState(item?.active ?? true);
  const [expiry, setExpiry] = useState(localDate(item && item.status === "active" ? item.expires_at : new Date(Date.now() + 7 * 86400_000).toISOString()));
  const expiryTime = new Date(expiry).getTime();
  const valid = owner.trim() && reason.trim() && Number.isFinite(expiryTime) && (!active || expiryTime > Date.now());
  const save = useMutation({ mutationFn: () => api.saveWatchEntry(item?.id ?? null, { entity_id: item?.identity.entity_id ?? entityId,
    owner: owner.trim(), reason: reason.trim(), expires_at: new Date(expiry).toISOString(), active, revision: item?.revision ?? 0 }), onSuccess: onSaved });
  return <DetailDrawer open title={item ? t("watch.edit") : t("watch.start")} onClose={onClose} footer={<>
    <Button onClick={onClose}>{t("watch.cancel")}</Button><Button variant="primary" disabled={!valid || save.isPending} onClick={() => save.mutate()}>{t("watch.save")}</Button>
  </>}>
    <div className="sli-ds-field"><label htmlFor="watch-owner">{t("watch.owner")}</label><input id="watch-owner" required maxLength={128} value={owner} disabled={save.isPending} onChange={(event) => setOwner(event.target.value)}/></div>
    <div className="sli-ds-field"><label htmlFor="watch-reason">{t("watch.reason")}</label><textarea id="watch-reason" required maxLength={500} value={reason} disabled={save.isPending} onChange={(event) => setReason(event.target.value)}/></div>
    <div className="sli-ds-field"><label htmlFor="watch-expiry">{t("watch.expiresAt")}</label><input id="watch-expiry" type="datetime-local" required value={expiry} disabled={save.isPending} onChange={(event) => setExpiry(event.target.value)}/></div>
    {item ? <label><input type="checkbox" checked={active} disabled={save.isPending} onChange={(event) => setActive(event.target.checked)}/>{t("watch.active")}</label> : null}
    {save.isError ? <Callout tone="danger" role="alert">{errorText(save.error)}</Callout> : null}
  </DetailDrawer>;
}

function WatchHistory({ item, onClose }: { item: WatchEntry; onClose: () => void }) {
  const { formatDateTime } = useDateFormatters();
  const query = useInfiniteQuery({ queryKey: ["watch", "history", item.id], initialPageParam: "",
    queryFn: ({ pageParam }) => api.watchEntries(new URLSearchParams({ id: item.id, ...(pageParam ? { cursor: pageParam } : {}) })),
    getNextPageParam: (page) => page.has_more ? page.next_cursor : undefined, retry: false });
  return <DetailDrawer open title={t("watch.history")} onClose={onClose}>
    {query.isLoading ? <StateView state="loading"/> : query.isError ? <StateView state={query.error instanceof ApiResponseError && query.error.status === 403 ? "denied" : "unavailable"}/> : query.data?.pages.flatMap((page) => page.items).map((version) => <section key={version.revision}>
      <h3>{t("watch.revision")} {version.revision}</h3><FactList facts={[
        { label: t("watch.account"), value: version.identity.sid }, { label: t("watch.owner"), value: version.owner },
        { label: t("watch.reason"), value: version.reason }, { label: t("watch.status"), value: t(`watch.${version.status}`) },
        { label: t("watch.expiresAt"), value: formatDateTime(version.expires_at) },
        { label: t("watch.validFrom"), value: formatDateTime(version.valid_from) },
        { label: t("watch.validTo"), value: version.valid_to ? formatDateTime(version.valid_to) : t("watch.current") },
        { label: t("watch.author"), value: `${version.actor_type}:${version.actor_id}` },
      ]}/></section>)}
    {query.hasNextPage ? <Button disabled={query.isFetchingNextPage} onClick={() => void query.fetchNextPage()}>{t("watch.more")}</Button> : null}
  </DetailDrawer>;
}
