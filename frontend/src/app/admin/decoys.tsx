import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ApiResponseError } from "../../api/client";
import type { DecoyInput, DecoyLabel, DecoyTouch } from "../../api/decoy-types";
import { Badge, Button, Callout, DataTable, DetailDrawer, FactList, StateView, formatDateTime, type TableColumn } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { useEffectiveAccess } from "../App";

const stamp = (value: string | null) => formatDateTime(value);
const reasons = new Set(["identity_unverified", "identity_stale", "authentication_audit_unverified", "source_not_ready", "audit_stale",
  "server_profile_required", "root_not_covered", "read_audit_missing", "exclusions_conflict", "audit_missing", "file_unverified", "label_disabled", "collection_gap"]);
const reasonText = (reason: string) => t((reasons.has(reason) ? `decoys.readiness.${reason}` : "decoys.unknown") as MessageKey);
const objectText = (item: DecoyLabel) => "path" in item.identity ? item.identity.path : item.identity.sid;
const errorText = (error: unknown) => error instanceof ApiResponseError && error.status === 403 ? t("decoys.denied")
  : error instanceof ApiResponseError && error.status === 409 ? t("decoys.conflict") : t("decoys.failed");
type HistoryTarget = { id: string; revision?: number };

function linkedVersion(): HistoryTarget | null {
  const params = new URLSearchParams(window.location.search);
  const id = params.get("decoy_id");
  const revision = Number(params.get("decoy_revision"));
  return id && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(id)
    && Number.isSafeInteger(revision) && revision > 0 ? { id, revision } : null;
}

export function DecoyRegistry() {
  const access = useEffectiveAccess();
  const client = useQueryClient();
  const [editing, setEditing] = useState<DecoyLabel | "new" | null>(null);
  const [history, setHistory] = useState<HistoryTarget | null>(linkedVersion);
  const [touches, setTouches] = useState<DecoyLabel | null>(null);
  const query = useInfiniteQuery({ queryKey: ["decoys"], initialPageParam: "",
    queryFn: ({ pageParam }) => api.decoys(new URLSearchParams(pageParam ? { cursor: pageParam } : {})),
    getNextPageParam: (page) => page.has_more ? page.next_cursor : undefined, retry: false });
  const canRegister = access?.subject.coarse_role === "admin"
    && [...(access.capabilities ?? []), ...(access.resource_bound_capabilities ?? [])].includes("decoys.manage")
    && access.reports?.some((report) => report.report_key === "decoys.registry" && report.allowed && report.allowed_actions.includes("manage_decoy"));
  const columns: TableColumn<DecoyLabel>[] = [
    { key: "kind", label: t("decoys.kind"), render: (row) => t(`decoys.${row.kind}`) },
    { key: "object", label: t("decoys.object"), render: objectText },
    { key: "scope", label: t("decoys.scope"), render: (row) => "path" in row.identity
      ? `${row.identity.source_instance_id} · ${row.identity.collection_scope_id}` : String(row.identity.domain_id) },
    { key: "owner", label: t("decoys.owner") }, { key: "reason", label: t("decoys.reason") },
    { key: "readiness", label: t("decoys.readiness"), render: (row) => <><Badge tone={row.readiness.state === "ready" ? "neutral" : "warning"}>{t(`decoys.${row.readiness.state}`)}</Badge>
      {row.readiness.reasons.map((reason) => <div key={reason}>{reasonText(reason)}</div>)}</> },
    { key: "revision", label: t("decoys.revision"), kind: "number" },
    { key: "actions", label: t("decoys.actions"), render: (row) => <><Button disabled={!row.can_manage} onClick={() => setEditing(row)}>{t("decoys.edit")}</Button>
      <Button onClick={() => setHistory({ id: row.id })}>{t("decoys.history")}</Button>
      {row.kind === "file" ? <Button onClick={() => setTouches(row)}>{t("decoys.touches")}</Button> : null}</> },
  ];
  return <section id="decoys" className="sli-ds-filters">
    <h2 className="sli-ds-section-title">{t("decoys.title")}</h2><Callout>{t("decoys.description")}</Callout>
    <Button disabled={!canRegister} onClick={() => setEditing("new")}>{t("decoys.register")}</Button>
    {query.isLoading ? <StateView state="loading"/> : query.isError ? <StateView state={query.error instanceof ApiResponseError && query.error.status === 403 ? "denied" : "unavailable"} onRetry={() => void query.refetch()}/> : <>
      {!query.data?.pages[0].items.length ? <StateView state="empty"/> : null}
      <DataTable columns={columns} rows={query.data?.pages.flatMap((page) => page.items) ?? []} rowKey={(row) => row.id} caption={t("decoys.title")}
        hasMore={query.hasNextPage} loadingMore={query.isFetchingNextPage} onLoadMore={() => void query.fetchNextPage()}/>
    </>}
    {editing ? <DecoyEditor item={editing === "new" ? null : editing} onClose={() => setEditing(null)} onSaved={() => {
      setEditing(null); void client.invalidateQueries({ queryKey: ["decoys"] });
    }}/> : null}
    {history ? <DecoyHistory item={history} onClose={() => setHistory(null)} onTouches={(version) => { setHistory(null); setTouches(version); }}/> : null}
    {touches ? <DecoyTouchHistory item={touches} onClose={() => setTouches(null)}/> : null}
  </section>;
}

function DecoyEditor({ item, onClose, onSaved }: { item: DecoyLabel | null; onClose: () => void; onSaved: () => void }) {
  const [kind, setKind] = useState<DecoyInput["kind"]>(item?.kind ?? "account");
  const [owner, setOwner] = useState(item?.owner ?? "");
  const [reason, setReason] = useState("");
  const [active, setActive] = useState(item?.active ?? true);
  const [identity, setIdentity] = useState<Record<string, string>>(Object.fromEntries(Object.entries(item?.identity ?? {}).map(([key, value]) => [key, String(value)])));
  const keys = kind === "account" ? ["domain_id", "entity_id", "sid", "guid"] : ["agent_id", "source_instance_id", "collection_scope_id", "path"];
  const valid = owner.trim() && reason.trim() && keys.every((key) => identity[key]?.trim())
    && (kind !== "account" || ["domain_id", "entity_id"].every((key) => /^[1-9][0-9]*$/.test(identity[key] ?? "") && Number.isSafeInteger(Number(identity[key]))));
  const save = useMutation({ mutationFn: () => {
    const target = kind === "account" ? { domain_id: Number(identity.domain_id), entity_id: Number(identity.entity_id), sid: identity.sid.trim(), guid: identity.guid.trim() }
      : { agent_id: identity.agent_id.trim(), source_instance_id: identity.source_instance_id.trim(), collection_scope_id: identity.collection_scope_id.trim(), path: identity.path.trim() };
    return api.saveDecoy(item?.id ?? null, { kind, identity: target, owner: owner.trim(), reason: reason.trim(), active, revision: item?.revision ?? 0 });
  }, onSuccess: onSaved });
  return <DetailDrawer open title={item ? t("decoys.edit") : t("decoys.register")} onClose={onClose} footer={<>
    <Button onClick={onClose}>{t("decoys.cancel")}</Button><Button variant="primary" disabled={!valid || save.isPending} onClick={() => save.mutate()}>{t("decoys.save")}</Button>
  </>}>
    <Callout>{t("decoys.description")}</Callout>
    <div className="sli-ds-field"><label htmlFor="decoy-kind">{t("decoys.kind")}</label><select id="decoy-kind" value={kind} disabled={save.isPending}
      onChange={(event) => { setKind(event.target.value as typeof kind); setIdentity({}); }}><option value="account">{t("decoys.account")}</option><option value="file">{t("decoys.file")}</option></select></div>
    {keys.map((key) => <div className="sli-ds-field" key={key}><label htmlFor={`decoy-${key}`}>{t(`decoys.identity.${key}` as MessageKey)}</label>
      <input id={`decoy-${key}`} required disabled={save.isPending} value={identity[key] ?? ""} onChange={(event) => setIdentity({ ...identity, [key]: event.target.value })}/></div>)}
    <div className="sli-ds-field"><label htmlFor="decoy-owner">{t("decoys.owner")}</label><input id="decoy-owner" required maxLength={128} value={owner} disabled={save.isPending} onChange={(event) => setOwner(event.target.value)}/></div>
    <div className="sli-ds-field"><label htmlFor="decoy-reason">{t("decoys.reason")}</label><textarea id="decoy-reason" required maxLength={500} value={reason} disabled={save.isPending} onChange={(event) => setReason(event.target.value)}/></div>
    <label><input type="checkbox" checked={active} disabled={save.isPending} onChange={(event) => setActive(event.target.checked)}/>{t("decoys.active")}</label>
    {save.isError ? <Callout tone="danger" role="alert">{errorText(save.error)}</Callout> : null}
  </DetailDrawer>;
}

function DecoyHistory({ item, onClose, onTouches }: { item: HistoryTarget; onClose: () => void; onTouches: (item: DecoyLabel) => void }) {
  const query = useInfiniteQuery({ queryKey: ["decoys", "history", item.id, item.revision], initialPageParam: "",
    queryFn: ({ pageParam }) => api.decoys(new URLSearchParams({ id: item.id,
      ...(item.revision ? { revision: String(item.revision) } : {}), ...(pageParam ? { cursor: pageParam } : {}) })),
    getNextPageParam: (page) => page.has_more ? page.next_cursor : undefined, retry: false });
  return <DetailDrawer open title={t("decoys.history")} onClose={onClose}>
    {query.isLoading ? <StateView state="loading"/> : query.isError ? <StateView state={query.error instanceof ApiResponseError && query.error.status === 403 ? "denied" : "unavailable"}/>
      : !query.data?.pages[0].items.length ? <StateView state="empty" detail={t("decoys.version_missing")}/>
      : query.data?.pages.flatMap((page) => page.items).map((version) => <section key={version.revision}>
      <h3>{t("decoys.revision")} {version.revision}</h3><FactList facts={[
        { label: t("decoys.id"), value: version.id },
        { label: t("decoys.object"), value: objectText(version) }, { label: t("decoys.owner"), value: version.owner },
        ...Object.entries(version.identity).map(([key, value]) => ({ label: t(`decoys.identity.${key}` as MessageKey), value: String(value) })),
        { label: t("decoys.reason"), value: version.reason }, { label: t("decoys.active"), value: t(version.active ? "decoys.yes" : "decoys.no") },
        { label: t("decoys.active_from"), value: stamp(version.active_from) }, { label: t("decoys.active_to"), value: stamp(version.active_to) },
        { label: t("decoys.author"), value: `${version.actor_type}:${version.actor_id}` },
        { label: t("decoys.checked_at"), value: stamp(version.readiness.checked_at) },
        { label: t("decoys.last_observation"), value: stamp(version.readiness.last_observation_at) },
      ]}/>{version.kind === "file" ? <Button onClick={() => onTouches(version)}>{t("decoys.touches")}</Button> : null}</section>)}
    {query.hasNextPage ? <Button disabled={query.isFetchingNextPage} onClick={() => void query.fetchNextPage()}>{t("decoys.more")}</Button> : null}
  </DetailDrawer>;
}

function DecoyTouchHistory({ item, onClose }: { item: DecoyLabel; onClose: () => void }) {
  const query = useInfiniteQuery({ queryKey: ["decoys", "touches", item.id, item.revision], initialPageParam: "",
    queryFn: ({ pageParam }) => api.decoyTouches(new URLSearchParams({ touches: item.id, revision: String(item.revision),
      ...(pageParam ? { cursor: pageParam } : {}) })),
    getNextPageParam: (page) => page.has_more ? page.next_cursor : undefined, retry: false });
  const columns: TableColumn<DecoyTouch>[] = [
    { key: "observed_at", label: t("decoys.touch.time"), render: (row) => stamp(row.observed_at) },
    { key: "meaning", label: t("decoys.touch.meaning"), render: (row) => t(`decoys.touch.${row.meaning}`) },
    { key: "outcome", label: t("decoys.touch.outcome"), render: (row) => t(`decoys.touch.${row.outcome}`) },
    { key: "event_id", label: t("decoys.touch.event_id"), render: (row) => String(row.event_id) },
    { key: "mode", label: t("decoys.touch.mode"), render: (row) => t(`decoys.touch.${row.mode}`) },
    { key: "denial_layer", label: t("decoys.touch.denial_layer"), render: (row) => row.denial_layer?.toUpperCase() ?? t("decoys.unknown") },
    { key: "subject_sid", label: t("decoys.identity.sid"), render: (row) => row.subject_sid ?? t("decoys.unknown") },
    { key: "access_mask", label: t("decoys.touch.access_mask"), render: (row) => row.access_mask == null ? t("decoys.unknown") : `0x${row.access_mask.toString(16)}` },
    { key: "evidence_key", label: t("decoys.touch.evidence") },
    { key: "sha256", label: t("decoys.touch.sha256") },
  ];
  return <DetailDrawer open title={t("decoys.touches")} onClose={onClose}>
    <FactList facts={[{ label: t("decoys.object"), value: objectText(item) },
      { label: t("decoys.revision"), value: String(item.revision) }]}/>
    <Callout>{t("decoys.touch.limitation")}</Callout>
    {query.isLoading ? <StateView state="loading"/> : query.isError
      ? <StateView state={query.error instanceof ApiResponseError && query.error.status === 403 ? "denied" : "unavailable"} onRetry={() => void query.refetch()}/>
      : <DataTable columns={columns} rows={query.data?.pages.flatMap((page) => page.items) ?? []} rowKey={(row) => row.id}
        caption={t("decoys.touches")} hasMore={query.hasNextPage} loadingMore={query.isFetchingNextPage}
        onLoadMore={() => void query.fetchNextPage()}/>}
  </DetailDrawer>;
}
