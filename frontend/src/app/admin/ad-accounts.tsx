import { useDateFormatters } from "../../design-system/useDateFormatters";
import { useQuery } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { Dialog, Heading, Modal, ModalOverlay } from "react-aria-components";
import { api, type AdOperationCredential } from "../../api/client";
import { Badge, DataTable, DetailDrawer, FactList, PageHeader, StateView } from "../../design-system";
import { t } from "../../i18n";

type Action = { kind: "add" } | { kind: "details" | "password" | "delete" | "check"; row: AdOperationCredential };

/** Write-only credential fields are local to the open drawer, never query data. */
export function AdAccountsPage() {
  const { formatDateTime } = useDateFormatters();
  const accounts = useQuery({ queryKey: ["ad-operation-credentials"], queryFn: api.adOperationCredentials, retry: false });
  const [action, setAction] = useState<Action>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<"save" | "check">();
  const inFlight = useRef(false);
  const domains = accounts.data?.domains ?? [];
  const items = accounts.data?.items ?? [];
  const available = accounts.data?.key_status.available === true;
  const open = (next: Action) => { setError(undefined); setAction(next); };
  const close = () => { if (!inFlight.current) setAction(undefined); };
  const execute = async (operation: () => Promise<unknown>, kind: "save" | "check" = "save") => {
    if (inFlight.current) return;
    inFlight.current = true; setBusy(true); setError(undefined);
    try { await operation(); setAction(undefined); await accounts.refetch(); }
    catch (failure) { setError(failure instanceof Error && failure.message === "ad_check_unavailable" ? "check" : kind); }
    finally { inFlight.current = false; setBusy(false); }
  };
  const title = action?.kind === "add" ? t("adAccounts.add") : action?.kind === "password" ? t("adAccounts.replace")
    : action?.kind === "delete" ? t("adAccounts.deleteTitle") : action?.kind === "check" ? t("adAccounts.checkTitle") : t("adAccounts.account");
  const selected = action && "row" in action ? action.row : undefined;
  const reference = selected ? { credential_id: selected.credential_id, credential_revision: selected.credential_revision } : undefined;
  const denied = accounts.error?.message === "ad_operations_denied";
  return <section className="sli-ds-report">
    <PageHeader title={t("adAccounts.title")} crumbs={[{ label: t("operations.settings.title"), href: "/app/settings" }, { label: t("adAccounts.title") }]}
      subtitle={items.length ? t("adAccounts.count", { count: items.length, domains: domains.length }) : t("adAccounts.empty")}
      actions={accounts.data ? <button type="button" className="sli-ds-button" data-variant="primary" disabled={!available} onClick={() => open({ kind: "add" })}>{t("adAccounts.add")}</button> : undefined}/>
    {accounts.isLoading ? <StateView state="loading"/> : accounts.error ? <StateView state={denied ? "denied" : "unavailable"}
      titleMessage={denied ? { code: "adAccounts.denied", params: {} } : undefined} detail={denied ? t("adAccounts.permission") : undefined} onRetry={() => void accounts.refetch()}/> : null}
    {accounts.data && !available ? <StateView state="unavailable" compact detail={t("adAccounts.keyUnavailable")}/> : null}
    {accounts.data && !items.length ? <StateView state="empty" titleMessage={{ code: "adAccounts.operationsUnavailable", params: {} }} detail={t("adAccounts.emptyHelp")}/> : null}
    {items.length ? <DataTable rows={items} rowKey={(row) => row.credential_id} caption={t("adAccounts.title")} columns={[
      { key: "label", label: t("adAccounts.label"), render: (row) => <><button type="button" className="sli-ds-link-button" onClick={() => open({ kind: "details", row })}>{row.label}</button><div>{row.username}</div></> },
      { key: "domain", label: t("adAccounts.domain"), mobile: false, value: (row) => domains.find((domain) => domain.id === row.domain_id)?.fqdn },
      { key: "username", label: t("adAccounts.account"), mobile: false },
      { key: "created_at", label: t("adAccounts.entered"), mobile: false, render: (row) => <>{formatDateTime(row.created_at)} · {row.created_by}</> },
      { key: "check_status", label: t("adAccounts.lastCheck"), render: () => <Badge tone="warning">{t("adAccounts.notChecked")}</Badge> },
      { key: "usages", label: t("adAccounts.usages"), mobile: false, render: () => t("adAccounts.unused") },
      { key: "actions", label: t("adAccounts.actions"), render: (row) => <details><summary className="sli-ds-button">{t("adAccounts.actions")}</summary>
        <button type="button" className="sli-ds-button" disabled={!available || busy} onClick={() => open({ kind: "check", row })}>{t("adAccounts.check")}</button>
        <button type="button" className="sli-ds-button" disabled={!available || busy} onClick={() => open({ kind: "password", row })}>{t("adAccounts.replace")}</button>
        <button type="button" className="sli-ds-button" disabled={busy} onClick={() => open({ kind: "delete", row })}>{t("adAccounts.delete")}</button>
      </details> },
    ]}/> : null}
    {action?.kind === "add" || action?.kind === "password" ? <CredentialForm key={selected?.credential_id ?? "new"} title={title} selected={selected}
      domains={domains} busy={busy} error={error !== undefined} close={close} onSave={(value) => void execute(async () => {
        const row = reference ? await api.replaceAdOperationPassword({ ...reference, password: value.password }) : await api.createAdOperationCredential(value);
        // Saving and checking are separate outcomes. Keep the saved row visible
        // even when the one-shot checker is unavailable; never imply a bind.
        setAction({ kind: "check", row });
        await accounts.refetch();
        try { await api.checkAdOperationCredential({ credential_id: row.credential_id, credential_revision: row.credential_revision }); }
        catch { setError("check"); throw new Error("ad_check_unavailable"); }
      })}/> : null}
    {action?.kind === "details" && selected ? <DetailDrawer open title={selected.label} subtitle={selected.username} onClose={close}>
      <FactList facts={[{ label: t("adAccounts.domain"), value: domains.find((domain) => domain.id === selected.domain_id)?.fqdn },
        { label: t("adAccounts.account"), value: selected.username }, { label: t("adAccounts.password"), value: t("adAccounts.saved") },
        { label: t("adAccounts.lastCheck"), value: t("adAccounts.notChecked") }, { label: t("adAccounts.usages"), value: t("adAccounts.unused") }]}/>
      <button type="button" className="sli-ds-button" disabled={!available} onClick={() => open({ kind: "password", row: selected })}>{t("adAccounts.replace")}</button>
    </DetailDrawer> : null}
    <ModalOverlay className="sli-ds-modal" isOpen={action?.kind === "delete" || action?.kind === "check"} isKeyboardDismissDisabled={busy} onOpenChange={(value) => { if (!value) close(); }}>
      <Modal className="sli-ds-modal__panel"><Dialog aria-label={title}>
        <div className="sli-ds-modal__head"><div><Heading slot="title" level={2}>{title}: {selected?.label}</Heading><p>{selected?.username}</p></div></div>
        <div className="sli-ds-modal__body">{action?.kind === "delete" ? <><b>{t("adAccounts.whatHappens")}</b><ul><li>{t("adAccounts.deleteSecret")}</li><li>{t("adAccounts.deleteOperations")}</li><li>{t("adAccounts.noAdChange")}</li></ul></> : <><b>{t("adAccounts.whatChecked")}</b><ul><li>{t("adAccounts.checkLogin")}</li><li>{t("adAccounts.checkGpo")}</li><li>{t("adAccounts.checkOu")}</li></ul><p>{t("adAccounts.readOnly")}</p></>}
          <p>{t("adAccounts.audit")}</p>{error ? <p role="alert">{t(error === "check" ? "adAccounts.checkUnavailable" : "adAccounts.error")}</p> : null}</div>
        <div className="sli-ds-modal__footer"><button type="button" className="sli-ds-button" disabled={busy} onClick={close}>{t("adAccounts.cancel")}</button>
          <button type="button" className="sli-ds-button" data-variant="primary" disabled={busy || !reference || (action?.kind === "check" && !available)} onClick={() => {
            if (reference) void execute(() => action?.kind === "delete" ? api.deleteAdOperationCredential(reference) : api.checkAdOperationCredential(reference), action?.kind === "check" ? "check" : "save");
          }}>{action?.kind === "delete" ? t("adAccounts.deleteTitle") : t("adAccounts.runCheck")}</button></div>
      </Dialog></Modal>
    </ModalOverlay>
  </section>;
}

function CredentialForm({ title, selected, domains, busy, error, close, onSave }: { title: string; selected?: AdOperationCredential;
  domains: Array<{ id: number; fqdn: string }>; busy: boolean; error: boolean; close: () => void;
  onSave: (value: { domain_id: number; label: string; username: string; password: string }) => void }) {
  const [label, setLabel] = useState("");
  const [domain, setDomain] = useState(domains[0]?.id ?? 0);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const valid = password.length > 0 && password.length <= 4096 && (selected || (label.trim() && username.trim() && domain));
  return <DetailDrawer open title={title} subtitle={selected?.username ?? t("adAccounts.forOperations")} onClose={close} footer={<>
    <button type="button" className="sli-ds-button" disabled={busy} onClick={close}>{t("adAccounts.cancel")}</button>
    <button type="button" className="sli-ds-button" data-variant="primary" disabled={busy || !valid} onClick={() => {
      const value = { domain_id: domain, label: label.trim(), username: username.trim(), password };
      setPassword(""); onSave(value);
    }}>{t("adAccounts.saveCheck")}</button></>}>
    {!selected ? <>
      <div className="sli-ds-field"><label htmlFor="ad-label">{t("adAccounts.label")}</label><input id="ad-label" value={label} maxLength={128} disabled={busy} onChange={(event) => setLabel(event.target.value)}/></div>
      <div className="sli-ds-field"><label htmlFor="ad-domain">{t("adAccounts.domain")}</label><select id="ad-domain" value={domain} disabled={busy} onChange={(event) => setDomain(Number(event.target.value))}>{domains.map((item) => <option key={item.id} value={item.id}>{item.fqdn}</option>)}</select></div>
      <div className="sli-ds-field"><label htmlFor="ad-username">{t("adAccounts.account")}</label><input id="ad-username" value={username} maxLength={1024} autoComplete="off" spellCheck={false} disabled={busy} onChange={(event) => setUsername(event.target.value)}/></div>
    </> : null}
    <div className="sli-ds-field"><label htmlFor="ad-password">{selected ? t("adAccounts.newPassword") : t("adAccounts.password")}</label>
      <input id="ad-password" type="password" autoComplete="new-password" value={password} maxLength={4096} disabled={busy} onChange={(event) => setPassword(event.target.value)}/><div className="sli-ds-field__help">{t("adAccounts.writeOnly")}</div></div>
    <p className="sli-ds-note">{selected ? t("adAccounts.replaceHelp") : t("adAccounts.recommendation")}</p>
    {error ? <p role="alert">{t("adAccounts.error")}</p> : null}
  </DetailDrawer>;
}
