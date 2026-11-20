import { useDateFormatters } from "../../design-system/useDateFormatters";
import { useEffect, useRef, useState } from "react";
import { Dialog, Heading, Modal, ModalOverlay } from "react-aria-components";
import { api, type GpoCredential, type GpoPlan, type GpoPlanSelection } from "../../api/client";
import { t } from "../../i18n";

/** This stage records an intention only; no token or writer command is issued. */
export function GpoPlanButton({ selection }: { selection: GpoPlanSelection }) {
  const { formatDateTime } = useDateFormatters();
  const [opened, setOpened] = useState(false);
  const [items, setItems] = useState<GpoCredential[]>([]);
  const [credentialId, setCredentialId] = useState("");
  const [lastCredentialId, setLastCredentialId] = useState<string | null>(null);
  const [method, setMethod] = useState<"gpo" | "share" | "manual">("gpo");
  const [plan, setPlan] = useState<GpoPlan>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [now, setNow] = useState(Date.now());
  const inFlight = useRef(false);
  useEffect(() => {
    if (!plan) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [plan]);
  const execute = async (operation: () => Promise<void>) => {
    if (inFlight.current) return;
    inFlight.current = true; setBusy(true); setError(false);
    try { await operation(); } catch { setError(true); }
    finally { inFlight.current = false; setBusy(false); }
  };
  const discard = async () => {
    setPlan(undefined); setAcknowledged(false);
    if (plan && Date.parse(plan.expires_at) > Date.now()) {
      await api.cancelGpoPlan({ plan_id: plan.plan_id, plan_sha256: plan.plan_sha256 });
    }
  };
  const preview = async (item: GpoCredential) => {
    setPlan(await api.previewGpoPlan({ ...selection, credential_id: item.credential_id, credential_revision: item.credential_revision }));
    setNow(Date.now());
  };
  const cancel = () => execute(async () => {
    try { await discard(); } finally { setOpened(false); }
  });
  const expired = plan ? Date.parse(plan.expires_at) <= now : false;
  return <>
    <button type="button" className="sli-ds-button" disabled={busy} onClick={() => void execute(async () => {
      setOpened(true); setPlan(undefined); setItems([]); setCredentialId(""); setLastCredentialId(null); setMethod("gpo");
      setAcknowledged(false); setConfirmed(false);
      const result = await api.gpoPlanCredentials(selection);
      setItems(result.items);
      const selected = result.items.find((item) => item.eligible && item.credential_id === result.selected_credential_id);
      setLastCredentialId(selected?.credential_id ?? null);
      if (selected) { setCredentialId(selected.credential_id); await preview(selected); }
    })}>{t("reports.ad.gpo.open")}</button>
    {error && !opened ? <p role="alert">{t("reports.ad.gpo.error")}</p> : null}
    {confirmed ? <p role="status">{t("reports.ad.gpo.confirmed")}</p> : null}
    <ModalOverlay className="sli-ds-modal" isOpen={opened} isKeyboardDismissDisabled={busy}
      onOpenChange={(open) => { if (!open && !busy) void cancel(); }}>
      <Modal className="sli-ds-modal__panel"><Dialog aria-label={t("reports.ad.gpo.title")}
        style={{ display: "grid", gridTemplateRows: "auto minmax(0, 1fr) auto", minHeight: 0, minWidth: 0, maxHeight: "inherit" }}>
          <div className="sli-ds-modal__head"><Heading slot="title" level={2}>{t("reports.ad.gpo.title")}</Heading></div>
          <div className="sli-ds-modal__body">
            <div role="radiogroup" aria-label={t("reports.ad.gpo.method")}>
              {(["gpo", "share", "manual"] as const).map((value) => <label className="sli-ds-field" key={value}>
                <input type="radio" name={`install-method-${selection.domain_id}`} checked={method === value} disabled={busy}
                  onChange={() => void execute(async () => {
                    setMethod(value); await discard();
                    const item = items.find((item) => item.eligible && item.credential_id === credentialId);
                    if (value === "gpo" && item) await preview(item);
                  })}/>
                <span>{t(`reports.ad.gpo.method.${value}`)}</span>
              </label>)}
            </div>
            {method !== "manual" ? <label className="sli-ds-field">
              <span>{t("reports.ad.gpo.credential")}</span>
              <select value={method === "gpo" ? credentialId : ""} disabled={busy || method !== "gpo"} onChange={(event) => {
                const id = event.target.value;
                void execute(async () => {
                  setCredentialId(id); await discard();
                  const item = items.find((item) => item.eligible && item.credential_id === id);
                  if (item) await preview(item);
                });
              }}>
                <option value="">{t("reports.ad.gpo.credential.choose")}</option>
                {items.map((item) => <option key={item.credential_id} value={item.credential_id} disabled={!item.eligible || method !== "gpo"}>
                  {item.label} · {item.username} · {t(item.eligible ? "reports.ad.gpo.credential.unverified" : "reports.ad.gpo.credential.unavailable")}
                  {item.credential_id === lastCredentialId ? ` · ${t("reports.ad.gpo.credential.lastUsed")}` : ""}
                </option>)}
              </select>
              <span className="sli-ds-field__help"><a href="/app/ad-accounts">{t("reports.ad.gpo.credential.manage")}</a></span>
            </label> : null}
            {method === "gpo" && plan ? <>
            <section>
              <h3>{t("reports.ad.gpo.targets", { count: plan.targets.length, domain: plan.domain_name })}</h3>
              <ul>{plan.targets.map((target) => <li key={target.entity_id}>{target.name}</li>)}</ul>
            </section>
            <section><h3>{t("reports.ad.gpo.package")}</h3>
              <p>{plan.package.version ? `${plan.package.version} · ` : ""}{t(`reports.ad.gpo.signature.${plan.package.signature ?? "unavailable"}`)}</p>
            </section>
            <p>{t("reports.ad.gpo.expires", { date: formatDateTime(plan.expires_at) })}</p>
            <label><input type="checkbox" checked={acknowledged} disabled={busy || expired} onChange={(event) => setAcknowledged(event.target.checked)}/>{t("reports.ad.gpo.acknowledge")}</label>
            {expired ? <p role="alert">{t("reports.ad.gpo.expired")}</p> : null}
            </> : null}
            {error ? <p role="alert">{t("reports.ad.gpo.error")}</p> : null}
          </div>
          <div className="sli-ds-modal__footer">
            <button type="button" className="sli-ds-button" disabled={busy} onClick={() => void cancel()}>{t("reports.ad.gpo.cancel")}</button>
            <button type="button" className="sli-ds-button" data-variant="primary" disabled={busy || method !== "gpo" || !plan || expired || !acknowledged} onClick={() => void execute(async () => {
              if (!plan || method !== "gpo") return;
              await api.confirmGpoPlan({ plan_id: plan.plan_id, plan_sha256: plan.plan_sha256, acknowledged: true,
                credential_id: plan.credential_binding.credential_id, credential_revision: plan.credential_binding.credential_revision });
              setPlan(undefined); setOpened(false); setConfirmed(true);
            })}>{t("reports.ad.gpo.confirm")}</button>
          </div>
      </Dialog></Modal>
    </ModalOverlay>
  </>;
}

export function ComputerGpoPlan({ rows }: { rows: Record<string, unknown>[] }) {
  const domains = new Map<number, number[]>();
  for (const row of rows) {
    const domain = row.domain_id, entity = row.entity_id;
    if (typeof domain !== "number" || typeof entity !== "number" || !Number.isSafeInteger(domain) || domain <= 0 ||
        !Number.isSafeInteger(entity) || entity <= 0 || row.computer_type === "domain_controller") continue;
    domains.set(domain, [...new Set([...(domains.get(domain) ?? []), entity])]);
  }
  return <>{[...domains].map(([domain, computers]) => <GpoPlanButton key={domain} selection={{ domain_id: domain, computer_entity_ids: computers }}/>)}</>;
}
