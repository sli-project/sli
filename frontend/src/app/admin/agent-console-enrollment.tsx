import { useEffect, useRef, useState } from "react";
import { Dialog, Heading, Modal, ModalOverlay } from "react-aria-components";
import { api, ApiResponseError, type AgentInstallPackage, type AgentInstallPackageSettings } from "../../api/client";
import { Button } from "../../design-system";
import { DateInput } from "../../design-system/PeriodPicker";
import { t } from "../../i18n";

export function AgentConsoleEnrollment({ onClose }: { onClose: () => void }) {
  const [ready, setReady] = useState<AgentInstallPackage>();
  const [serverUrl, setServerUrl] = useState("");
  const [hostLimit, setHostLimit] = useState("");
  const [expires, setExpires] = useState("");
  const [limitsOpen, setLimitsOpen] = useState(false);
  const [addressStatus, setAddressStatus] = useState<"loading" | "loaded" | "failed">("loading");
  const [attempt, setAttempt] = useState(0);
  const [addressError, setAddressError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const mounted = useRef(false);
  const savedLimit = ready?.host_limit?.toString() ?? "";
  const savedDate = ready?.expires_at?.slice(0, 10) ?? "";
  const changed = serverUrl.trim() !== (ready?.server_url ?? "") || hostLimit !== savedLimit || expires !== savedDate;

  function apply(packageInfo: AgentInstallPackage) {
    setReady(packageInfo);
    setServerUrl(packageInfo.server_url ?? "");
    setHostLimit(packageInfo.host_limit?.toString() ?? "");
    setExpires(packageInfo.expires_at?.slice(0, 10) ?? "");
  }

  useEffect(() => {
    mounted.current = true;
    let active = true;
    api.agentInstallPackage().then((packageInfo) => {
      if (!active) return;
      apply(packageInfo);
      setAddressStatus("loaded");
      if (!packageInfo.package_url) setError(t("agents.console.packageError"));
    }, () => {
      if (active) setAddressStatus("failed");
    });
    return () => { active = false; mounted.current = false; };
  }, [attempt]);

  async function download() {
    if (busy || !serverUrl.trim() || addressStatus === "loading") return;
    let packageInfo = ready;
    if (changed) {
      setBusy(true);
      setError(undefined);
      setAddressError(undefined);
      const input: AgentInstallPackageSettings = { server_url: serverUrl.trim() };
      if (hostLimit !== savedLimit) input.host_limit = hostLimit ? Number(hostLimit) : null;
      if (expires !== savedDate) input.expires_at = expires ? expires + "T23:59:59.999Z" : null;
      try {
        packageInfo = await api.configureAgentInstallPackage(input);
        if (!mounted.current) return;
        apply(packageInfo);
        setAddressStatus("loaded");
      } catch (failure) {
        if (!mounted.current) return;
        if (failure instanceof ApiResponseError && failure.code === "invalid_agent_console_server_url") {
          const names = failure.payload?.allowed_hosts;
          const hosts = Array.isArray(names) ? names.filter((name): name is string => typeof name === "string") : [];
          setAddressError(hosts.length ? t("agents.console.serverUrlInvalid", { hosts: hosts.join(", ") }) : t("agents.console.serverUrlNoHosts"));
        } else {
          setError(t(failure instanceof ApiResponseError && failure.code === "agent_console_package_unavailable"
            ? "agents.console.packageError" : "agents.console.saveError"));
        }
        return;
      } finally {
        if (mounted.current) setBusy(false);
      }
    }
    if (packageInfo?.package_url) {
      const link = document.createElement("a");
      link.href = packageInfo.package_url;
      link.click();
    }
  }

  return <ModalOverlay className="sli-ds-modal" isOpen isDismissable onOpenChange={(open) => { if (!open) onClose(); }}>
    <Modal className="sli-ds-modal__panel"><Dialog aria-label={t("agents.addComputer")}>
      <form onSubmit={(event) => { event.preventDefault(); void download(); }}>
        <div className="sli-ds-modal__head"><Heading slot="title">{t("agents.addComputer")}</Heading></div>
        <div className="sli-ds-modal__body">
          <div><Button variant="primary" type="submit"
            disabled={busy || addressStatus === "loading" || !serverUrl.trim() || (!changed && !ready?.package_url)}>{t("agents.console.download")}</Button></div>
          <div className="sli-ds-field">
            <label htmlFor="agent-console-server-url">{t("agents.console.serverUrl")}</label>
            <input id="agent-console-server-url" type="text" inputMode="url" autoComplete="off" spellCheck={false} maxLength={1024}
              value={serverUrl} disabled={busy || addressStatus === "loading"} aria-invalid={!!addressError}
              aria-describedby={addressError ? "agent-console-address-error" : undefined}
              onChange={(event) => { setServerUrl(event.target.value); setAddressError(undefined); }}/>
            {addressError && <span className="sli-ds-field__error" id="agent-console-address-error" role="alert">{addressError}</span>}
          </div>
          {!changed && ready?.sha256 && <div className="sli-ds-field">
            <span>SHA-256</span><code>{ready.sha256.slice(0, 32)}<wbr/>{ready.sha256.slice(32)}</code>
          </div>}
          <div><Button aria-expanded={limitsOpen} aria-controls={limitsOpen ? "agent-package-limits" : undefined}
            onClick={() => setLimitsOpen(!limitsOpen)}>{t("agents.console.restrict")}</Button></div>
          {limitsOpen && <div id="agent-package-limits" className="sli-ds-filters__fields" inert={busy || addressStatus === "loading"}>
            <div className="sli-ds-field">
              <label htmlFor="agent-console-limit">{t("agents.console.hostLimit")}</label>
              <input id="agent-console-limit" type="number" min={1} max={2147483647} value={hostLimit}
                onChange={(event) => setHostLimit(event.target.value)}/>
            </div>
            <div className="sli-ds-field">
              <label htmlFor="agent-console-expiry">{t("agents.console.expiry")}</label>
              <DateInput id="agent-console-expiry" label={t("agents.console.expiry")} precision="date" value={expires} onChange={setExpires}/>
            </div>
          </div>}
          {addressStatus === "failed" && <div>
            <span role="alert">{t("agents.console.serverUrlLoadError")}</span>{" "}
            <Button disabled={busy} onClick={() => {
              setAddressError(undefined);
              setError(undefined);
              setAddressStatus("loading");
              setAttempt((value) => value + 1);
            }}>{t("state.retry")}</Button>
          </div>}
          {error && <span role="alert">{error}</span>}
        </div>
        <div className="sli-ds-modal__footer"><Button onClick={onClose}>{t("agents.dismiss")}</Button></div>
      </form>
    </Dialog></Modal>
  </ModalOverlay>;
}
