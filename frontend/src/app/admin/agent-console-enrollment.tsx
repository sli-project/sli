import { Checkbox } from "../../design-system/Checkbox";
import { useEffect, useState } from "react";
import { Dialog, Heading, Modal, ModalOverlay } from "react-aria-components";
import { api, ApiResponseError } from "../../api/client";
import { t } from "../../i18n";

type IssuedCommand = Awaited<ReturnType<typeof api.createAgentConsoleToken>>;

export function AgentConsoleEnrollment({ onClose }: { onClose: () => void }) {
  const [serverUrl, setServerUrl] = useState(window.location.origin);
  const [addressStatus, setAddressStatus] = useState<"loading" | "loaded" | "failed">("loading");
  const [addressAttempt, setAddressAttempt] = useState(0);
  const [addressError, setAddressError] = useState<string>();
  const [hostLimit, setHostLimit] = useState("1");
  const [manageWindowsAudit, setManageWindowsAudit] = useState(true);
  const [issued, setIssued] = useState<IssuedCommand>();
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<"issue" | "package" | "copy">();
  useEffect(() => {
    let active = true;
    api.agentConsoleSettings().then((settings) => {
      if (!active) return;
      setServerUrl(settings.server_url ?? window.location.origin);
      setAddressStatus("loaded");
    }, () => {
      if (active) setAddressStatus("failed");
    });
    return () => { active = false; };
  }, [addressAttempt]);
  useEffect(() => {
    if (!issued) return;
    const timer = window.setTimeout(() => {
      setIssued(undefined);
      setCopied(false);
      setError(undefined);
    }, Math.max(0, Date.parse(issued.expires_at) - Date.now()));
    return () => window.clearTimeout(timer);
  }, [issued]);
  async function issue() {
    if (busy || issued || addressStatus === "loading") return;
    setBusy(true);
    setError(undefined);
    setAddressError(undefined);
    try {
      setIssued(await api.createAgentConsoleToken(Number(hostLimit || 1), manageWindowsAudit, serverUrl));
    } catch (failure) {
      if (failure instanceof ApiResponseError && failure.code === "invalid_agent_console_server_url") {
        const names = failure.payload?.allowed_hosts;
        const hosts = Array.isArray(names) ? names.filter((name): name is string => typeof name === "string") : [];
        setAddressError(hosts.length
          ? t("agents.console.serverUrlInvalid", { hosts: hosts.join(", ") })
          : t("agents.console.serverUrlNoHosts"));
      } else {
        setError(failure instanceof ApiResponseError && failure.code === "agent_console_package_unavailable" ? "package" : "issue");
      }
    } finally {
      setBusy(false);
    }
  }
  async function copy(command: string) {
    setCopied(false);
    setError(undefined);
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
    } catch {
      setError("copy");
    }
  }
  return <ModalOverlay className="sli-ds-modal" isOpen isDismissable onOpenChange={(value) => { if (!value) onClose(); }}>
    <Modal className="sli-ds-modal__panel"><Dialog aria-label={t("agents.addComputer")}>
      <form onSubmit={(event) => { event.preventDefault(); void issue(); }}>
        <div className="sli-ds-modal__head"><Heading slot="title">{t("agents.addComputer")}</Heading></div>
        <div className="sli-ds-modal__body">
          {issued ? <div className="sli-ds-field">
            <label htmlFor="agent-console-command">{t("agents.console.powerShell")}</label>
            <textarea id="agent-console-command" readOnly rows={5} value={issued.command} onFocus={(event) => event.target.select()}/>
            <div>
              <button className="sli-ds-button" data-variant="primary" type="button" onClick={() => { void copy(issued.command); }}>{t("agents.copy")}</button>
            </div>
          </div> : <>
            <div className="sli-ds-field">
              <label htmlFor="agent-console-server-url">{t("agents.console.serverUrl")}</label>
              <input id="agent-console-server-url" type="text" inputMode="url" autoComplete="off" spellCheck={false} maxLength={1024}
                value={serverUrl} disabled={busy || addressStatus === "loading"} aria-invalid={!!addressError}
                aria-describedby={addressError ? "agent-console-address-error" : addressStatus === "failed" ? "agent-console-address-load-error" : undefined}
                onChange={(event) => { setServerUrl(event.target.value); setAddressError(undefined); }}/>
              {addressError && <span className="sli-ds-field__error" id="agent-console-address-error" role="alert">{addressError}</span>}
              {addressStatus === "failed" && <div>
                <span className="sli-ds-field__error" id="agent-console-address-load-error" role="alert">{t("agents.console.serverUrlLoadError")}</span>{" "}
                <button className="sli-ds-button" type="button" disabled={busy} onClick={() => {
                  setAddressError(undefined);
                  setAddressStatus("loading");
                  setAddressAttempt((attempt) => attempt + 1);
                }}>{t("state.retry")}</button>
              </div>}
            </div>
            <div className="sli-ds-filters__fields">
              <div className="sli-ds-field">
                <label htmlFor="agent-console-limit">{t("agents.console.hostLimit")}</label>
                <input id="agent-console-limit" type="number" min={1} max={100} value={hostLimit}
                  style={{ boxSizing: "border-box" }} disabled={busy} onChange={(event) => setHostLimit(event.target.value)}/>
              </div>
              <button className="sli-ds-button" data-variant="primary" type="submit" disabled={busy || addressStatus === "loading"}>{t("agents.console.issue")}</button>
            </div>
            <Checkbox checked={manageWindowsAudit} disabled={busy} onChange={(event) => setManageWindowsAudit(event.target.checked)}>{t("agents.console.manageWindowsAudit")}</Checkbox>
          </>}
          {copied && <span role="status">{t("agents.copied")}</span>}
          {error && <span role="alert">{t(error === "copy" ? "agents.copyError" : error === "package" ? "agents.console.packageError" : "agents.console.issueError")}</span>}
        </div>
        <div className="sli-ds-modal__footer">
          <a className="sli-ds-button" href={issued?.package_url ?? "/api/v1/agent/installer/SliAgent.msi"}>{t("agents.console.download")}</a>
          <button className="sli-ds-button" type="button" onClick={onClose}>{t("agents.dismiss")}</button>
        </div>
      </form>
    </Dialog></Modal>
  </ModalOverlay>;
}
