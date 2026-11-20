import { useEffect, useState } from "react";
import { Dialog, Heading, Modal, ModalOverlay } from "react-aria-components";
import { api, ApiResponseError } from "../../api/client";
import { t } from "../../i18n";

type IssuedCommand = Awaited<ReturnType<typeof api.createAgentConsoleToken>>;

export function AgentConsoleEnrollment({ onClose }: { onClose: () => void }) {
  const [hostLimit, setHostLimit] = useState("1");
  const [issued, setIssued] = useState<IssuedCommand>();
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<"issue" | "package" | "copy">();
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
    if (busy || issued) return;
    setBusy(true);
    setError(undefined);
    try {
      setIssued(await api.createAgentConsoleToken(Number(hostLimit || 1)));
    } catch (failure) {
      setError(failure instanceof ApiResponseError && failure.code === "agent_console_package_unavailable" ? "package" : "issue");
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
          </div> : <div className="sli-ds-filters__fields">
            <div className="sli-ds-field">
              <label htmlFor="agent-console-limit">{t("agents.console.hostLimit")}</label>
              <input id="agent-console-limit" type="number" min={1} max={100} value={hostLimit}
                style={{ boxSizing: "border-box" }} disabled={busy} onChange={(event) => setHostLimit(event.target.value)}/>
            </div>
            <button className="sli-ds-button" data-variant="primary" type="submit" disabled={busy}>{t("agents.console.issue")}</button>
          </div>}
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
