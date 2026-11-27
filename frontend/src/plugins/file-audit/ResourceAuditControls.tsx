import { useRef, useState } from "react";
import { api, ApiResponseError } from "../../api/client";
import { Button, Checkbox, type TableColumn, useOverlays } from "../../design-system";
import { t } from "../../i18n";
import type { FileAuditRow } from "./report";

type Action = "apply" | "restore";
type Target = {
  id: string; share: string; server: string; agent: string; source: string; scope: string; revision: number;
  state: string; canRestore: boolean;
};

function target(row: FileAuditRow): Target | undefined {
  const { id, share_name, source_name, agent_id, source_instance_id, collection_scope_id, audit_state, audit_revision } = row;
  if (typeof id !== "string" || typeof share_name !== "string" || typeof source_name !== "string"
    || typeof agent_id !== "string" || typeof source_instance_id !== "string" || typeof collection_scope_id !== "string"
    || typeof audit_revision !== "number" || typeof audit_state !== "string"
    || audit_state === "applying" || audit_state === "restoring") return undefined;
  return { id, share: share_name, server: source_name, agent: agent_id, source: source_instance_id,
    scope: collection_scope_id, revision: audit_revision, state: audit_state, canRestore: audit_state === "enabled" || row.audit_can_restore === true };
}

export function useResourceAuditControls(rows: FileAuditRow[], page: string, refresh: () => void) {
  const { openModal, closeModal } = useOverlays();
  const [selection, setSelection] = useState<{ page: string; ids: string[] }>({ page, ids: [] });
  const [pending, setPending] = useState<Record<string, { revision: number; action: Action }>>({});
  const [errors, setErrors] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const submitting = useRef(false);
  const displayRows = rows.map(row => {
    const operation = pending[String(row.id)];
    return operation && Number(row.audit_policy_revision ?? 0) < operation.revision
      ? { ...row, audit_state: operation.action === "apply" ? "applying" : "restoring" } : row;
  });
  const targets = displayRows.flatMap(row => target(row) ?? []);
  const selected = targets.filter(row => selection.page === page && selection.ids.includes(row.id));
  const canChange = (action: Action, row: Target) => action === "apply"
    ? row.state !== "enabled" : row.canRestore;
  const change = (action: Action) => {
    const affected = selected.filter(row => canChange(action, row));
    const groups = new Map<string, Target[]>();
    for (const row of affected) groups.set(row.agent, [...(groups.get(row.agent) ?? []), row]);
    openModal({
      title: t(action === "apply" ? "file-audit.resources.enable" : "file-audit.resources.disable"),
      body: <>
        <p>{t(action === "apply" ? "file-audit.resources.enableChanges" : "file-audit.resources.disableChanges")}</p>
        <ul>{affected.map(row => <li key={row.id}>{row.server} · {row.share}</li>)}</ul>
      </>,
      footer: <>
        <Button onClick={closeModal}>{t("agents.cancel")}</Button>
        <Button type="submit" variant="primary">{t(action === "apply" ? "file-audit.resources.confirmEnable" : "file-audit.resources.confirmDisable")}</Button>
      </>,
      onSubmit: async event => {
        event.preventDefault();
        if (submitting.current) return;
        submitting.current = true;
        closeModal();
        setBusy(true);
        setErrors([]);
        try {
          await Promise.all([...groups.values()].map(async items => {
            const first = items[0];
            try {
              const received = await api.agentAction("file-audit", { agent_id: first.agent, source_instance_id: first.source,
                expected_revision: first.revision, action, collection_scope_ids: items.map(row => row.scope) });
              const result = received as { policy_revision?: number; command_id?: string; state?: string } | undefined;
              if (result?.policy_revision !== first.revision + 1 || !result.command_id || result.state !== "pending") throw new Error();
              const revision = result.policy_revision;
              setPending(current => ({ ...current, ...Object.fromEntries(items.map(row => [row.id, { revision, action }])) }));
              setSelection(current => ({ ...current, ids: current.ids.filter(id => !items.some(row => row.id === id)) }));
            } catch (error) {
              const reason = error instanceof ApiResponseError && error.code === "file_audit_management_disabled" ? t("file-audit.resources.managementOff")
                : error instanceof ApiResponseError && error.code === "file_audit_resource_overlap" ? t("file-audit.resources.overlap")
                : error instanceof ApiResponseError && error.status === 409 ? t("file-audit.resources.changed")
                : error instanceof ApiResponseError && error.status === 403 ? t("state.denied.title")
                : t("file-audit.screen.audit_failed");
              setErrors(current => [...current, t("file-audit.resources.commandFailed", { server: first.server, reason })]);
            }
          }));
        } finally {
          submitting.current = false;
          setBusy(false);
          refresh();
        }
      },
    });
  };
  const label = t("file-audit.resources.selectPage");
  const column: TableColumn<FileAuditRow> | undefined = targets.length || displayRows.some(row => typeof row.audit_revision === "number") ? {
    key: "select", label, width: "3rem",
    renderHeader: () => <Checkbox aria-label={label} disabled={busy || targets.length === 0}
      checked={targets.length > 0 && targets.length === selected.length} indeterminate={selected.length > 0 && selected.length < targets.length}
      onChange={event => setSelection({ page, ids: event.target.checked ? targets.map(row => row.id) : [] })}/>,
    render: row => {
      const item = target(row);
      return <span>{item ? <Checkbox aria-label={t("file-audit.resources.selectShare", { share: item.share, server: item.server })}
        checked={selected.some(row => row.id === item.id)} disabled={busy} onChange={event => setSelection({
          page, ids: event.target.checked ? [...selected.map(row => row.id), item.id] : selected.filter(row => row.id !== item.id).map(row => row.id),
        })}/> : null}</span>;
    },
  } : undefined;
  return { displayRows, column, toolbar: column ? <>
    <Button disabled={busy || !selected.some(row => canChange("apply", row))} onClick={() => change("apply")}>{t("file-audit.resources.enable")}</Button>
    <Button disabled={busy || !selected.some(row => canChange("restore", row))} onClick={() => change("restore")}>{t("file-audit.resources.disable")}</Button>
  </> : undefined, errors };
}
