import { useEffect, useId, useRef, type ReactNode } from "react";
import { t } from "../i18n";
import { Button } from "./Primitives";

/** Side panel for a selected row or entity; traps focus and closes on Escape. */
export function DetailDrawer({ open, title, subtitle, onClose, children, footer, inline, actions }: {
  open: boolean;
  title: string;
  subtitle?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  inline?: boolean;
  actions?: ReactNode;
}) {
  const panel = useRef<HTMLElement | null>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  const titleId = useId();

  useEffect(() => {
    if (!open || inline) return;
    const previous = document.activeElement as HTMLElement | null;
    const focusable = () => [...(panel.current?.querySelectorAll<HTMLElement>("button:not(:disabled),a[href],input:not(:disabled),select:not(:disabled),textarea:not(:disabled),[tabindex='0']") ?? [])]
      .filter((element) => !element.closest('[hidden],[inert],[aria-hidden="true"]') && getComputedStyle(element).display !== "none" && getComputedStyle(element).visibility !== "hidden");
    panel.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (panel.current?.closest("[inert]")) return;
      if (event.key === "Escape") { event.preventDefault(); closeRef.current(); return; }
      if (event.key !== "Tab") return;
      const items = focusable();
      if (!items.length) { event.preventDefault(); return; }
      const first = items[0], last = items[items.length - 1];
      if (!items.includes(document.activeElement as HTMLElement)) { event.preventDefault(); (event.shiftKey ? last : first).focus(); }
      else if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("keydown", onKey); if (previous?.isConnected) previous.focus({ preventScroll: true }); };
  }, [open, inline]);

  if (!open) return null;
  const content = <aside ref={panel} className="sli-ds-drawer__panel" data-inline={inline || undefined}
    role={inline ? undefined : "dialog"} aria-modal={inline ? undefined : true} aria-labelledby={titleId} tabIndex={inline ? undefined : -1}>
      <header className="sli-ds-drawer__header">
        <div>
          <h2 id={titleId}>{title}</h2>
          {subtitle ? <div className="sli-ds-drawer__subtitle">{subtitle}</div> : null}
        </div>
        <div className="sli-ds-header__actions">{actions}<Button variant="ghost" onClick={onClose} aria-label={t("drawer.close")}>✕</Button></div>
      </header>
      <div className="sli-ds-drawer__body">{children}</div>
      {footer ? <footer className="sli-ds-drawer__footer">{footer}</footer> : null}
    </aside>;
  return inline ? content : <div className="sli-ds-drawer" data-open>
    <div className="sli-ds-drawer__scrim" onClick={onClose} aria-hidden="true"/>{content}
  </div>;
}

/** Definition list for drawer and entity-card facts; missing values are shown explicitly. */
export function FactList({ facts }: { facts: Array<{ label: string; value: ReactNode }> }) {
  return <dl className="sli-ds-facts">{facts.map((fact) => <div key={fact.label}>
    <dt>{fact.label}</dt>
    <dd>{fact.value === null || fact.value === undefined || fact.value === "" ? t("table.noValue") : fact.value}</dd>
  </div>)}</dl>;
}
