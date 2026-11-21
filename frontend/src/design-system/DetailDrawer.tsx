import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { t } from "../i18n";
import { Button } from "./Primitives";

/** Side panel for a selected row or entity; traps focus and closes on Escape. */
export function DetailDrawer({ open, title, subtitle, onClose, children, footer, dock = false }: {
  open: boolean;
  title: string;
  subtitle?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  dock?: boolean;
}) {
  const panel = useRef<HTMLElement | null>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  const titleId = useId();
  const [docked, setDocked] = useState(false);
  useEffect(() => {
    if (!dock || typeof window.matchMedia !== "function") return;
    const media = window.matchMedia("(min-width: 2200px)");
    const update = () => setDocked(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, [dock]);

  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    const focusable = () => [...(panel.current?.querySelectorAll<HTMLElement>("button:not(:disabled),a[href],input:not(:disabled),select:not(:disabled),textarea:not(:disabled),[tabindex='0']") ?? [])]
      .filter((element) => !element.closest('[hidden],[inert],[aria-hidden="true"]') && getComputedStyle(element).display !== "none" && getComputedStyle(element).visibility !== "hidden");
    if (!docked) panel.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (panel.current?.closest("[inert]")) return;
      if (event.key === "Escape") { event.preventDefault(); closeRef.current(); return; }
      if (docked || event.key !== "Tab") return;
      const items = focusable();
      if (!items.length) { event.preventDefault(); return; }
      const first = items[0], last = items[items.length - 1];
      if (!items.includes(document.activeElement as HTMLElement)) { event.preventDefault(); (event.shiftKey ? last : first).focus(); }
      else if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("keydown", onKey); if (previous?.isConnected) previous.focus({ preventScroll: true }); };
  }, [open, docked]);

  if (!open) return null;
  return <div className="sli-ds-drawer" data-open data-dockable={dock || undefined} data-dock={docked || undefined}>
    <div className="sli-ds-drawer__scrim" onClick={onClose} aria-hidden="true"/>
    <aside ref={panel} className="sli-ds-drawer__panel" role={docked ? undefined : "dialog"} aria-modal={docked ? undefined : true} aria-labelledby={titleId} tabIndex={-1}>
      <header className="sli-ds-drawer__header">
        <div>
          <h2 id={titleId}>{title}</h2>
          {subtitle ? <div className="sli-ds-drawer__subtitle">{subtitle}</div> : null}
        </div>
        <Button variant="ghost" onClick={onClose} aria-label={t("drawer.close")}>✕</Button>
      </header>
      <div className="sli-ds-drawer__body">{children}</div>
      {footer ? <footer className="sli-ds-drawer__footer">{footer}</footer> : null}
    </aside>
  </div>;
}

/** Definition list for drawer and entity-card facts; missing values are shown explicitly. */
export function FactList({ facts }: { facts: Array<{ label: string; value: ReactNode }> }) {
  return <dl className="sli-ds-facts">{facts.map((fact) => <div key={fact.label}>
    <dt>{fact.label}</dt>
    <dd>{fact.value === null || fact.value === undefined || fact.value === "" ? t("table.noValue") : fact.value}</dd>
  </div>)}</dl>;
}
