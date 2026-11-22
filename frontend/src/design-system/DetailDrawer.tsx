import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { t } from "../i18n";
import { Button } from "./Primitives";

/** Side panel for a selected row or entity; traps focus and closes on Escape. */
export function DetailDrawer({ open, title, subtitle, eyebrow, headerActions, onClose, children, footer, inline: inlineRequested = false, responsive = false }: {
  open: boolean;
  title: string;
  subtitle?: ReactNode;
  eyebrow?: ReactNode;
  headerActions?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  inline?: boolean;
  responsive?: boolean;
}) {
  const panel = useRef<HTMLElement | null>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  const titleId = useId();
  const [wide, setWide] = useState(false);
  const inline = inlineRequested || (responsive && wide);

  useEffect(() => {
    if (!responsive || typeof window.matchMedia !== "function") return;
    const screen = window.matchMedia("(min-width: 2200px)");
    const update = () => setWide(screen.matches);
    update();
    screen.addEventListener("change", update);
    return () => screen.removeEventListener("change", update);
  }, [responsive]);

  useEffect(() => {
    if (!open || (inline && !inlineRequested)) return;
    const previous = document.activeElement as HTMLElement | null;
    const focusable = () => [...(panel.current?.querySelectorAll<HTMLElement>("button:not(:disabled),a[href],input:not(:disabled),select:not(:disabled),textarea:not(:disabled),[tabindex='0']") ?? [])]
      .filter((element) => !element.closest('[hidden],[inert],[aria-hidden="true"]') && getComputedStyle(element).display !== "none" && getComputedStyle(element).visibility !== "hidden");
    if (!inline) panel.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (panel.current?.closest("[inert]")) return;
      if (event.key === "Escape") { event.preventDefault(); closeRef.current(); return; }
      if (inline || event.key !== "Tab") return;
      const items = focusable();
      if (!items.length) { event.preventDefault(); return; }
      const first = items[0], last = items[items.length - 1];
      if (!items.includes(document.activeElement as HTMLElement)) { event.preventDefault(); (event.shiftKey ? last : first).focus(); }
      else if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("keydown", onKey); if (!inline && previous?.isConnected) previous.focus({ preventScroll: true }); };
  }, [open, inline, inlineRequested]);

  if (!open) return null;
  return <div className="sli-ds-drawer" data-open data-inline={inline || undefined} data-responsive={responsive || undefined}>
    {inline ? null : <div className="sli-ds-drawer__scrim" onClick={onClose} aria-hidden="true"/>}
    <aside ref={panel} className="sli-ds-drawer__panel" role={inline ? undefined : "dialog"} aria-modal={inline ? undefined : true} aria-labelledby={titleId} tabIndex={-1}
      onKeyDown={inline && !inlineRequested ? (event) => { if (event.key === "Escape") { event.stopPropagation(); onClose(); } } : undefined}>
      <header className="sli-ds-drawer__header">
        <div>
          {eyebrow ? <div className="sli-ds-drawer__eyebrow">{eyebrow}</div> : null}
          <h2 id={titleId}>{title}</h2>
          {subtitle ? <div className="sli-ds-drawer__subtitle">{subtitle}</div> : null}
        </div>
        {headerActions ? <div className="sli-ds-header__actions">{headerActions}<Button variant="ghost" onClick={onClose} aria-label={t("drawer.close")}>✕</Button></div>
          : <Button variant="ghost" onClick={onClose} aria-label={t("drawer.close")}>✕</Button>}
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
