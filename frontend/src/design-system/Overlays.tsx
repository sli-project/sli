import { createContext, useCallback, useContext, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { t } from "../i18n";
import { DetailDrawer } from "./DetailDrawer";
import { Icon } from "./Icon";

export type ModalState = { title: string; subtitle?: string; body: ReactNode; footer?: ReactNode; formId?: string; onSubmit?: (event: FormEvent<HTMLFormElement>) => void };
export type DrawerState = { title: string; body: ReactNode; eyebrow?: string; variant?: "default" | "entity" };
export type OverlayApi = {
  openModal: (modal: ModalState) => void;
  closeModal: () => void;
  openDrawer: (drawer: DrawerState, returnFocus?: HTMLElement | null) => void;
  closeDrawer: () => void;
  toast: (title: string, copy: string) => void;
};

const OverlayContext = createContext<OverlayApi | null>(null);
const TOAST_LIFETIME_MS = 4500;

export function useOverlays(): OverlayApi {
  const value = useContext(OverlayContext);
  if (!value) throw new Error("OverlayProvider is missing");
  return value;
}

/**
 * Toast, modal dialog and side drawer for the whole product.
 * Focus returns to the element that opened an overlay; Escape closes it.
 * The application shell (`[data-sli-shell]`) is made inert while an overlay is open.
 */
export function OverlayProvider({ children }: { children: ReactNode }) {
  const [modal, setModal] = useState<ModalState | null>(null);
  const [drawer, setDrawer] = useState<DrawerState | null>(null);
  const [toasts, setToasts] = useState<Array<{ id: number; title: string; copy: string }>>([]);
  const focusReturn = useRef<HTMLElement | null>(null);
  const modalRef = useRef<HTMLDivElement | null>(null);
  const serial = useRef(0);
  const timers = useRef(new Set<number>());
  const rememberFocus = () => { focusReturn.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; };
  const restoreFocus = () => requestAnimationFrame(() => focusReturn.current?.focus());
  const openModal = useCallback((next: ModalState) => { rememberFocus(); setModal(next); }, []);
  const closeModal = useCallback(() => { setModal(null); restoreFocus(); }, []);
  const openDrawer = useCallback((next: DrawerState, returnFocus?: HTMLElement | null) => {
    if (returnFocus !== undefined) focusReturn.current = returnFocus;
    else rememberFocus();
    setDrawer(next);
  }, []);
  const closeDrawer = useCallback(() => { setDrawer(null); restoreFocus(); }, []);
  const toast = useCallback((title: string, copy: string) => {
    const id = ++serial.current;
    setToasts((items) => [...items, { id, title, copy }]);
    const timer = window.setTimeout(() => {
      timers.current.delete(timer);
      setToasts((items) => items.filter((item) => item.id !== id));
    }, TOAST_LIFETIME_MS);
    timers.current.add(timer);
  }, []);
  useEffect(() => () => { timers.current.forEach((timer) => window.clearTimeout(timer)); timers.current.clear(); }, []);
  useEffect(() => {
    if (!modal) return;
    const handleKey = (event: KeyboardEvent) => { if (event.key === "Escape") { event.preventDefault(); closeModal(); } };
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [modal, closeModal]);
  useEffect(() => {
    if (modal) requestAnimationFrame(() => (modalRef.current?.querySelector<HTMLElement>(".sli-ds-modal__body input,.sli-ds-modal__body select,.sli-ds-modal__body textarea") ?? modalRef.current?.querySelector<HTMLElement>("button"))?.focus());
  }, [modal]);
  useEffect(() => {
    const shell = document.querySelector<HTMLElement>("[data-sli-shell]");
    const blocked = Boolean(modal || drawer);
    if (shell) shell.inert = blocked;
    const previousOverflow = document.body.style.overflow;
    if (blocked) document.body.style.overflow = "hidden";
    return () => {
      if (shell) shell.inert = false;
      document.body.style.overflow = previousOverflow;
    };
  }, [drawer, modal]);
  return <OverlayContext.Provider value={{ openModal, closeModal, openDrawer, closeDrawer, toast }}>
    {children}
    {modal ? <div className="sli-ds-modal" onMouseDown={(event) => { if (event.target === event.currentTarget) closeModal(); }}>
      <div className="sli-ds-modal__panel" role="dialog" aria-modal="true" aria-labelledby="sli-ds-modal-title" ref={modalRef}>
        <form id={modal.formId} onSubmit={modal.onSubmit}>
          <div className="sli-ds-modal__head">
            <div><h2 id="sli-ds-modal-title">{modal.title}</h2>{modal.subtitle ? <p>{modal.subtitle}</p> : null}</div>
            <button className="sli-ds-button" data-variant="ghost" type="button" onClick={closeModal} aria-label={t("drawer.close")}><Icon name="close"/></button>
          </div>
          <div className="sli-ds-modal__body">{modal.body}</div>
          {modal.footer ? <div className="sli-ds-modal__footer">{modal.footer}</div> : null}
        </form>
      </div>
    </div> : null}
    <DetailDrawer open={Boolean(drawer)} title={drawer?.title ?? ""} subtitle={drawer?.eyebrow} onClose={closeDrawer}>{drawer?.body}</DetailDrawer>
    <div className="sli-ds-toasts" role="status" aria-live="polite">{toasts.map((item) => <div className="sli-ds-toast" key={item.id}>
      <Icon name="info"/><div><div className="sli-ds-toast__title">{item.title}</div><div className="sli-ds-toast__copy">{item.copy}</div></div>
    </div>)}</div>
  </OverlayContext.Provider>;
}
