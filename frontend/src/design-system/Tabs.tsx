import { createContext, useContext, useId, type KeyboardEvent, type ReactNode } from "react";

type TabItem = { key: string; label: ReactNode };
type TabsContextValue = { id: string; items: TabItem[]; active: string; onChange: (key: string) => void };
const TabsContext = createContext<TabsContextValue | null>(null);

function useTabs() {
  const value = useContext(TabsContext);
  if (!value) throw new Error("TabList and TabPanel require Tabs");
  return value;
}

/** Controlled tabs with a shared result panel, including loading and empty states. */
export function Tabs({ items, active, onChange, children }: Omit<TabsContextValue, "id"> & { children: ReactNode }) {
  const id = useId();
  return <TabsContext.Provider value={{ id, items, active, onChange }}>{children}</TabsContext.Provider>;
}

export function TabList({ label }: { label: string }) {
  const { id, items, active, onChange } = useTabs();
  const navigate = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    let next: number;
    switch (event.key) {
      case "ArrowRight": next = (index + 1) % items.length; break;
      case "ArrowLeft": next = (index - 1 + items.length) % items.length; break;
      case "Home": next = 0; break;
      case "End": next = items.length - 1; break;
      default: return;
    }
    event.preventDefault();
    onChange(items[next].key);
    event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus();
  };
  return <div className="sli-ds-header__meta" role="tablist" aria-label={label}>
    {items.map((item, index) => <button key={item.key} type="button" role="tab" id={`${id}-tab-${item.key}`} aria-controls={`${id}-panel`}
      className="sli-ds-chip" aria-selected={item.key === active} aria-pressed={item.key === active} tabIndex={item.key === active ? 0 : -1}
      onClick={() => onChange(item.key)} onKeyDown={(event) => navigate(event, index)}>{item.label}</button>)}
  </div>;
}

export function TabPanel({ children }: { children: ReactNode }) {
  const { id, active } = useTabs();
  return <div id={`${id}-panel`} role="tabpanel" aria-labelledby={`${id}-tab-${active}`} tabIndex={0} className="sli-ds-report__views">{children}</div>;
}
