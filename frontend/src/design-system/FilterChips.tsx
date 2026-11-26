import type { ButtonHTMLAttributes, ReactNode } from "react";

/** Toggles an independent filter, with an optional result count. */
export function FilterChip({ children, count, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { count?: string | number }) {
  return <button type="button" className="sli-ds-chip" {...props}>
    {children}{count === undefined ? null : <> <strong>{count}</strong></>}
  </button>;
}

/** Changes a result filter in place. Use TabList to switch between views. */
export function FilterChips({ label, items, value, onChange }: {
  label: string;
  items: { key: string; label: ReactNode; count?: string }[];
  value: string;
  onChange: (key: string) => void;
}) {
  return <div className="sli-ds-filter-chips" role="group" aria-label={label}>
    {items.map((item) => <FilterChip key={item.key} aria-pressed={item.key === value} count={item.count}
      onClick={() => onChange(item.key)}>{item.label}</FilterChip>)}
  </div>;
}
