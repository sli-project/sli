import type { ButtonHTMLAttributes, ReactNode } from "react";
import { Icon } from "./Icon";

export type Tone = "neutral" | "accent" | "success" | "warning" | "danger";

/** Small status label; `tone` maps to the semantic colour roles. */
export function Badge({ tone = "neutral", children }: { tone?: Tone; children: ReactNode }) {
  return <span className="sli-ds-badge" data-tone={tone === "neutral" ? undefined : tone}>{children}</span>;
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & { icon?: string; variant?: "primary" | "ghost" };

export function Button({ icon, variant, className, children, type = "button", ...props }: ButtonProps) {
  return <button type={type} className={className ? `sli-ds-button ${className}` : "sli-ds-button"} data-variant={variant} {...props}>{icon ? <Icon name={icon}/> : null}{children}</button>;
}

/** Explanation block with an icon; tone follows the semantic roles. */
export function Callout({ tone = "warning", icon, title, children, role }: { tone?: Tone; icon?: string; title?: ReactNode; children?: ReactNode; role?: "status" | "alert" }) {
  return <section className="sli-ds-callout" data-tone={tone} role={role}>
    {icon ? <Icon name={icon}/> : null}
    <div>{title ? <div className="sli-ds-callout__title">{title}</div> : null}{children ? <div className="sli-ds-callout__copy">{children}</div> : null}</div>
  </section>;
}

/** Honest empty/unavailable block for a section of a card or drawer. */
export function EmptyState({ title, copy, icon, action }: { title: string; copy: ReactNode; icon?: string; action?: ReactNode }) {
  return <div className="sli-ds-state" data-tone="neutral">
    {icon ? <Icon name={icon}/> : null}
    <div className="sli-ds-state__title">{title}</div>
    <div className="sli-ds-state__text">{copy}</div>
    {action}
  </div>;
}

/** Titled surface for a group of related content. */
export function Panel({ title, subtitle, children }: { title: ReactNode; subtitle?: ReactNode; children: ReactNode }) {
  return <section className="sli-ds-panel">
    <div className="sli-ds-panel__head"><h2 className="sli-ds-panel__title">{title}</h2>{subtitle ? <p className="sli-ds-panel__subtitle">{subtitle}</p> : null}</div>
    <div className="sli-ds-panel__body">{children}</div>
  </section>;
}
