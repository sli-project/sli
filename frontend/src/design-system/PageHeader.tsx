import type { ReactNode } from "react";
import { t } from "../i18n";

export type Crumb = { label: string; href?: string };

export function PageHeader({ title, subtitle, crumbs, actions, meta }: {
  title: string;
  subtitle?: ReactNode;
  crumbs?: Crumb[];
  actions?: ReactNode;
  /** Scope/coverage line under the title (domain, observed time). */
  meta?: ReactNode;
}) {
  return <header className="sli-ds-header">
    {crumbs?.length ? <nav className="sli-ds-crumbs" aria-label={t("reports.breadcrumbs_aria")}>
      <ol>{crumbs.map((crumb, index) => <li key={`${crumb.label}-${index}`}>{crumb.href && index < crumbs.length - 1 ? <a href={crumb.href}>{crumb.label}</a> : <span aria-current={index === crumbs.length - 1 ? "page" : undefined}>{crumb.label}</span>}</li>)}</ol>
    </nav> : null}
    <div className="sli-ds-header__row">
      <div className="sli-ds-header__main">
        <h1 className="sli-ds-header__title" data-page-heading tabIndex={-1}>{title}</h1>
        {subtitle ? <p className="sli-ds-header__subtitle">{subtitle}</p> : null}
        {meta ? <div className="sli-ds-header__meta">{meta}</div> : null}
      </div>
      {actions ? <div className="sli-ds-header__actions">{actions}</div> : null}
    </div>
  </header>;
}
