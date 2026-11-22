import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useLocation, useNavigate } from "@tanstack/react-router";
import { api } from "../api/client";
import { t } from "../i18n";
import { useDateFormatters } from "../design-system/useDateFormatters";
import { Icon } from "../design-system/Icon";
import { selectedDomain } from "./domain-navigation";

export function DomainSwitcher({ access, domain }: { access: Awaited<ReturnType<typeof api.v4Access>>; domain?: string }) {
  const { formatDateTime } = useDateFormatters();
  const location = useLocation();
  const navigate = useNavigate();
  const container = useRef<HTMLDetailsElement>(null);
  const trigger = useRef<HTMLElement>(null);
  const [query, setQuery] = useState("");
  const [opened, setOpened] = useState(false);
  const domains = useQuery({ queryKey: ["domains", access], queryFn: api.domains, retry: false, staleTime: 30_000 });
  const summary = useQuery({ queryKey: ["domains", "summary", { ...access, evaluated_at_utc: undefined }], queryFn: () => api.homeSummaryV2(),
    enabled: opened && (domains.data?.items.length ?? 0) >= 2, retry: false, staleTime: Infinity, gcTime: Infinity });
  const selected = domain || selectedDomain(location.searchStr);
  useEffect(() => {
    const close = (event: MouseEvent) => {
      if (!container.current?.contains(event.target as Node) && container.current) container.current.open = false;
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);
  const items = domains.data?.items ?? [];
  if (items.length === 0) return null;
  const measured = summary.isError ? [] : summary.data?.domains ?? [];
  const rows = items.map((domain) => {
    const data = measured.find((item) => item.id === domain.id)?.summary;
    return { ...domain, count: data?.problems_found?.count ?? null,
      incomplete: domain.freshness.snapshot_state !== "complete" || !domain.freshness.observed_at_utc
        || (data?.observation_health?.state !== undefined && data.observation_health.state !== "ok") };
  }).sort((a, b) => Number(b.incomplete) - Number(a.incomplete) || a.display_name.localeCompare(b.display_name));
  const choose = (id?: number) => {
    if (container.current) container.current.open = false;
    setQuery("");
    trigger.current?.focus();
    const allScope = location.pathname === "/" ? "accessible" : "all";
    void navigate({ search: ((previous: Record<string, unknown>) => ({ ...previous, domain: id, domain_id: undefined, scope: id === undefined ? allScope : undefined })) as never });
  };
  const count = (value: number | null | undefined) => value == null ? <span className="sli-ds-domain__count">—</span>
    : value > 0 ? <span className="sli-ds-domain__count">{value}</span> : null;
  const label = items.find((item) => String(item.id) === selected)?.display_name ?? (selected ? "—" : t("shell.domain.all"));
  return <details className="sli-ds-domain" ref={container} onToggle={(event) => { if (event.currentTarget.open) setOpened(true); else setQuery(""); }}
    onKeyDown={(event) => { if (event.key === "Escape") { event.preventDefault(); if (container.current) container.current.open = false; trigger.current?.focus(); } }}>
    <summary className="sli-ds-button" ref={trigger} aria-label={`${t("shell.domain.label")}: ${label}`} title={label}>
      <Icon name="report"/><b>{label}</b><Icon name="chevron-down"/>
    </summary>
    <div className="sli-ds-domain__menu" aria-label={t("shell.domain.label")}>
      {items.length >= 7 ? <label className="sli-ds-field sli-ds-domain__search"><input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("shell.domain.search")} aria-label={t("shell.domain.search")}/></label> : null}
      <button type="button" className="sli-ds-domain__opt" aria-current={selected === null ? "true" : undefined} onClick={() => choose()}><span>{t("shell.domain.all")}</span>{count(summary.isError ? null : summary.data?.problems_found.count)}</button>
      {rows.filter((item) => item.display_name.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase())).map((item) =>
        <button type="button" className="sli-ds-domain__opt" key={item.id} aria-current={String(item.id) === selected ? "true" : undefined} onClick={() => choose(item.id)}>
          <span>{item.display_name}{item.is_archived ? ` · ${t("domain.archive.label")} · ${item.freshness.observed_at_utc ? t("domain.archive.asOf", { date: formatDateTime(item.freshness.observed_at_utc) }) : t("domain.archive.unknownDate")}` : ""}</span>{count(item.count)}
        </button>)}
      {query && !rows.some((item) => item.display_name.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase())) ? <p className="sli-ds-domain__empty">{t("shell.domain.notFound")}</p> : null}
    </div>
  </details>;
}
