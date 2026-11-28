import { useEffect, useId, useRef, useState } from "react";
import { useQueries } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { api } from "../api/client";
import { Button } from "../design-system";
import { t } from "../i18n";
import { globalSearchTarget } from "./navigation";

const objectTypes = [
  { type: "computer", label: "shell.search.computers" },
  { type: "user", label: "shell.search.users" },
  { type: "ad_group", label: "shell.search.groups" },
] as const;

export function HeaderSearch({ currentSearch, journalQuery, onHome, canSearchObjects, onNavigate }: {
  currentSearch: string;
  journalQuery: string | null;
  onHome: boolean;
  canSearchObjects: boolean;
  onNavigate: () => void;
}) {
  const navigate = useNavigate();
  const resultsId = useId();
  const input = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState(journalQuery ?? "");
  const [focused, setFocused] = useState(false);
  const [debounced, setDebounced] = useState("");
  useEffect(() => { setQuery(journalQuery ?? ""); }, [journalQuery]);
  const term = query.trim();
  useEffect(() => {
    const timeout = window.setTimeout(() => setDebounced(term), 250);
    return () => window.clearTimeout(timeout);
  }, [term]);
  const showResults = focused && term.length > 0;
  const readObjects = showResults && canSearchObjects && term === debounced;
  const results = useQueries({ queries: objectTypes.map(({ type }) => ({
    queryKey: ["shell", "object-search", type, debounced],
    queryFn: ({ signal }: { signal: AbortSignal }) => api.v4Objects(new URLSearchParams({ q: debounced, type, limit: "5" }), signal),
    enabled: readObjects,
    staleTime: 30_000,
    retry: false,
  })) });
  const target = globalSearchTarget(query, currentSearch, onHome);
  const close = () => {
    setFocused(false);
    onNavigate();
  };
  return <form className="sli-ds-shell__search" role="search" onSubmit={(event) => {
    event.preventDefault();
    close();
    void navigate({ to: target.to, search: target.search });
  }} onFocus={() => setFocused(true)} onBlur={(event) => {
    if (!event.currentTarget.contains(event.relatedTarget)) setFocused(false);
  }} onKeyDown={(event) => {
    if (event.key === "Escape" && showResults) {
      event.preventDefault();
      event.stopPropagation();
      input.current?.focus();
      setFocused(false);
    }
  }}>
    <Button type="submit" variant="ghost" className="sli-ds-shell__search-submit" icon="search" aria-label={t("shell.search.submit")}/>
    <input id="global-search" ref={input} name="q" type="search" value={query} maxLength={256}
      aria-controls={showResults ? resultsId : undefined} onChange={(event) => { setQuery(event.target.value); setFocused(true); }}
      placeholder={t("shell.search.placeholder")} aria-label={t("shell.search.aria")}/>
    {showResults ? <div id={resultsId} className="sli-ds-suggestions sli-ds-shell__search-results">
      <div className="sli-ds-suggestions__list">
        {readObjects ? results.map(({ data }, index) => {
          const items = data?.items ?? [];
          const group = objectTypes[index];
          return items.length ? <div key={group.type} role="group" aria-label={t(group.label)}>
            <div className="sli-ds-shell__menu-title">{t(group.label)}</div>
            {items.map((item) => <Link key={item.object_id} className="sli-ds-suggestions__item"
              to="/entities/$entityId" params={{ entityId: item.object_id }} onClick={close}>{item.display_name}</Link>)}
          </div> : null;
        }) : null}
        {readObjects && results.some((result) => result.isError) ? <p role="status" className="sli-ds-suggestions__item">{t("shell.search.objectsFailed")}</p> : null}
      </div>
      <Link className="sli-ds-suggestions__item" to={target.to} search={target.search} onClick={close}>{t("shell.search.journal")}</Link>
    </div> : null}
  </form>;
}
