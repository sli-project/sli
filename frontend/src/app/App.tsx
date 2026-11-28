import { AccessRequestContext } from "./access-request-state";
import { createContext, useContext, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, Outlet, useLocation, useRouter } from "@tanstack/react-router";
import { api } from "../api/client";
import { Icon, IconSprite, OverlayProvider, StateView, useOverlays } from "../design-system";
import { t, type MessageKey } from "../i18n";
import { buildNavigation, isActivePath, journalSearchPath, previewModulePath } from "./navigation";
import { AdminRelatedLinks, adminNavigationPath } from "./admin/navigation-pages";
import { THEME_PREFERENCES, setTheme, storedTheme, type ThemePreference } from "./theme";
import { DomainSwitcher } from "./DomainSwitcher";
import { selectedDomain } from "./domain-navigation";
import { PageHeaderContext } from "../design-system/PageHeader";
import { HeaderSearch } from "./HeaderSearch";

import { DEFAULT_TIME_ZONE, TimeZoneContext } from "../shared/time-zone";
export { DEFAULT_TIME_ZONE, useTimeZone } from "../shared/time-zone";

const storedTimeZone = () => {
  const stored = localStorage.getItem("sli.timeZone");
  return stored || DEFAULT_TIME_ZONE;
};

type EffectiveAccessState = Awaited<ReturnType<typeof api.v4Access>> | undefined;
const EffectiveAccessContext = createContext<EffectiveAccessState>(undefined);
export const useEffectiveAccess = () => useContext(EffectiveAccessContext);

/*
  Состояние запроса прав отделено от самих прав намеренно.

  Раньше наружу отдавалось только `access.data`, а оно равно `undefined` и пока
  запрос идёт, и когда запрос упал. Каждая страница отчёта проверяет
  `access === undefined` и показывает «Загружаем разрешённые данные…», поэтому
  при отказе сервера прав экран грузился **бесконечно**: пользователь ждал
  данные, которых уже никогда не будет.

  Найдено 02.08.2026 на живой копии, когда отчётные запросы падали по таймауту
  базы: страница GPO висела на строке загрузки, хотя ответ был получен и был
  ошибкой. Это `B9` в чистом виде — состояние обязано быть объяснено.
*/
export type СостояниеПрав = "загружается" | "отказ" | "получены";
const AccessStatusContext = createContext<СостояниеПрав>("загружается");
export const useAccessStatus = () => useContext(AccessStatusContext);

function ShellContent() {
  const bootstrap = useQuery({ queryKey: ["bootstrap"], queryFn: api.bootstrap, staleTime: 60_000 });
  const access = useQuery({ queryKey: ["v4", "access", "shell"], queryFn: () => api.v4Access(), staleTime: 60_000, retry: false });
  const catalog = useQuery({ queryKey: ["report-v2", "catalog"], queryFn: api.reportsV2Catalog, staleTime: 30_000, retry: false });
  const queryClient = useQueryClient();
  const location = useLocation();
  const { history } = useRouter();
  const { toast } = useOverlays();
  const [timeZone, setStoredTimeZone] = useState(storedTimeZone);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const sidebarRef = useRef<HTMLElement | null>(null);
  const mobileMenuButtonRef = useRef<HTMLButtonElement | null>(null);
  const profileMenuRef = useRef<HTMLDivElement | null>(null);
  const previousPathnameRef = useRef(location.pathname);
  const [profileMenuOpen, setProfileMenuOpen] = useState(false);
  const [theme, setThemeState] = useState<ThemePreference>(storedTheme);
  const chooseTheme = (value: ThemePreference) => { setTheme(value); setThemeState(value); };
  const [committedSearch, setCommittedSearch] = useState(location.searchStr);
  useLayoutEffect(() => {
    // Home and report pages initialize their filters from the browser URL.
    history.flush();
    setCommittedSearch(location.searchStr);
  }, [history, location.searchStr]);
  const search = new URLSearchParams(committedSearch);
  const journalQuery = isActivePath(journalSearchPath, location.pathname) ? search.get("q") : null;
  const logout = useMutation({
    mutationFn: api.logout,
    onSuccess: () => {
      queryClient.clear();
      sessionStorage.clear();
      window.location.assign("/login");
    },
    onError: (error: Error) => toast(t("shell.profile.logoutFailed"), error.message),
  });
  const setTimeZone = (value: string) => { localStorage.setItem("sli.timeZone", value); setStoredTimeZone(value); };
  const capabilities = new Set(access.data?.capabilities ?? bootstrap.data?.capabilities ?? []);
  const reports = access.data?.reports.filter((report) => report.allowed) ?? [];
  const navigation = useMemo(() => buildNavigation({
    reports: new Set(reports.map((report) => report.report_key)),
    capabilities,
  }, catalog.data?.navigation), [access.data, bootstrap.data, catalog.data]);
  const adminSections = navigation.filter((section) => section.id === "operations" || section.id === "admin");
  const workSections = navigation.filter((section) => section.id !== "operations" && section.id !== "admin");
  const adminItems = adminSections.flatMap((section) => section.groups.flatMap((group) => group.items));
  const relatedPath = adminNavigationPath(location.pathname);
  const navigationPath = adminItems.some((item) => item.path === location.pathname) ? location.pathname
    : relatedPath === "/admin/status" ? adminItems.find((item) => item.id === "admin-status")?.path ?? relatedPath
    : ["/admin/language-time", "/admin/update", "/admin/activity"].includes(relatedPath) ? "/settings" : relatedPath;
  const inAdminZone = adminItems.some((item) => isActivePath(item.path, navigationPath));
  const sidebarSections = inAdminZone ? adminSections : workSections;
  const isHome = location.pathname === "/";
  const isReport = location.pathname.startsWith("/report/");
  const isProblemsQueue = location.pathname === "/report/security.problems";
  const queueAgents = useQuery({ queryKey: ["shell", "agents"], queryFn: api.agentCollection,
    enabled: isProblemsQueue && Boolean(access.data), staleTime: 60_000, retry: false });
  const agents = queueAgents.data?.agent_collection;
  const workspaceAccess = access.data?.capabilities.includes("workspace.view") ? access.data : undefined;
  const domainControl = workspaceAccess && isReport ? (id?: string) => <DomainSwitcher access={workspaceAccess} domain={id}/> : undefined;
  const scopeKey = isHome ? committedSearch : JSON.stringify([selectedDomain(committedSearch), search.get("scope")]);
  useEffect(() => {
    if (mobileMenuOpen) requestAnimationFrame(() => sidebarRef.current?.querySelector<HTMLElement>('a,button,[tabindex]:not([tabindex="-1"])')?.focus());
  }, [mobileMenuOpen]);
  useEffect(() => {
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && mobileMenuOpen) {
        event.preventDefault();
        setMobileMenuOpen(false);
        requestAnimationFrame(() => mobileMenuButtonRef.current?.focus());
      }
      if (event.key === "Tab" && mobileMenuOpen) {
        const focusable = Array.from(sidebarRef.current?.querySelectorAll<HTMLElement>('a[href],button:not([disabled]),[tabindex]:not([tabindex="-1"])') ?? []);
        if (!focusable.length) return;
        const first = focusable[0]; const last = focusable.at(-1)!;
        if (!sidebarRef.current?.contains(document.activeElement)) { event.preventDefault(); first.focus(); }
        else if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      } else if (event.key === "Escape") {
        setProfileMenuOpen(false);
      }
    };
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [mobileMenuOpen]);
  useEffect(() => {
    if (!profileMenuOpen) return;
    const closeOnOutsideClick = (event: MouseEvent) => {
      if (!profileMenuRef.current?.contains(event.target as Node)) setProfileMenuOpen(false);
    };
    document.addEventListener("mousedown", closeOnOutsideClick);
    return () => document.removeEventListener("mousedown", closeOnOutsideClick);
  }, [profileMenuOpen]);
  useEffect(() => {
    setMobileMenuOpen(false);
    setProfileMenuOpen(false);
    if (previousPathnameRef.current === location.pathname) return;
    previousPathnameRef.current = location.pathname;
    requestAnimationFrame(() => document.querySelector<HTMLElement>("[data-page-heading]")?.focus({ preventScroll: true }));
  }, [location.pathname]);
  const username = access.data?.subject.username ?? bootstrap.data?.principal?.username ?? t("shell.user.default");
  const initials = username.split(/[ ._-]+/).filter(Boolean).slice(0, 2).map((part) => part[0]?.toUpperCase()).join("") || "?";
  return <TimeZoneContext.Provider value={{ timeZone, setTimeZone }}><EffectiveAccessContext.Provider value={access.data}><AccessRequestContext.Provider value={{ error: access.error, isFetching: access.isFetching, retry: () => { void access.refetch(); } }}><AccessStatusContext.Provider value={access.isError ? "отказ" : access.data ? "получены" : "загружается"}>
    <a className="sli-ds-skip-link" href="#main">{t("shell.skip")}</a><IconSprite/>
    <div className="sli-ds-shell" data-sli-shell data-menu-open={mobileMenuOpen}>
      <aside className="sli-ds-shell__sidebar" aria-label={t("shell.sidebar.aria")} ref={sidebarRef}>
        <Link to="/" className="sli-ds-shell__brand" onClick={() => setMobileMenuOpen(false)}><span className="sli-ds-shell__brand-mark"><Icon name="shield"/></span><span><span className="sli-ds-shell__brand-name">SLI</span><span className="sli-ds-shell__brand-caption">{t("shell.brand.caption")}</span></span></Link>
        <nav className="sli-ds-shell__nav" aria-label={t("shell.nav.aria")}>
          {inAdminZone ? <Link to="/" className="sli-ds-shell__item" data-route="back-to-work" onClick={() => setMobileMenuOpen(false)}>
            <Icon name="chevron-left"/><span>{t("shell.backToWork")}</span>
          </Link> : null}
          {sidebarSections.map((section) => <section className="sli-ds-shell__section" key={section.id} aria-label={section.title}>
            {section.groups.length !== 1 || section.groups[0].items.length !== 1 || section.groups[0].items[0].label !== section.title
              ? <div className="sli-ds-shell__section-title">{section.title}</div> : null}
            {section.groups.map((group) => <div key={group.id} role="group" aria-label={group.title || section.title}>
              {inAdminZone && group.title ? <div className="sli-ds-shell__group-title">{group.title}</div> : null}
              {group.items.map((item) => {
                const active = isActivePath(item.path, navigationPath);
                return <Link key={item.id} to={item.path} data-route={item.path.replace(/^\//, "") || "workspace"}
                  className="sli-ds-shell__item" data-active={active || undefined} aria-current={active ? "page" : undefined}
                  onClick={() => setMobileMenuOpen(false)}><Icon name={item.icon}/><span>{item.label}</span></Link>;
              })}
            </div>)}
          </section>)}
          {!inAdminZone && adminItems[0] ? <Link to={adminItems[0].path} className="sli-ds-shell__item sli-ds-shell__admin" data-route="administration" onClick={() => setMobileMenuOpen(false)}>
            <Icon name="sliders"/><span>{t("shell.admin")}</span>
          </Link> : null}
        </nav>
      </aside>
      <div className="sli-ds-shell__scrim" aria-hidden="true" onClick={() => { setMobileMenuOpen(false); requestAnimationFrame(() => mobileMenuButtonRef.current?.focus()); }}/>
      <header className="sli-ds-shell__topbar">
        <button className="sli-ds-button sli-ds-shell__menu-button" data-variant="ghost" ref={mobileMenuButtonRef} type="button" aria-label={t("shell.menu.open")} aria-expanded={mobileMenuOpen} onClick={() => setMobileMenuOpen(true)}><Icon name="menu"/></button>
        {!isProblemsQueue ? <HeaderSearch key={location.pathname} currentSearch={committedSearch} journalQuery={journalQuery}
          onHome={isHome} canSearchObjects={capabilities.has("objects.view") || access.data?.resource_bound_capabilities?.includes("objects.view") === true}
          onNavigate={() => setMobileMenuOpen(false)}/> : null}
        {isProblemsQueue && agents && agents.state !== "unavailable" && Number.isFinite(agents.active_agents) && Number.isFinite(agents.current_agents)
          ? <span className="sli-ds-shell__indicator">{t("problems.queue.agentStatus", { current: agents.current_agents, total: agents.active_agents })}</span> : null}
        <div className="sli-ds-shell__profile" ref={profileMenuRef}>
          <button type="button" className="sli-ds-button sli-ds-shell__control" aria-label={username} aria-haspopup="menu" aria-expanded={profileMenuOpen} onClick={() => setProfileMenuOpen((open) => !open)}>
            <span aria-hidden="true" className="sli-ds-shell__avatar">{initials}</span><span className="sli-ds-shell__label-title" title={username}>{username}</span><Icon name="chevron-down"/>
          </button>
          {profileMenuOpen ? <div className="sli-ds-shell__menu" role="menu">
            <Link to="/settings" role="menuitem" className="sli-ds-button" data-variant="ghost" onClick={() => setProfileMenuOpen(false)}>{t("shell.adminNav.locale")}</Link>
            <div className="sli-ds-shell__menu-title" role="presentation">{t("shell.profile.theme.title")}</div>
            {THEME_PREFERENCES.map((value) => <button key={value} type="button" className="sli-ds-button" data-variant="ghost" role="menuitemradio" aria-checked={theme === value} data-theme-option={value} onClick={() => chooseTheme(value)}><span className="sli-ds-shell__menu-mark" aria-hidden="true">{theme === value ? <Icon name="check"/> : null}</span>{t(`shell.profile.theme.${value}` as MessageKey)}</button>)}
            <div className="sli-ds-shell__menu-sep" role="separator"/>
            <button type="button" className="sli-ds-button" data-variant="ghost" role="menuitem" disabled={logout.isPending} onClick={() => logout.mutate()}><Icon name="logout"/>{logout.isPending ? t("shell.profile.loggingOut") : t("shell.profile.logout")}</button>
          </div> : null}
        </div>
      </header>
      <main className="sli-ds-shell__main" id="main" tabIndex={-1}>
        <div className="sli-ds-shell__content" key={scopeKey}>
          <PageHeaderContext.Provider value={{ domain: domainControl }}>
            {previewModulePath(location.pathname) && (catalog.isError || catalog.data?.navigation?.modules_preview !== true)
              ? <StateView state={catalog.isPending ? "loading" : "unavailable"} message={t("plugins.status.moduleUnavailable")}/> : <Outlet/>}
          </PageHeaderContext.Provider>
          {inAdminZone ? <AdminRelatedLinks pathname={location.pathname} access={{ capabilities, reports: new Set(reports.map((report) => report.report_key)) }}/> : null}
        </div>
      </main>
    </div>
  </AccessStatusContext.Provider></AccessRequestContext.Provider></EffectiveAccessContext.Provider></TimeZoneContext.Provider>;
}

export function AppShell() {
  return <OverlayProvider><ShellContent/></OverlayProvider>;
}

