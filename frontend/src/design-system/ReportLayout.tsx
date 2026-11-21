import type { ReactNode } from "react";
import { t } from "../i18n";
import type { ApiMessage } from "../i18n/messages";
import { PageHeader, type Crumb } from "./PageHeader";
import { StateView, type ResultState } from "./StateView";
import { LoadingRegion, MetricStripSkeleton, TableSkeleton } from "./Skeleton";
import { TabPanel } from "./Tabs";

/**
 * The one report page composition (ADR 0009 rule 3):
 * header → metrics → filters → view tabs → state banner → views, plus an optional drawer.
 * Tabs stay above the state: an empty main table must not hide other views.
 * Reports fill the slots; they do not define their own page geometry.
 * While loading, the metrics/table slots show skeletons of the final geometry.
 */
export function ReportLayout({ title, subtitle, crumbs, meta, actions, metrics, filters, tabs, tabbed = false, state = "ok", stateMessage, stateDetail, stateActions, stateView, staleAge, onRetry, busy = false, children, drawer, dockDrawer = false }: {
  title: string;
  subtitle?: ReactNode;
  crumbs?: Crumb[];
  meta?: ReactNode;
  actions?: ReactNode;
  metrics?: ReactNode;
  filters?: ReactNode;
  tabs?: ReactNode;
  /** Uses the surrounding Tabs provider to label all result states. */
  tabbed?: boolean;
  state?: ResultState;
  stateMessage?: ApiMessage;
  stateDetail?: ReactNode;
  stateActions?: ReactNode;
  /** Report-specific state copy and coverage, composed from StateView. */
  stateView?: ReactNode;
  staleAge?: string;
  onRetry?: () => void;
  /** Data is being refreshed while the previous data stays visible. */
  busy?: boolean;
  children?: ReactNode;
  drawer?: ReactNode;
  dockDrawer?: boolean;
}) {
  const blocking = state === "loading" || state === "empty" || state === "unavailable" || state === "denied" || state === "not_collected" || state === "error";
  const result = state === "loading"
    ? <LoadingRegion>{metrics ? null : <MetricStripSkeleton/>}<TableSkeleton/></LoadingRegion>
    : blocking ? stateView ?? <StateView state={state} message={stateMessage} detail={stateDetail} actions={stateActions} onRetry={onRetry}/> : children;
  const view = tabbed ? <TabPanel>{result}</TabPanel> : blocking ? result : <div className="sli-ds-report__views">{result}</div>;
  return <section className="sli-ds-report" data-state={state} data-busy={busy || undefined} aria-busy={busy || undefined}>
    {busy ? <div className="sli-ds-busybar" role="progressbar" aria-label={t("state.refreshing")}/> : null}
    <PageHeader title={title} subtitle={subtitle} crumbs={crumbs} meta={meta} actions={actions}/>
    {state !== "denied" ? metrics : null}
    {state !== "denied" ? filters : null}
    {tabbed || state !== "denied" ? tabs : null}
    {state === "partial" || state === "stale" || state === "processing" ? stateView ?? <StateView state={state} message={stateMessage} detail={stateDetail} age={staleAge} compact/> : null}
    {dockDrawer ? <div className="sli-ds-split-layout">{view}{drawer}</div> : <>{view}{drawer}</>}
  </section>;
}
