import type { ReactNode } from "react";
import { t } from "../i18n";
import type { ApiMessage } from "../i18n/messages";
import { PageHeader, type Crumb, type PageHeaderControls } from "./PageHeader";
import { StateView, type ResultState } from "./StateView";
import { LoadingRegion, MetricStripSkeleton, TableSkeleton } from "./Skeleton";
import { TabPanel } from "./Tabs";
import { Panel } from "./Primitives";

/**
 * The one report page composition (ADR 0009 rule 3):
 * header → metrics → filters → view tabs → state banner → views, plus an optional drawer.
 * Tabs stay above the state: an empty main table must not hide other views.
 * Reports fill the slots; they do not define their own page geometry.
 * While loading, the metrics/table slots show skeletons of the final geometry.
 */
export function ReportLayout({ title, subtitle, crumbs, meta, actions, controls, domain, showDomain, metrics, filters, tabs, tabbed = false, panel = false, state = "ok", stateMessage, stateDetail, stateActions, stateView, staleAge, onRetry, busy = false, children, drawer, inlineDrawer, side, split = false }: {
  title: string;
  subtitle?: ReactNode;
  crumbs?: Crumb[];
  meta?: ReactNode;
  actions?: ReactNode;
  controls?: PageHeaderControls;
  domain?: string;
  showDomain?: boolean;
  metrics?: ReactNode;
  filters?: ReactNode;
  tabs?: ReactNode;
  /** Uses the surrounding Tabs provider to label all result states. */
  tabbed?: boolean;
  panel?: boolean;
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
  side?: ReactNode;
  inlineDrawer?: ReactNode;
  split?: boolean;
}) {
  const blocking = state === "loading" || state === "empty" || state === "unavailable" || state === "denied" || state === "not_collected" || state === "error";
  const result = state === "loading"
    ? <LoadingRegion>{metrics ? null : <MetricStripSkeleton/>}<TableSkeleton/></LoadingRegion>
    : blocking ? stateView ?? <StateView state={state} message={stateMessage} detail={stateDetail} actions={stateActions} onRetry={onRetry}/> : children;
  const reportContent = side ? <div className="sli-ds-report__side">{result}{side}</div> : result;
  const views = tabbed ? <TabPanel>{reportContent}</TabPanel> : blocking && !split ? result : <div className="sli-ds-report__views" data-split={Boolean(inlineDrawer) || undefined}>
    {inlineDrawer ? <div className="sli-ds-report__list">{reportContent}</div> : reportContent}
    {inlineDrawer}
  </div>;
  const content = <>
    {tabbed || state !== "denied" ? tabs : null}
    {state === "partial" || state === "stale" || state === "processing" ? stateView ?? <StateView state={state} message={stateMessage} detail={stateDetail} age={staleAge} compact/> : null}
    {split ? <div className="sli-ds-report__split">{views}{drawer}</div> : views}
  </>;
  return <section className="sli-ds-report" data-state={state} data-busy={busy || undefined} aria-busy={busy || undefined}>
    {busy ? <div className="sli-ds-busybar" role="progressbar" aria-label={t("state.refreshing")}/> : null}
    <PageHeader title={title} subtitle={subtitle} crumbs={crumbs} meta={meta} actions={actions} controls={controls} domain={domain} showDomain={showDomain}/>
    {state !== "denied" ? metrics : null}
    {state !== "denied" ? filters : null}
    {panel ? <Panel>{content}</Panel> : content}
    {split ? null : drawer}
  </section>;
}
