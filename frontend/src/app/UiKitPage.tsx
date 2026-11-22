import { useMemo, useState } from "react";
import { t } from "../i18n";
import { shortWeekday } from "../shared/date-time";
import {
  CardSkeleton, Chart, DataTable, DetailDrawer, FactList, FilterBar, MetricStrip, MetricStripSkeleton, ReportLayout, StateView, TableSkeleton,
  type ChartSpec, type FilterField, type FilterValues, type ResultState, type SortState, type TableColumn,
} from "../design-system";

/*
  Living catalogue of the SLI design system (ADR 0013). It shows only
  synthetic demo data and is not linked from the navigation.
*/

type DemoRow = { id: string; host: string; os: string; logons: number; lastSeen: string | null };

const DEMO_ROWS: DemoRow[] = Array.from({ length: 8 }, (_, index) => ({
  id: String(index + 1),
  host: index === 3 ? "очень-длинное-имя-компьютера-для-проверки-переноса.example.test" : `ws-${String(index + 1).padStart(3, "0")}.example.test`,
  os: index % 3 === 0 ? "Windows Server 2022" : "Windows 11",
  logons: (index + 1) * 37,
  lastSeen: index === 5 ? null : new Date(Date.UTC(2026, 8, 20 + index, 8, 15)).toISOString(),
}));

function demoColumns(): TableColumn<DemoRow>[] { return [
  { key: "host", label: t("uiKit.computer"), sortable: true },
  { key: "os", label: t("uiKit.os"), sortable: true },
  { key: "logons", label: t("uiKit.logons"), kind: "number", sortable: true },
  { key: "lastSeen", label: t("uiKit.lastLogon"), kind: "datetime", sortable: true, hiddenByDefault: false },
]; }

function demoFields(): FilterField[] { return [
  { key: "q", label: t("uiKit.search"), kind: "text" },
  { key: "os", label: t("uiKit.os"), kind: "select", options: [{ value: "win11", label: "Windows 11", count: 5 }, { value: "ws2022", label: "Windows Server 2022", count: 3 }] },
  { key: "period", label: t("uiKit.period"), kind: "period" },
]; }

const STATES: ResultState[] = ["loading", "empty", "partial", "stale", "unavailable", "denied"];

function demoSeries(): ChartSpec {
  const start = Date.UTC(2026, 8, 1);
  return {
    kind: "timeseries",
    series: [
      { name: t("uiKit.successfulLogons"), points: Array.from({ length: 28 }, (_, day) => ({ x: new Date(start + day * 86_400_000).toISOString(), y: 40 + Math.round(20 * Math.sin(day / 3)) })) },
      { name: t("uiKit.failures"), points: Array.from({ length: 28 }, (_, day) => ({ x: new Date(start + day * 86_400_000).toISOString(), y: 4 + (day % 5) })) },
    ],
  };
}

function demoHeatmap(): ChartSpec {
  const days = Array.from({ length: 7 }, (_, day) => shortWeekday(new Date(Date.UTC(2026, 8, 7 + day))));
  const hours = Array.from({ length: 24 }, (_, hour) => String(hour));
  return { kind: "heatmap", data: { xLabels: hours, yLabels: days, cells: days.flatMap((_, y) => hours.map((__, x) => ({ x, y, value: y < 5 && x >= 8 && x <= 18 ? 10 + ((x * y) % 7) : (x * 3 + y) % 3 }))) } };
}

export function UiKitPage() {
  const [filters, setFilters] = useState<FilterValues>({ period: { preset: "30d" } });
  const [sort, setSort] = useState<SortState>({ field: "host", direction: "asc" });
  const [selected, setSelected] = useState<DemoRow | null>(null);
  const [osFilter, setOsFilter] = useState<string | null>(null);
  const [theme, setTheme] = useState<"auto" | "light" | "dark">("auto");
  const [density, setDensity] = useState<"normal" | "compact">("normal");
  const series = useMemo(demoSeries, []);
  const heatmap = useMemo(demoHeatmap, []);

  const applyTheme = (value: typeof theme) => {
    setTheme(value);
    document.documentElement.dataset.theme = value === "auto" ? "system" : value;
  };
  const applyDensity = (value: typeof density) => {
    setDensity(value);
    if (value === "normal") delete document.documentElement.dataset.density; else document.documentElement.dataset.density = value;
  };
  const rows = DEMO_ROWS
    .filter((row) => !osFilter || (osFilter === "server" ? row.os.includes("Server") : !row.os.includes("Server")))
    .sort((a, b) => {
      const left = a[sort.field as keyof DemoRow] ?? "", right = b[sort.field as keyof DemoRow] ?? "";
      const order = left < right ? -1 : left > right ? 1 : 0;
      return sort.direction === "asc" ? order : -order;
    });

  return <div className="sli-ds-report">
    <ReportLayout
      title={t("uiKit.title")}
      subtitle={t("uiKit.subtitle")}
      crumbs={[{ label: t("uiKit.administration") }, { label: t("uiKit.designSystem") }]}
      meta={<><span>{t("uiKit.theme")}: <select aria-label={t("uiKit.theme")} value={theme} onChange={(event) => applyTheme(event.target.value as typeof theme)}><option value="auto">{t("uiKit.themeAuto")}</option><option value="light">{t("uiKit.themeLight")}</option><option value="dark">{t("uiKit.themeDark")}</option></select></span>
        <span>{t("uiKit.density")}: <select aria-label={t("uiKit.density")} value={density} onChange={(event) => applyDensity(event.target.value as typeof density)}><option value="normal">{t("uiKit.densityNormal")}</option><option value="compact">{t("uiKit.densityCompact")}</option></select></span></>}
      actions={<button type="button" className="sli-ds-button">{t("uiKit.export")}</button>}
      metrics={<MetricStrip items={[
        { key: "all", label: t("uiKit.computers"), value: DEMO_ROWS.length, tone: "accent", onSelect: () => setOsFilter(null), active: osFilter === null },
        { key: "server", label: t("uiKit.servers"), value: 3, onSelect: () => setOsFilter("server"), active: osFilter === "server" },
        { key: "ws", label: t("uiKit.workstations"), value: 5, onSelect: () => setOsFilter("ws"), active: osFilter === "ws" },
        { key: "unknown", label: t("uiKit.noLogons"), value: null, tone: "warning", caption: t("uiKit.notCollected") },
      ]}/>}
      filters={<FilterBar fields={demoFields()} values={filters} defaults={{ period: { preset: "30d" } }} onApply={setFilters}/>}
      state="partial"
      stateDetail={t("uiKit.partialExample")}
      drawer={<DetailDrawer open={selected !== null} title={selected?.host ?? ""} subtitle={selected?.os} onClose={() => setSelected(null)}>
        <FactList facts={[{ label: t("uiKit.os"), value: selected?.os }, { label: t("uiKit.logonsInPeriod"), value: selected?.logons }, { label: t("uiKit.lastLogon"), value: selected?.lastSeen }]}/>
      </DetailDrawer>}
    >
      <DataTable caption={t("uiKit.table")} columns={demoColumns()} rows={rows} rowKey={(row) => row.id}
        sort={sort} onSort={(field) => setSort((current) => ({ field, direction: current.field === field && current.direction === "asc" ? "desc" : "asc" }))}
        onRowClick={setSelected} selectedKey={selected?.id} total={DEMO_ROWS.length} hasMore onLoadMore={() => {}}/>
      <Chart title={t("uiKit.dailyLogons")} spec={series}/>
      <Chart title={t("uiKit.activity")} spec={heatmap} height={240}/>
    </ReportLayout>
    <section aria-label={t("uiKit.skeletons")} style={{ display: "grid", gap: "var(--sli-space-3)" }}>
      <h2>{t("uiKit.skeletons")}</h2>
      <MetricStripSkeleton/>
      <TableSkeleton columns={4} rows={4}/>
      <CardSkeleton/>
    </section>
    <section aria-label={t("uiKit.states")} style={{ display: "grid", gap: "var(--sli-space-3)" }}>
      <h2>{t("uiKit.honestStates")}</h2>
      {STATES.map((state) => <StateView key={state} state={state} age={t("uiKit.sampleAge")} onRetry={() => {}}/>)}
    </section>
  </div>;
}
