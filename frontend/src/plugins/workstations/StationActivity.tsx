import type { MouseEvent } from "react";
import { DataTable, SeverityBadge, type TableColumn } from "../../design-system";
import { t } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
import { formatNumber } from "../../shared/format";
import { hardwareChangeLabel, hardwareChangeValues, type HardwareChange } from "./hardware-model";
import { localHref, patchedSearch, resetEvents, STATION_SEVERITIES, type ActivityInterval, type ActivityTab,
  type StationActivity, type StationDevice, type StationLogon, type StationProgram, type StationSeverity } from "./model";

type ChangeSearch = (patch: Record<string, string | null>) => void;
type HardwareFact = ActivityInterval & { id: string; severity: StationSeverity; title: string; object: string; count: number };

export function notableHardware(changes: HardwareChange[]): HardwareFact[] {
  const grouped = new Map<string, HardwareFact>();
  for (const change of changes) {
    if (change.severity !== "medium" && change.severity !== "low") continue;
    const id = JSON.stringify([change.section, change.component_id, change.field, change.kind, change.severity]);
    const previous = grouped.get(id);
    if (!previous) grouped.set(id, { id, title: hardwareChangeLabel(change), severity: change.severity, first: change.time, last: change.time,
      count: 1, object: [change.component, change.field ? hardwareChangeValues(change) : null].filter(Boolean).join(" · ") });
    else {
      previous.count++;
      if (Date.parse(change.time) < Date.parse(previous.first)) previous.first = change.time;
    }
  }
  return [...grouped.values()];
}

export function followStationLink(event: MouseEvent<HTMLAnchorElement>, update: () => void) {
  if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
  event.preventDefault();
  update();
}

export function ActivityCounts({ activity, hardware = [], search, update }: {
  activity: StationActivity | null | undefined; hardware?: HardwareFact[]; search: URLSearchParams; update: ChangeSearch;
}) {
  const importance = STATION_SEVERITIES.flatMap(severity => {
    const count = [...(activity?.notable ?? []), ...hardware].filter(row => row.severity === severity).length;
    return count ? [t(`workstations.activity.count_${severity}`, { count: formatNumber(count) })] : [];
  });
  const links: [ActivityTab, string][] = [
    ["important", t("workstations.activity.important_summary", { count: importance.join(", ") || "0" })],
  ];
  if (activity) links.push(
    ["programs", t("workstations.activity.programs_summary", { count: formatNumber(activity.programs.length) })],
    ["logons", t("workstations.activity.logons_summary", { count: formatNumber(activity.logons.length) })],
    ["devices", t("workstations.activity.devices_summary", { count: formatNumber(activity.devices.length) })],
  );
  return <div className="sli-workstations__context">
    <span>{links.map(([tab, label], index) => {
      const patch = { ...resetEvents, station_tab: tab, program: null };
      return <span key={tab}>{index ? " · " : null}<a href={localHref(patchedSearch(search, patch))}
        onClick={event => followStationLink(event, () => update(patch))}>{label}</a></span>;
    })}</span>
  </div>;
}

const userLabel = (name: string | null) => name ?? t("workstations.activity.unknown_account");
const logonTypes = ["2", "3", "4", "5", "7", "8", "9", "10", "11", "12", "13"] as const;

export function ActivityTable({ tab, activity, hardware = [], search, timeZone, update }: {
  tab: ActivityTab; activity: StationActivity | null | undefined; hardware?: HardwareFact[]; search: URLSearchParams; timeZone: string; update: ChangeSearch;
}) {
  const caption = t(`workstations.activity.${tab}`);
  const emptyContent = t(`workstations.activity.${tab}_empty`);
  const time = (value: string) => formatDateTime(value, timeZone, { seconds: true });
  const interval: TableColumn<ActivityInterval>[] = [
    { key: "first", label: t("workstations.activity.first"), render: row => time(row.first), minWidth: "10rem" },
    { key: "last", label: t("workstations.activity.last"), render: row => time(row.last), minWidth: "10rem" },
  ];
  const common = { caption, compact: true, density: "compact" as const, localPagination: true, emptyContent };
  switch (tab) {
    case "important": {
      const facts = (activity?.notable ?? []).map(row => ({ ...row, id: JSON.stringify([row.fact, row.object, row.first, row.last]),
        title: t(`workstations.activity.fact_${row.fact}`) }));
      const rows = [...facts, ...hardware].sort((a, b) => STATION_SEVERITIES.indexOf(a.severity) - STATION_SEVERITIES.indexOf(b.severity)
        || Date.parse(b.last) - Date.parse(a.last));
      return <DataTable {...common} rows={rows} rowKey={row => row.id} columns={[
        { key: "importance", label: t("workstations.activity.importance"), width: "11%", render: row => <SeverityBadge severity={row.severity}/> },
        { key: "fact", label: t("workstations.activity.fact"), width: "24%", value: row => row.title },
        { key: "object", label: t("workstations.activity.object"), width: "27%", value: row => row.object || "—" },
        ...interval,
        { key: "count", label: t("workstations.workspace.observations"), width: "10%", align: "end",
          render: row => row.count > 1 ? `×${formatNumber(row.count)}` : "1" },
      ]}/>;
    }
    case "programs": {
      const patchFor = (path: string) => ({ ...resetEvents, station_tab: "events", view: "all", program: path });
      return <DataTable<StationProgram> {...common} rows={activity?.programs ?? []} rowKey={row => row.path} onRowClick={row => update(patchFor(row.path))} columns={[
        { key: "name", label: t("workstations.activity.program"), width: "15%", render: row => {
          const patch = patchFor(row.path);
          return <a className="sli-ds-table__link" href={localHref(patchedSearch(search, patch))}
            onClick={event => { event.stopPropagation(); followStationLink(event, () => update(patch)); }}>{row.name}</a>;
        } },
        { key: "path", label: t("workstations.workspace.process_path"), value: row => row.path, width: "32%", minWidth: "16rem" },
        ...interval,
        { key: "starts", label: t("workstations.activity.starts"), kind: "number", width: "9%", value: row => row.count },
        { key: "users", label: t("workstations.activity.users"), value: row => row.users.join(", ") || userLabel(null) },
      ]}/>;
    }
    case "logons":
      return <DataTable<StationLogon> {...common} rows={activity?.logons ?? []} rowKey={row => JSON.stringify([row.account, row.type])} columns={[
        { key: "account", label: t("workstations.workspace.account"), value: row => userLabel(row.account) },
        { key: "type", label: t("workstations.workspace.logon_type"), value: row => {
          const type = logonTypes.find(code => code === row.type);
          return type ? t(`reports.v2.events.journal.logon_type.${type}`) : t("workstations.activity.unknown_type");
        } },
        { key: "last", label: t("workstations.activity.last"), render: row => time(row.last) },
        { key: "count", label: t("workstations.workspace.observations"), kind: "number", value: row => row.count },
        { key: "failures", label: t("workstations.activity.failures"), kind: "number", value: row => row.failures },
      ]}/>;
    case "devices":
      return <DataTable<StationDevice> {...common} rows={activity?.devices ?? []} rowKey={row => JSON.stringify([row.class, row.name, row.first, row.last])} columns={[
        { key: "class", label: t("workstations.workspace.device_class"), value: row => row.class ?? t("workstations.activity.unknown_type") },
        { key: "name", label: t("workstations.workspace.device_name"), value: row => row.name ?? t("workstations.activity.unknown_device") },
        ...interval,
      ]}/>;
  }
}
