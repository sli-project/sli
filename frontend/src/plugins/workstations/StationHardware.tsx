import { DataTable, FactList, type TableColumn } from "../../design-system";
import { t } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
import { formatNumber } from "../../shared/format";
import { hardwareChangeValues, hardwareField, hardwareSection, hardwareValue, type HardwareChange, type HardwareField,
  type HardwareRow, type HardwareSection, type StationHardware as Inventory } from "./hardware-model";

function HardwareTable({ section, rows, fields, extra = [] }: { section: HardwareSection; rows: HardwareRow[] | null;
  fields: HardwareField[]; extra?: TableColumn<HardwareRow>[] }) {
  if (!rows?.length) return <p className="sli-workstations__local-state">—</p>;
  const columns: TableColumn<HardwareRow>[] = fields.map(field => ({ key: field, label: hardwareField(field, section),
    value: row => field === "mount" && !row.mount && row.partition
      ? t("workstations.hardware.partition", { number: formatNumber(row.partition) }) : hardwareValue(row[field], field, section) }));
  return <DataTable caption={hardwareSection(section)} rows={rows} rowKey={row => row.id} columns={[...columns, ...extra]}
    compact density="compact" stickyHeader={false} showFooter={false}/>;
}

export function StationHardware({ hardware, timeZone }: { hardware: Inventory | null | undefined; timeZone: string }) {
  if (!hardware) return <p role="status" className="sli-workstations__local-state">{t("workstations.hardware.not_received")}</p>;
  const i = hardware.inventory;
  const fact = (section: HardwareSection, field: HardwareField) => ({ label: hardwareField(field, section),
    value: hardwareValue(i[section]?.[0]?.[field], field, section) });
  const tables: [HardwareSection, HardwareField[]][] = [
    ["disk", ["model", "size", "type", "interface", "serial"]],
    ["video", ["model"]],
    ["network", ["name", "mac", "speed"]],
    ["monitor", ["model", "serial"]],
  ];
  const diskModels = new Map(i.disk?.map(disk => [disk.id, disk.model]));
  return <div className="sli-workstations__collection">
    <section><h2>{hardwareSection("computer")}</h2><FactList facts={[
      fact("computer", "manufacturer"), fact("computer", "model"), fact("computer", "serial"),
      fact("bios", "version"), fact("bios", "date"), fact("security", "secure_boot"), fact("security", "tpm_version"), fact("security", "tpm_enabled"),
    ]}/></section>
    <section><h2>{hardwareSection("processor")}</h2><HardwareTable section="processor" rows={i.processor} fields={["model", "cores", "threads"]}/></section>
    <section><h2>{hardwareSection("memory")}</h2><FactList facts={[{ ...fact("memory", "size"), label: t("workstations.hardware.memory_total") }]}/>
      <HardwareTable section="memory_module" rows={i.memory_module} fields={["slot", "size", "speed", "manufacturer"]}/></section>
    {tables.map(([section, fields]) => <section key={section}><h2>{hardwareSection(section)}</h2><HardwareTable section={section} rows={i[section]} fields={fields}/>
      {section === "disk" && <HardwareTable section="volume" rows={i.volume} fields={["mount", "bitlocker"]}
        extra={[{ key: "disk", label: t("workstations.hardware.volume_disk"), value: row => row.disk_id ? String(diskModels.get(row.disk_id) ?? "—") : "—" }]}/>}
    </section>)}
    <section><h2>{t("workstations.hardware.history")}</h2><DataTable<HardwareChange>
      caption={t("workstations.hardware.history")} rows={hardware.changes} rowKey={row => row.id}
      compact density="compact" localPagination emptyContent={t("workstations.hardware.history_empty")} columns={[
        { key: "time", label: t("workstations.hardware.time"), minWidth: "10rem", value: row => formatDateTime(row.time, timeZone, { seconds: true }) },
        { key: "kind", label: t("workstations.hardware.change"), value: row => t(`workstations.hardware.${row.kind}`) },
        { key: "component", label: t("workstations.hardware.component"), value: row => [hardwareSection(row.section), row.component,
          row.field && row.field !== "version" ? hardwareField(row.field, row.section) : null].filter(Boolean).join(" · ") },
        { key: "values", label: t("workstations.hardware.before_after"), value: hardwareChangeValues },
      ]}/></section>
  </div>;
}
