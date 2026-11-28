import { t, type MessageKey } from "../../i18n";
import { formatNumber } from "../../shared/format";

export type HardwareSection = "computer" | "bios" | "security" | "processor" | "memory" | "memory_module"
  | "disk" | "volume" | "video" | "network" | "monitor";
export type HardwareField = "manufacturer" | "model" | "serial" | "version" | "date" | "tpm_version" | "secure_boot"
  | "tpm_enabled" | "cores" | "threads" | "size" | "slot" | "speed" | "type" | "interface" | "mount" | "bitlocker" | "name" | "mac";
type HardwareValue = string | number | boolean | null;
export type HardwareRow = Partial<Record<HardwareField, HardwareValue>> & {
  id: string; disk_id?: string | null; partition?: number | null; system?: boolean | null;
};
export type HardwareChange = {
  id: string; time: string; section: HardwareSection; component_id: string; component: string | null;
  kind: "added" | "removed" | "replaced" | "version_changed" | "changed";
  field: HardwareField | null; before: HardwareValue; after: HardwareValue; severity: "medium" | "low" | null;
};
export type StationHardware = { inventory: Record<HardwareSection, HardwareRow[] | null>; observed_at: string; changes: HardwareChange[] };

const label = (key: string) => t(`workstations.hardware.${key}` as MessageKey);
export const hardwareSection = (section: HardwareSection) => label(`section_${section}`);
export const hardwareField = (field: HardwareField, section: HardwareSection) => label(field === "speed" ? `speed_${section}` : field);

export function hardwareValue(value: HardwareValue | undefined, field: HardwareField | null, section: HardwareSection): string {
  if (value == null || value === "") return "—";
  if (typeof value === "boolean" || field === "bitlocker") return label(value === true || value === "on" ? "on" : "off");
  if (typeof value === "number") {
    if (field === "size") {
      const base = section === "disk" ? 1000 : 1024;
      const units = ["bytes", "kilobytes", "megabytes", "gigabytes", "terabytes"] as const;
      const scale = Math.max(0, Math.min(units.length - 1, Math.floor(Math.log(value) / Math.log(base))));
      return `${formatNumber(Math.round(value / base ** scale * 100) / 100)} ${label(units[scale])}`;
    }
    if (field === "speed") {
      if (section === "memory_module") return `${formatNumber(value)} ${label("mt_per_second")}`;
      return value >= 1e9 ? `${formatNumber(value / 1e9)} ${label("gbps")}` : `${formatNumber(value / 1e6)} ${label("mbps")}`;
    }
    return formatNumber(value);
  }
  return value;
}

export function hardwareChangeLabel(change: HardwareChange): string {
  if (change.severity === "medium") {
    if (change.field === "secure_boot" || change.field === "tpm_enabled" || change.field === "bitlocker") return label(`${change.field}_disabled`);
    if (change.section === "disk" && (change.kind === "added" || change.kind === "removed")) return label(`disk_${change.kind}`);
  }
  return `${hardwareSection(change.section)} · ${label(change.kind)}`;
}

export function hardwareChangeValues(change: HardwareChange): string {
  const value = (item: HardwareValue) => hardwareValue(item, change.field, change.section);
  return `${value(change.before)} → ${value(change.after)}`;
}
