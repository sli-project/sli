import { useMemo } from "react";
import { useTimeZone } from "../shared/time-zone";
import { formatCell, formatDateTime, type CellKind } from "./format";

/** Bind dates to this render, not an effect-updated module global. */
export function useDateFormatters() {
  const { timeZone } = useTimeZone();
  return useMemo(() => ({
    formatDateTime: (value: string | Date | null | undefined, withTime = true) => formatDateTime(value, withTime, timeZone),
    formatCell: (value: unknown, kind: CellKind = "text") => formatCell(value, kind, timeZone),
  }), [timeZone]);
}
