import type { ReactNode } from "react";
import { t } from "../i18n";

/**
 * Loading placeholders. They approximate the final geometry (DataTable rows,
 * MetricStrip tiles, cards) so data arriving does not shift the layout.
 * Purely decorative: the accessible "loading" text lives in LoadingRegion
 * (role=status), skeleton nodes are aria-hidden.
 */
export function Skeleton({ variant = "line", width, height }: { variant?: "line" | "block"; width?: string | number; height?: string | number }) {
  return <span className="sli-ds-skeleton" data-variant={variant} aria-hidden="true" style={{ width, height }}/>;
}

const LINE_WIDTHS = ["72%", "48%", "86%", "58%", "66%"];

export function TableSkeleton({ columns = 5, rows = 8 }: { columns?: number; rows?: number }) {
  return <div className="sli-ds-table sli-ds-skeleton-table" aria-hidden="true">
    <div className="sli-ds-table__scroll">
      <table>
        <thead><tr>{Array.from({ length: columns }, (_, c) => <th key={c}><Skeleton width={`${50 + (c * 17) % 40}%`}/></th>)}</tr></thead>
        <tbody>{Array.from({ length: rows }, (_, r) => <tr key={r}>
          {Array.from({ length: columns }, (_, c) => <td key={c}><Skeleton width={LINE_WIDTHS[(r + c) % LINE_WIDTHS.length]}/></td>)}
        </tr>)}</tbody>
      </table>
    </div>
  </div>;
}

export function MetricStripSkeleton({ count = 4 }: { count?: number }) {
  return <div className="sli-ds-metrics" aria-hidden="true">
    {Array.from({ length: count }, (_, index) => <div key={index} className="sli-ds-metric sli-ds-skeleton-metric">
      <Skeleton width="55%"/>
      <Skeleton variant="block" width="40%" height="1.6em"/>
    </div>)}
  </div>;
}

export function CardSkeleton({ lines = 3 }: { lines?: number }) {
  return <div className="sli-ds-skeleton-card" aria-hidden="true">
    <Skeleton width="38%"/>
    {Array.from({ length: lines }, (_, index) => <Skeleton key={index} width={LINE_WIDTHS[index % LINE_WIDTHS.length]}/>)}
  </div>;
}

/** Skeleton wrapper with the accessible loading announcement for screen readers. */
export function LoadingRegion({ children, label }: { children: ReactNode; label?: string }) {
  return <div className="sli-ds-loading" role="status" aria-live="polite" aria-busy="true">
    <span className="sli-ds-visually-hidden">{label ?? t("state.loading")}</span>
    {children}
  </div>;
}
