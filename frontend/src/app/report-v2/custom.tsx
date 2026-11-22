import { EMPTY_VALUE } from "../../shared/format";
import type { ComponentType } from "react";
import { useTimeZone } from "../App";
import { formatDateTime } from "../../shared/date-time";
import type { ReportResultDto } from "../../api/report-v2-types";
import { ProblemLifecycle } from "../problem-lifecycle";
import { SecurityProblemAclEvidence } from "../security-problem-acl-evidence";
import { DecoyVersionLink } from "../decoy-version-link";
import { RiskBadge } from "../problem-risk-acceptance";
import { SecurityChainsView } from "../security-chains-view";
import { VpnActivityStrip, type ActivityWindow } from "../vpn-activity-strip";
import { VpnPrintSheet } from "../vpn-print-sheet";
import { VpnConnectionSessionEvidence } from "../vpn-session-evidence";
import { AgentStatus, DnsIp, LastWorkplace } from "../../plugins/ad/ReportAdditions";
import { homeOccurrences } from "../home-view";

type Row = Record<string, unknown>;
export type RowComponentProps = { row: Row; parent: Row; params: URLSearchParams };

function VpnSessionEvidenceRow({ row, params }: RowComponentProps) {
  const { timeZone } = useTimeZone();
  const domain = Number(params.get("domain"));
  return <VpnConnectionSessionEvidence sourceDomainId={domain} sessionRowId={String(row.session_row_id ?? "")} formatTime={(value) => (value ? formatDateTime(value, timeZone) : EMPTY_VALUE)}/>;
}

/**
 * Report-specific components referenced by name from a declaration
 * (`Detail.row_component`). Only additional views live here — never a page.
 */
export const ROW_COMPONENTS: Record<string, ComponentType<RowComponentProps>> = {
  "vpn.session-evidence": VpnSessionEvidenceRow,
  "problems.acl-evidence": SecurityProblemAclEvidence,
};

export type ActionComponentProps = { row: Row };

function ProblemLifecycleActions({ row }: ActionComponentProps) {
  const { timeZone } = useTimeZone();
  return <ProblemLifecycle row={row} formatTime={(value) => (value ? formatDateTime(value, timeZone) : EMPTY_VALUE)}/>;
}

/** Row-level actions referenced by name (`Detail.actions`); they call the domain's own mutation API. */
export const ACTION_COMPONENTS: Record<string, ComponentType<ActionComponentProps>> = {
  "problems.lifecycle": ProblemLifecycleActions,
};

export type ViewComponentProps = { params: URLSearchParams; result?: ReportResultDto };

/** Whole-view components referenced by name (`View(kind="custom", component=...)`). */
export const VIEW_COMPONENTS: Record<string, ComponentType<ViewComponentProps>> = {
  "security.chains": SecurityChainsView,
};

export type CellComponentProps = { row: Row; window?: ActivityWindow };

function ProblemRiskBadge({ row }: CellComponentProps) {
  const { timeZone } = useTimeZone();
  return <RiskBadge row={row} formatTime={(value) => value ? formatDateTime(value, timeZone) : EMPTY_VALUE}/>;
}

function ProblemOccurrences({ row }: CellComponentProps) {
  const { timeZone } = useTimeZone();
  if (typeof row.occurrence_count !== "number") return null;
  const text = homeOccurrences(row.occurrence_count);
  if (!Array.isArray(row.problem_cohort)) return <span>{text}</span>;
  const params = new URLSearchParams(window.location.search);
  params.delete("id");
  params.delete("cursor");
  params.set("tz", timeZone);
  params.set("cohort", JSON.stringify(row.problem_cohort));
  return <a href={`/app/report/security.problems?${params}`} onClick={(event) => event.stopPropagation()}>{text}</a>;
}

/** Table cell components referenced by name (`Column.component`). */
export const CELL_COMPONENTS: Record<string, ComponentType<CellComponentProps>> = {
  "decoys.version": DecoyVersionLink,
  "ad.agent": AgentStatus,
  "ad.dns-ip": DnsIp,
  "ad.last-workplace": ({ row }) => <LastWorkplace row={row} compact/>,
  "problems.risk-badge": ProblemRiskBadge,
  "problems.occurrences": ProblemOccurrences,
  "vpn.activity-strip": VpnActivityStrip,
};

export type PageActionProps = { rows: Row[]; result?: ReportResultDto };

/** Page-level actions over the loaded rows (`ReportDefinition.page_actions`). */
export const PAGE_ACTIONS: Record<string, ComponentType<PageActionProps>> = {
  "vpn.print-sheet": VpnPrintSheet,
};
