export type HomeSeverity = "critical" | "high" | "medium" | "low" | "unknown";

export type HomeQueueFilter = "all" | "unassigned" | "in_work";
export type HomeQueuePage = { filter: HomeQueueFilter; page: number; limit: number };

export type HomeObservation = {
  at: string;
  event_id: number;
  source: string | null;
  href: string | null;
};

export type HomeProblem = {
  id: number;
  name: string | null;
  fact: string | null;
  severity: HomeSeverity;
  at: string | null;
  status: "new" | "confirmed" | "repeated" | "active" | "review";
  assignee: string | null;
  assignee_state: "assigned" | "unassigned" | "mixed" | "unknown";
  occurrence_count: number;
  repeats_href?: string | null;
  source: string | null;
  observations: HomeObservation[];
  href: string;
  object_href: string | null;
};

export type HomeCheckReport = "ad.infrastructure" | "ad.users.v2" | "ad.computers.v6" | "ad.gpo.v2";

export type HomeWeakSpot = {
  id: string;
  label: string | null;
  label_key?: "reports.v2.ad.gpo.v2.reasons.version_mismatch.title" | null;
  count: number;
  report: HomeCheckReport;
  href: string;
};

export type HomeChange = {
  at: string;
  name: string | null;
  href?: string | null;
  before_at?: string | null;
} & (
  | { event_id: number; initiator: string | null; value: string | null; before?: string | null; after?: string | null }
  | { kind: "password"; field: string; before: string | null; after: string | null }
  | { kind: "gpo"; operation: string; label: string | null; before: string | null; after: string | null }
);

export type HomePeriod = {
  domains: { id: number; name: string }[];
  domain_id: number | null;
  from: string;
  to: string;
  updated_at: string;
  active_operator_count: number | null;
  since_previous_login: {
    from: string;
    to: string;
    new_count: number;
    closed_count: number;
    new_href: string;
  } | null;
  problems: {
    open_count: number | null;
    unassigned_count: number | null;
    in_work_count: number | null;
    page: number | null;
    items: HomeProblem[];
    href: string | null;
  } | null;
  weak_spots: { items: HomeWeakSpot[]; failed: HomeCheckReport[] } | null;
  changes: { items: HomeChange[]; href: string | null } | null;
};
