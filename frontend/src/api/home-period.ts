export type HomeSeverity = "critical" | "high" | "medium" | "low";

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
  at: string;
  source: string | null;
  observations: HomeObservation[];
  href: string;
  object_href: string | null;
  events_href: string | null;
};

export type HomeController = {
  id: number;
  name: string | null;
  at: string | null;
  passed: number;
  failures: { key: "dns" | "sysvol" | "services" | "connectivity" | "advertising" | "time" | "os"; actual: string | null }[];
  href: string | null;
};

export type HomeChange = {
  at: string;
  name: string | null;
  href?: string;
} & (
  | { event_id: number; initiator: string | null; value: string | null }
  | { kind: "password"; field: string; before: string | null; after: string | null }
  | { kind: "gpo"; operation: string; label: string | null; before: string | null; after: string | null }
);

export type HomePeriod = {
  domains: { id: number; name: string }[];
  domain_id: number | null;
  from: string;
  to: string;
  updated_at: string;
  problems: { new_count: number | null; closed_count: number | null; open_count: number | null; items: HomeProblem[]; href: string | null } | null;
  controllers: { items: HomeController[]; href: string | null } | null;
  changes: { items: HomeChange[]; href: string | null } | null;
  activity: {
    hours: { at: string; failed: number | null; succeeded: number | null; typical: number | null }[];
    markers: { at: string; severity: HomeSeverity; name?: string; fact?: string }[];
  } | null;
};
