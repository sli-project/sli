import { EMPTY_VALUE } from "../shared/format";
import type { FileAclSnapshotEvidence } from "../api/report-v2-types";
import { Badge } from "../design-system";
import { t } from "../i18n";
import { formatDateTime } from "../shared/date-time";
import { useTimeZone } from "./App";

/** A retained grant describes its snapshot, never current or effective access. */
export function SecurityProblemAclEvidence({ row }: { row: Record<string, unknown> }) {
  const { timeZone } = useTimeZone();
  if (row.storage_kind !== "file_audit_snapshot") return null;
  const snapshot = row as FileAclSnapshotEvidence;
  return <section aria-label={t("evidence.acl.snapshot")}>
    <p>{t("evidence.acl.observed_at")} · {snapshot.observed_at_utc
      ? <time dateTime={snapshot.observed_at_utc}>{formatDateTime(snapshot.observed_at_utc, timeZone)}</time> : EMPTY_VALUE}</p>
    {snapshot.availability === "unavailable" ? <p role="alert">{t("evidence.acl.unavailable")}</p> : <ul>{snapshot.grants.map((grant) => <li key={JSON.stringify([grant.path, grant.layer])}>
      <dl>
        <dt>{t("evidence.acl.paths")}</dt><dd>{grant.path}</dd>
        <dt>{t("evidence.acl.layer")}</dt><dd>{grant.layer === "ntfs" ? "NTFS" : "SMB"}</dd>
        <dt>{t("evidence.acl.principals")}</dt><dd>{t("evidence.acl.everyone")}</dd>
      </dl>
      <Badge tone="warning">{t("security.scenarios.filters.risk.medium")}</Badge>
    </li>)}</ul>}
  </section>;
}
