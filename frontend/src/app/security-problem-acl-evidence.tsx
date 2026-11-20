import { EMPTY_VALUE } from "../shared/format";
import type { FileAclSnapshotEvidence } from "../api/report-v2-types";
import { Badge } from "../design-system";
import { t, type MessageKey } from "../i18n";
import { formatDateTime } from "../shared/date-time";
import { useTimeZone } from "./App";

const limitationKeys: Record<string, MessageKey> = {
  native_source_unavailable: "evidence.acl.unavailable",
  privileges_and_conditional_aces_not_evaluated: "evidence.acl.limitations.privileges_and_conditional_aces_not_evaluated",
};
const coverageKeys: Record<FileAclSnapshotEvidence["coverage"]["state"], MessageKey> = {
  complete: "evidence.acl.coverage.complete", partial: "evidence.acl.coverage.partial",
  failed: "evidence.acl.coverage.failed", unknown: "evidence.acl.coverage.unknown",
};

/** A retained grant describes its snapshot, never current or effective access. */
export function SecurityProblemAclEvidence({ row }: { row: Record<string, unknown> }) {
  const { timeZone } = useTimeZone();
  if (row.storage_kind !== "file_audit_snapshot") return null;
  const snapshot = row as FileAclSnapshotEvidence;
  if (snapshot.availability === "unavailable") return <section aria-label={t("evidence.acl.snapshot")}>
    <p className="sli-ds-note">{t("evidence.acl.historical")}</p>
    <p className="sli-ds-note">{t("evidence.acl.unavailable")}</p>
  </section>;
  const limitations = [...new Set(snapshot.limitations.map((code) => t(Object.hasOwn(limitationKeys, code) ? limitationKeys[code] : "evidence.acl.limitations.unknown")))];
  return <section aria-label={t("evidence.acl.snapshot")}>
    <p className="sli-ds-note">{t("evidence.acl.historical")}</p>
    <p>{t("evidence.acl.observed_at")}: {snapshot.observed_at_utc
      ? <time dateTime={snapshot.observed_at_utc}>{formatDateTime(snapshot.observed_at_utc, timeZone)}</time> : EMPTY_VALUE}</p>
    <p>{t("evidence.acl.coverage")}: <Badge tone={snapshot.coverage.state === "complete" ? "neutral" : "warning"}>{t(coverageKeys[snapshot.coverage.state])}</Badge></p>
    {snapshot.coverage.unread_objects != null ? <p className="sli-ds-note">{t("evidence.acl.coverage.unread", { count: snapshot.coverage.unread_objects })}</p> : null}
    {snapshot.coverage.has_more === true ? <p className="sli-ds-note">{t("evidence.acl.coverage.more")}</p> : null}
    <ul>{snapshot.grants.map((grant) => <li key={JSON.stringify([grant.path, grant.layer])}>
      <dl>
        <dt>{t("evidence.acl.paths")}</dt><dd>{grant.path}</dd>
        <dt>{t("evidence.acl.layer")}</dt><dd>{grant.layer === "ntfs" ? "NTFS" : "SMB"}</dd>
        <dt>{t("evidence.acl.principals")}</dt><dd>{t("evidence.acl.everyone")}</dd>
      </dl>
      <Badge tone="warning">{t("security.scenarios.filters.risk.medium")}</Badge>
    </li>)}</ul>
    {snapshot.grants_has_more ? <p className="sli-ds-note">{t("evidence.acl.more_grants")}</p> : null}
    {limitations.length ? <ul className="sli-ds-state__text">{limitations.map((text) => <li key={text}>{text}</li>)}</ul> : null}
  </section>;
}
