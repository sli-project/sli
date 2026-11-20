import { t } from "../i18n";

export function DecoyVersionLink({ row }: { row: Record<string, unknown> }) {
  const id = row.decoy_id;
  const revision = row.decoy_revision;
  if (typeof id !== "string" || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(id)
      || typeof revision !== "number" || !Number.isSafeInteger(revision) || revision <= 0) return null;
  const params = new URLSearchParams({ decoy_id: id, decoy_revision: String(revision) });
  return <a href={`/app/platform-settings?${params}#decoys`} onClick={(event) => event.stopPropagation()}>
    {t("decoys.event_version", { revision })}
  </a>;
}
