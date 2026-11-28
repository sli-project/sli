import { t } from "../i18n";
import { Button } from "./Primitives";

export function TableDensity({ compact, onChange }: { compact: boolean; onChange: (compact: boolean) => void }) {
  return <div className="sli-ds-header__actions" role="group" aria-label={t("table.density")}>
    <Button variant={compact ? "primary" : undefined} aria-pressed={compact} onClick={() => onChange(true)}>{t("table.density.compact")}</Button>
    <Button variant={!compact ? "primary" : undefined} aria-pressed={!compact} onClick={() => onChange(false)}>{t("table.density.comfortable")}</Button>
  </div>;
}
