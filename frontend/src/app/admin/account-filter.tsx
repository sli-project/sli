import { Select } from "../../design-system/Select";
import { useId } from "react";
import { t } from "../../i18n";

export type AccountFilter = "people" | "service";

/** Only the server's report-key association classifies an account. */
export function filterAccounts<T extends { is_service: boolean }>(users: T[], filter: AccountFilter): T[] {
  return users.filter((user) => (user.is_service === true) === (filter === "service"));
}

export function AccountFilterField({ value, onChange }: { value: AccountFilter; onChange: (value: AccountFilter) => void }) {
  const id = useId();
  return <div className="sli-ds-field">
    <label htmlFor={id}>{t("access.accountFilter.label")}</label>
    <Select label={t("access.accountFilter.label")} id={id} value={value} onChange={(selectedValue) => onChange(selectedValue === "service" ? "service" : "people")}
      options={[{ value: "people", label: t("access.accountFilter.people") }, { value: "service", label: t("access.accountFilter.service") }]}/>
  </div>;
}
