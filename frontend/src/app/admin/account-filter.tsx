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
    <select id={id} value={value} onChange={(event) => onChange(event.target.value === "service" ? "service" : "people")}>
      <option value="people">{t("access.accountFilter.people")}</option>
      <option value="service">{t("access.accountFilter.service")}</option>
    </select>
  </div>;
}
