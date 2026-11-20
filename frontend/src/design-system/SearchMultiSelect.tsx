import { useEffect, useMemo, useState } from "react";
import { ComboBox, Input, Label, ListBox, ListBoxItem, Popover } from "react-aria-components";
import { t } from "../i18n";
import { Button } from "./Primitives";

export type SearchOption = { value: string; label: string; important?: boolean };

/** One searchable control with removable selections and bounded suggestions. */
export function SearchMultiSelect({ label, options, values, onChange }: {
  label: string; options: SearchOption[]; values: string[]; onChange: (values: string[]) => void;
}) {
  const [search, setSearch] = useState("");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [recent, setRecent] = useState<string[]>([]);
  useEffect(() => {
    if (selectedKey !== null && !values.includes(selectedKey)) setSelectedKey(null);
  }, [selectedKey, values]);
  const suggestions = useMemo(() => {
    const query = search.trim().toLocaleLowerCase();
    const rank = (option: SearchOption) => option.important ? -1 : recent.includes(option.value) ? recent.indexOf(option.value) : Infinity;
    return options.filter((option) => !values.includes(option.value) && option.label.toLocaleLowerCase().includes(query))
      .sort((a, b) => rank(a) - rank(b) || a.label.localeCompare(b.label)).slice(0, 50);
  }, [options, values, search, recent]);
  return <div className="sli-ds-field" data-kind="search-multiselect">
    <ComboBox inputValue={search} onInputChange={setSearch} selectedKey={selectedKey} menuTrigger="focus"
      allowsCustomValue allowsEmptyCollection items={suggestions} onSelectionChange={(key) => {
        if (key === null) return;
        const value = String(key);
        if (values.includes(value)) return;
        setSelectedKey(value);
        onChange([...values, value]);
        setRecent((current) => [value, ...current.filter((item) => item !== value)].slice(0, 20));
        setSearch("");
      }}>
      <Label>{label}</Label>
      <Input type="search" placeholder={t("filters.search")}/>
      <Popover className="sli-ds-suggestions" isNonModal>
        <ListBox className="sli-ds-suggestions__list" renderEmptyState={() => t("filters.no_matches")}>
          {(option: SearchOption) => <ListBoxItem id={option.value} textValue={option.label} className="sli-ds-suggestions__item">
            {option.important ? <span aria-label={t("filters.important")}>★ </span> : null}{option.label}
          </ListBoxItem>}
        </ListBox>
      </Popover>
    </ComboBox>
    {values.length ? <div className="sli-ds-header__meta" aria-label={t("filters.selected", { label })}>
      {values.map((value) => {
        const text = options.find((option) => option.value === value)?.label ?? value;
        return <Button key={value} className="sli-ds-chip" aria-label={t("filters.remove", { label: text })} onClick={() => onChange(values.filter((item) => item !== value))}>
          {text}<span aria-hidden="true"> ×</span>
        </Button>;
      })}
    </div> : null}
  </div>;
}
