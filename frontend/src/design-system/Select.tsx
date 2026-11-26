import { Button, ListBox, ListBoxItem, Popover, Select as AriaSelect, SelectValue } from "react-aria-components";
import { Icon } from "./Icon";

type Option = { value: string | number; label: string; disabled?: boolean };

/** Styled menu with keyboard selection and support for ordinary form submissions. */
export function Select({ label, options, value, defaultValue, onChange, disabled, required, name, id, "aria-describedby": describedBy, "aria-invalid": invalid, multiple }: {
  label: string;
  options: Option[];
  disabled?: boolean;
  required?: boolean;
  name?: string;
  id?: string;
  "aria-describedby"?: string;
  "aria-invalid"?: boolean;
} & ({
  multiple?: false;
  value?: string | number;
  defaultValue?: string | number;
  onChange?: (value: string) => void;
} | {
  multiple: true;
  value: string[];
  defaultValue?: never;
  onChange: (value: string[]) => void;
})) {
  return <AriaSelect className="sli-ds-select" aria-label={label} name={name} isDisabled={disabled} isRequired={required}
    selectionMode={multiple ? "multiple" : "single"} value={value == null || Array.isArray(value) ? value : String(value)}
    defaultValue={defaultValue == null ? undefined : String(defaultValue)} isInvalid={invalid} validationBehavior="native"
    onChange={(next) => {
      if (multiple) onChange(Array.isArray(next) ? next.map(String) : []);
      else onChange?.(next == null ? "" : String(next));
    }}>
    <Button id={id} aria-describedby={describedBy} className="sli-ds-button sli-ds-select__trigger">
      <SelectValue className="sli-ds-select__value">{({ selectedText }) => selectedText || label}</SelectValue>
      <Icon name="chevron-down"/>
    </Button>
    <Popover className="sli-ds-suggestions sli-ds-select__menu">
      <ListBox className="sli-ds-suggestions__list" items={options}>
        {(option) => <ListBoxItem id={String(option.value)} textValue={option.label} isDisabled={option.disabled} className="sli-ds-suggestions__item">
          {option.label}
        </ListBoxItem>}
      </ListBox>
    </Popover>
  </AriaSelect>;
}
