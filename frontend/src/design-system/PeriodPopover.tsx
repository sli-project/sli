import type { ReactNode, Ref } from "react";
import { t } from "../i18n";
import { Icon } from "./Icon";

export function PeriodPopover({ label, fieldLabel = t("period.label"), children, onDismiss, pickerRef }: {
  label: string;
  fieldLabel?: string;
  children: ReactNode;
  onDismiss?: () => void;
  pickerRef?: Ref<HTMLDetailsElement>;
}) {
  return <details className="sli-ds-header__period" ref={pickerRef}
    onToggle={(event) => { if (!event.currentTarget.open) onDismiss?.(); }}
    onKeyDown={(event) => {
      const picker = event.currentTarget;
      if (event.key !== "Escape" || !picker.open) return;
      event.stopPropagation();
      picker.open = false;
      picker.querySelector("summary")?.focus();
    }}>
    <summary className="sli-ds-button" aria-label={fieldLabel + " · " + label}>
      <Icon name="calendar"/><span>{label}</span><Icon name="chevron-down"/>
    </summary>
    <div className="sli-ds-header__period-menu">{children}</div>
  </details>;
}
