import type { ReactNode } from "react";
import { Label, Radio, RadioGroup } from "react-aria-components";
import { t } from "../i18n";
import { Button } from "./Primitives";

export type PageSize = { value: number; options: number[]; onChange: (size: number) => void };

export function Pager({ pageSize, label, onPrevious, onNext, busy, children }: {
  pageSize?: PageSize;
  label?: ReactNode;
  onPrevious?: () => void;
  onNext?: () => void;
  busy?: boolean;
  children?: ReactNode;
}) {
  return <div className="sli-ds-table__footer">
    {pageSize ? <RadioGroup className="sli-ds-pager__size" orientation="horizontal" value={String(pageSize.value)}
      onChange={(value) => pageSize.onChange(Number(value))}>
      <Label>{t("table.rowsPerPage")}</Label>
      <div className="sli-ds-segments">
        {pageSize.options.map((size) => <Radio className="sli-ds-segment" key={size} value={String(size)}>{size}</Radio>)}
      </div>
    </RadioGroup> : null}
    {children}
    {label != null ? <div className="sli-ds-pager__navigation">
      <Button icon="chevron-left" aria-label={t("table.previous")} disabled={busy || !onPrevious} onClick={onPrevious}/>
      <span aria-live="polite">{label}</span>
      <Button icon="chevron-right" aria-label={t("table.next")} disabled={busy || !onNext} onClick={onNext}/>
    </div> : null}
  </div>;
}
