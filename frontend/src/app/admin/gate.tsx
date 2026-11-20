import { AccessRequestStateView, useAccessRequest } from "../access-request-state";
import type { ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { PageHeader, StateView } from "../../design-system";
import { useEffectiveAccess } from "../App";

/** Административные страницы требуют возможности; сервер повторяет проверку на каждом запросе. */
export function CapabilityGate({ title, anyOf, label, children }: { title: string; anyOf: string[]; label: string; children: ReactNode }) {
  const access = useEffectiveAccess();
  const accessRequest = useAccessRequest();
  if (!access || accessRequest?.error) return <section className="sli-ds-report"><PageHeader title={title}/><AccessRequestStateView/></section>;
  if (!access.capabilities.some((capability) => anyOf.includes(capability))) {
    return <section className="sli-ds-report"><PageHeader title={title}/>
      <StateView state="denied" detail={<>Нет возможности {label}. <Link to="/access-user">Открыть мой доступ</Link></>}/></section>;
  }
  return <>{children}</>;
}

export { Badge } from "../../design-system/Primitives";
export const Note = ({ title, children }: { title: string; children: ReactNode }) => <div className="sli-ds-state sli-ds-state--banner" data-tone="warning" role="note"><div className="sli-ds-state__title">{title}</div><div className="sli-ds-state__text">{children}</div></div>;
export const FieldError = ({ error }: { error?: Error | null }) => (error ? <p className="sli-ds-field__error" role="alert">{error.message}</p> : null);

export function ChoiceGroup({ legend, options, selected, onToggle }: { legend: string; options: Array<{ key: string; label: string }>; selected: string[]; onToggle: (key: string) => void }) {
  return <fieldset className="sli-ds-choices"><legend>{legend}</legend>
    {options.map((option) => <label key={option.key}><input type="checkbox" checked={selected.includes(option.key)} onChange={() => onToggle(option.key)}/>{option.label}</label>)}
  </fieldset>;
}

export const toggleValue = (values: string[], value: string) => (values.includes(value) ? values.filter((item) => item !== value) : [...values, value]);
