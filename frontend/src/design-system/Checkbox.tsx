import type { InputHTMLAttributes, ReactNode } from "react";

export function Checkbox({ children, className, onClick, indeterminate = false, ...props }: Omit<InputHTMLAttributes<HTMLInputElement>, "type"> & { children?: ReactNode; indeterminate?: boolean }) {
  return <label onClick={onClick ? (event) => event.stopPropagation() : undefined} className={className ? `sli-ds-check ${className}` : "sli-ds-check"}>
    <input {...props} ref={input => { if (input) input.indeterminate = indeterminate; }} onClick={onClick} type="checkbox"/>
    {children}
  </label>;
}
