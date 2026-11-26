import type { InputHTMLAttributes, ReactNode } from "react";

export function Checkbox({ children, className, onClick, ...props }: Omit<InputHTMLAttributes<HTMLInputElement>, "type"> & { children?: ReactNode }) {
  return <label onClick={onClick ? (event) => event.stopPropagation() : undefined} className={className ? `sli-ds-check ${className}` : "sli-ds-check"}>
    <input {...props} onClick={onClick} type="checkbox"/>
    {children}
  </label>;
}
