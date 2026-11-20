import { useState } from "react";
import { t } from "../i18n";

/** Identifiers remain available verbatim for investigation and copying. */
export function TechnicalKey({ value, label }: { value: string; label: string }) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  };
  return <details onClick={(event) => event.stopPropagation()}>
    <summary>{label}</summary>
    <code style={{ overflowWrap: "anywhere" }}>{value}</code>{" "}
    <button type="button" className="sli-ds-button" onClick={() => void copy()}>{t(copyState === "copied" ? "entities.key.copied" : "entities.key.copy")}</button>
    {copyState === "failed" ? <span role="status">{t("entities.key.copyFailed")}</span> : null}
  </details>;
}
