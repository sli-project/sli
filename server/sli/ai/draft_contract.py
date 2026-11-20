"""AI wording is untrusted assistance, never a semantic decision."""
from __future__ import annotations

from typing import Any
import html

# Legacy HTML reports mirror reports.ai.draft_only in frontend/src/i18n.
# Keep runtime independent of TypeScript sources, which are not shipped.
DRAFT_LABELS = {"ru": "черновик ИИ, не решение", "en": "AI draft, not a decision"}


def draft_notice() -> str:
    return (f'<span class="pill" data-ai-draft-label-ru="{html.escape(DRAFT_LABELS["ru"], quote=True)}" '
            f'data-ai-draft-label-en="{html.escape(DRAFT_LABELS["en"], quote=True)}">'
            f'{html.escape(DRAFT_LABELS["ru"])}</span>')


def draft_provenance() -> dict[str, str]:
    """Server-owned provenance applies to every field in the draft envelope."""
    return {"source": "ai", "authority": "draft_only", "confidence": "not_applicable"}


def _draft(value: Any) -> Any:
    if isinstance(value, dict):
        # Discard model-supplied authority and unmeasured confidence at every level.
        return {**{key: _draft(item) for key, item in value.items()
                   if key not in {"provenance", "status", "severity", "risk", "risk_class",
                                  "overall_risk", "confidence"}},
                "provenance": draft_provenance()}
    if isinstance(value, list):
        return [_draft(item) for item in value]
    return value


def as_draft_result(result: dict[str, Any]) -> dict[str, Any]:
    """Normalize new and historical results; job status is server execution metadata."""
    value = {key: result[key] for key in ("job", "ai_call_performed", "validation_errors") if key in result}
    value["status"] = ("completed_with_validation_warnings" if result.get("validation_errors") else "completed") if result.get("ai_call_performed") else "prepared"
    if result.get("status") == "failed":
        value["status"] = "failed"
    if result.get("status") == "prepared_blocked_by_leak_check" and not result.get("ai_call_performed"):
        value["status"] = "prepared_blocked_by_leak_check"
    value["provenance"] = draft_provenance()
    for key in ("analysis", "raw_response"):
        if key in result:
            value[key] = _draft(result[key])
    return value
