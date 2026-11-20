"""Structured, read-only Active Directory context integration."""

from server.ad_context.contracts import validate_bundle
from server.ad_context.enrichment import explain_privileged_membership_event

__all__ = ["explain_privileged_membership_event", "validate_bundle"]
