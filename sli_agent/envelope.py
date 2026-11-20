# SPDX-License-Identifier: Apache-2.0
"""Canonical, signed ADR-0022 envelopes. Errors contain fixed codes only."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

DOMAIN = b"SLI-AGENT-ENVELOPE-V1\0"
MAX_PACKET_BYTES = 60 * 1024
FIELDS = frozenset({"contract_id", "packet_id", "agent_id", "source_instance_id", "module_id",
    "module_version", "policy_revision", "channel", "generation", "sequence", "cursor_before",
    "cursor_after", "payload_contract", "payload_sha256", "record_count", "payload_bytes",
    "observed_at_utc", "continuity_state", "filtered_count", "lost_count"})


class EnvelopeError(ValueError):
    pass


def canonical(value) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False).encode("ascii")
    except (ValueError, TypeError, RecursionError):
        raise EnvelopeError("agent_packet_invalid") from None


def timestamp(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.utcoffset() is None or result.utcoffset().total_seconds() != 0:
            raise ValueError()
        return result
    except (ValueError, TypeError, AttributeError):
        raise EnvelopeError("agent_packet_invalid") from None


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def validate_envelope(envelope):
    def require(condition):
        if not condition:
            raise EnvelopeError("agent_packet_invalid")
    require(isinstance(envelope, dict) and set(envelope) == FIELDS)
    require(envelope["contract_id"] == "sli.agent-envelope.v1")
    for name in ("packet_id", "agent_id", "source_instance_id", "module_id", "module_version",
                 "policy_revision", "channel", "generation", "payload_contract"):
        require(isinstance(envelope[name], str) and 0 < len(envelope[name]) <= 512)
    try:
        require(str(UUID(envelope["agent_id"])) == envelope["agent_id"])
        require(str(UUID(envelope["packet_id"])) == envelope["packet_id"])
    except ValueError:
        raise EnvelopeError("agent_packet_invalid") from None
    for name in ("module_id", "payload_contract"):
        require(re.fullmatch(r"[a-z][a-z0-9_.-]{0,127}", envelope[name]) is not None)
    require(re.fullmatch(r"\d+\.\d+\.\d+", envelope["module_version"]) is not None)
    require(isinstance(envelope["payload_sha256"], str) and
            re.fullmatch(r"[0-9a-f]{64}", envelope["payload_sha256"]) is not None)
    for name in ("sequence", "record_count", "payload_bytes", "filtered_count"):
        require(type(envelope[name]) is int and 0 <= envelope[name] <= 2**63 - 1)
    require(envelope["sequence"] > 0)
    require(envelope["lost_count"] is None or type(envelope["lost_count"]) is int and envelope["lost_count"] >= 0)
    require(envelope["continuity_state"] in ("complete", "not_proven", "gap", "filtered"))
    for name in ("cursor_before", "cursor_after"):
        cursor = envelope[name]
        require(isinstance(cursor, dict) and set(cursor) == {"strategy", "token"})
        require(cursor["strategy"] in ("record_id", "bookmark", "file_offset", "snapshot"))
        require(isinstance(cursor["token"], str) and len(cursor["token"]) <= 4096)
    timestamp(envelope["observed_at_utc"])
    return envelope


def make_packet(key, *, agent_id, sequence, sample, now=None):
    payload = sample.payload
    envelope = {"contract_id": "sli.agent-envelope.v1", "packet_id": str(uuid4()),
        "agent_id": agent_id, "source_instance_id": sample.source_instance_id,
        "module_id": sample.module_id, "module_version": sample.module_version,
        "policy_revision": sample.policy_revision, "channel": sample.channel,
        "generation": sample.generation, "sequence": sequence,
        "cursor_before": sample.cursor_before, "cursor_after": sample.cursor_after,
        "payload_contract": payload["contract"], "payload_sha256": digest(payload),
        "record_count": len(payload.get("records", [])), "payload_bytes": len(canonical(payload)),
        "observed_at_utc": (now or datetime.now(timezone.utc)).isoformat(),
        "continuity_state": sample.continuity_state, "filtered_count": sample.filtered_count,
        "lost_count": sample.lost_count}
    validate_envelope(envelope)
    raw = DOMAIN + canonical(envelope)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        signature = key.sign(raw, ec.ECDSA(hashes.SHA256()))
    elif isinstance(key, rsa.RSAPrivateKey):
        signature = key.sign(raw, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                             salt_length=padding.PSS.DIGEST_LENGTH), hashes.SHA256())
    else:
        raise EnvelopeError("agent_key_unsupported")
    packet = {"envelope": envelope, "payload": payload, "signature": base64.b64encode(signature).decode("ascii")}
    if len(canonical(packet)) > MAX_PACKET_BYTES:
        raise EnvelopeError("agent_packet_size_limit")
    return packet


def verify_packet(packet, public_key):
    if not isinstance(packet, dict) or set(packet) != {"envelope", "payload", "signature"}:
        raise EnvelopeError("agent_packet_invalid")
    if len(canonical(packet)) > MAX_PACKET_BYTES:
        raise EnvelopeError("agent_packet_size_limit")
    envelope = validate_envelope(packet["envelope"])
    payload = packet["payload"]
    if (not isinstance(payload, dict) or payload.get("contract") != envelope["payload_contract"]
            or digest(payload) != envelope["payload_sha256"] or len(canonical(payload)) != envelope["payload_bytes"]
            or not isinstance(payload.get("records", []), list)
            or len(payload.get("records", [])) != envelope["record_count"]):
        raise EnvelopeError("agent_payload_hash_mismatch")
    try:
        signature = base64.b64decode(packet["signature"], validate=True)
        raw = DOMAIN + canonical(envelope)
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, raw, ec.ECDSA(hashes.SHA256()))
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, raw, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                              salt_length=padding.PSS.DIGEST_LENGTH), hashes.SHA256())
        else:
            raise ValueError()
    except (InvalidSignature, ValueError, TypeError):
        raise EnvelopeError("agent_signature_invalid") from None
    return envelope
