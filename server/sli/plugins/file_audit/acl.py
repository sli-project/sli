"""Conservative SDDL access masks; unsupported ACEs never become allow grants."""
from dataclasses import dataclass
import re

ALIASES = {"WD": "S-1-1-0", "AU": "S-1-5-11", "SY": "S-1-5-18", "BA": "S-1-5-32-544",
           "BU": "S-1-5-32-545", "AN": "S-1-5-7", "CO": "S-1-3-0", "CG": "S-1-3-1"}
RIGHTS = {"FA": 0x1f01ff, "FR": 0x120089, "FW": 0x120116, "FX": 0x1200a0,
          "SD": 0x10000, "RC": 0x20000, "WD": 0x40000, "WO": 0x80000,
          "GA": 0x1f01ff, "GR": 0x120089, "GW": 0x120116, "GX": 0x1200a0}
WRITE_MASK = 0x6 | 0x40 | 0x10000 | 0x40000 | 0x80000


def mapped_mask(mask):
    for flag, key in ((0x10000000, "GA"), (0x80000000, "GR"), (0x40000000, "GW"), (0x20000000, "GX")):
        if mask & flag:
            mask = (mask & ~flag) | RIGHTS[key]
    return mask


@dataclass(frozen=True)
class Ace:
    kind: str
    sid: str
    mask: int
    inherited: bool
    inherit_only: bool


def parse_dacl(sddl):
    """Return ACEs and completeness; NULL/conditional/object ACLs need review."""
    if not isinstance(sddl, str) or len(sddl) > 65536 or not sddl.startswith("D:"):
        return (), False
    header = sddl[2:].split("(", 1)[0]
    if not re.fullmatch(r"(?:P|AI|AR)*", header):
        return (), False
    aces, position = [], len(header) + 2
    for match in re.finditer(r"\(([^()]*)\)", sddl):
        if match.start() != position:
            return (), False
        fields = match[1].split(";")
        if len(fields) != 6:
            return (), False
        kind, flags, rights, object_guid, inherit_guid, sid = fields
        if kind not in ("A", "D") or object_guid or inherit_guid:
            return (), False
        pairs = [flags[i:i + 2] for i in range(0, len(flags), 2)]
        if any(flag not in ("OI", "CI", "NP", "IO", "ID") for flag in pairs):
            return (), False
        sid = ALIASES.get(sid, sid)
        if not re.fullmatch(r"S-1-(?:[0-9]+-)*[0-9]+", sid):
            return (), False
        try:
            if rights.startswith("0x"):
                mask = int(rights, 16)
            else:
                mask = 0
                for i in range(0, len(rights), 2):
                    mask |= RIGHTS[rights[i:i + 2]]
            if not 0 <= mask <= 0xffffffff:
                raise ValueError
        except (ValueError, KeyError):
            return (), False
        aces.append(Ace(kind, sid, mapped_mask(mask), "ID" in pairs, "IO" in pairs))
        position = match.end()
    return tuple(aces), position == len(sddl)


def access_mask(aces, token):
    """Evaluate the actual ACE order. Deny applies only to unresolved bits."""
    allowed, denied = 0, 0
    for ace in aces:
        if ace.inherit_only or ace.sid not in token:
            continue
        if ace.kind == "D":
            denied |= ace.mask & ~allowed
        else:
            allowed |= ace.mask & ~denied
    return allowed


def token_for(sid, principal, local_groups):
    token = {sid, "S-1-1-0"}
    complete = principal.get("complete") is True and local_groups.get("complete") is True
    if complete:
        token.update(principal.get("group_sids", ()))
        if sid != "S-1-5-7":
            token.add("S-1-5-11")
    groups = local_groups.get("groups", ())
    for _ in range(len(groups) + 1):
        previous = set(token)
        token.update(group["group_sid"] for group in groups if token.intersection(group["member_sids"]))
        if token == previous:
            break
    return token, complete
