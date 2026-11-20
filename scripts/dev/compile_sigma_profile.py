"""Compile the pinned Sigma profile offline; print only IDs, hashes and reasons."""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

from scripts.dev.verify_sigma_package import CONFIG, verify_package
from server.sli.sigma.compiler import COMPILER_VERSION, IR_VERSION, CompiledRule, UnsupportedRule, compile_rule


@dataclass(frozen=True)
class UnsupportedEntry:
    rule_id: str
    reason: str


@dataclass(frozen=True, repr=False)
class ProfileCompilation:
    compiled: tuple[CompiledRule, ...]
    unsupported: tuple[UnsupportedEntry, ...]

    def summary(self) -> dict:
        return {
            "compiler_version": COMPILER_VERSION,
            "ir_version": IR_VERSION,
            "compiled": [{"rule_id": rule.rule_id, "source_sha256": rule.source_sha256,
                          "plan_sha256": rule.plan_sha256} for rule in self.compiled],
            "unsupported": [{"rule_id": rule.rule_id, "reason": rule.reason} for rule in self.unsupported],
        }


def compile_profile(archive: Path, config: Path = CONFIG) -> ProfileCompilation:
    # Integrity, UUIDs and attribution are checked before any compilation.
    rules = verify_package(archive, config)
    compiled = []
    unsupported = []
    for rule in rules:
        try:
            plan = compile_rule(rule.raw_yaml, source_uri=rule.source_uri,
                                upstream_commit=rule.upstream_commit, license_id=rule.license)
        except UnsupportedRule as error:
            unsupported.append(UnsupportedEntry(rule.id, str(error)))
        else:
            compiled.append(plan)
    return ProfileCompilation(tuple(compiled), tuple(unsupported))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = compile_profile(args.archive)
    except Exception:
        print("Sigma stage 04: FAILED (package, manifest or parser mismatch)")
        return 1
    print(json.dumps(result.summary(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
