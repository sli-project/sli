"""Run one Linux CI shard of the existing server xUnit suite."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET


def shard_classes(classes: list[str], shard: int, count: int) -> list[str]:
    if not 1 <= shard <= count <= len(classes) or len(set(classes)) != len(classes):
        raise ValueError("invalid shard or duplicate test classes")
    # Spread the classes named for database fixtures across the runners.
    ordered = sorted(classes, key=lambda name: (
        not any(word in name for word in ("Postgres", "Database", "Benchmark")), name,
    ))
    return ordered[shard - 1::count]


def plan_shard(
    cases: list[dict],
    excluded_classes: set[str],
    excluded_methods: set[str],
    shard: int,
    count: int,
) -> tuple[list[str], set[str]]:
    required_classes: set[str] = set()
    required_methods: set[str] = set()
    explicit_methods: set[str] = set()
    for case in cases:
        class_name = case["Class"]
        method = f'{class_name}.{case["Method"]}'
        if class_name in excluded_classes or method in excluded_methods:
            continue
        if case["Explicit"]:
            explicit_methods.add(method)
        else:
            required_classes.add(class_name)
            required_methods.add(method)
    selected = shard_classes(list(required_classes), shard, count)
    # Keep manually requested xUnit profiles out of the default run.
    return selected, excluded_methods | (explicit_methods - required_methods)


def verify_results(results: Path, selected: list[str]) -> None:
    root = ET.parse(results).getroot()
    assemblies = root.findall("assembly")
    if not assemblies or any(
        int(assembly.get(status, "0"))
        for assembly in assemblies
        for status in ("failed", "errors", "skipped", "not-run")
    ):
        raise ValueError("Server tests failed, were skipped, or did not run")
    passed = {test.get("type") for test in root.iter("test") if test.get("result") == "Pass"}
    missing = set(selected) - passed
    if missing:
        raise ValueError(f"Server test classes without passing cases: {', '.join(sorted(missing))}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("shard", type=int)
    parser.add_argument("count", type=int)
    args = parser.parse_args()
    exclusions = {"class": set(), "method": set()}
    manifest = Path(__file__).with_name("server_dotnet_exclusions.txt")
    for line in manifest.read_text(encoding="utf-8").splitlines():
        entry = line.partition("#")[0].strip()
        if entry:
            kind, name = entry.split()
            exclusions[kind].add(name)

    results = Path("server-dotnet-results.xml")
    results.unlink(missing_ok=True)
    command = [os.environ.get("DOTNET_HOST_PATH", "dotnet"), "run", "--project",
               "tests/Sli.Server.Tests/Sli.Server.Tests.csproj", "--no-build", "--"]
    discovery = subprocess.run(
        [*command, "-list", "full/json", "-noColor"], check=True, stdout=subprocess.PIPE,
    )
    selected, omit_methods = plan_shard(
        json.loads(discovery.stdout), exclusions["class"], exclusions["method"], args.shard, args.count,
    )
    for method in sorted(omit_methods):
        command.extend(("-method-", method))
    for name in selected:
        command.extend(("-class", name))
    command.extend((
        "-failSkips", "-noColor", "-noAutoReporters", "-reporter", "verbose",
        "-longRunning", "300", "-result-xml", str(results),
    ))
    print(f"Server test shard {args.shard}/{args.count}: {len(selected)} classes", flush=True)
    subprocess.run(command, check=True)
    verify_results(results, selected)


if __name__ == "__main__":
    main()
