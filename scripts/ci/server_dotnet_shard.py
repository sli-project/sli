"""Run and verify one shard of the server xUnit PR or nightly suite."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

if __package__:
    from .shard_balance import balance, estimated_weights, read_durations
else:
    from shard_balance import balance, estimated_weights, read_durations


def read_rules(path: Path) -> list[list[str]]:
    return [
        entry.split()
        for line in path.read_text(encoding="utf-8").splitlines()
        if (entry := line.partition("#")[0].strip())
    ]


def plan_profiles(cases: list[dict], exclusions: list[list[str]], rules: list[list[str]]) -> dict[str, Counter]:
    excluded = {tuple(rule) for rule in exclusions}
    weights: Counter = Counter()
    default_methods: set[str] = set()
    targets: dict[tuple[str, str], set[str]] = defaultdict(set)
    for case in cases:
        class_name = case["Class"]
        method = f'{class_name}.{case["Method"]}'
        if ("class", class_name) in excluded or ("method", method) in excluded:
            continue
        targets["class", class_name].add(method)
        targets["method", method].add(method)
        namespace = class_name
        while "." in namespace:
            namespace = namespace.rsplit(".", 1)[0]
            targets["namespace", namespace].add(method)
        weights[method] += 1
        if not case["Explicit"]:
            default_methods.add(method)

    profiles = {label: set() for label in ("load", "outside-beta", "security")}
    for label, kind, name in rules:
        if (kind, name) not in targets:
            raise ValueError(f"CI profile rule matches no runnable test: {label} {kind} {name}")
        profiles[label].update(targets[kind, name])

    nightly_only = profiles["load"] | profiles["outside-beta"]
    missing_security = profiles["security"] - (default_methods - nightly_only)
    if missing_security:
        raise ValueError(f"Security tests missing from PR: {', '.join(sorted(missing_security))}")
    return {
        "pr": Counter({name: weights[name] for name in default_methods - nightly_only}),
        "nightly": Counter({name: weights[name] for name in default_methods | nightly_only}),
        "nightly-only": Counter({name: weights[name] for name in nightly_only}),
        "security": Counter({name: weights[name] for name in profiles["security"]}),
    }


def shard_methods(
    methods: Counter, shard: int, count: int, *,
    keep_classes: bool = True, durations: dict[str, float] | None = None,
) -> set[str]:
    groups: dict[str, set[str]] = defaultdict(set)
    weights: Counter = Counter()
    for method in methods:
        name = method.rsplit(".", 1)[0]
        group = name if keep_classes else method
        groups[group].add(method)
        database = any(word in name for word in ("Postgres", "Database", "Benchmark"))
        weights[group] += methods[method] * (4 if database else 1)
    if not 1 <= shard <= count:
        raise ValueError("invalid shard count")
    if keep_classes and durations:
        weights = estimated_weights(groups, durations)
    selected_groups = balance(weights, count)[shard - 1]
    return {method for group in selected_groups for method in groups[group]}


def verify_results(results: Path, selected: set[str]) -> None:
    root = ET.parse(results).getroot()
    assemblies = root.findall("assembly")
    if not assemblies or any(
        int(assembly.get(status, "0"))
        for assembly in assemblies
        for status in ("failed", "errors", "skipped", "not-run")
    ):
        raise ValueError("Server tests failed, were skipped, or did not run")
    passed = {
        f"{test.get('type')}.{test.get('method')}"
        for test in root.iter("test") if test.get("result") == "Pass"
    }
    if missing := selected - passed:
        raise ValueError(f"Server test methods without passing cases: {', '.join(sorted(missing))}")
    if unexpected := passed - selected:
        raise ValueError(f"Unexpected server test methods: {', '.join(sorted(unexpected))}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("shard", type=int)
    parser.add_argument("count", type=int)
    parser.add_argument("--profile", choices=("pr", "nightly"), default="pr")
    parser.add_argument("--split-classes", action="store_true", help="Balance methods across isolated runners")
    parser.add_argument("--describe", action="store_true", help="List profile classes and shard sizes without running tests")
    args = parser.parse_args()

    command = [os.environ.get("DOTNET_HOST_PATH", "dotnet"), "run", "--project",
               "tests/Sli.Server.Tests/Sli.Server.Tests.csproj", "--no-build", "--"]
    discovery = subprocess.run(
        [*command, "-list", "full/json", "-noColor", "-preEnumerateTheories"],
        check=True, stdout=subprocess.PIPE,
    )
    directory = Path(__file__).parent
    profiles = plan_profiles(
        json.loads(discovery.stdout),
        read_rules(directory / "server_dotnet_exclusions.txt"),
        read_rules(directory / "server_dotnet_ci_profiles.txt"),
    )
    methods = profiles[args.profile]
    # Keep tests from the same xUnit class together unless explicitly split.
    keep_classes = not args.split_classes
    durations = read_durations(directory / "server_test_durations.json") if args.profile == "pr" else {}
    if args.profile == "pr" and keep_classes and not durations:
        print("No historical server durations available; using discovery weights", flush=True)
    selected = shard_methods(methods, args.shard, args.count, keep_classes=keep_classes, durations=durations)
    if args.describe:
        for label in ("nightly-only", "security"):
            classes = {method.rsplit(".", 1)[0] for method in profiles[label]}
            print(f"{label} ({len(classes)} classes):")
            print(*sorted(classes), sep="\n")
        for shard in range(1, args.count + 1):
            names = shard_methods(methods, shard, args.count, keep_classes=keep_classes, durations=durations)
            print(f"{args.profile} shard {shard}/{args.count}: {len(names)} methods, "
                  f"{sum(methods[name] for name in names)} discovered cases")
        return

    results = Path("server-dotnet-results.xml")
    results.unlink(missing_ok=True)
    for method in sorted(selected):
        command.extend(("-method", method))
    if args.profile == "nightly":
        command.extend(("-explicit", "on"))
    command.extend((
        "-failSkips", "-noColor", "-noAutoReporters", "-reporter", "verbose",
        "-longRunning", "300", "-result-xml", str(results),
    ))
    print(f"Server {args.profile} shard {args.shard}/{args.count}: {len(selected)} methods", flush=True)
    subprocess.run(command, check=True)
    verify_results(results, selected)


if __name__ == "__main__":
    main()
